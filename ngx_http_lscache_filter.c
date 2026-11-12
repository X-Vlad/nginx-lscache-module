/*
 * ngx_http_lscache_filter.c - response header + body capture.
 *
 * Header filter:
 *   - Parse X-LiteSpeed-Cache-Control tokens into ctx->cc_flags + max_age.
 *   - Parse X-LiteSpeed-Tag into ctx->tags[].
 *   - Capture LSC-Cookie into ctx->lsc_cookie. Materialize as Set-Cookie
 *     on the outgoing response.
 *   - Capture X-LiteSpeed-Purge (response form) into ctx->inline_purge and
 *     execute it immediately (inline purge from a backend response).
 *   - Strip X-LiteSpeed-*, LSC-Cookie from the outgoing response (hash=0).
 *   - Detect Set-Cookie. If present without LSC-Cookie, refuse to cache
 *     (session-leak guard: Set-Cookie is the canonical way to leak
 *     auth state between clients via a shared cache).
 *   - Decide capturing based on cc_flags, method, min_age/max_age clamps.
 *   - Emit X-LiteSpeed-Cache: miss / no-cache.
 *
 * Body filter:
 *   - When ctx->capturing: open tmp_fd on first chunk, write a placeholder
 *     24-byte header, then mirror each in-memory / in-file buffer.
 *   - On last_buf: rewrite the header with real body_len + status + flags
 *     + expires. Then, in this order: write the .meta sidecar, the
 *     index markers (hosts/, tags/, vary/), and last rename(2) the data
 *     file into place, so nothing servable lacks its headers or its
 *     purge markers.
 *   - On error or aborted request: unlink tmp via the cleanup handler.
 */

#include "ngx_http_lscache_module.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>


static ngx_http_output_header_filter_pt  next_header_filter;
static ngx_http_output_body_filter_pt    next_body_filter;


/* ═══════════════════════════════════════════════════════════════════════════
 * Forward declarations (file-local helpers)
 * ═══════════════════════════════════════════════════════════════════════ */

static void lsc_parse_cache_control(ngx_str_t *value,
    ngx_uint_t *cc_flags, time_t *max_age);
static void lsc_parse_tags(ngx_http_request_t *r, ngx_str_t *value,
    ngx_http_lsc_ctx_t *ctx);
static void lsc_strip_and_collect(ngx_http_request_t *r,
    ngx_http_lsc_ctx_t *ctx);
static ngx_int_t lsc_emit_status_header(ngx_http_request_t *r,
    ngx_http_lsc_ctx_t *ctx, int want_no_cache);
static ngx_int_t lsc_materialize_lsc_cookie(ngx_http_request_t *r,
    ngx_http_lsc_ctx_t *ctx);
static ngx_int_t lsc_setup_capture(ngx_http_request_t *r,
    ngx_http_lsc_ctx_t *ctx);
static ngx_int_t lsc_collect_headers(ngx_http_request_t *r,
    ngx_http_lsc_ctx_t *ctx);
static ngx_int_t lsc_write_meta(ngx_http_request_t *r,
    ngx_http_lsc_ctx_t *ctx);
static void lsc_write_refs(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx);


/* ═══════════════════════════════════════════════════════════════════════════
 * Filter wiring (called from postconfigure)
 * ═══════════════════════════════════════════════════════════════════════ */

void
lsc_filters_install(void)
{
    next_header_filter         = ngx_http_top_header_filter;
    ngx_http_top_header_filter = lsc_header_filter;

    next_body_filter           = ngx_http_top_body_filter;
    ngx_http_top_body_filter   = lsc_body_filter;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Parse a comma-separated X-LiteSpeed-Cache-Control header.
 * ═══════════════════════════════════════════════════════════════════════ */

static void
lsc_parse_cache_control(ngx_str_t *value, ngx_uint_t *cc_flags,
    time_t *max_age)
{
    u_char *p, *end, *tok, *tend;
    size_t  tl;

    p   = value->data;
    end = value->data + value->len;

    while (p < end) {
        while (p < end && (*p == ' ' || *p == ',' || *p == '\t')) p++;
        if (p >= end) break;

        tok = p;
        while (p < end && *p != ',') p++;
        tend = p;
        while (tend > tok && (tend[-1] == ' ' || tend[-1] == '\t')) tend--;
        tl = tend - tok;
        if (tl == 0) continue;

        if (tl == 8 && ngx_strncasecmp(tok, (u_char *)"no-cache", 8) == 0) {
            *cc_flags |= LSC_CC_NO_CACHE;
        } else if (tl == 8
                   && ngx_strncasecmp(tok, (u_char *)"no-store", 8) == 0)
        {
            *cc_flags |= LSC_CC_NO_STORE;
        } else if (tl == 6
                   && ngx_strncasecmp(tok, (u_char *)"public", 6) == 0)
        {
            *cc_flags |= LSC_CC_PUBLIC;
        } else if (tl == 7
                   && ngx_strncasecmp(tok, (u_char *)"private", 7) == 0)
        {
            *cc_flags |= LSC_CC_PRIVATE;
        } else if (tl == 7
                   && ngx_strncasecmp(tok, (u_char *)"no-vary", 7) == 0)
        {
            *cc_flags |= LSC_CC_NO_VARY;
        } else if (tl > 8
                   && ngx_strncasecmp(tok, (u_char *)"max-age=", 8) == 0)
        {
            ngx_int_t age = ngx_atoi(tok + 8, tl - 8);
            if (age != NGX_ERROR && age > 0) {
                *max_age = age;
                *cc_flags |= LSC_CC_HAS_MAX_AGE;
            }
        } else if (tl > 9
                   && ngx_strncasecmp(tok, (u_char *)"s-maxage=", 9) == 0)
        {
            ngx_int_t age = ngx_atoi(tok + 9, tl - 9);
            if (age != NGX_ERROR && age > 0
                && !(*cc_flags & LSC_CC_HAS_MAX_AGE))
            {
                *max_age = age;
                *cc_flags |= LSC_CC_HAS_MAX_AGE;
            }
        } else if ((tl == 3 && ngx_strncasecmp(tok, (u_char *)"esi", 3) == 0)
                   || (tl >= 4
                       && ngx_strncasecmp(tok, (u_char *)"esi=", 4) == 0))
        {
            *cc_flags |= LSC_CC_ESI;
        }
        /* unknown tokens (e.g. "max-stale") are silently ignored */
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Parse a comma-separated X-LiteSpeed-Tag header into ctx->tags[].
 * ═══════════════════════════════════════════════════════════════════════ */

static void
lsc_parse_tags(ngx_http_request_t *r, ngx_str_t *value,
    ngx_http_lsc_ctx_t *ctx)
{
    u_char *p, *end, *tok, *tend, *copy;
    size_t  tl;
    ngx_str_t tag_check;

    p   = value->data;
    end = value->data + value->len;

    while (p < end && ctx->ntags < LSC_MAX_TAGS) {
        while (p < end && (*p == ' ' || *p == ',' || *p == '\t')) p++;
        if (p >= end) break;

        tok = p;
        while (p < end && *p != ',') p++;
        tend = p;
        while (tend > tok && (tend[-1] == ' ' || tend[-1] == '\t')) tend--;

        /* drop the optional "public:" prefix (LiteSpeed marks a tag as
         * public-side even on a private-cache entry; we collapse it). */
        if (tend - tok > 7
            && ngx_strncasecmp(tok, (u_char *)"public:", 7) == 0)
        {
            tok += 7;
        }

        tl = tend - tok;
        if (tl == 0 || tl > LSC_MAX_TAG_LEN) continue;

        tag_check.data = tok;
        tag_check.len  = tl;
        if (lsc_safe_name(&tag_check) != NGX_OK) continue;

        copy = ngx_pnalloc(r->pool, tl);
        if (copy == NULL) continue;
        ngx_memcpy(copy, tok, tl);
        ctx->tags[ctx->ntags].data = copy;
        ctx->tags[ctx->ntags].len  = tl;
        ctx->ntags++;
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Walk headers_out and collect protocol fields into ctx, then strip them.
 *
 * Set hash=0 to hide a header from the outgoing response. We collect the
 * value into ctx->* (allocated in r->pool, since the header's memory may be
 * reused) so that later phases / body filter still see them.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_str_t
lsc_pool_dup(ngx_pool_t *pool, ngx_str_t src)
{
    ngx_str_t  out;
    out.data = ngx_pnalloc(pool, src.len);
    if (out.data == NULL) { out.len = 0; return out; }
    ngx_memcpy(out.data, src.data, src.len);
    out.len = src.len;
    return out;
}


static void
lsc_strip_and_collect(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t       i;

    part = &r->headers_out.headers.part;
    h    = part->elts;
    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; h = part->elts; i = 0;
        }
        if (h[i].hash == 0) continue;

        if (h[i].key.len == sizeof("X-LiteSpeed-Cache-Control") - 1
            && ngx_strncasecmp(h[i].key.data,
                (u_char *)"X-LiteSpeed-Cache-Control",
                sizeof("X-LiteSpeed-Cache-Control") - 1) == 0)
        {
            lsc_parse_cache_control(&h[i].value, &ctx->cc_flags,
                                     &ctx->max_age);
            h[i].hash = 0;

        } else if (h[i].key.len == sizeof("X-LiteSpeed-Tag") - 1
                   && ngx_strncasecmp(h[i].key.data,
                       (u_char *)"X-LiteSpeed-Tag",
                       sizeof("X-LiteSpeed-Tag") - 1) == 0)
        {
            lsc_parse_tags(r, &h[i].value, ctx);
            h[i].hash = 0;

        } else if (h[i].key.len == sizeof("X-LiteSpeed-Vary") - 1
                   && ngx_strncasecmp(h[i].key.data,
                       (u_char *)"X-LiteSpeed-Vary",
                       sizeof("X-LiteSpeed-Vary") - 1) == 0)
        {
            ctx->vary_directive = lsc_pool_dup(r->pool, h[i].value);
            h[i].hash = 0;

        } else if (h[i].key.len == sizeof("X-LiteSpeed-Purge") - 1
                   && ngx_strncasecmp(h[i].key.data,
                       (u_char *)"X-LiteSpeed-Purge",
                       sizeof("X-LiteSpeed-Purge") - 1) == 0)
        {
            ctx->inline_purge = lsc_pool_dup(r->pool, h[i].value);
            h[i].hash = 0;

        } else if (h[i].key.len == sizeof("LSC-Cookie") - 1
                   && ngx_strncasecmp(h[i].key.data,
                       (u_char *)"LSC-Cookie",
                       sizeof("LSC-Cookie") - 1) == 0)
        {
            /* Reject CR/LF/NUL injection in the side-channel cookie
             * value. Anything containing them comes from a compromised
             * or buggy upstream; refuse to cache the response rather
             * than sanitize silently. */
            ngx_uint_t k;
            int        injected = 0;
            for (k = 0; k < h[i].value.len; k++) {
                u_char c = h[i].value.data[k];
                if (c == '\r' || c == '\n' || c == '\0') {
                    injected = 1;
                    break;
                }
            }
            if (injected) {
                ctx->no_store = 1;
                h[i].hash = 0;
                continue;
            }
            if (!ctx->has_lsc_cookie) {
                ctx->lsc_cookie = lsc_pool_dup(r->pool, h[i].value);
                ctx->has_lsc_cookie = 1;
            }
            h[i].hash = 0;

        } else if (h[i].key.len == sizeof("X-LiteSpeed-Location") - 1
                   && ngx_strncasecmp(h[i].key.data,
                       (u_char *)"X-LiteSpeed-Location",
                       sizeof("X-LiteSpeed-Location") - 1) == 0)
        {
            /* internal LSWS routing header, never client-visible */
            h[i].hash = 0;

        } else if (h[i].key.len == sizeof("Set-Cookie") - 1
                   && ngx_strncasecmp(h[i].key.data,
                       (u_char *)"Set-Cookie",
                       sizeof("Set-Cookie") - 1) == 0)
        {
            ctx->has_set_cookie = 1;

        } else if (h[i].key.len == sizeof("Content-Encoding") - 1
                   && ngx_strncasecmp(h[i].key.data,
                       (u_char *)"Content-Encoding",
                       sizeof("Content-Encoding") - 1) == 0)
        {
            /* A body the backend already encoded fits only the clients
             * that accept that encoding. Not stored: nginx compresses
             * the stored plain body itself, per client. */
            if (!(h[i].value.len == 8
                  && ngx_strncasecmp(h[i].value.data, (u_char *)"identity",
                                     8) == 0))
            {
                ctx->has_content_encoding = 1;
            }

        } else if (h[i].key.len == sizeof("Vary") - 1
                   && ngx_strncasecmp(h[i].key.data,
                       (u_char *)"Vary", sizeof("Vary") - 1) == 0)
        {
            /* RFC 7234 Vary: we accept only `Accept-Encoding` (or empty).
             * Anything else means the response cannot be safely shared
             * across clients, so refuse to cache. */
            u_char *vp, *vend, *tok, *tend;
            size_t  tlen;
            int     unsafe = 0;

            vp   = h[i].value.data;
            vend = h[i].value.data + h[i].value.len;
            while (vp < vend) {
                while (vp < vend && (*vp == ' ' || *vp == ',' || *vp == '\t'))
                    vp++;
                if (vp >= vend) break;
                tok = vp;
                while (vp < vend && *vp != ',') vp++;
                tend = vp;
                while (tend > tok && (tend[-1] == ' ' || tend[-1] == '\t'))
                    tend--;
                tlen = tend - tok;
                if (tlen == 0) continue;
                if (tlen == 15
                    && ngx_strncasecmp(tok, (u_char *)"Accept-Encoding",
                                       15) == 0)
                {
                    continue;
                }
                unsafe = 1;
                break;
            }
            if (unsafe) ctx->has_unsafe_vary = 1;
        }
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Add X-LiteSpeed-Cache response header (miss / no-cache).
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_emit_status_header(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx,
    int want_no_cache)
{
    ngx_str_t v;

    if (want_no_cache) { ngx_str_set(&v, "no-cache"); }
    else               { ngx_str_set(&v, "miss"); }
    if (lsc_push_header(r, "X-LiteSpeed-Cache",
                        sizeof("X-LiteSpeed-Cache") - 1, &v) == NULL)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Materialize LSC-Cookie -> Set-Cookie on the outgoing response.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_materialize_lsc_cookie(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx)
{
    if (!ctx->has_lsc_cookie || ctx->lsc_cookie.len == 0) return NGX_OK;

    if (lsc_push_header(r, "Set-Cookie", sizeof("Set-Cookie") - 1,
                        &ctx->lsc_cookie) == NULL)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Cleanup handler: removes tmp file if the request died before finalize.
 *
 * It looks at the context, never at a copy of the descriptor: the body
 * filter closes the file itself on success, and a second close of a
 * remembered number would close whatever got that number since (another
 * visitor's socket, for one).
 * ═══════════════════════════════════════════════════════════════════════ */

static void
lsc_tmp_cleanup(void *data)
{
    ngx_http_lsc_ctx_t *ctx = *(ngx_http_lsc_ctx_t **) data;

    if (ctx->tmp_fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->tmp_fd);
        ctx->tmp_fd = NGX_INVALID_FILE;
    }
    if (ctx->tmp_path) {
        (void) ngx_delete_file(ctx->tmp_path);
        ctx->tmp_path = NULL;
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Which response headers go into the cache with the body.
 *
 * Everything the backend sent, except: what nginx makes itself on every
 * answer, hop-by-hop headers, the protocol's own headers, and
 * Set-Cookie (a cookie is one visitor's; LSC-Cookie is the shared one).
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_uint_t
lsc_header_skipped(ngx_str_t *key)
{
    static ngx_str_t exact[] = {
        ngx_string("Set-Cookie"),        ngx_string("Date"),
        ngx_string("Server"),            ngx_string("Connection"),
        ngx_string("Keep-Alive"),        ngx_string("Transfer-Encoding"),
        ngx_string("Content-Length"),    ngx_string("Content-Type"),
        ngx_string("Content-Encoding"),  ngx_string("Content-Range"),
        ngx_string("Last-Modified"),     ngx_string("ETag"),
        ngx_string("Accept-Ranges"),     ngx_string("Age"),
        ngx_string("Upgrade"),           ngx_string("Trailer"),
        ngx_string("TE"),                ngx_string("LSC-Cookie"),
        ngx_string("Proxy-Authenticate"),
        ngx_string("Proxy-Authorization"),
        ngx_string("WWW-Authenticate"),
        ngx_null_string
    };
    static ngx_str_t prefix[] = {
        ngx_string("X-LiteSpeed-"), ngx_string("X-LSCache"),
        ngx_string("X-Accel-"),
        ngx_null_string
    };
    ngx_uint_t i;

    for (i = 0; exact[i].len; i++) {
        if (key->len == exact[i].len
            && ngx_strncasecmp(key->data, exact[i].data, key->len) == 0)
        {
            return 1;
        }
    }
    for (i = 0; prefix[i].len; i++) {
        if (key->len >= prefix[i].len
            && ngx_strncasecmp(key->data, prefix[i].data, prefix[i].len) == 0)
        {
            return 1;
        }
    }
    return 0;
}


/* Builds ctx->hdr_block ("hdr Name: value\n" lines). NGX_DECLINED when
 * the headers do not fit or hold bytes a meta line cannot carry: the
 * response is then not stored at all, never stored without them. */
static ngx_int_t
lsc_collect_headers(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t       i, k, pass;
    size_t           total = 0;
    u_char          *p = NULL;

    for (pass = 0; pass < 2; pass++) {
        part = &r->headers_out.headers.part;
        h    = part->elts;
        for (i = 0;; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) break;
                part = part->next; h = part->elts; i = 0;
            }
            if (h[i].hash == 0 || h[i].key.len == 0) continue;
            if (lsc_header_skipped(&h[i].key)) continue;

            if (pass == 0) {
                for (k = 0; k < h[i].key.len; k++) {
                    u_char c = h[i].key.data[k];
                    if (c <= 0x20 || c >= 0x7F || c == ':') {
                        return NGX_DECLINED;
                    }
                }
                for (k = 0; k < h[i].value.len; k++) {
                    u_char c = h[i].value.data[k];
                    if (c == '\r' || c == '\n' || c == '\0') {
                        return NGX_DECLINED;
                    }
                }
                total += 4 + h[i].key.len + 2 + h[i].value.len + 1;
                if (total > LSC_HEADER_BLOCK_MAX) return NGX_DECLINED;
            } else {
                p = ngx_cpymem(p, "hdr ", 4);
                p = ngx_cpymem(p, h[i].key.data, h[i].key.len);
                *p++ = ':'; *p++ = ' ';
                p = ngx_cpymem(p, h[i].value.data, h[i].value.len);
                *p++ = '\n';
            }
        }
        if (pass == 0) {
            if (total == 0) return NGX_OK;
            ctx->hdr_block.data = ngx_pnalloc(r->pool, total);
            if (ctx->hdr_block.data == NULL) return NGX_DECLINED;
            p = ctx->hdr_block.data;
        }
    }
    ctx->hdr_block.len = p - ctx->hdr_block.data;
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Compute the cache key + paths once we know vary + privacy.
 *
 * Returns NGX_OK on success, NGX_DECLINED if any setup step failed (in
 * which case ctx->capturing is cleared and the request continues uncached).
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_setup_capture(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx)
{
    ngx_http_lsc_main_conf_t *mcf;
    ngx_http_lsc_loc_conf_t  *lcf;
    ngx_str_t                 vary_string = ngx_null_string;
    ngx_str_t                 client_id   = ngx_null_string;
    ngx_str_t                 empty       = ngx_null_string;
    u_char                    base_bin[LSC_KEY_BIN_LEN];
    ngx_pool_cleanup_t       *cln;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_lscache_module);
    if (mcf->path.len == 0) return NGX_DECLINED;

    /* the host is part of the key and of the index; without one (an
     * HTTP/1.0 request with no Host) nothing is stored */
    lsc_request_host(r, &ctx->host);
    if (ctx->host.len == 0 || ctx->host.len > 255
        || lsc_safe_name(&ctx->host) != NGX_OK)
    {
        ctx->host.len = 0;
        return NGX_DECLINED;
    }

    if (ctx->vary_directive.len > 0
        && !(ctx->cc_flags & LSC_CC_NO_VARY))
    {
        if (lsc_build_vary_string(r, &ctx->vary_directive, &vary_string)
            != NGX_OK)
        {
            return NGX_DECLINED;
        }
    }
    if (ctx->is_private) {
        if (lsc_resolve_client_id(r, &client_id) != NGX_OK) {
            return NGX_DECLINED;       /* a visitor we cannot tell apart */
        }
    }
    ctx->vary_string = vary_string;
    ctx->client_id   = client_id;

    lsc_compute_key(r, &vary_string, &client_id, 1, ctx->key_bin);
    lsc_hex_encode(ctx->key_bin, LSC_KEY_BIN_LEN, ctx->key_hex);

    /* index key: host + URL only; names the folder that lists every
     * variant of this URL ("purge this URL", the lookup walk) */
    lsc_compute_key(r, &empty, &empty, 0, base_bin);
    lsc_hex_encode(base_bin, LSC_KEY_BIN_LEN, ctx->base_key_hex);

    if (lsc_variant_room(r, ctx->base_key_hex, ctx->key_hex,
                         lcf->max_variants) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    if (lsc_collect_headers(r, ctx) != NGX_OK) return NGX_DECLINED;

    if (lsc_data_path(r->pool, &mcf->path, ctx->key_hex,
                       &ctx->final_data_path) != NGX_OK
        || lsc_meta_path(r->pool, &mcf->path, ctx->key_hex,
                          &ctx->final_meta_path) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    /* register cleanup before the open so we never leak a tmp on error */
    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_lsc_ctx_t *));
    if (cln == NULL) return NGX_DECLINED;
    cln->handler = lsc_tmp_cleanup;
    *(ngx_http_lsc_ctx_t **) cln->data = ctx;

    if (lsc_open_tmp(r, &ctx->tmp_fd, &ctx->tmp_path) != NGX_OK) {
        ctx->tmp_fd   = NGX_INVALID_FILE;
        ctx->tmp_path = NULL;
        return NGX_DECLINED;
    }

    /* write 24-byte placeholder header */
    {
        u_char hdr[24];
        ngx_memzero(hdr, sizeof(hdr));
        hdr[0] = 'L'; hdr[1] = 'S'; hdr[2] = 'C'; hdr[3] = '1';
        if (ngx_write_fd(ctx->tmp_fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
        {
            return NGX_DECLINED;
        }
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Write the .meta sidecar. Runs BEFORE the data file is renamed into
 * place, so a servable data file always has its meta. NGX_OK or
 * NGX_ERROR (the entry must then not be stored).
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_write_meta(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx)
{
    u_char                   *buf, *p;
    size_t                    bufsz;
    ngx_fd_t                  fd;
    ngx_uint_t                i, k;
    ngx_str_t                 bk, ct;
    u_char                    meta_tmp[LSC_PATH_MAX];
    u_char                   *mp;

    ct = r->headers_out.content_type;
    if (ct.len > LSC_CONTENT_TYPE_MAX) return NGX_ERROR;
    for (k = 0; k < ct.len; k++) {
        if (ct.data[k] == '\r' || ct.data[k] == '\n' || ct.data[k] == '\0') {
            return NGX_ERROR;
        }
    }

    /* every variable part is counted; the fixed words and numbers fit
     * in the 512 with room to spare */
    bufsz = 512
          + ct.len
          + ctx->lsc_cookie.len
          + ctx->host.len
          + ctx->vary_directive.len
          + ctx->hdr_block.len;
    for (i = 0; i < ctx->ntags; i++) bufsz += ctx->tags[i].len + 8;
    if (bufsz > LSC_META_MAX) return NGX_ERROR;

    buf = ngx_pnalloc(r->pool, bufsz);
    if (buf == NULL) return NGX_ERROR;

    p = buf;
    p = ngx_sprintf(p, "version 2\n");
    p = ngx_sprintf(p, "status %ui\n", ctx->resp_status);
    p = ngx_sprintf(p, "expires %T\n", (time_t)(ngx_time() + ctx->max_age));
    p = ngx_sprintf(p, "is_private %d\n", ctx->is_private ? 1 : 0);
    bk.data = ctx->base_key_hex;
    bk.len  = LSC_KEY_HEX_LEN;
    p = ngx_sprintf(p, "base %V\n", &bk);
    p = ngx_sprintf(p, "host %V\n", &ctx->host);
    if (ct.len > 0) {
        p = ngx_sprintf(p, "content-type %V\n", &ct);
    }
    if (ctx->has_lsc_cookie && ctx->lsc_cookie.len > 0) {
        p = ngx_sprintf(p, "lsc_cookie %V\n", &ctx->lsc_cookie);
    }
    if (ctx->vary_directive.len > 0) {
        p = ngx_cpymem(p, "vary_directive ", 15);
        for (k = 0; k < ctx->vary_directive.len; k++) {
            u_char c = ctx->vary_directive.data[k];
            if (c == '\n' || c == '\r' || c == '\0') c = ' ';
            *p++ = c;
        }
        *p++ = '\n';
    }
    for (i = 0; i < ctx->ntags; i++) {
        p = ngx_sprintf(p, "tag %V\n", &ctx->tags[i]);
    }
    if (ctx->hdr_block.len > 0) {
        p = ngx_cpymem(p, ctx->hdr_block.data, ctx->hdr_block.len);
    }
    if ((size_t) (p - buf) > bufsz) {
        /* cannot happen; if the sum above is ever wrong, stop here
         * loudly instead of going on with a damaged heap */
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "lscache: meta buffer overrun");
        ngx_abort();
    }

    /* the folder of the data file */
    {
        u_char  parent[LSC_PATH_MAX];
        u_char *slash;
        if (ctx->final_meta_path.len >= sizeof(parent)) return NGX_ERROR;
        ngx_memcpy(parent, ctx->final_meta_path.data,
                   ctx->final_meta_path.len);
        parent[ctx->final_meta_path.len] = '\0';
        slash = parent + ctx->final_meta_path.len;
        while (slash > parent && *slash != '/') slash--;
        if (slash == parent) return NGX_ERROR;
        *slash = '\0';
        if (lsc_mkpath(parent, 0750, r->connection->log) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* write to a name of our own, then rename: readers see the old
     * meta or the new one, never a half */
    if (ctx->final_meta_path.len + 40 >= sizeof(meta_tmp)) return NGX_ERROR;
    mp = ngx_sprintf(meta_tmp, "%V.%P.%08xD", &ctx->final_meta_path,
                     ngx_pid, (uint32_t) ngx_random());
    *mp = '\0';

    fd = open((char *) meta_tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
              0640);
    if (fd < 0) return NGX_ERROR;
    if (ngx_write_fd(fd, buf, p - buf) != (ssize_t)(p - buf)) {
        ngx_close_file(fd);
        (void) ngx_delete_file(meta_tmp);
        return NGX_ERROR;
    }
    ngx_close_file(fd);
    if (ngx_rename_file(meta_tmp, ctx->final_meta_path.data) != 0) {
        (void) ngx_delete_file(meta_tmp);
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Index markers (hosts/, vary/, tags/): empty files that let a purge
 * find the entry. Written before the data file too: an entry that can
 * be served can always be purged.
 * ═══════════════════════════════════════════════════════════════════════ */

static void
lsc_write_refs(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx)
{
    ngx_http_lsc_main_conf_t *mcf;
    ngx_uint_t                i;
    ngx_str_t                 path;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);

    if (lsc_host_path(r->pool, &mcf->path, &ctx->host, ctx->key_hex,
                      &path) == NGX_OK)
    {
        (void) lsc_touch_ref(path.data, path.len, r->connection->log);
    }
    if (lsc_vary_path(r->pool, &mcf->path, ctx->base_key_hex,
                       ctx->key_hex, &path) == NGX_OK)
    {
        (void) lsc_touch_ref(path.data, path.len, r->connection->log);
    }
    for (i = 0; i < ctx->ntags; i++) {
        if (lsc_tag_path(r->pool, &mcf->path, &ctx->tags[i], ctx->key_hex,
                          &path) != NGX_OK) continue;
        (void) lsc_touch_ref(path.data, path.len, r->connection->log);
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Header filter entry point.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_header_filter(ngx_http_request_t *r)
{
    ngx_http_lsc_loc_conf_t *lcf;
    ngx_http_lsc_ctx_t      *ctx;
    ngx_uint_t               method_allowed = 0;
    ngx_str_t                bypass_val, no_cache_val;

    if (r != r->main) return next_header_filter(r);

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_lscache_module);
    if (lcf == NULL || !lcf->enable) return next_header_filter(r);

    ctx = lsc_ensure_ctx(r);
    if (ctx == NULL) return next_header_filter(r);

    /* on a HIT, serve.c built the response from cache; do not touch it */
    if (ctx->served_from_cache) return next_header_filter(r);

    lsc_strip_and_collect(r, ctx);

    /* run inline purge from the response form of X-LiteSpeed-Purge.
     * is_inline=1 scopes tag, url and asterisk operations to this Host so
     * a compromised tenant cannot wipe another tenant's tagged entries
     * on a shared lscache_path. */
    if (ctx->inline_purge.len > 0) {
        (void) lsc_execute_purge(r, &ctx->inline_purge, 1, NULL);
    }

    /* materialize the LSC-Cookie side channel on this very response */
    if (lsc_materialize_lsc_cookie(r, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    /* lscache_no_cache: prevent storing (request still goes through) */
    if (lcf->no_cache) {
        if (ngx_http_complex_value(r, lcf->no_cache, &no_cache_val) == NGX_OK
            && no_cache_val.len > 0
            && !(no_cache_val.len == 1 && no_cache_val.data[0] == '0'))
        {
            ctx->no_store = 1;
        }
    }

    /* The status as the backend gave it. Filters below ours may turn
     * the answer into 304 or 206 for this one client; what is stored
     * is the full answer. */
    ctx->resp_status = r->headers_out.status;

    /* method gate: only a GET answer is stored (a HEAD has no body, and
     * the key has no method in it) */
    if (r->method == NGX_HTTP_GET
        && (lcf->methods_bitmap & NGX_HTTP_GET))
    {
        method_allowed = 1;
    }

    /* "no upstream caching intent" -> module is idle on this response */
    if (ctx->cc_flags == 0) {
        return next_header_filter(r);
    }

    /* Did the backend EXPRESS intent to store? */
    int store_intent = (ctx->cc_flags & LSC_CC_HAS_MAX_AGE)
                    && !(ctx->cc_flags & (LSC_CC_NO_CACHE | LSC_CC_NO_STORE));

    /* policy blockers (apply only when store intent was present) */
    int policy_block = 0;
    if (!method_allowed)             policy_block = 1;
    if (ctx->max_age < lcf->min_age) policy_block = 1;
    if (ctx->has_set_cookie
        && !(ctx->cc_flags & LSC_CC_PRIVATE)
        && !ctx->has_lsc_cookie)
    {
        policy_block = 1;
    }
    if (ctx->has_unsafe_vary) policy_block = 1;
    if (ctx->has_content_encoding) policy_block = 1;
    /* partial, conditional and interim answers are one client's */
    if (ctx->resp_status < 200 || ctx->resp_status == 204
        || ctx->resp_status == 206 || ctx->resp_status == 304)
    {
        policy_block = 1;
    }
    /* protocol values that do not fit a meta record */
    if (ctx->vary_directive.len > LSC_VARY_DIRECTIVE_MAX
        || ctx->lsc_cookie.len > LSC_LSC_COOKIE_MAX)
    {
        policy_block = 1;
    }
    if (ctx->max_age > lcf->max_age) ctx->max_age = lcf->max_age;

    if (ctx->cc_flags & LSC_CC_PRIVATE) ctx->is_private = 1;

    /* lscache_bypass: skip store side */
    if (lcf->bypass) {
        if (ngx_http_complex_value(r, lcf->bypass, &bypass_val) == NGX_OK
            && bypass_val.len > 0
            && !(bypass_val.len == 1 && bypass_val.data[0] == '0'))
        {
            policy_block = 1;
            ctx->status  = LSC_ST_BYPASS;
        }
    }

    /* lscache_min_uses: only start caching after the Nth observation of
     * the same base key (per-worker counter). Compute base_key now so the
     * gate (and debug headers) see it even when we never capture. */
    if (store_intent && lcf->min_uses > 1) {
        ngx_str_t empty = ngx_null_string;
        u_char    base_bin[LSC_KEY_BIN_LEN];
        lsc_compute_key(r, &empty, &empty, 0, base_bin);
        lsc_hex_encode(base_bin, LSC_KEY_BIN_LEN, ctx->base_key_hex);
        if (lsc_bump_uses(ctx->base_key_hex) < lcf->min_uses) {
            policy_block = 1;
        }
    }

    if (store_intent && !policy_block) {
        if (lsc_setup_capture(r, ctx) == NGX_OK) {
            ctx->capturing = 1;
        }
        if (ctx->status == LSC_ST_NONE) ctx->status = LSC_ST_MISS;
        if (lsc_emit_status_header(r, ctx, 0) != NGX_OK) return NGX_ERROR;
    } else if (store_intent && policy_block) {
        /* would have stored but was refused for security/policy */
        if (lsc_emit_status_header(r, ctx, 1) != NGX_OK) return NGX_ERROR;
    } else {
        /* upstream said no-cache / no-store; this is an uncached pass-through */
        if (ctx->status == LSC_ST_NONE) ctx->status = LSC_ST_MISS;
        if (lsc_emit_status_header(r, ctx, 0) != NGX_OK) return NGX_ERROR;
    }

    /* lscache_debug headers (never enable in production) */
    if (lcf->debug && ctx->key_hex[0] != 0) {
        ngx_str_t dv;
        dv.data = ctx->key_hex;
        dv.len  = LSC_KEY_HEX_LEN;
        (void) lsc_push_header(r, "X-LSCache-Debug-Key",
                               sizeof("X-LSCache-Debug-Key") - 1, &dv);
        if (ctx->vary_directive.len > 0) {
            /* sanitize: vary_directive is upstream-controlled; CR/LF in
             * the value would split the response and inject arbitrary
             * headers. Replace each control byte with a space. */
            u_char *safe = ngx_pnalloc(r->pool, ctx->vary_directive.len);
            if (safe != NULL) {
                ngx_uint_t k;
                for (k = 0; k < ctx->vary_directive.len; k++) {
                    u_char c = ctx->vary_directive.data[k];
                    if (c < 0x20 || c == 0x7F) c = ' ';
                    safe[k] = c;
                }
                dv.data = safe;
                dv.len  = ctx->vary_directive.len;
                (void) lsc_push_header(r, "X-LSCache-Debug-Vary",
                                       sizeof("X-LSCache-Debug-Vary") - 1,
                                       &dv);
            }
        }
    }

    return next_header_filter(r);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Body filter entry point.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_write_buf(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx, ngx_buf_t *b)
{
    size_t  sz = ngx_buf_size(b);
    if (sz == 0) return NGX_OK;

    /* Cache file format encodes body_len as u32. Refuse capture once
     * the response exceeds UINT32_MAX bytes - a silent truncation
     * combined with Range serving would let a client read past the
     * recorded body_last offset. */
    if (sz > UINT32_MAX - (size_t) ctx->bytes_written) {
        return NGX_ERROR;
    }
    if (ngx_buf_in_memory(b)) {
        if (ngx_write_fd(ctx->tmp_fd, b->pos, sz) != (ssize_t)sz) {
            return NGX_ERROR;
        }
        ctx->bytes_written += sz;
        return NGX_OK;
    }

    if (b->in_file && b->file) {
        u_char  fbuf[16384];
        off_t   off = b->file_pos;
        off_t   end = b->file_last;
        ssize_t got;
        size_t  want;
        while (off < end) {
            want = (size_t)(end - off);
            if (want > sizeof(fbuf)) want = sizeof(fbuf);
            got = ngx_read_file(b->file, fbuf, want, off);
            if (got <= 0) return NGX_ERROR;
            if (ngx_write_fd(ctx->tmp_fd, fbuf, got) != got) return NGX_ERROR;
            off += got;
            ctx->bytes_written += got;
        }
        return NGX_OK;
    }
    /* unknown buf flavor - skip capture */
    return NGX_ERROR;
}


static void
lsc_abort_capture(ngx_http_lsc_ctx_t *ctx)
{
    if (ctx->tmp_fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->tmp_fd);
        ctx->tmp_fd = NGX_INVALID_FILE;
    }
    if (ctx->tmp_path) {
        (void) ngx_delete_file(ctx->tmp_path);
        ctx->tmp_path = NULL;
    }
    ctx->capturing = 0;
}


ngx_int_t
lsc_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_lsc_ctx_t *ctx;
    ngx_chain_t        *cl;
    int                 last_buf = 0;

    if (r != r->main) return next_body_filter(r, in);

    ctx = ngx_http_get_module_ctx(r, ngx_http_lscache_module);
    if (ctx == NULL || !ctx->capturing) return next_body_filter(r, in);

    for (cl = in; cl; cl = cl->next) {
        if (lsc_write_buf(r, ctx, cl->buf) != NGX_OK) {
            lsc_abort_capture(ctx);
            return next_body_filter(r, in);
        }
        if (cl->buf->last_buf) last_buf = 1;
    }

    if (!last_buf) return next_body_filter(r, in);

    /* finalize: rewrite the 24-byte header with real lengths/status/flags,
     * then meta, index markers and the atomic rename(2) of the data. */
    {
        u_char   hdr[24];
        uint32_t body_len = (uint32_t)ctx->bytes_written;
        uint64_t expires  = (uint64_t)(ngx_time() + ctx->max_age);
        uint16_t status   = (uint16_t)ctx->resp_status;
        uint16_t flags    = 0;

        if (ctx->is_private)       flags |= LSC_FF_PRIVATE;
        if (ctx->has_lsc_cookie)   flags |= LSC_FF_HAS_LSC_COOKIE;

        hdr[0] = 'L'; hdr[1] = 'S'; hdr[2] = 'C'; hdr[3] = '1';
        hdr[4]  = (u_char)( body_len        & 0xFF);
        hdr[5]  = (u_char)((body_len >> 8)  & 0xFF);
        hdr[6]  = (u_char)((body_len >> 16) & 0xFF);
        hdr[7]  = (u_char)((body_len >> 24) & 0xFF);
        hdr[8] = hdr[9] = hdr[10] = hdr[11] = 0;
        hdr[12] = (u_char)( expires        & 0xFF);
        hdr[13] = (u_char)((expires >> 8)  & 0xFF);
        hdr[14] = (u_char)((expires >> 16) & 0xFF);
        hdr[15] = (u_char)((expires >> 24) & 0xFF);
        hdr[16] = (u_char)((expires >> 32) & 0xFF);
        hdr[17] = (u_char)((expires >> 40) & 0xFF);
        hdr[18] = (u_char)((expires >> 48) & 0xFF);
        hdr[19] = (u_char)((expires >> 56) & 0xFF);
        hdr[20] = (u_char)( status        & 0xFF);
        hdr[21] = (u_char)((status >> 8)  & 0xFF);
        hdr[22] = (u_char)( flags         & 0xFF);
        hdr[23] = (u_char)((flags  >> 8)  & 0xFF);

        if (lseek(ctx->tmp_fd, 0, SEEK_SET) != 0) {
            lsc_abort_capture(ctx);
            return next_body_filter(r, in);
        }
        if (ngx_write_fd(ctx->tmp_fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
        {
            lsc_abort_capture(ctx);
            return next_body_filter(r, in);
        }

        /* No fsync: the cache can be rebuilt, and a file a crash left
         * short fails the size check on the way out. */
        ngx_close_file(ctx->tmp_fd);
        ctx->tmp_fd = NGX_INVALID_FILE;
        ctx->capturing = 0;

        /* meta and index markers first, the data file last: whatever
         * can be served has its headers and can be found by a purge */
        if (lsc_write_meta(r, ctx) != NGX_OK) {
            (void) ngx_delete_file(ctx->tmp_path);
            ctx->tmp_path = NULL;
        } else {
            struct stat old;
            off_t       old_size = 0;

            lsc_write_refs(r, ctx);
            if (stat((char *) ctx->final_data_path.data, &old) == 0) {
                old_size = old.st_size;
            }
            if (lsc_finalize_tmp(r, ctx->tmp_path, &ctx->final_data_path)
                != NGX_OK)
            {
                (void) ngx_delete_file(ctx->tmp_path);
                ctx->tmp_path = NULL;
                /* take back the meta and the markers written above */
                (void) lsc_unlink_entry(r, ctx->key_hex, -1, NULL);
            } else {
                ctx->finalized = 1;
                ctx->tmp_path  = NULL;     /* rename consumed it */
                lsc_account(r, (off_t) LSC_FILE_HEADER_BYTES
                               + ctx->bytes_written - old_size);
                lsc_maintain(r);
            }
        }
    }

    return next_body_filter(r, in);
}
