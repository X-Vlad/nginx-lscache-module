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
 *     + expires, fsync, rename(2) to the final data path. Write .meta
 *     sidecar and back-reference index files (hosts/, tags/, vary/).
 *   - On error or aborted request: unlink tmp via the cleanup handler.
 */

#include "ngx_http_lscache_module.h"

#include <unistd.h>


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
static void lsc_write_meta_and_refs(ngx_http_request_t *r,
    ngx_http_lsc_ctx_t *ctx);

typedef struct {
    ngx_fd_t  fd;
    u_char   *path;
} lsc_tmp_cleanup_t;


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
    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) return NGX_ERROR;
    h->hash = 1;
    ngx_str_set(&h->key, "X-LiteSpeed-Cache");
    if (want_no_cache) {
        ngx_str_set(&h->value, "no-cache");
    } else {
        ngx_str_set(&h->value, "miss");
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Materialize LSC-Cookie -> Set-Cookie on the outgoing response.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_materialize_lsc_cookie(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx)
{
    ngx_table_elt_t *h;

    if (!ctx->has_lsc_cookie || ctx->lsc_cookie.len == 0) return NGX_OK;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) return NGX_ERROR;
    h->hash = 1;
    ngx_str_set(&h->key, "Set-Cookie");
    h->value = ctx->lsc_cookie;
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Cleanup handler: removes tmp file if the request died before finalize.
 * ═══════════════════════════════════════════════════════════════════════ */

static void
lsc_tmp_cleanup(void *data)
{
    lsc_tmp_cleanup_t *c = data;
    if (c->fd != NGX_INVALID_FILE) {
        ngx_close_file(c->fd);
        c->fd = NGX_INVALID_FILE;
    }
    if (c->path) {
        (void) ngx_delete_file(c->path);
        c->path = NULL;
    }
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
    ngx_str_t                 vary_string = ngx_null_string;
    ngx_str_t                 client_id   = ngx_null_string;
    ngx_str_t                 empty       = ngx_null_string;
    u_char                    base_bin[LSC_KEY_BIN_LEN];
    ngx_pool_cleanup_t       *cln;
    lsc_tmp_cleanup_t        *cln_data;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (mcf->path.len == 0) return NGX_DECLINED;

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
        (void) lsc_resolve_client_id(r, &client_id);
    }
    ctx->vary_string = vary_string;
    ctx->client_id   = client_id;

    lsc_compute_key(r, &vary_string, &client_id, ctx->key_bin);
    lsc_hex_encode(ctx->key_bin, LSC_KEY_BIN_LEN, ctx->key_hex);

    /* base key: same inputs except empty vary_string + empty client_id;
     * used as the index for "purge all variants of this URL" */
    lsc_compute_key(r, &empty, &empty, base_bin);
    lsc_hex_encode(base_bin, LSC_KEY_BIN_LEN, ctx->base_key_hex);

    if (lsc_data_path(r->pool, &mcf->path, ctx->key_hex,
                       &ctx->final_data_path) != NGX_OK
        || lsc_meta_path(r->pool, &mcf->path, ctx->key_hex,
                          &ctx->final_meta_path) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    /* capture host (lowercased for storage) */
    {
        ngx_str_t raw = ngx_null_string;
        if (r->headers_in.host && r->headers_in.host->value.len > 0) {
            raw = r->headers_in.host->value;
        } else if (r->headers_in.server.len > 0) {
            raw = r->headers_in.server;
        }
        if (raw.len > 0 && raw.len <= 255) {
            u_char *lh = ngx_pnalloc(r->pool, raw.len);
            if (lh) {
                ngx_uint_t i;
                for (i = 0; i < raw.len; i++) lh[i] = ngx_tolower(raw.data[i]);
                ctx->host.data = lh;
                ctx->host.len  = raw.len;
            }
        }
    }

    /* register cleanup before the open so we never leak a tmp on error */
    cln = ngx_pool_cleanup_add(r->pool, sizeof(lsc_tmp_cleanup_t));
    if (cln == NULL) return NGX_DECLINED;
    cln->handler = lsc_tmp_cleanup;
    cln_data = cln->data;
    cln_data->fd   = NGX_INVALID_FILE;
    cln_data->path = NULL;

    if (lsc_open_tmp(r, &ctx->tmp_fd, &ctx->tmp_path) != NGX_OK) {
        return NGX_DECLINED;
    }
    cln_data->fd   = ctx->tmp_fd;
    cln_data->path = ctx->tmp_path;

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
 * After a successful rename(2), write the .meta sidecar and back-reference
 * empty files (hosts/, tags/, vary/).
 *
 * Best-effort; failures here only mean the entry can't be located by some
 * purge selectors. The data file is still usable for direct-key lookups.
 * ═══════════════════════════════════════════════════════════════════════ */

static void
lsc_write_meta_and_refs(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx)
{
    ngx_http_lsc_main_conf_t *mcf;
    u_char                   *buf, *p;
    size_t                    bufsz;
    ngx_fd_t                  fd;
    ngx_uint_t                i;
    ngx_str_t                 path;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);

    /* ---- meta sidecar ---- */
    bufsz = 1024
          + (r->headers_out.content_type.len)
          + ctx->lsc_cookie.len
          + ctx->host.len
          + LSC_MAX_TAGS * (LSC_MAX_TAG_LEN + 8);
    buf = ngx_pnalloc(r->pool, bufsz);
    if (buf == NULL) return;

    p = buf;
    p = ngx_sprintf(p, "version 1\n");
    p = ngx_sprintf(p, "status %ui\n", (ngx_uint_t)r->headers_out.status);
    p = ngx_sprintf(p, "expires %T\n", (time_t)(ngx_time() + ctx->max_age));
    p = ngx_sprintf(p, "is_private %d\n", ctx->is_private ? 1 : 0);
    {
        ngx_str_t bk;
        bk.data = ctx->base_key_hex;
        bk.len  = LSC_KEY_HEX_LEN;
        p = ngx_sprintf(p, "base %V\n", &bk);
    }

    if (ctx->host.len > 0) {
        p = ngx_sprintf(p, "host %V\n", &ctx->host);
    }
    if (r->headers_out.content_type.len > 0) {
        p = ngx_sprintf(p, "content-type %V\n",
                         &r->headers_out.content_type);
    }
    if (ctx->has_lsc_cookie && ctx->lsc_cookie.len > 0) {
        p = ngx_sprintf(p, "lsc_cookie %V\n", &ctx->lsc_cookie);
    }
    if (ctx->vary_directive.len > 0) {
        /* sanitize: ASCII printable, drop newlines (single-line record) */
        ngx_uint_t k;
        p = ngx_cpymem(p, "vary_directive ", 15);
        for (k = 0; k < ctx->vary_directive.len; k++) {
            u_char c = ctx->vary_directive.data[k];
            if (c == '\n' || c == '\r') c = ' ';
            *p++ = c;
        }
        *p++ = '\n';
    }
    for (i = 0; i < ctx->ntags; i++) {
        p = ngx_sprintf(p, "tag %V\n", &ctx->tags[i]);
    }

    /* write meta to a separate tmp, then rename for atomicity */
    {
        u_char  meta_tmp[LSC_PATH_MAX];
        u_char *mp = meta_tmp;
        if (ctx->final_meta_path.len + 5 >= sizeof(meta_tmp)) return;
        mp = ngx_cpymem(mp, ctx->final_meta_path.data,
                          ctx->final_meta_path.len);
        mp = ngx_cpymem(mp, ".tmp", 4);
        *mp = '\0';

        fd = ngx_open_file(meta_tmp, NGX_FILE_WRONLY,
                            NGX_FILE_CREATE_OR_OPEN | NGX_FILE_TRUNCATE,
                            0640);
        if (fd == NGX_INVALID_FILE) return;
        if (ngx_write_fd(fd, buf, p - buf) != (ssize_t)(p - buf)) {
            ngx_close_file(fd);
            (void) ngx_delete_file(meta_tmp);
            return;
        }
        ngx_close_file(fd);
        if (ngx_rename_file(meta_tmp, ctx->final_meta_path.data) != 0) {
            (void) ngx_delete_file(meta_tmp);
        }
    }

    /* ---- back-references (best-effort, empty marker files) ---- */
    if (ctx->host.len > 0) {
        if (lsc_safe_name(&ctx->host) == NGX_OK
            && lsc_host_path(r->pool, &mcf->path, &ctx->host, ctx->key_hex,
                              &path) == NGX_OK)
        {
            u_char  parent[LSC_PATH_MAX];
            u_char *slash;
            if (path.len < sizeof(parent)) {
                ngx_memcpy(parent, path.data, path.len);
                parent[path.len] = '\0';
                slash = parent + path.len;
                while (slash > parent && *slash != '/') slash--;
                if (slash > parent) {
                    *slash = '\0';
                    (void) lsc_mkpath(parent, 0750, r->connection->log);
                }
            }
            fd = ngx_open_file(path.data, NGX_FILE_WRONLY,
                                NGX_FILE_CREATE_OR_OPEN | NGX_FILE_TRUNCATE,
                                0640);
            if (fd != NGX_INVALID_FILE) ngx_close_file(fd);
        }
    }

    if (lsc_vary_path(r->pool, &mcf->path, ctx->base_key_hex,
                       ctx->key_hex, &path) == NGX_OK)
    {
        u_char  parent[LSC_PATH_MAX];
        u_char *slash;
        if (path.len < sizeof(parent)) {
            ngx_memcpy(parent, path.data, path.len);
            parent[path.len] = '\0';
            slash = parent + path.len;
            while (slash > parent && *slash != '/') slash--;
            if (slash > parent) {
                *slash = '\0';
                (void) lsc_mkpath(parent, 0750, r->connection->log);
            }
        }
        fd = ngx_open_file(path.data, NGX_FILE_WRONLY,
                            NGX_FILE_CREATE_OR_OPEN | NGX_FILE_TRUNCATE,
                            0640);
        if (fd != NGX_INVALID_FILE) ngx_close_file(fd);
    }

    for (i = 0; i < ctx->ntags; i++) {
        if (lsc_safe_name(&ctx->tags[i]) != NGX_OK) continue;
        if (lsc_tag_path(r->pool, &mcf->path, &ctx->tags[i], ctx->key_hex,
                          &path) != NGX_OK) continue;
        {
            u_char  parent[LSC_PATH_MAX];
            u_char *slash;
            if (path.len < sizeof(parent)) {
                ngx_memcpy(parent, path.data, path.len);
                parent[path.len] = '\0';
                slash = parent + path.len;
                while (slash > parent && *slash != '/') slash--;
                if (slash > parent) {
                    *slash = '\0';
                    (void) lsc_mkpath(parent, 0750, r->connection->log);
                }
            }
        }
        fd = ngx_open_file(path.data, NGX_FILE_WRONLY,
                            NGX_FILE_CREATE_OR_OPEN | NGX_FILE_TRUNCATE,
                            0640);
        if (fd != NGX_INVALID_FILE) ngx_close_file(fd);
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

    /* method gate */
    if      (r->method == NGX_HTTP_GET
             && (lcf->methods_bitmap & NGX_HTTP_GET))   method_allowed = 1;
    else if (r->method == NGX_HTTP_HEAD
             && (lcf->methods_bitmap & NGX_HTTP_HEAD))  method_allowed = 1;
    else if (r->method == NGX_HTTP_POST
             && (lcf->methods_bitmap & NGX_HTTP_POST))  method_allowed = 1;

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
        lsc_compute_key(r, &empty, &empty, base_bin);
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
        ngx_table_elt_t *dh = ngx_list_push(&r->headers_out.headers);
        if (dh) {
            dh->hash = 1;
            ngx_str_set(&dh->key, "X-LSCache-Debug-Key");
            dh->value.data = ctx->key_hex;
            dh->value.len  = LSC_KEY_HEX_LEN;
        }
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
                dh = ngx_list_push(&r->headers_out.headers);
                if (dh) {
                    dh->hash = 1;
                    ngx_str_set(&dh->key, "X-LSCache-Debug-Vary");
                    dh->value.data = safe;
                    dh->value.len  = ctx->vary_directive.len;
                }
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
     * fsync, atomic rename(2), then write the meta sidecar + back-refs. */
    {
        u_char   hdr[24];
        uint32_t body_len = (uint32_t)ctx->bytes_written;
        uint64_t expires  = (uint64_t)(ngx_time() + ctx->max_age);
        uint16_t status   = (uint16_t)r->headers_out.status;
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

#if !(NGX_WIN32)
        (void) fsync(ctx->tmp_fd);
#endif
        ngx_close_file(ctx->tmp_fd);
        ctx->tmp_fd = NGX_INVALID_FILE;

        if (lsc_finalize_tmp(r, ctx->tmp_path, &ctx->final_data_path)
            != NGX_OK)
        {
            (void) ngx_delete_file(ctx->tmp_path);
            ctx->tmp_path = NULL;
            ctx->capturing = 0;
        } else {
            ctx->finalized = 1;
            ctx->tmp_path  = NULL;     /* rename consumed it */
            lsc_write_meta_and_refs(r, ctx);
            lsc_maybe_evict(r);
        }
    }

    return next_body_filter(r, in);
}
