/*
 * ngx_http_lscache_serve.c - PRECONTENT cache lookup + serve-from-cache.
 *
 * Lookup is more subtle than "compute key, open file" because we don't know
 * which X-LiteSpeed-Vary directive the backend used for THIS URL until we
 * look inside a cached entry. So:
 *
 *   1. If PURGE method: hand to lsc_purge_handler.
 *   2. Only GET / HEAD are eligible for serving.
 *   3. Check bypass complex value; if set, mark BYPASS and decline.
 *   4. Compute the fast key: host + URL + this request's default vary
 *      (the _lscache_vary cookie, lscache_vary_extra), no vary directive,
 *      no client id. Try data/<fast_key>: the usual public page. A
 *      private entry is never served here.
 *   5. Otherwise walk vary/<base_key>/ (base_key: host + URL only), at
 *      most lscache_max_variants candidates, and for each hex key:
 *        a. Read its .meta sidecar.
 *        b. Pull the original "vary_directive" line.
 *        c. Build vary_string with current request + that directive.
 *        d. If the entry is private, resolve client_id from this request
 *           (no identity: skip the entry).
 *        e. Recompute key; if it equals the candidate filename, serve it.
 *      An entry is served only with its .meta and only when the data
 *      file has the size its header states.
 *   6. NGX_DECLINED on miss -> request continues to fastcgi / proxy / static.
 *
 * Serve uses an `in_file` buf with file_pos=24 (skip the LSC1 header), so
 * nginx sendfile()s the body straight off disk.
 */

#include "ngx_http_lscache_module.h"

#include <sys/stat.h>


/* ═══════════════════════════════════════════════════════════════════════════
 * Read and parse meta sidecar into a small struct.
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    ngx_str_t  content_type;
    ngx_str_t  lsc_cookie;
    ngx_str_t  vary_directive;
    int        is_private;
} lsc_meta_t;


static void
lsc_parse_meta(u_char *buf, size_t n, lsc_meta_t *m)
{
    u_char *line, *end, *eol;

    ngx_memzero(m, sizeof(*m));
    line = buf;
    end  = buf + n;

    while (line < end) {
        eol = (u_char *)ngx_strlchr(line, end, '\n');
        if (eol == NULL) eol = end;

        if (eol - line > 13
            && ngx_strncmp(line, "content-type ", 13) == 0)
        {
            m->content_type.data = line + 13;
            m->content_type.len  = eol - m->content_type.data;
        } else if (eol - line > 11
                   && ngx_strncmp(line, "lsc_cookie ", 11) == 0)
        {
            m->lsc_cookie.data = line + 11;
            m->lsc_cookie.len  = eol - m->lsc_cookie.data;
        } else if (eol - line > 15
                   && ngx_strncmp(line, "vary_directive ", 15) == 0)
        {
            m->vary_directive.data = line + 15;
            m->vary_directive.len  = eol - m->vary_directive.data;
        } else if (eol - line > 11
                   && ngx_strncmp(line, "is_private ", 11) == 0
                   && line[11] == '1')
        {
            m->is_private = 1;
        }
        line = eol + 1;
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Read meta sidecar into r->pool. Returns NGX_OK + populates *m on success,
 * or NGX_DECLINED on missing/empty. The data pointers in *m are owned by
 * *out_buf (we keep one allocation alive for them).
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_load_meta(ngx_http_request_t *r, u_char *hex_key, lsc_meta_t *m,
    u_char **out_buf, ssize_t *out_n)
{
    ngx_http_lsc_main_conf_t *mcf;
    ngx_str_t                 mpath;
    ngx_fd_t                  fd;
    u_char                   *buf;
    ssize_t                   n;
    struct stat               st;
    size_t                    to_read;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (lsc_meta_path(r->pool, &mcf->path, hex_key, &mpath) != NGX_OK) {
        return NGX_DECLINED;
    }
    fd = ngx_open_file(mpath.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) return NGX_DECLINED;

    /* size the buffer to the actual file (capped at LSC_META_MAX) so we
     * don't truncate trailing fields (vary_directive, late tags).
     * Use fstat on the open fd, not stat by path - the file may have
     * been unlinked since we opened it but our fd is still valid. */
    to_read = 0;
    if (fstat(fd, &st) == 0 && st.st_size > 0) {
        to_read = (size_t) st.st_size;
    }
    if (to_read == 0) { ngx_close_file(fd); return NGX_DECLINED; }
    if (to_read > LSC_META_MAX) to_read = LSC_META_MAX;

    buf = ngx_pnalloc(r->pool, to_read + 1);
    if (buf == NULL) { ngx_close_file(fd); return NGX_DECLINED; }
    n = ngx_read_fd(fd, buf, to_read);
    ngx_close_file(fd);
    if (n <= 0) return NGX_DECLINED;
    buf[n] = '\0';

    lsc_parse_meta(buf, (size_t)n, m);
    *out_buf = buf;
    *out_n   = n;
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Decode the 24-byte cache file header.
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t body_len;
    uint64_t expires;
    uint16_t status;
    uint16_t flags;
} lsc_file_hdr_t;


static ngx_int_t
lsc_decode_hdr(u_char hdr[24], lsc_file_hdr_t *out)
{
    int i;
    if (hdr[0] != 'L' || hdr[1] != 'S' || hdr[2] != 'C' || hdr[3] != '1') {
        return NGX_ERROR;
    }
    out->body_len = (uint32_t)hdr[4]
                  | ((uint32_t)hdr[5] << 8)
                  | ((uint32_t)hdr[6] << 16)
                  | ((uint32_t)hdr[7] << 24);
    out->expires = 0;
    for (i = 0; i < 8; i++) {
        out->expires |= ((uint64_t)hdr[12 + i]) << (i * 8);
    }
    out->status  = (uint16_t)hdr[20] | ((uint16_t)hdr[21] << 8);
    out->flags   = (uint16_t)hdr[22] | ((uint16_t)hdr[23] << 8);
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Serve one cache entry: open data file, validate, build response, send.
 *
 * Returns >= NGX_HTTP_SPECIAL_RESPONSE or NGX_OK on success (handler should
 * propagate). Returns NGX_DECLINED if entry was missing / expired / corrupt.
 * ═══════════════════════════════════════════════════════════════════════ */

/* Put the stored "hdr Name: value" lines back on the response. The
 * strings stay in the meta buffer, which lives as long as the request. */
static ngx_int_t
lsc_replay_headers(ngx_http_request_t *r, u_char *buf, size_t n)
{
    u_char          *line, *end, *eol, *colon;
    ngx_table_elt_t *h;
    ngx_str_t        value;
    size_t           klen;

    line = buf;
    end  = buf + n;
    while (line < end) {
        eol = (u_char *) ngx_strlchr(line, end, '\n');
        if (eol == NULL) eol = end;

        if (eol - line > 4 && ngx_strncmp(line, "hdr ", 4) == 0) {
            line += 4;
            colon = (u_char *) ngx_strlchr(line, eol, ':');
            if (colon != NULL && colon > line && colon + 2 <= eol
                && colon[1] == ' ')
            {
                klen       = colon - line;
                value.data = colon + 2;
                value.len  = eol - value.data;
                h = lsc_push_header(r, (char *) line, klen, &value);
                if (h == NULL) return NGX_ERROR;

                if (klen == 8
                    && ngx_strncasecmp(line, (u_char *) "Location", 8) == 0)
                {
                    r->headers_out.location = h;
                } else if (klen == 7
                    && ngx_strncasecmp(line, (u_char *) "Expires", 7) == 0)
                {
                    r->headers_out.expires = h;
#if (nginx_version >= 1023000)
                } else if (klen == 13
                    && ngx_strncasecmp(line, (u_char *) "Cache-Control", 13)
                       == 0)
                {
                    ngx_table_elt_t **ph;
                    for (ph = &r->headers_out.cache_control; *ph;
                         ph = &(*ph)->next) { /* void */ }
                    *ph = h;
#endif
                }
            }
        }
        line = eol + 1;
    }
    return NGX_OK;
}


static ngx_int_t
lsc_serve_entry(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx, u_char *hex,
    int allow_private)
{
    ngx_http_lsc_main_conf_t *mcf;
    ngx_str_t                 dpath;
    ngx_fd_t                  fd;
    u_char                    hdr[24];
    lsc_file_hdr_t            fh;
    lsc_meta_t                m;
    u_char                   *meta_buf = NULL;
    ssize_t                   meta_n   = 0;
    ngx_table_elt_t          *h;
    ngx_buf_t                *b;
    ngx_file_t               *file;
    ngx_pool_cleanup_t       *cln;
    ngx_pool_cleanup_file_t  *clnf;
    ngx_chain_t               out;
    ngx_int_t                 rc;
    struct stat               dst;
    ngx_str_t                 sv;

    ngx_memzero(&m, sizeof(m));

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (lsc_data_path(r->pool, &mcf->path, hex, &dpath) != NGX_OK) {
        return NGX_DECLINED;
    }

    fd = ngx_open_file(dpath.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) return NGX_DECLINED;

    if (ngx_read_fd(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)
        || lsc_decode_hdr(hdr, &fh) != NGX_OK
        || (time_t)fh.expires <= ngx_time()
        || (fh.flags & LSC_FF_STALE)
        /* a private entry is reached only through the variant walk,
         * which has checked whose it is */
        || ((fh.flags & LSC_FF_PRIVATE) && !allow_private)
        /* a file cut short (crash, full disk) is not an entry */
        || fstat(fd, &dst) != 0
        || dst.st_size != (off_t) fh.body_len + LSC_FILE_HEADER_BYTES)
    {
        /* fresh, valid entries serve; stale-flagged entries fall through
         * to upstream so the next response captures and overwrites them. */
        ngx_close_file(fd);
        return NGX_DECLINED;
    }

    /* no meta, no entry: the meta holds the headers and says whether
     * the entry is private */
    if (lsc_load_meta(r, hex, &m, &meta_buf, &meta_n) != NGX_OK
        || (m.is_private && !allow_private))
    {
        ngx_close_file(fd);
        return NGX_DECLINED;
    }

    /* build response headers */
    r->headers_out.status = fh.status ? fh.status : NGX_HTTP_OK;
    r->headers_out.content_length_n = fh.body_len;

    if (m.content_type.len > 0) {
        u_char *cb = ngx_pnalloc(r->pool, m.content_type.len);
        if (cb) {
            ngx_memcpy(cb, m.content_type.data, m.content_type.len);
            r->headers_out.content_type.data = cb;
            r->headers_out.content_type.len  = m.content_type.len;
            r->headers_out.content_type_len  = m.content_type.len;
        }
    }

    if (lsc_replay_headers(r, meta_buf, (size_t) meta_n) != NGX_OK) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    if (fh.flags & LSC_FF_PRIVATE) { ngx_str_set(&sv, "hit,private"); }
    else                           { ngx_str_set(&sv, "hit,public"); }
    h = lsc_push_header(r, "X-LiteSpeed-Cache",
                        sizeof("X-LiteSpeed-Cache") - 1, &sv);
    if (h == NULL) { ngx_close_file(fd); return NGX_ERROR; }

    /* record hit state on the context so var handlers and the rest of the
     * filter chain can see it. (Done up front so debug headers can read
     * ctx->key_hex below.) */
    ctx->served_from_cache = 1;
    ctx->status = LSC_ST_HIT;
    if (fh.flags & LSC_FF_PRIVATE) ctx->is_private = 1;
    ngx_memcpy(ctx->key_hex, hex, LSC_KEY_HEX_LEN);

    /* Last-Modified from cache file mtime + ETag derived from
     * (last_modified, content_length) so nginx's precondition filter
     * can answer both If-Modified-Since and If-None-Match with 304. */
    {
        ngx_file_info_t fi;
        if (ngx_fd_info(fd, &fi) != NGX_FILE_ERROR) {
            r->headers_out.last_modified_time = ngx_file_mtime(&fi);
        }
    }
    (void) ngx_http_set_etag(r);
    /* enable byte-range responses; the range filter slices the file buf. */
    r->allow_ranges = 1;

    /* lscache_debug instrumentation */
    {
        ngx_http_lsc_loc_conf_t *lcf =
            ngx_http_get_module_loc_conf(r, ngx_http_lscache_module);
        if (lcf && lcf->debug) {
            sv.data = ctx->key_hex;
            sv.len  = LSC_KEY_HEX_LEN;
            (void) lsc_push_header(r, "X-LSCache-Debug-Key",
                                   sizeof("X-LSCache-Debug-Key") - 1, &sv);
            if (m.vary_directive.len > 0) {
                u_char *safe = ngx_pnalloc(r->pool, m.vary_directive.len);
                if (safe != NULL) {
                    ngx_uint_t k;
                    for (k = 0; k < m.vary_directive.len; k++) {
                        u_char c = m.vary_directive.data[k];
                        if (c < 0x20 || c == 0x7F) c = ' ';
                        safe[k] = c;
                    }
                    sv.data = safe;
                    sv.len  = m.vary_directive.len;
                    (void) lsc_push_header(r, "X-LSCache-Debug-Vary",
                                           sizeof("X-LSCache-Debug-Vary") - 1,
                                           &sv);
                }
            }
        }
    }

    if (m.lsc_cookie.len > 0) {
        u_char *cb = ngx_pnalloc(r->pool, m.lsc_cookie.len);
        if (cb) {
            ngx_memcpy(cb, m.lsc_cookie.data, m.lsc_cookie.len);
            sv.data = cb;
            sv.len  = m.lsc_cookie.len;
            (void) lsc_push_header(r, "Set-Cookie", sizeof("Set-Cookie") - 1,
                                   &sv);
        }
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
        ngx_close_file(fd);
        rc = ngx_http_send_header(r);
        ngx_http_finalize_request(r, rc);
        return NGX_DONE;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_close_file(fd);
        ngx_http_finalize_request(r, rc);
        return NGX_DONE;
    }

    /* file buf that nginx can sendfile() directly */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) { ngx_close_file(fd); return NGX_ERROR; }
    file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (file == NULL) { ngx_close_file(fd); return NGX_ERROR; }
    file->fd   = fd;
    file->name = dpath;
    file->log  = r->connection->log;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) { ngx_close_file(fd); return NGX_ERROR; }
    cln->handler = ngx_pool_cleanup_file;
    clnf = cln->data;
    clnf->fd   = fd;
    clnf->name = file->name.data;
    clnf->log  = r->connection->log;

    b->file        = file;
    b->file_pos    = 24;
    b->file_last   = 24 + (off_t)fh.body_len;
    b->in_file     = 1;
    b->last_buf    = 1;
    b->last_in_chain = 1;

    out.buf  = b;
    out.next = NULL;
    rc = ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Try one variant key: open its meta, rebuild the candidate key, verify it
 * matches the on-disk filename, then serve.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_try_variant(ngx_http_request_t *r, ngx_http_lsc_ctx_t *ctx,
    u_char *variant_hex)
{
    lsc_meta_t  m;
    u_char     *mbuf = NULL;
    ssize_t     mn   = 0;
    u_char      candidate_bin[LSC_KEY_BIN_LEN];
    u_char      candidate_hex[LSC_KEY_HEX_LEN];
    ngx_str_t   vary_string = ngx_null_string;
    ngx_str_t   client_id   = ngx_null_string;

    if (lsc_load_meta(r, variant_hex, &m, &mbuf, &mn) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (m.vary_directive.len > 0) {
        if (lsc_build_vary_string(r, &m.vary_directive, &vary_string)
            != NGX_OK)
        {
            return NGX_DECLINED;
        }
    }
    if (m.is_private) {
        if (lsc_resolve_client_id(r, &client_id) != NGX_OK) {
            return NGX_DECLINED;   /* a visitor we cannot tell apart */
        }
    }

    lsc_compute_key(r, &vary_string, &client_id, 1, candidate_bin);
    lsc_hex_encode(candidate_bin, LSC_KEY_BIN_LEN, candidate_hex);

    if (ngx_memcmp(candidate_hex, variant_hex, LSC_KEY_HEX_LEN) != 0) {
        return NGX_DECLINED;
    }
    return lsc_serve_entry(r, ctx, variant_hex, 1);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * PRECONTENT entry point.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_precontent_handler(ngx_http_request_t *r)
{
    ngx_http_lsc_loc_conf_t  *lcf;
    ngx_http_lsc_main_conf_t *mcf;
    ngx_http_lsc_ctx_t       *ctx;
    ngx_str_t                 empty = ngx_null_string;
    ngx_str_t                 bypass_val;
    u_char                    base_bin[LSC_KEY_BIN_LEN];
    u_char                    base_hex[LSC_KEY_HEX_LEN];
    u_char                    fast_bin[LSC_KEY_BIN_LEN];
    u_char                    fast_hex[LSC_KEY_HEX_LEN];
    ngx_uint_t                tried = 0;
    ngx_int_t                 rc;
    u_char                    vdir_buf[LSC_PATH_MAX];
    u_char                   *vp;
    ngx_str_t                 vdir;
    ngx_dir_t                 d;
    u_char                   *raw, vhex[LSC_KEY_HEX_LEN];
    size_t                    nl;
    ngx_uint_t                i;

    if (r != r->main) return NGX_DECLINED;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_lscache_module);
    if (lcf == NULL || !lcf->enable) return NGX_DECLINED;

    /* PURGE: handle before fastcgi/proxy/static rejects with 405. */
    if (r->method_name.len == 5
        && ngx_strncmp(r->method_name.data, (u_char *)"PURGE", 5) == 0)
    {
        return lsc_purge_handler(r);
    }

    /* Inject X-LSCache: on into the request so fastcgi_pass / proxy_pass
     * forwards it to the upstream as HTTP_X_LSCACHE. The LiteSpeed Cache
     * plugin uses that header to detect an LSCache-compatible front-end
     * and start emitting its X-LiteSpeed-* protocol headers. Without it
     * the plugin classifies the server as "NONE" and silently strips
     * cache control output. */
    (void) lsc_advertise_protocol(r);

    /* only GET / HEAD are servable from cache */
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_DECLINED;
    }

    ctx = lsc_ensure_ctx(r);
    if (ctx == NULL) return NGX_DECLINED;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (mcf->path.len == 0) return NGX_DECLINED;

    /* bypass: skip lookup; the response (if cacheable) may still be stored */
    if (lcf->bypass) {
        if (ngx_http_complex_value(r, lcf->bypass, &bypass_val) == NGX_OK
            && bypass_val.len > 0
            && !(bypass_val.len == 1 && bypass_val.data[0] == '0'))
        {
            ctx->bypass = 1;
            ctx->status = LSC_ST_BYPASS;
            return NGX_DECLINED;
        }
    }

    /* index key: host + URL only; names the folder of this URL's
     * variants */
    lsc_compute_key(r, &empty, &empty, 0, base_bin);
    lsc_hex_encode(base_bin, LSC_KEY_BIN_LEN, base_hex);
    ngx_memcpy(ctx->base_key_hex, base_hex, LSC_KEY_HEX_LEN);

    /* fast path: the public entry stored without X-LiteSpeed-Vary for
     * this request's default vary (the usual case) */
    lsc_compute_key(r, &empty, &empty, 1, fast_bin);
    lsc_hex_encode(fast_bin, LSC_KEY_BIN_LEN, fast_hex);
    rc = lsc_serve_entry(r, ctx, fast_hex, 0);
    if (rc != NGX_DECLINED) return rc;

    /* slow path: walk vary/<base>/ and try each variant */
    if (mcf->path.len + sizeof("/vary/") + LSC_KEY_HEX_LEN + 1
        >= sizeof(vdir_buf))
    {
        return NGX_DECLINED;
    }
    vp = ngx_cpymem(vdir_buf, mcf->path.data, mcf->path.len);
    vp = ngx_cpymem(vp, "/vary/", 6);
    vp = ngx_cpymem(vp, base_hex, LSC_KEY_HEX_LEN);
    *vp = '\0';
    vdir.data = vdir_buf;
    vdir.len  = vp - vdir_buf;

    if (ngx_open_dir(&vdir, &d) != NGX_OK) {
        ctx->status = LSC_ST_MISS;
        return NGX_DECLINED;
    }

    for (;;) {
        ngx_set_errno(0);
        if (ngx_read_dir(&d) != NGX_OK) break;
        nl = ngx_de_namelen(&d);
        if (nl != LSC_KEY_HEX_LEN) continue;
        raw = ngx_de_name(&d);

        /* the fast-path key was tried already */
        if (ngx_memcmp(raw, fast_hex, LSC_KEY_HEX_LEN) == 0) continue;

        /* the store side keeps the folder within lscache_max_variants;
         * never read more than that many metas for one request */
        if (++tried > lcf->max_variants) break;

        for (i = 0; i < LSC_KEY_HEX_LEN; i++) {
            u_char c = raw[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) break;
        }
        if (i != LSC_KEY_HEX_LEN) continue;
        ngx_memcpy(vhex, raw, LSC_KEY_HEX_LEN);

        rc = lsc_try_variant(r, ctx, vhex);
        if (rc != NGX_DECLINED) {
            ngx_close_dir(&d);
            return rc;
        }
    }
    ngx_close_dir(&d);

    ctx->status = LSC_ST_MISS;
    return NGX_DECLINED;
}
