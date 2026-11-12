/*
 * ngx_http_lscache_purge.c - PURGE method handler + inline purge executor.
 *
 * Out-of-band PURGE method:
 *   - Check client IP against lscache_purge_allowed; 403 if not allowed.
 *   - Read X-LiteSpeed-Purge request header.
 *   - Call lsc_execute_purge.
 *   - Return 200 + "X-LiteSpeed-Purge-OK: <n>" where n is entries purged.
 *
 * Inline purge (called from header filter on backend responses carrying
 * X-LiteSpeed-Purge):
 *   - Same parser + executor.
 *   - No 403 check (the backend is trusted).
 *
 * X-LiteSpeed-Purge syntax:
 *     *                                wildcard, all public entries for Host
 *     private, *                       wildcard, all private entries for Host
 *     [public,] tag=t1, tag=t2         tag list, public-only
 *     private, tag=t1                  tag list, private-only
 *     [public,] url=/foo               exact URL, public-only
 *     private, url=/foo                exact URL, private-only
 *     pub-block ; private-block        ';' separates blocks
 *     stale, t1, t2                    flag tags as stale (lazy refresh) instead
 *                                      of unlinking; next matching request
 *                                      refetches and overwrites.
 *     t1, t2~s, t3                     per-tag "~s" suffix promotes that one
 *                                      tag to the stale path; others use the
 *                                      block's default action.
 *
 * Security:
 *   - Tag names and url values pass through lsc_safe_name (rejects "..",
 *     '\0', control chars, '/').
 *   - PURGE is gated by lscache_purge_allowed (default 127.0.0.1 + ::1).
 */

#include "ngx_http_lscache_module.h"


/* ═══════════════════════════════════════════════════════════════════════════
 * Default ACL: localhost only. Called when lscache_purge_allowed was never
 * configured.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_purge_default_acl(ngx_conf_t *cf, ngx_http_lsc_main_conf_t *mcf)
{
    lsc_acl_t *acl;

    if (mcf->purge_acl != NULL && mcf->purge_acl->nelts > 0) return NGX_OK;

    if (mcf->purge_acl == NULL) {
        mcf->purge_acl = ngx_array_create(cf->pool, 2, sizeof(lsc_acl_t));
        if (mcf->purge_acl == NULL) return NGX_ERROR;
    }

    acl = ngx_array_push(mcf->purge_acl);
    if (acl == NULL) return NGX_ERROR;
    ngx_memzero(acl, sizeof(lsc_acl_t));
    acl->family = AF_INET;
    acl->bits   = 32;
    if (inet_pton(AF_INET, "127.0.0.1", &acl->addr.v4) != 1) return NGX_ERROR;

    acl = ngx_array_push(mcf->purge_acl);
    if (acl == NULL) return NGX_ERROR;
    ngx_memzero(acl, sizeof(lsc_acl_t));
    acl->family = AF_INET6;
    acl->bits   = 128;
    if (inet_pton(AF_INET6, "::1", &acl->addr.v6) != 1) return NGX_ERROR;

    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Parse "lscache_purge_allowed <CIDR>..." entries.
 *
 * Accepts: bare IP (v4/v6), CIDR (v4/v6), or "all".
 * ═══════════════════════════════════════════════════════════════════════ */

char *
lsc_set_purge_allowed(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_lsc_main_conf_t *mcf = conf;
    ngx_str_t                *value = cf->args->elts;
    ngx_uint_t                i;
    lsc_acl_t                *acl;
    u_char                    ipbuf[64], *slash;
    ngx_int_t                 bits_parsed;
    ngx_uint_t                ilen, bits;

    if (mcf->purge_acl == NULL) {
        mcf->purge_acl = ngx_array_create(cf->pool, 4, sizeof(lsc_acl_t));
        if (mcf->purge_acl == NULL) return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        acl = ngx_array_push(mcf->purge_acl);
        if (acl == NULL) return NGX_CONF_ERROR;
        ngx_memzero(acl, sizeof(lsc_acl_t));

        if (value[i].len == 3
            && ngx_strncasecmp(value[i].data, (u_char *)"all", 3) == 0)
        {
            acl->is_all = 1;
            continue;
        }

        ilen = value[i].len;
        bits = 0;
        slash = NULL;

        {
            ngx_uint_t j;
            for (j = 0; j < value[i].len; j++) {
                if (value[i].data[j] == '/') { slash = &value[i].data[j]; break; }
            }
        }
        if (slash) {
            ilen = slash - value[i].data;
            bits_parsed = ngx_atoi(slash + 1,
                                    value[i].len - ilen - 1);
            if (bits_parsed == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "lscache: invalid CIDR mask in \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            bits = (ngx_uint_t) bits_parsed;
        }
        if (ilen >= sizeof(ipbuf)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "lscache: address too long in \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(ipbuf, value[i].data, ilen);
        ipbuf[ilen] = '\0';

        if (inet_pton(AF_INET, (char *)ipbuf, &acl->addr.v4) == 1) {
            acl->family = AF_INET;
            acl->bits   = slash ? bits : 32;
            if (acl->bits > 32) acl->bits = 32;
        } else if (inet_pton(AF_INET6, (char *)ipbuf, &acl->addr.v6) == 1) {
            acl->family = AF_INET6;
            acl->bits   = slash ? bits : 128;
            if (acl->bits > 128) acl->bits = 128;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "lscache: invalid IP \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Match the client connection's sockaddr against the configured ACL.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_purge_ip_allowed(ngx_http_request_t *r)
{
    ngx_http_lsc_main_conf_t *mcf;
    struct sockaddr          *sa;
    lsc_acl_t                *acls, *a;
    ngx_uint_t                i;
    int                       client_family;
    struct in_addr            client_v4;
    struct in6_addr          *client_v6 = NULL;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (mcf->purge_acl == NULL || mcf->purge_acl->nelts == 0) return 0;

    sa = r->connection->sockaddr;
    if (sa == NULL) return 0;

    /* Normalize v4-mapped IPv6 (::ffff:a.b.c.d) to a real AF_INET
     * address so v4 ACL entries match clients that arrive over a
     * dual-stack listener. Without this, allowlisting "127.0.0.1"
     * silently denies localhost requests when nginx listens on `::`. */
    if (sa->sa_family == AF_INET6) {
        client_v6 = &((struct sockaddr_in6 *) sa)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(client_v6)) {
            ngx_memcpy(&client_v4, client_v6->s6_addr + 12, 4);
            client_family = AF_INET;
        } else {
            client_family = AF_INET6;
        }
    } else if (sa->sa_family == AF_INET) {
        client_v4 = ((struct sockaddr_in *) sa)->sin_addr;
        client_family = AF_INET;
    } else {
        return 0;
    }

    acls = mcf->purge_acl->elts;
    for (i = 0; i < mcf->purge_acl->nelts; i++) {
        a = &acls[i];
        if (a->is_all) return 1;

        if (a->family == AF_INET && client_family == AF_INET) {
            uint32_t mask;
            if (a->bits == 0)        mask = 0;
            else if (a->bits >= 32)  mask = 0xFFFFFFFFu;
            else                     mask = htonl(0xFFFFFFFFu << (32 - a->bits));
            if ((client_v4.s_addr & mask) == (a->addr.v4.s_addr & mask))
                return 1;
        } else if (a->family == AF_INET6 && client_family == AF_INET6) {
            ngx_uint_t j, full = a->bits / 8, rem = a->bits % 8;
            int ok = 1;
            for (j = 0; j < 16 && ok; j++) {
                uint8_t m = (j < full)  ? 0xFFu
                          : (j == full) ? (rem ? (uint8_t)((0xFFu << (8 - rem))
                                                            & 0xFFu) : 0)
                                        : 0;
                if ((client_v6->s6_addr[j] & m) != (a->addr.v6.s6_addr[j] & m))
                    ok = 0;
            }
            if (ok) return 1;
        }
    }
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Execute one purge block (everything between two ';' separators).
 *
 * Block syntax:
 *   [public,|private,|stale,] entry [, entry ...]
 *   entry: '*' | 'url=<u>' | 'tag=<t>' | <bare-tag>
 * ═══════════════════════════════════════════════════════════════════════ */

static void
lsc_purge_block(ngx_http_request_t *r, u_char *block_start, u_char *block_end,
    int is_inline, ngx_uint_t *count)
{
    ngx_http_lsc_main_conf_t *mcf;
    int             want_private = 0;  /* default: public */
    int             want_stale   = 0;  /* default: immediate delete */
    u_char         *p = block_start, *e = block_end, *tok_start, *tok_end;
    ngx_str_t       host;
    ngx_str_t      *host_filter;
    ngx_str_t       dir;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);

    lsc_request_host(r, &host);
    /* For inline purges (driven by an upstream response), restrict
     * tag, url and asterisk purges to entries matching this Host. This
     * prevents a compromised tenant's PHP plugin from wiping other
     * tenants' tag entries when the cache root is shared. Out-of-band
     * PURGE callers are gated by lscache_purge_allowed and don't need
     * this restriction. */
    host_filter = (is_inline && host.len > 0) ? &host : NULL;

    while (p < e) {
        /* skip whitespace and commas */
        while (p < e && (*p == ' ' || *p == ',' || *p == '\t' || *p == '\r'))
            p++;
        if (p >= e) break;

        tok_start = p;
        while (p < e && *p != ',') p++;
        tok_end = p;
        while (tok_end > tok_start && (tok_end[-1] == ' '
                                       || tok_end[-1] == '\t'
                                       || tok_end[-1] == '\r'))
            tok_end--;

        if (tok_end == tok_start) continue;

        /* leading prefixes only at the start of the block */
        if (tok_end - tok_start == 6
            && ngx_strncasecmp(tok_start, (u_char *)"public", 6) == 0)
        {
            want_private = 0;
            continue;
        }
        if (tok_end - tok_start == 7
            && ngx_strncasecmp(tok_start, (u_char *)"private", 7) == 0)
        {
            want_private = 1;
            continue;
        }
        if (tok_end - tok_start == 5
            && ngx_strncasecmp(tok_start, (u_char *)"stale", 5) == 0)
        {
            /* mark the rest of this block's targets stale instead of
             * unlinking. The data files survive (still readable in
             * fallback paths) and the next matching request rebuilds
             * the entry by capturing the upstream response. */
            want_stale = 1;
            continue;
        }

        /* '*' wildcard */
        if (tok_end - tok_start == 1 && *tok_start == '*') {
            if (host.len > 0 && lsc_safe_name(&host) == NGX_OK) {
                ngx_str_t empty = ngx_null_string;
                /* build "<root>/hosts/<host>" (no key suffix) */
                u_char *buf = ngx_pnalloc(r->pool,
                    mcf->path.len + sizeof("/hosts/") + host.len + 1);
                if (buf != NULL) {
                    u_char *bp = ngx_cpymem(buf, mcf->path.data, mcf->path.len);
                    bp = ngx_cpymem(bp, "/hosts/", 7);
                    bp = ngx_cpymem(bp, host.data, host.len);
                    *bp = '\0';
                    dir.data = buf;
                    dir.len  = bp - buf;
                    if (want_stale) {
                        (void) lsc_walk_mark_stale(r, &dir, want_private,
                                                    host_filter, count);
                    } else {
                        (void) lsc_walk_unlink(r, &dir, want_private,
                                                host_filter, count);
                    }
                }
                (void) empty;
            }
            continue;
        }

        /* tag=NAME */
        if (tok_end - tok_start > 4
            && ngx_strncasecmp(tok_start, (u_char *)"tag=", 4) == 0)
        {
            ngx_str_t tag;
            tag.data = tok_start + 4;
            tag.len  = tok_end - tag.data;
            if (lsc_safe_name(&tag) != NGX_OK) continue;

            u_char *buf = ngx_pnalloc(r->pool,
                mcf->path.len + sizeof("/tags/") + tag.len + 1);
            if (buf != NULL) {
                u_char *bp = ngx_cpymem(buf, mcf->path.data, mcf->path.len);
                bp = ngx_cpymem(bp, "/tags/", 6);
                bp = ngx_cpymem(bp, tag.data, tag.len);
                *bp = '\0';
                dir.data = buf;
                dir.len  = bp - buf;
                if (want_stale) {
                    (void) lsc_walk_mark_stale(r, &dir, want_private,
                                                host_filter, count);
                } else {
                    (void) lsc_walk_unlink(r, &dir, want_private,
                                            host_filter, count);
                }
            }
            continue;
        }

        /* url=<u> */
        if (tok_end - tok_start > 4
            && ngx_strncasecmp(tok_start, (u_char *)"url=", 4) == 0)
        {
            ngx_str_t uri_part, args_part = ngx_null_string;
            u_char   *qm;
            u_char    base_bin[LSC_KEY_BIN_LEN];
            u_char    base_hex[LSC_KEY_HEX_LEN];
            int       is_https = 0;
            u_char   *buf;
            ngx_uint_t k;

            uri_part.data = tok_start + 4;
            uri_part.len  = tok_end - uri_part.data;

            /* reject control chars and '..' in the url= value */
            for (k = 0; k < uri_part.len; k++) {
                u_char c = uri_part.data[k];
                if (c == 0 || c < 0x20 || c == 0x7F) break;
                if (c == '.' && k + 1 < uri_part.len
                    && uri_part.data[k + 1] == '.') break;
            }
            if (k != uri_part.len) continue;

            qm = (u_char *)ngx_strlchr(uri_part.data,
                                       uri_part.data + uri_part.len, '?');
            if (qm) {
                args_part.data = qm + 1;
                args_part.len  = uri_part.data + uri_part.len - args_part.data;
                uri_part.len   = qm - uri_part.data;
            }

#if (NGX_HTTP_SSL)
            if (r->connection->ssl) is_https = 1;
#endif

            {
                ngx_str_t empty = ngx_null_string;
                lsc_compute_key_full(is_https, &host,
                                     &uri_part, &args_part,
                                     &empty, &empty, &empty, base_bin);
            }
            lsc_hex_encode(base_bin, LSC_KEY_BIN_LEN, base_hex);

            buf = ngx_pnalloc(r->pool, mcf->path.len + sizeof("/vary/")
                                       + LSC_KEY_HEX_LEN + 1);
            if (buf != NULL) {
                u_char *bp = ngx_cpymem(buf, mcf->path.data, mcf->path.len);
                bp = ngx_cpymem(bp, "/vary/", 6);
                bp = ngx_cpymem(bp, base_hex, LSC_KEY_HEX_LEN);
                *bp = '\0';
                dir.data = buf;
                dir.len  = bp - buf;
                if (want_stale) {
                    (void) lsc_walk_mark_stale(r, &dir, want_private,
                                                host_filter, count);
                } else {
                    (void) lsc_walk_unlink(r, &dir, want_private,
                                            host_filter, count);
                }
            }
            continue;
        }

        /* bare tag (no "tag=" prefix) - rare but allowed */
        {
            ngx_str_t tag;
            int       tag_stale = want_stale;
            tag.data = tok_start;
            tag.len  = tok_end - tok_start;
            /* per-tag "~s" suffix promotes just this tag to stale */
            if (tag.len > 2 && tag.data[tag.len - 2] == '~'
                && (tag.data[tag.len - 1] == 's'
                    || tag.data[tag.len - 1] == 'S'))
            {
                tag.len   -= 2;
                tag_stale  = 1;
            }
            if (lsc_safe_name(&tag) != NGX_OK) continue;

            u_char *buf = ngx_pnalloc(r->pool,
                mcf->path.len + sizeof("/tags/") + tag.len + 1);
            if (buf != NULL) {
                u_char *bp = ngx_cpymem(buf, mcf->path.data, mcf->path.len);
                bp = ngx_cpymem(bp, "/tags/", 6);
                bp = ngx_cpymem(bp, tag.data, tag.len);
                *bp = '\0';
                dir.data = buf;
                dir.len  = bp - buf;
                if (tag_stale) {
                    (void) lsc_walk_mark_stale(r, &dir, want_private,
                                                host_filter, count);
                } else {
                    (void) lsc_walk_unlink(r, &dir, want_private,
                                            host_filter, count);
                }
            }
        }
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Top-level executor: split on ';' into blocks, then dispatch.
 * ═══════════════════════════════════════════════════════════════════════ */

/* Hard caps on inputs to bound worst-case work per purge request. A
 * malicious upstream emitting a huge X-LiteSpeed-Purge or thousands
 * of ';' blocks could otherwise stall a worker. */
#define LSC_PURGE_HEADER_MAX  65536
#define LSC_PURGE_BLOCK_MAX   64

ngx_int_t
lsc_execute_purge(ngx_http_request_t *r, ngx_str_t *purge_header,
    int is_inline, ngx_uint_t *count_out)
{
    u_char     *p, *end, *block_start;
    ngx_uint_t  count = 0;
    ngx_uint_t  blocks = 0;

    if (purge_header == NULL || purge_header->len == 0) {
        if (count_out) *count_out = 0;
        return NGX_OK;
    }

    if (purge_header->len > LSC_PURGE_HEADER_MAX) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "lscache: oversized X-LiteSpeed-Purge (%uz bytes) truncated to %uz",
            purge_header->len, (size_t) LSC_PURGE_HEADER_MAX);
        end = purge_header->data + LSC_PURGE_HEADER_MAX;
    } else {
        end = purge_header->data + purge_header->len;
    }

    p   = purge_header->data;
    block_start = p;

    while (p <= end) {
        if (p == end || *p == ';') {
            if (blocks >= LSC_PURGE_BLOCK_MAX) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "lscache: X-LiteSpeed-Purge block cap (%ui) reached, ignoring remainder",
                    (ngx_uint_t) LSC_PURGE_BLOCK_MAX);
                break;
            }
            lsc_purge_block(r, block_start, p, is_inline, &count);
            blocks++;
            if (p == end) break;
            block_start = p + 1;
        }
        p++;
    }

    if (count_out) *count_out = count;
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * PURGE method handler.
 *
 * Called from the PRECONTENT phase. Returns NGX_DONE after sending its own
 * response (headers only, no body).
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_table_elt_t *
lsc_find_request_header(ngx_http_request_t *r, const char *name, size_t len)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t       i;

    part = &r->headers_in.headers.part;
    h    = part->elts;
    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; h = part->elts; i = 0;
        }
        if (h[i].key.len == len
            && ngx_strncasecmp(h[i].key.data, (u_char *)name, len) == 0)
        {
            return &h[i];
        }
    }
    return NULL;
}


ngx_int_t
lsc_purge_handler(ngx_http_request_t *r)
{
    ngx_table_elt_t      *purge_hdr, *resp_hdr;
    ngx_http_lsc_ctx_t   *ctx;
    ngx_uint_t            count = 0;
    ngx_str_t             header_value;
    ngx_int_t             rc;
    u_char               *buf;

    if (!lsc_purge_ip_allowed(r)) {
        return NGX_HTTP_FORBIDDEN;
    }

    ctx = lsc_ensure_ctx(r);
    if (ctx) ctx->status = LSC_ST_PURGE;

    purge_hdr = lsc_find_request_header(r, "X-LiteSpeed-Purge",
                                        sizeof("X-LiteSpeed-Purge") - 1);
    if (purge_hdr != NULL && purge_hdr->value.len > 0) {
        header_value = purge_hdr->value;
        (void) lsc_execute_purge(r, &header_value, 0, &count);
    } else {
        /* no header at all -> purge the exact URL of this request as public */
        ngx_str_t synthetic;
        u_char    buf2[2048];
        u_char   *bp = buf2;
        bp = ngx_cpymem(bp, "url=", 4);
        if (r->uri.len + r->args.len + 8 < sizeof(buf2)) {
            bp = ngx_cpymem(bp, r->uri.data, r->uri.len);
            if (r->args.len > 0) {
                *bp++ = '?';
                bp = ngx_cpymem(bp, r->args.data, r->args.len);
            }
            synthetic.data = buf2;
            synthetic.len  = bp - buf2;
            (void) lsc_execute_purge(r, &synthetic, 0, &count);
        }
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    buf = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (buf == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    header_value.data = buf;
    header_value.len  = ngx_sprintf(buf, "%ui", count) - buf;
    resp_hdr = lsc_push_header(r, "X-LiteSpeed-Purge-OK",
                               sizeof("X-LiteSpeed-Purge-OK") - 1,
                               &header_value);
    if (resp_hdr == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) return rc;
    rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}
