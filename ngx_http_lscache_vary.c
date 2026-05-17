/*
 * ngx_http_lscache_vary.c - vary_string assembly + client id resolution.
 *
 * vary_string is one of the SHA-1 inputs in lsc_compute_key.
 * It encodes the application's declared cache variations for this URL.
 *
 * Input directive (from upstream response):
 *   X-LiteSpeed-Vary: cookie=wp_logged_in,value=ismobile,cookie=cart_hash
 *
 * Algorithm:
 *   1. Tokenize on ','.
 *   2. For each cookie=NAME segment: read request cookie NAME, append
 *      "cookie:NAME=<value-or-empty>\n".
 *   3. For each value=NAME segment: read request header
 *      X-LSCache-Vary-NAME, append "value:NAME=<value-or-empty>\n".
 *   4. Sort segments lexicographically by NAME so the order of the
 *      cookie= / value= tokens in the directive doesn't change the key.
 *
 * Private client id resolution (called when ctx->is_private):
 *   First non-empty wins, in priority order:
 *     1. Cookie "_lscache_vary"   (the WP plugin sets this)
 *     2. Cookie "wp_session"
 *     3. Cookie "PHPSESSID"
 *     4. r->connection->addr_text (remote IP, fallback)
 */

#include "ngx_http_lscache_module.h"


/* ═══════════════════════════════════════════════════════════════════════════
 * Manual Cookie header walker. Avoids ngx_http_parse_multi_header_lines
 * because that function's signature changed between nginx 1.23 and earlier
 * releases, and we want one build to work across 1.24 / 1.28 / 1.30.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_get_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *out)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t       i;
    u_char          *p, *end, *kstart, *vstart;
    size_t           klen;

    part = &r->headers_in.headers.part;
    h    = part->elts;

    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; h = part->elts; i = 0;
        }
        if (h[i].key.len != 6
            || ngx_strncasecmp(h[i].key.data, (u_char *)"Cookie", 6) != 0)
        {
            continue;
        }

        p   = h[i].value.data;
        end = p + h[i].value.len;
        while (p < end) {
            while (p < end && (*p == ' ' || *p == ';' || *p == '\t')) p++;
            if (p >= end) break;

            kstart = p;
            while (p < end && *p != '=' && *p != ';') p++;
            klen = p - kstart;
            /* trim trailing whitespace on key */
            while (klen > 0 && (kstart[klen - 1] == ' '
                                || kstart[klen - 1] == '\t'))
                klen--;

            if (klen == name->len
                && ngx_strncmp(kstart, name->data, klen) == 0
                && p < end && *p == '=')
            {
                p++;            /* past '=' */
                vstart = p;
                while (p < end && *p != ';') p++;
                out->data = vstart;
                out->len  = p - vstart;
                while (out->len > 0
                    && (out->data[out->len - 1] == ' '
                        || out->data[out->len - 1] == '\t'
                        || out->data[out->len - 1] == '\r'))
                    out->len--;
                return NGX_OK;
            }

            /* skip the value of an unrelated cookie */
            while (p < end && *p != ';') p++;
        }
    }
    return NGX_DECLINED;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Vary string segment, sortable by name.
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    ngx_str_t name;
    ngx_str_t value;
    unsigned  is_cookie:1;
} lsc_vary_seg_t;


static int
lsc_seg_cmp(const lsc_vary_seg_t *a, const lsc_vary_seg_t *b)
{
    size_t m = a->name.len < b->name.len ? a->name.len : b->name.len;
    int    c = ngx_memcmp(a->name.data, b->name.data, m);
    if (c != 0) return c;
    if (a->name.len < b->name.len) return -1;
    if (a->name.len > b->name.len) return  1;
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Look up request header X-LSCache-Vary-<NAME> (case-insensitive)
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_lookup_vary_header(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *out)
{
    u_char            hdr_name[256];
    size_t            hlen;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;
    u_char           *p;

    if (name->len + sizeof("X-LSCache-Vary-") - 1 >= sizeof(hdr_name)) {
        return NGX_DECLINED;
    }
    p = ngx_cpymem(hdr_name, "X-LSCache-Vary-", sizeof("X-LSCache-Vary-") - 1);
    p = ngx_cpymem(p, name->data, name->len);
    hlen = p - hdr_name;

    part = &r->headers_in.headers.part;
    h    = part->elts;
    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; h = part->elts; i = 0;
        }
        if (h[i].key.len == hlen
            && ngx_strncasecmp(h[i].key.data, hdr_name, hlen) == 0)
        {
            *out = h[i].value;
            return NGX_OK;
        }
    }
    return NGX_DECLINED;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Build vary_string from the parsed directive + current request state.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_build_vary_string(ngx_http_request_t *r, ngx_str_t *vary_directive,
    ngx_str_t *out)
{
    lsc_vary_seg_t  segs[LSC_MAX_VARY_SEGMENTS];
    ngx_uint_t      nsegs = 0, i, j;
    u_char         *p, *end, *seg_start, *seg_end, *eq, *op;
    size_t          total;

    out->data = NULL;
    out->len  = 0;
    if (vary_directive == NULL || vary_directive->len == 0) return NGX_OK;

    p   = vary_directive->data;
    end = vary_directive->data + vary_directive->len;

    while (p < end && nsegs < LSC_MAX_VARY_SEGMENTS) {
        while (p < end && (*p == ' ' || *p == ',' || *p == '\t' || *p == '\r'))
            p++;
        if (p >= end) break;

        seg_start = p;
        while (p < end && *p != ',') p++;
        seg_end = p;
        while (seg_end > seg_start && (seg_end[-1] == ' '
                                       || seg_end[-1] == '\t'
                                       || seg_end[-1] == '\r'))
            seg_end--;

        eq = (u_char *)ngx_strlchr(seg_start, seg_end, '=');
        if (eq == NULL) continue;

        /* prefix is "cookie" or "value" */
        if (eq - seg_start == 6
            && ngx_strncasecmp(seg_start, (u_char *)"cookie", 6) == 0)
        {
            segs[nsegs].is_cookie = 1;
        } else if (eq - seg_start == 5
                   && ngx_strncasecmp(seg_start, (u_char *)"value", 5) == 0)
        {
            segs[nsegs].is_cookie = 0;
        } else {
            continue;
        }

        segs[nsegs].name.data = eq + 1;
        segs[nsegs].name.len  = seg_end - (eq + 1);
        if (segs[nsegs].name.len == 0) continue;

        /* honor lscache_strip_cookies: skip cookie vary segments whose name
         * the operator marked as "irrelevant to the cache key" (typically
         * analytics cookies like _ga, _gid, fbp, etc.) */
        if (segs[nsegs].is_cookie) {
            ngx_http_lsc_loc_conf_t *lcf =
                ngx_http_get_module_loc_conf(r, ngx_http_lscache_module);
            if (lcf != NULL && lcf->strip_cookies != NULL) {
                ngx_str_t *names = lcf->strip_cookies->elts;
                ngx_uint_t k;
                int        skip = 0;
                for (k = 0; k < lcf->strip_cookies->nelts; k++) {
                    if (names[k].len == segs[nsegs].name.len
                        && ngx_strncasecmp(names[k].data,
                                            segs[nsegs].name.data,
                                            names[k].len) == 0)
                    {
                        skip = 1;
                        break;
                    }
                }
                if (skip) continue;
            }
        }

        segs[nsegs].value.data = NULL;
        segs[nsegs].value.len  = 0;

        if (segs[nsegs].is_cookie) {
            ngx_str_t v;
            if (lsc_get_cookie(r, &segs[nsegs].name, &v) == NGX_OK) {
                segs[nsegs].value = v;
            }
        } else {
            ngx_str_t v;
            if (lsc_lookup_vary_header(r, &segs[nsegs].name, &v) == NGX_OK) {
                segs[nsegs].value = v;
            }
        }
        nsegs++;
    }

    if (nsegs == 0) return NGX_OK;

    /* insertion sort by name (nsegs <= 16) */
    for (i = 1; i < nsegs; i++) {
        lsc_vary_seg_t tmp = segs[i];
        j = i;
        while (j > 0 && lsc_seg_cmp(&segs[j - 1], &tmp) > 0) {
            segs[j] = segs[j - 1];
            j--;
        }
        segs[j] = tmp;
    }

    total = 0;
    for (i = 0; i < nsegs; i++) {
        /* "cookie:" = 7 / "value:" = 6, then NAME, '=', VALUE, '\n' */
        total += (segs[i].is_cookie ? 7 : 6)
              + segs[i].name.len + 1 + segs[i].value.len + 1;
    }

    out->data = ngx_pnalloc(r->pool, total);
    if (out->data == NULL) return NGX_ERROR;

    op = out->data;
    for (i = 0; i < nsegs; i++) {
        if (segs[i].is_cookie) op = ngx_cpymem(op, "cookie:", 7);
        else                    op = ngx_cpymem(op, "value:",  6);
        op = ngx_cpymem(op, segs[i].name.data, segs[i].name.len);
        *op++ = '=';
        if (segs[i].value.len > 0) {
            op = ngx_cpymem(op, segs[i].value.data, segs[i].value.len);
        }
        *op++ = '\n';
    }
    out->len = op - out->data;
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Private cache: resolve a client identifier.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_resolve_client_id(ngx_http_request_t *r, ngx_str_t *out)
{
    static const struct {
        const char *name;
        size_t      len;
    } candidates[] = {
        { "_lscache_vary", 13 },
        { "wp_session",    10 },
        { "PHPSESSID",      9 },
    };
    ngx_uint_t i;
    ngx_str_t  name, value;

    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        name.data = (u_char *) candidates[i].name;
        name.len  = candidates[i].len;
        if (lsc_get_cookie(r, &name, &value) == NGX_OK && value.len > 0) {
            *out = value;
            return NGX_OK;
        }
    }
    *out = r->connection->addr_text;
    return NGX_OK;
}
