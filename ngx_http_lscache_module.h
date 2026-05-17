/*
 * ngx_http_lscache_module.h - LiteSpeed Cache plugin protocol for nginx
 *
 * Types, constants, cross-file declarations.
 *
 * License: BSD-2-Clause
 */
#ifndef _NGX_HTTP_LSCACHE_MODULE_H_
#define _NGX_HTTP_LSCACHE_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <arpa/inet.h>
#include <sys/stat.h>


/* ═══════════════════════════════════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════════════════════════════ */

#define LSC_KEY_BIN_LEN        20    /* SHA-1 output */
#define LSC_KEY_HEX_LEN        40
#define LSC_MAX_TAGS           64
#define LSC_MAX_TAG_LEN        128
#define LSC_MAX_VARY_SEGMENTS  16
#define LSC_FILE_MAGIC         0x4C534331U  /* 'L','S','C','1' read as big-endian u32 */
#define LSC_FILE_HEADER_BYTES  24
#define LSC_HEADER_BLOCK_MAX   16384
#define LSC_PATH_MAX           4096
#define LSC_META_MAX           32768       /* hard cap on meta sidecar size */
#define LSC_LSC_COOKIE_MAX     4096        /* cap on LSC-Cookie value length */

/* X-LiteSpeed-Cache-Control bit flags (parsed from upstream response) */
#define LSC_CC_NO_CACHE        0x0001
#define LSC_CC_NO_STORE        0x0002
#define LSC_CC_PUBLIC          0x0004
#define LSC_CC_PRIVATE         0x0008
#define LSC_CC_NO_VARY         0x0010
#define LSC_CC_HAS_MAX_AGE     0x0020
#define LSC_CC_ESI             0x0040   /* esi=on marker; the directive is parsed but the body is cached as-is (no ESI fragment expansion) */

/* Cache file flags (16-bit field in the on-disk header) */
#define LSC_FF_PRIVATE         0x0001
#define LSC_FF_HAS_LSC_COOKIE  0x0002
#define LSC_FF_STALE           0x0004   /* lazy-purged: next request refetches */

/* $lscache_status enum (matches the 5 user-visible states) */
#define LSC_ST_NONE    0
#define LSC_ST_MISS    1
#define LSC_ST_HIT     2
#define LSC_ST_BYPASS  3
#define LSC_ST_PURGE   4


/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration structures
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    int                family;     /* AF_INET / AF_INET6 / 0 for "all" */
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } addr;
    ngx_uint_t         bits;
    unsigned           is_all:1;
} lsc_acl_t;

typedef struct {
    ngx_str_t       path;        /* lscache_path (cycle-scope; required) */
    off_t           max_size;    /* lscache_max_size */
    ngx_array_t    *purge_acl;   /* of lsc_acl_t; default 127.0.0.1 + ::1 */
} ngx_http_lsc_main_conf_t;

typedef struct {
    ngx_flag_t      enable;              /* lscache on/off */
    ngx_uint_t      methods_bitmap;      /* NGX_HTTP_GET | NGX_HTTP_HEAD | ... */
    ngx_uint_t      min_uses;
    time_t          min_age;
    time_t          max_age;
    ngx_array_t    *strip_cookies;       /* of ngx_str_t */
    ngx_http_complex_value_t *bypass;
    ngx_http_complex_value_t *no_cache;
    ngx_flag_t      debug;
} ngx_http_lsc_loc_conf_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * Per-request context
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    /* derived in PRECONTENT */
    u_char          key_bin[LSC_KEY_BIN_LEN];
    u_char          key_hex[LSC_KEY_HEX_LEN];
    u_char          base_key_hex[LSC_KEY_HEX_LEN]; /* vary/client-stripped key */
    ngx_str_t       vary_string;                   /* derived from directive */
    ngx_str_t       host;                          /* lowercased Host header */
    ngx_str_t       client_id;                     /* private cache id */

    /* lifecycle flags */
    unsigned        lookup_done:1;
    unsigned        served_from_cache:1;
    unsigned        capturing:1;
    unsigned        is_private:1;
    unsigned        has_lsc_cookie:1;
    unsigned        bypass:1;
    unsigned        no_store:1;
    unsigned        has_set_cookie:1;
    unsigned        has_unsafe_vary:1;
    unsigned        finalized:1;
    ngx_uint_t      status;            /* LSC_ST_* */

    /* parsed from upstream response */
    ngx_uint_t      cc_flags;
    time_t          max_age;
    ngx_str_t       tags[LSC_MAX_TAGS];
    ngx_uint_t      ntags;
    ngx_str_t       lsc_cookie;        /* LSC-Cookie side channel value */
    ngx_str_t       vary_directive;    /* raw X-LiteSpeed-Vary value */
    ngx_str_t       inline_purge;      /* X-LiteSpeed-Purge (response form) */

    /* capture-path state */
    ngx_fd_t        tmp_fd;
    u_char         *tmp_path;
    ngx_str_t       final_data_path;
    ngx_str_t       final_meta_path;
    off_t           bytes_written;     /* body bytes */
    off_t           hdr_block_len;     /* size of preserved header block */
} ngx_http_lsc_ctx_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * Module extern
 * ═══════════════════════════════════════════════════════════════════════ */

extern ngx_module_t ngx_http_lscache_module;


/* ═══════════════════════════════════════════════════════════════════════════
 * Cross-file declarations
 * ═══════════════════════════════════════════════════════════════════════ */

/* module.c */
ngx_http_lsc_ctx_t *lsc_ensure_ctx(ngx_http_request_t *r);

/* filter.c - response header + body capture */
ngx_int_t lsc_header_filter(ngx_http_request_t *r);
ngx_int_t lsc_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
void      lsc_filters_install(void);

/* serve.c - PRECONTENT cache lookup + serve */
ngx_int_t lsc_precontent_handler(ngx_http_request_t *r);

/* storage.c - key derivation, file paths, atomic write */
void      lsc_compute_key(ngx_http_request_t *r, ngx_str_t *vary_string,
                          ngx_str_t *client_id,
                          u_char out_bin[LSC_KEY_BIN_LEN]);
void      lsc_compute_key_full(ngx_pool_t *pool, int is_https,
                               ngx_str_t *host, ngx_str_t *uri,
                               ngx_str_t *args, ngx_str_t *vary_string,
                               ngx_str_t *client_id,
                               u_char out_bin[LSC_KEY_BIN_LEN]);
void      lsc_hex_encode(const u_char *bin, ngx_uint_t bin_len, u_char *hex);
ngx_int_t lsc_safe_name(ngx_str_t *s);
ngx_int_t lsc_mkpath(u_char *path, mode_t mode, ngx_log_t *log);

ngx_int_t lsc_data_path(ngx_pool_t *pool, ngx_str_t *root, u_char *hex_key,
                        ngx_str_t *out);
ngx_int_t lsc_meta_path(ngx_pool_t *pool, ngx_str_t *root, u_char *hex_key,
                        ngx_str_t *out);
ngx_int_t lsc_tag_path(ngx_pool_t *pool, ngx_str_t *root, ngx_str_t *tag,
                       u_char *hex_key, ngx_str_t *out);
ngx_int_t lsc_host_path(ngx_pool_t *pool, ngx_str_t *root, ngx_str_t *host,
                        u_char *hex_key, ngx_str_t *out);
ngx_int_t lsc_vary_path(ngx_pool_t *pool, ngx_str_t *root, u_char *base_hex,
                        u_char *hex_key, ngx_str_t *out);

ngx_int_t lsc_open_tmp(ngx_http_request_t *r, ngx_fd_t *fd_out,
                       u_char **path_out);
ngx_int_t lsc_finalize_tmp(ngx_http_request_t *r, u_char *tmp_path,
                           ngx_str_t *final_path);

/* If `host_filter` is non-NULL and the entry's meta carries a host
 * that doesn't match, the action is skipped. This is how inline purges
 * (from an upstream response) are scoped to the requesting host so a
 * compromised tenant cannot wipe other tenants' tagged entries on a
 * shared lscache_path. Pass NULL for the out-of-band PURGE path. */
ngx_int_t lsc_unlink_entry(ngx_http_request_t *r, u_char *hex_key,
                           int want_private, ngx_str_t *host_filter);
ngx_int_t lsc_walk_unlink(ngx_http_request_t *r, ngx_str_t *dir,
                          int want_private, ngx_str_t *host_filter,
                          ngx_uint_t *count);
ngx_int_t lsc_mark_stale(ngx_http_request_t *r, u_char *hex_key,
                         int want_private, ngx_str_t *host_filter);
ngx_int_t lsc_walk_mark_stale(ngx_http_request_t *r, ngx_str_t *dir,
                              int want_private, ngx_str_t *host_filter,
                              ngx_uint_t *count);

/* purge.c - PURGE method + inline purge
 *
 * is_inline:
 *   0 = out-of-band PURGE request (gated by lscache_purge_allowed; the
 *       caller is a trusted admin and can purge tags across all hosts
 *       on this lscache_path).
 *   1 = inline purge triggered by an upstream response header. The
 *       upstream may be one tenant's PHP-FPM on a shared cache root,
 *       so tag, asterisk and url= operations are restricted to entries
 *       whose meta records this request's Host. */
ngx_int_t lsc_purge_handler(ngx_http_request_t *r);
ngx_int_t lsc_execute_purge(ngx_http_request_t *r, ngx_str_t *purge_header,
                            int is_inline, ngx_uint_t *count_out);
ngx_int_t lsc_purge_ip_allowed(ngx_http_request_t *r);
char     *lsc_set_purge_allowed(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t lsc_purge_default_acl(ngx_conf_t *cf,
                                ngx_http_lsc_main_conf_t *mcf);

/* vary.c - vary_string assembly */
ngx_int_t lsc_build_vary_string(ngx_http_request_t *r,
                                ngx_str_t *vary_directive,
                                ngx_str_t *out);
ngx_int_t lsc_resolve_client_id(ngx_http_request_t *r, ngx_str_t *out);

/* module.c - request-counter for lscache_min_uses gating */
ngx_uint_t lsc_bump_uses(u_char hex[LSC_KEY_HEX_LEN]);

/* module.c - tell the upstream WP / Drupal / Magento plugin that the
 * front-end speaks the LSCache protocol (injects X-LSCache: on into the
 * request so fastcgi_pass / proxy_pass forwards it as HTTP_X_LSCACHE). */
ngx_int_t lsc_advertise_protocol(ngx_http_request_t *r);

/* storage.c - periodic eviction when over lscache_max_size */
void      lsc_maybe_evict(ngx_http_request_t *r);


#endif /* _NGX_HTTP_LSCACHE_MODULE_H_ */
