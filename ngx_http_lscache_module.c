/*
 * ngx_http_lscache_module.c - module definition, config, phase wiring,
 * per-worker min_uses counter, variable handlers.
 */

#include "ngx_http_lscache_module.h"


/* ═══════════════════════════════════════════════════════════════════════════
 * Forward declarations
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t lsc_preconfigure(ngx_conf_t *cf);
static ngx_int_t lsc_postconfigure(ngx_conf_t *cf);
static void     *lsc_create_main_conf(ngx_conf_t *cf);
static char     *lsc_init_main_conf(ngx_conf_t *cf, void *conf);
static void     *lsc_create_loc_conf(ngx_conf_t *cf);
static char     *lsc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char     *lsc_set_methods(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static char     *lsc_set_strip_cookies(ngx_conf_t *cf, ngx_command_t *cmd,
                                        void *conf);
static char     *lsc_set_complex(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);

static ngx_int_t lsc_var_status(ngx_http_request_t *r,
                                 ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t lsc_var_key(ngx_http_request_t *r,
                              ngx_http_variable_value_t *v, uintptr_t data);


/* ═══════════════════════════════════════════════════════════════════════════
 * Directive table
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_command_t lsc_commands[] = {

    { ngx_string("lscache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lsc_loc_conf_t, enable),
      NULL },

    { ngx_string("lscache_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_lsc_main_conf_t, path),
      NULL },

    { ngx_string("lscache_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_lsc_main_conf_t, max_size),
      NULL },

    { ngx_string("lscache_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      lsc_set_methods,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lscache_purge_allowed"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      lsc_set_purge_allowed,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lscache_min_uses"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lsc_loc_conf_t, min_uses),
      NULL },

    { ngx_string("lscache_min_age"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lsc_loc_conf_t, min_age),
      NULL },

    { ngx_string("lscache_max_age"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lsc_loc_conf_t, max_age),
      NULL },

    { ngx_string("lscache_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      lsc_set_complex,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lsc_loc_conf_t, bypass),
      NULL },

    { ngx_string("lscache_no_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      lsc_set_complex,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lsc_loc_conf_t, no_cache),
      NULL },

    { ngx_string("lscache_strip_cookies"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      lsc_set_strip_cookies,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lscache_debug"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lsc_loc_conf_t, debug),
      NULL },

    ngx_null_command
};


/* ═══════════════════════════════════════════════════════════════════════════
 * Module context
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_http_module_t lsc_module_ctx = {
    lsc_preconfigure,         /* preconfiguration */
    lsc_postconfigure,        /* postconfiguration */
    lsc_create_main_conf,     /* create main conf */
    lsc_init_main_conf,       /* init main conf */
    NULL,                     /* create server conf */
    NULL,                     /* merge server conf */
    lsc_create_loc_conf,      /* create location conf */
    lsc_merge_loc_conf        /* merge location conf */
};

ngx_module_t ngx_http_lscache_module = {
    NGX_MODULE_V1,
    &lsc_module_ctx,
    lsc_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


/* ═══════════════════════════════════════════════════════════════════════════
 * Config callbacks
 * ═══════════════════════════════════════════════════════════════════════ */

static void *
lsc_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_lsc_main_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lsc_main_conf_t));
    if (conf == NULL) return NULL;
    conf->max_size = NGX_CONF_UNSET;
    return conf;
}


static char *
lsc_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_lsc_main_conf_t *mcf = conf;

    if (mcf->max_size == NGX_CONF_UNSET) {
        mcf->max_size = (off_t)1024 * 1024 * 1024;
    }
    if (lsc_purge_default_acl(cf, mcf) != NGX_OK) return NGX_CONF_ERROR;
    return NGX_CONF_OK;
}


static void *
lsc_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_lsc_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lsc_loc_conf_t));
    if (conf == NULL) return NULL;
    conf->enable   = NGX_CONF_UNSET;
    conf->debug    = NGX_CONF_UNSET;
    conf->min_uses = NGX_CONF_UNSET_UINT;
    conf->min_age  = NGX_CONF_UNSET;
    conf->max_age  = NGX_CONF_UNSET;
    return conf;
}


static char *
lsc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_lsc_loc_conf_t *prev = parent;
    ngx_http_lsc_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->debug,  prev->debug,  0);
    ngx_conf_merge_uint_value(conf->min_uses, prev->min_uses, 1);
    ngx_conf_merge_sec_value(conf->min_age, prev->min_age, 1);
    ngx_conf_merge_sec_value(conf->max_age, prev->max_age, 86400);

    if (conf->methods_bitmap == 0) {
        conf->methods_bitmap = prev->methods_bitmap
            ? prev->methods_bitmap
            : (NGX_HTTP_GET | NGX_HTTP_HEAD);
    }
    if (conf->bypass == NULL)        conf->bypass        = prev->bypass;
    if (conf->no_cache == NULL)      conf->no_cache      = prev->no_cache;
    if (conf->strip_cookies == NULL) conf->strip_cookies = prev->strip_cookies;
    return NGX_CONF_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Per-request context: create once, lazily.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_http_lsc_ctx_t *
lsc_ensure_ctx(ngx_http_request_t *r)
{
    ngx_http_lsc_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lscache_module);
    if (ctx != NULL) return ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_lsc_ctx_t));
    if (ctx == NULL) return NULL;
    ctx->tmp_fd = NGX_INVALID_FILE;
    ctx->status = LSC_ST_NONE;
    ngx_http_set_ctx(r, ctx, ngx_http_lscache_module);
    return ctx;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Variable registration
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_http_variable_t lsc_vars[] = {
    { ngx_string("lscache_status"), NULL, lsc_var_status, 0, 0, 0 },
    { ngx_string("lscache_key"),    NULL, lsc_var_key,    0, 0, 0 },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
lsc_preconfigure(ngx_conf_t *cf)
{
    ngx_http_variable_t *v, *vp;

    for (vp = lsc_vars; vp->name.len; vp++) {
        v = ngx_http_add_variable(cf, &vp->name, vp->flags);
        if (v == NULL) return NGX_ERROR;
        v->get_handler = vp->get_handler;
        v->data = vp->data;
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Postconfiguration - register phase handler + filters
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_postconfigure(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = lsc_precontent_handler;

    lsc_filters_install();
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Directive parsers
 * ═══════════════════════════════════════════════════════════════════════ */

static char *
lsc_set_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_lsc_loc_conf_t *lcf = conf;
    ngx_str_t               *value;
    ngx_uint_t               i;

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *m = &value[i];
        if (m->len == 3
            && ngx_strncasecmp(m->data, (u_char *)"GET", 3) == 0) {
            lcf->methods_bitmap |= NGX_HTTP_GET;
        } else if (m->len == 4
                   && ngx_strncasecmp(m->data, (u_char *)"HEAD", 4) == 0) {
            lcf->methods_bitmap |= NGX_HTTP_HEAD;
        } else if (m->len == 4
                   && ngx_strncasecmp(m->data, (u_char *)"POST", 4) == 0) {
            lcf->methods_bitmap |= NGX_HTTP_POST;
        } else {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "lscache: unsupported method \"%V\" (use GET, HEAD, or POST)",
                m);
        }
    }
    return NGX_CONF_OK;
}


static char *
lsc_set_strip_cookies(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_lsc_loc_conf_t *lcf = conf;
    ngx_str_t               *value, *s;
    ngx_uint_t               i;

    if (lcf->strip_cookies == NULL) {
        lcf->strip_cookies = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                               sizeof(ngx_str_t));
        if (lcf->strip_cookies == NULL) return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        s = ngx_array_push(lcf->strip_cookies);
        if (s == NULL) return NGX_CONF_ERROR;
        *s = value[i];
    }
    return NGX_CONF_OK;
}


static char *
lsc_set_complex(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                                *p = conf;
    ngx_str_t                           *value;
    ngx_http_complex_value_t           **cv;
    ngx_http_compile_complex_value_t     ccv;

    cv = (ngx_http_complex_value_t **)(p + cmd->offset);
    if (*cv != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (*cv == NULL) return NGX_CONF_ERROR;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf            = cf;
    ccv.value         = &value[1];
    ccv.complex_value = *cv;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return NGX_CONF_ERROR;
    return NGX_CONF_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Variable handlers
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
lsc_var_status(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_lsc_ctx_t *ctx;
    static u_char       dash[]   = "-";
    static u_char       hit[]    = "HIT";
    static u_char       miss[]   = "MISS";
    static u_char       bypass[] = "BYPASS";
    static u_char       purge[]  = "PURGE";

    v->valid = 1; v->no_cacheable = 1; v->not_found = 0;
    v->data = dash; v->len = 1;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lscache_module);
    if (ctx == NULL) return NGX_OK;

    switch (ctx->status) {
    case LSC_ST_HIT:    v->data = hit;    v->len = 3; break;
    case LSC_ST_MISS:   v->data = miss;   v->len = 4; break;
    case LSC_ST_BYPASS: v->data = bypass; v->len = 6; break;
    case LSC_ST_PURGE:  v->data = purge;  v->len = 5; break;
    default: break;
    }
    return NGX_OK;
}


static ngx_int_t
lsc_var_key(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_lsc_ctx_t *ctx;

    v->valid = 1; v->no_cacheable = 1;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lscache_module);
    if (ctx == NULL || ctx->key_hex[0] == 0) {
        v->not_found = 1; v->len = 0; v->data = NULL;
        return NGX_OK;
    }

    v->not_found = 0;
    v->data = ctx->key_hex;
    v->len  = LSC_KEY_HEX_LEN;
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Per-worker use counter for lscache_min_uses.
 *
 * Open-addressed FNV-1a table, 1024 slots, capped probe distance. On
 * collisions past the probe limit we evict the canonical slot; the use
 * count for that key resets to 1 which is the safe default (we delay the
 * cache by another request or two).
 *
 * Worker-local: under multi-worker deployments min_uses is per-worker, not
 * cluster-wide. A request requires N hits on the SAME worker before the
 * Nth response gets cached. Cluster-wide enforcement would require a shared
 * memory zone (not used by this module).
 * ═══════════════════════════════════════════════════════════════════════ */

#define LSC_USES_SLOTS  1024
#define LSC_USES_PROBE  16

typedef struct {
    u_char     hex[LSC_KEY_HEX_LEN];
    ngx_uint_t count;
    time_t     last_seen;
    unsigned   used:1;
} lsc_uses_entry_t;

static lsc_uses_entry_t lsc_uses_table[LSC_USES_SLOTS];


static uint32_t
lsc_uses_hash(u_char *hex)
{
    uint32_t h = 2166136261u;
    int      i;
    for (i = 0; i < LSC_KEY_HEX_LEN; i++) {
        h = (h ^ (uint32_t)hex[i]) * 16777619u;
    }
    return h;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Advertise the LSCache protocol to upstream apps.
 *
 * The LiteSpeed Cache plugin family (WordPress, Drupal, Magento, etc.)
 * classifies the runtime via $_SERVER['HTTP_X_LSCACHE']. Without an
 * LSCache-compatible front-end the plugin disables its page-cache
 * output entirely. We inject the header here so users do not have to
 * remember a magic fastcgi_param in every .conf - turning `lscache on`
 * is enough for the plugin to start emitting protocol headers.
 *
 * Security: we ALWAYS strip any client-supplied X-LSCache header before
 * adding our own. Trusting a client-controlled X-LSCache would let any
 * remote visitor claim "trusted front-end" status to the upstream
 * plugin, unlocking private-cache markers and other privileged paths.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_advertise_protocol(ngx_http_request_t *r)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t       i;
    u_char          *lc;

    /* strip every client-supplied X-LSCache header */
    part = &r->headers_in.headers.part;
    h    = part->elts;
    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; h = part->elts; i = 0;
        }
        if (h[i].hash == 0) continue;
        if (h[i].key.len == sizeof("X-LSCache") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *)"X-LSCache",
                               sizeof("X-LSCache") - 1) == 0)
        {
            h[i].hash = 0;
            h[i].value.len = 0;
        }
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) return NGX_ERROR;
    h->hash = 1;
    ngx_str_set(&h->key,   "X-LSCache");
    ngx_str_set(&h->value, "on");

    lc = ngx_pnalloc(r->pool, h->key.len);
    if (lc != NULL) {
        ngx_strlow(lc, h->key.data, h->key.len);
        h->lowcase_key = lc;
    } else {
        h->lowcase_key = h->key.data;
    }
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    return NGX_OK;
}


ngx_uint_t
lsc_bump_uses(u_char hex[LSC_KEY_HEX_LEN])
{
    uint32_t           h = lsc_uses_hash(hex);
    ngx_uint_t         i, slot;
    lsc_uses_entry_t  *e;

    for (i = 0; i < LSC_USES_PROBE; i++) {
        slot = (h + i) & (LSC_USES_SLOTS - 1);
        e = &lsc_uses_table[slot];
        if (!e->used) {
            ngx_memcpy(e->hex, hex, LSC_KEY_HEX_LEN);
            e->count     = 1;
            e->last_seen = ngx_time();
            e->used      = 1;
            return 1;
        }
        if (ngx_memcmp(e->hex, hex, LSC_KEY_HEX_LEN) == 0) {
            e->count++;
            e->last_seen = ngx_time();
            return e->count;
        }
    }

    /* probe exhausted - replace the canonical slot */
    slot = h & (LSC_USES_SLOTS - 1);
    e = &lsc_uses_table[slot];
    ngx_memcpy(e->hex, hex, LSC_KEY_HEX_LEN);
    e->count     = 1;
    e->last_seen = ngx_time();
    e->used      = 1;
    return 1;
}
