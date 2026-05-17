/*
 * ngx_http_lscache_storage.c - cache key, on-disk layout, atomic write.
 *
 * Layout:
 *   <lscache_path>/data/<hh>/<hh>/<hex-key>       cache file (header + body)
 *   <lscache_path>/data/<hh>/<hh>/<hex-key>.meta  metadata sidecar (text)
 *   <lscache_path>/tags/<tag>/<hex-key>           tag back-reference (empty)
 *   <lscache_path>/hosts/<host>/<hex-key>         host back-reference (empty)
 *   <lscache_path>/vary/<base-hex>/<hex-key>      vary back-reference (empty)
 *   <lscache_path>/tmp/<pid>-<seq>                in-flight writes
 *
 * Key:
 *   SHA1(scheme + "\n" + host + "\n" + uri + "\n" + args + "\n"
 *        + vary_string + "\n" + client_id)
 *
 * Path traversal guard: every user-controlled component flowing into a path
 * (tag name, URL component, host name) passes through lsc_safe_name. Reject
 * "..", "\0", control chars, '/'.
 */

#include "ngx_http_lscache_module.h"
#include <ngx_sha1.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>


static const u_char lsc_hex_chars[] = "0123456789abcdef";

/* Per-worker tmp file sequence; safe because nginx workers are single-threaded
 * and the tmp filename also embeds ngx_pid. */
static ngx_uint_t  lsc_tmp_seq = 0;


/* ═══════════════════════════════════════════════════════════════════════════
 * Hex encode (SHA-1 output -> 40-char lowercase)
 * ═══════════════════════════════════════════════════════════════════════ */

void
lsc_hex_encode(const u_char *bin, ngx_uint_t bin_len, u_char *hex)
{
    ngx_uint_t i;
    for (i = 0; i < bin_len; i++) {
        hex[i * 2]     = lsc_hex_chars[(bin[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = lsc_hex_chars[ bin[i]       & 0x0F];
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Lowercase a buffer into a freshly allocated pool buffer
 * ═══════════════════════════════════════════════════════════════════════ */

static u_char *
lsc_tolower_dup(ngx_pool_t *pool, u_char *src, size_t len)
{
    u_char    *dst;
    ngx_uint_t i;

    dst = ngx_pnalloc(pool, len);
    if (dst == NULL) return NULL;
    for (i = 0; i < len; i++) dst[i] = ngx_tolower(src[i]);
    return dst;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Compute the SHA-1 cache key.
 *
 * scheme + "\n" + host + "\n" + uri + "\n" + args + "\n"
 *        + vary_string + "\n" + client_id
 *
 * lsc_compute_key_full is the explicit-input form (used by the purge
 * executor when only a URL is known). lsc_compute_key wraps it with
 * inputs from the current request.
 * ═══════════════════════════════════════════════════════════════════════ */

void
lsc_compute_key_full(ngx_pool_t *pool, int is_https,
    ngx_str_t *host, ngx_str_t *uri, ngx_str_t *args,
    ngx_str_t *vary_string, ngx_str_t *client_id,
    u_char out_bin[LSC_KEY_BIN_LEN])
{
    ngx_sha1_t  sha;
    u_char     *lower;
    static const u_char nl = '\n';

    ngx_sha1_init(&sha);

    if (is_https) ngx_sha1_update(&sha, (u_char *)"https", 5);
    else          ngx_sha1_update(&sha, (u_char *)"http",  4);
    ngx_sha1_update(&sha, &nl, 1);

    if (host && host->len > 0) {
        lower = lsc_tolower_dup(pool, host->data, host->len);
        if (lower) ngx_sha1_update(&sha, lower,      host->len);
        else       ngx_sha1_update(&sha, host->data, host->len);
    }
    ngx_sha1_update(&sha, &nl, 1);

    if (uri && uri->len > 0) {
        ngx_sha1_update(&sha, uri->data, uri->len);
    }
    ngx_sha1_update(&sha, &nl, 1);

    if (args && args->len > 0) {
        ngx_sha1_update(&sha, args->data, args->len);
    }
    ngx_sha1_update(&sha, &nl, 1);

    if (vary_string && vary_string->len > 0) {
        ngx_sha1_update(&sha, vary_string->data, vary_string->len);
    }
    ngx_sha1_update(&sha, &nl, 1);

    if (client_id && client_id->len > 0) {
        ngx_sha1_update(&sha, client_id->data, client_id->len);
    }

    ngx_sha1_final(out_bin, &sha);
}


void
lsc_compute_key(ngx_http_request_t *r, ngx_str_t *vary_string,
    ngx_str_t *client_id, u_char out_bin[LSC_KEY_BIN_LEN])
{
    ngx_str_t host = ngx_null_string;
    int       is_https = 0;

#if (NGX_HTTP_SSL)
    if (r->connection->ssl) is_https = 1;
#endif

    if (r->headers_in.host && r->headers_in.host->value.len > 0) {
        host = r->headers_in.host->value;
    } else if (r->headers_in.server.len > 0) {
        host = r->headers_in.server;
    }

    lsc_compute_key_full(r->pool, is_https, &host, &r->uri, &r->args,
                         vary_string, client_id, out_bin);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Validate a user-supplied path component (tag name, url segment, host name).
 *
 * Rejects:
 *   - empty string
 *   - any byte < 0x20 or 0x7F
 *   - '/'
 *   - '\\'
 *   - "..". Anywhere in the string. Apache/LiteSpeed tag names never need
 *     two consecutive dots.
 *   - length > 1024
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_safe_name(ngx_str_t *s)
{
    ngx_uint_t i;

    if (s == NULL || s->len == 0 || s->len > 1024) return NGX_ERROR;

    /* reject anything that resolves to the current directory or a parent
     * after path concatenation: bare ".", ".." and any leading '.' that
     * would create a hidden file or skip into the parent. */
    if (s->data[0] == '.') return NGX_ERROR;

    for (i = 0; i < s->len; i++) {
        u_char c = s->data[i];
        if (c < 0x20 || c == 0x7F) return NGX_ERROR;
        if (c == '/' || c == '\\') return NGX_ERROR;
        if (c == '.' && i + 1 < s->len && s->data[i + 1] == '.') return NGX_ERROR;
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * mkdir -p (creates all missing parents).
 *
 * Mutates `path` temporarily but restores it before returning.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_mkpath(u_char *path, mode_t mode, ngx_log_t *log)
{
    u_char *p, *slash;
    size_t  len;

    if (path == NULL || *path == '\0') return NGX_ERROR;

    if (mkdir((char *)path, mode) == 0) return NGX_OK;
    if (errno == EEXIST) return NGX_OK;
    if (errno != ENOENT) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
            "lscache: mkdir \"%s\" failed", path);
        return NGX_ERROR;
    }

    /* parent doesn't exist; find last slash, recurse, then retry */
    len = ngx_strlen(path);
    p = path + len;
    while (p > path && *p != '/') p--;
    if (p == path) return NGX_ERROR;

    slash = p;
    *slash = '\0';
    if (lsc_mkpath(path, mode, log) != NGX_OK) {
        *slash = '/';
        return NGX_ERROR;
    }
    *slash = '/';

    if (mkdir((char *)path, mode) == 0) return NGX_OK;
    if (errno == EEXIST) return NGX_OK;
    ngx_log_error(NGX_LOG_ERR, log, errno,
        "lscache: mkdir \"%s\" failed", path);
    return NGX_ERROR;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Path builders.
 *
 * All produce NUL-terminated buffers in `out->data`. `out->len` excludes NUL.
 * Layout uses two 2-char shards from the start of the hex key so a single
 * directory holds at most ~256 entries on a uniform key distribution.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_data_path(ngx_pool_t *pool, ngx_str_t *root, u_char *hex_key,
    ngx_str_t *out)
{
    /* <root>/data/HH/HH/<40> */
    u_char *p;
    out->len = root->len + sizeof("/data/") - 1 + 2 + 1 + 2 + 1
             + LSC_KEY_HEX_LEN;
    out->data = ngx_pnalloc(pool, out->len + 1);
    if (out->data == NULL) return NGX_ERROR;

    p = ngx_cpymem(out->data, root->data, root->len);
    p = ngx_cpymem(p, "/data/", 6);
    *p++ = hex_key[0]; *p++ = hex_key[1]; *p++ = '/';
    *p++ = hex_key[2]; *p++ = hex_key[3]; *p++ = '/';
    p = ngx_cpymem(p, hex_key, LSC_KEY_HEX_LEN);
    *p = '\0';
    return NGX_OK;
}

ngx_int_t
lsc_meta_path(ngx_pool_t *pool, ngx_str_t *root, u_char *hex_key,
    ngx_str_t *out)
{
    /* <root>/data/HH/HH/<40>.meta */
    u_char *p;
    out->len = root->len + sizeof("/data/") - 1 + 2 + 1 + 2 + 1
             + LSC_KEY_HEX_LEN + sizeof(".meta") - 1;
    out->data = ngx_pnalloc(pool, out->len + 1);
    if (out->data == NULL) return NGX_ERROR;

    p = ngx_cpymem(out->data, root->data, root->len);
    p = ngx_cpymem(p, "/data/", 6);
    *p++ = hex_key[0]; *p++ = hex_key[1]; *p++ = '/';
    *p++ = hex_key[2]; *p++ = hex_key[3]; *p++ = '/';
    p = ngx_cpymem(p, hex_key, LSC_KEY_HEX_LEN);
    p = ngx_cpymem(p, ".meta", 5);
    *p = '\0';
    return NGX_OK;
}

ngx_int_t
lsc_tag_path(ngx_pool_t *pool, ngx_str_t *root, ngx_str_t *tag,
    u_char *hex_key, ngx_str_t *out)
{
    /* <root>/tags/<tag>/<40> */
    u_char *p;
    if (lsc_safe_name(tag) != NGX_OK) return NGX_ERROR;
    out->len = root->len + sizeof("/tags/") - 1 + tag->len + 1
             + LSC_KEY_HEX_LEN;
    out->data = ngx_pnalloc(pool, out->len + 1);
    if (out->data == NULL) return NGX_ERROR;

    p = ngx_cpymem(out->data, root->data, root->len);
    p = ngx_cpymem(p, "/tags/", 6);
    p = ngx_cpymem(p, tag->data, tag->len);
    *p++ = '/';
    p = ngx_cpymem(p, hex_key, LSC_KEY_HEX_LEN);
    *p = '\0';
    return NGX_OK;
}

ngx_int_t
lsc_host_path(ngx_pool_t *pool, ngx_str_t *root, ngx_str_t *host,
    u_char *hex_key, ngx_str_t *out)
{
    /* <root>/hosts/<host>/<40> */
    u_char *p;
    if (lsc_safe_name(host) != NGX_OK) return NGX_ERROR;
    out->len = root->len + sizeof("/hosts/") - 1 + host->len + 1
             + LSC_KEY_HEX_LEN;
    out->data = ngx_pnalloc(pool, out->len + 1);
    if (out->data == NULL) return NGX_ERROR;

    p = ngx_cpymem(out->data, root->data, root->len);
    p = ngx_cpymem(p, "/hosts/", 7);
    p = ngx_cpymem(p, host->data, host->len);
    *p++ = '/';
    p = ngx_cpymem(p, hex_key, LSC_KEY_HEX_LEN);
    *p = '\0';
    return NGX_OK;
}

ngx_int_t
lsc_vary_path(ngx_pool_t *pool, ngx_str_t *root, u_char *base_hex,
    u_char *hex_key, ngx_str_t *out)
{
    /* <root>/vary/<40-base>/<40> */
    u_char *p;
    out->len = root->len + sizeof("/vary/") - 1 + LSC_KEY_HEX_LEN + 1
             + LSC_KEY_HEX_LEN;
    out->data = ngx_pnalloc(pool, out->len + 1);
    if (out->data == NULL) return NGX_ERROR;

    p = ngx_cpymem(out->data, root->data, root->len);
    p = ngx_cpymem(p, "/vary/", 6);
    p = ngx_cpymem(p, base_hex, LSC_KEY_HEX_LEN);
    *p++ = '/';
    p = ngx_cpymem(p, hex_key, LSC_KEY_HEX_LEN);
    *p = '\0';
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Open a unique tmp file for capture-path writes.
 *
 * Name: "<lscache_path>/tmp/<pid>-<seq>". O_EXCL prevents collisions.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_open_tmp(ngx_http_request_t *r, ngx_fd_t *fd_out, u_char **path_out)
{
    ngx_http_lsc_main_conf_t *mcf;
    u_char                   *path, *tdir, *p;
    ngx_fd_t                  fd;
    ngx_uint_t                seq, attempt;
    uint32_t                  rnd;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (mcf->path.len == 0) return NGX_ERROR;

    /* ensure <root>/tmp exists - 0750 so other system users cannot
     * peek at in-flight cache writes (which may carry LSC-Cookie
     * material or other session-bearing payloads). */
    tdir = ngx_pnalloc(r->pool, mcf->path.len + sizeof("/tmp"));
    if (tdir == NULL) return NGX_ERROR;
    p = ngx_cpymem(tdir, mcf->path.data, mcf->path.len);
    p = ngx_cpymem(p, "/tmp", 4);
    *p = '\0';
    if (lsc_mkpath(tdir, 0750, r->connection->log) != NGX_OK) {
        return NGX_ERROR;
    }

    path = ngx_pnalloc(r->pool, mcf->path.len + sizeof("/tmp/") + 64);
    if (path == NULL) return NGX_ERROR;

    /* Try a few O_EXCL opens with pid + per-worker seq + random suffix.
     * O_EXCL is what prevents two workers (or a PID-reused worker after
     * a crash) from clobbering each other's tmp files. */
    for (attempt = 0; attempt < 8; attempt++) {
        seq = ++lsc_tmp_seq;
        rnd = (uint32_t) ngx_random();
        p = ngx_sprintf(path, "%V/tmp/%P-%uA-%08xD",
                        &mcf->path, ngx_pid, seq, rnd);
        *p = '\0';

        fd = open((char *) path,
                  O_WRONLY | O_CREAT | O_EXCL
#ifdef O_CLOEXEC
                  | O_CLOEXEC
#endif
                  , 0640);
        if (fd >= 0) {
            *fd_out = fd;
            *path_out = path;
            return NGX_OK;
        }
        if (errno != EEXIST) break;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
        "lscache: open tmp file \"%s\" failed", path);
    return NGX_ERROR;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Atomic finalize: rename(2) from tmp -> final path.
 *
 * Creates the destination directory tree if missing. rename(2) is atomic on
 * the same filesystem, so concurrent finalizers compete and last writer wins
 * without corruption.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_finalize_tmp(ngx_http_request_t *r, u_char *tmp_path,
    ngx_str_t *final_path)
{
    u_char  parent[LSC_PATH_MAX];
    u_char *slash;

    if (final_path->len >= LSC_PATH_MAX) return NGX_ERROR;
    ngx_memcpy(parent, final_path->data, final_path->len);
    parent[final_path->len] = '\0';

    /* strip the final segment */
    slash = parent + final_path->len;
    while (slash > parent && *slash != '/') slash--;
    if (slash == parent) return NGX_ERROR;
    *slash = '\0';

    if (lsc_mkpath(parent, 0750, r->connection->log) != NGX_OK) {
        return NGX_ERROR;
    }

    if (rename((char *)tmp_path, (char *)final_path->data) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
            "lscache: rename \"%s\" -> \"%V\" failed", tmp_path, final_path);
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Unlink one cache entry by hex key (used by all purge paths).
 *
 * Reads the .meta sidecar for back-references (tags, host, base_key) and the
 * is_private flag, then unlinks: data, meta, tags/<t>/<key>, hosts/<h>/<key>,
 * vary/<base>/<key>. Missing files are not errors (a concurrent purger may
 * have already removed them).
 *
 * want_private:
 *    0  - only unlink public entries (is_private == 0 in meta)
 *    1  - only unlink private entries (is_private == 1)
 *   -1  - unlink regardless
 *
 * If the meta sidecar is missing we treat the entry as public for filter
 * purposes (so * and tag= without a 'private,' prefix still work even if
 * meta vanished).
 *
 * Returns NGX_OK if the data file was unlinked, NGX_DECLINED otherwise.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_unlink_entry(ngx_http_request_t *r, u_char *hex_key, int want_private,
    ngx_str_t *host_filter)
{
    ngx_http_lsc_main_conf_t *mcf;
    ngx_str_t                 data_path, meta_path, side_path;
    ngx_fd_t                  fd;
    u_char                   *meta_buf;
    ssize_t                   nread = 0;
    u_char                   *line, *end, *eol;
    ngx_int_t                 rc = NGX_DECLINED;
    ngx_uint_t                i;
    int                       entry_private = 0;
    int                       host_matches = (host_filter == NULL);
    struct stat               mst;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (mcf->path.len == 0) return NGX_ERROR;

    if (lsc_data_path(r->pool, &mcf->path, hex_key, &data_path) != NGX_OK
        || lsc_meta_path(r->pool, &mcf->path, hex_key, &meta_path) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Size the meta read buffer to the actual file size (bounded by
     * LSC_META_MAX). A truncated read would silently drop back-
     * references at the tail of the file, leaving orphan marker files
     * in tags/, hosts/, vary/ - effectively a slow leak in disk usage
     * and a way for purges to silently miss entries. */
    meta_buf = NULL;
    fd = ngx_open_file(meta_path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd != NGX_INVALID_FILE) {
        size_t to_read = 0;
        if (fstat(fd, &mst) == 0 && mst.st_size > 0) {
            to_read = (size_t) mst.st_size;
        }
        if (to_read > LSC_META_MAX) to_read = LSC_META_MAX;
        if (to_read > 0) {
            meta_buf = ngx_pnalloc(r->pool, to_read + 1);
            if (meta_buf != NULL) {
                nread = ngx_read_fd(fd, meta_buf, to_read);
                if (nread <= 0) nread = 0;
                meta_buf[nread] = '\0';
            }
        }
        ngx_close_file(fd);
        if (meta_buf == NULL) nread = 0;

        line = meta_buf;
        end  = meta_buf + nread;
        while (line < end) {
            eol = (u_char *)ngx_strlchr(line, end, '\n');
            if (eol == NULL) eol = end;

            if (eol - line >= 12
                && ngx_strncmp(line, "is_private ", 11) == 0)
            {
                if (line[11] == '1') entry_private = 1;
            } else if (host_filter != NULL
                       && eol - line > 5
                       && ngx_strncmp(line, "host ", 5) == 0)
            {
                u_char *hv = line + 5;
                size_t  hl = eol - hv;
                while (hl > 0 && (hv[hl - 1] == '\r' || hv[hl - 1] == ' '))
                    hl--;
                if (hl == host_filter->len
                    && ngx_strncasecmp(hv, host_filter->data, hl) == 0)
                {
                    host_matches = 1;
                }
            }
            line = eol + 1;
        }
    }

    if (want_private == 0 && entry_private != 0) return NGX_DECLINED;
    if (want_private == 1 && entry_private == 0) return NGX_DECLINED;
    if (!host_matches) return NGX_DECLINED;

    /* now actually remove back-refs */
    if (nread > 0) {
        line = meta_buf;
        end  = meta_buf + nread;
        while (line < end) {
            eol = (u_char *)ngx_strlchr(line, end, '\n');
            if (eol == NULL) eol = end;

            if (eol - line > 4 && ngx_strncmp(line, "tag ", 4) == 0) {
                ngx_str_t tag;
                tag.data = line + 4;
                tag.len  = eol - tag.data;
                while (tag.len > 0 && (tag.data[tag.len - 1] == '\r'
                                       || tag.data[tag.len - 1] == ' '))
                    tag.len--;
                if (tag.len > 0
                    && lsc_safe_name(&tag) == NGX_OK
                    && lsc_tag_path(r->pool, &mcf->path, &tag, hex_key,
                                    &side_path) == NGX_OK)
                {
                    (void) ngx_delete_file(side_path.data);
                }
            } else if (eol - line > 5
                       && ngx_strncmp(line, "host ", 5) == 0)
            {
                ngx_str_t host;
                host.data = line + 5;
                host.len  = eol - host.data;
                while (host.len > 0 && (host.data[host.len - 1] == '\r'
                                        || host.data[host.len - 1] == ' '))
                    host.len--;
                if (host.len > 0
                    && lsc_safe_name(&host) == NGX_OK
                    && lsc_host_path(r->pool, &mcf->path, &host, hex_key,
                                     &side_path) == NGX_OK)
                {
                    (void) ngx_delete_file(side_path.data);
                }
            } else if (eol - line > 5
                       && ngx_strncmp(line, "base ", 5) == 0)
            {
                u_char *base = line + 5;
                size_t  blen = eol - base;
                while (blen > 0 && (base[blen - 1] == '\r'
                                    || base[blen - 1] == ' '))
                    blen--;
                if (blen == LSC_KEY_HEX_LEN) {
                    ngx_uint_t ok = 1;
                    for (i = 0; i < LSC_KEY_HEX_LEN; i++) {
                        u_char c = base[i];
                        if (!((c >= '0' && c <= '9')
                              || (c >= 'a' && c <= 'f')))
                        { ok = 0; break; }
                    }
                    if (ok
                        && lsc_vary_path(r->pool, &mcf->path, base,
                                         hex_key, &side_path) == NGX_OK)
                    {
                        (void) ngx_delete_file(side_path.data);
                    }
                }
            }

            line = eol + 1;
        }
    }

    if (ngx_delete_file(data_path.data) == 0) rc = NGX_OK;
    (void) ngx_delete_file(meta_path.data);
    return rc;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Walk a back-reference directory and unlink every entry it points at.
 *
 * Each filename in `dir` is the 40-char hex key of a cache entry. For each,
 * call lsc_unlink_entry with the desired privacy filter and bump *count for
 * the ones we actually unlinked.
 *
 * `dir->data` must be NUL-terminated.
 * ═══════════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════════════
 * Size-based eviction (driven by the lscache_max_size directive).
 *
 * Triggered every ~100 successful writes (per worker). Walks data/<HH>/<HH>/,
 * sums file sizes. If the total exceeds max_size, sorts entries by mtime
 * ascending and unlinks oldest until total drops below max_size.
 *
 * Concurrent workers may run this in parallel; double-unlinks are harmless
 * because lsc_unlink_entry's unlink() returns -1/ENOENT and we ignore it.
 * ═══════════════════════════════════════════════════════════════════════ */

#define LSC_EVICT_TRIGGER_EVERY  100
#define LSC_EVICT_MAX_ENTRIES    65536

typedef struct {
    u_char  hex[LSC_KEY_HEX_LEN];
    time_t  mtime;
    off_t   size;
} lsc_evict_t;


static ngx_uint_t lsc_writes_since_check = 0;


static int
lsc_evict_cmp_mtime(const void *a, const void *b)
{
    const lsc_evict_t *ea = a, *eb = b;
    if (ea->mtime < eb->mtime) return -1;
    if (ea->mtime > eb->mtime) return  1;
    return 0;
}


static void
lsc_walk_data_shard(u_char *shard_path, ngx_pool_t *pool, ngx_array_t *out,
    ngx_log_t *log)
{
    ngx_dir_t  d;
    ngx_str_t  p;
    u_char     file_path[LSC_PATH_MAX];
    ngx_uint_t i;
    size_t     nl, shard_len;
    u_char    *name;

    p.data = shard_path;
    p.len  = ngx_strlen(shard_path);
    if (ngx_open_dir(&p, &d) != NGX_OK) return;

    shard_len = p.len;
    for (;;) {
        ngx_set_errno(0);
        if (ngx_read_dir(&d) != NGX_OK) break;
        nl = ngx_de_namelen(&d);
        if (nl != LSC_KEY_HEX_LEN) continue;
        name = ngx_de_name(&d);

        for (i = 0; i < LSC_KEY_HEX_LEN; i++) {
            u_char c = name[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) break;
        }
        if (i != LSC_KEY_HEX_LEN) continue;
        if (out->nelts >= LSC_EVICT_MAX_ENTRIES) break;

        if (shard_len + 1 + LSC_KEY_HEX_LEN >= sizeof(file_path)) continue;
        ngx_memcpy(file_path, shard_path, shard_len);
        file_path[shard_len] = '/';
        ngx_memcpy(file_path + shard_len + 1, name, LSC_KEY_HEX_LEN);
        file_path[shard_len + 1 + LSC_KEY_HEX_LEN] = '\0';

        {
            struct stat st;
            lsc_evict_t *e;
            if (stat((char *)file_path, &st) != 0) continue;
            if (!S_ISREG(st.st_mode)) continue;
            e = ngx_array_push(out);
            if (e == NULL) break;
            ngx_memcpy(e->hex, name, LSC_KEY_HEX_LEN);
            e->mtime = st.st_mtime;
            e->size  = st.st_size;
        }
    }
    ngx_close_dir(&d);
    (void) pool;
    (void) log;
}


void
lsc_maybe_evict(ngx_http_request_t *r)
{
    ngx_http_lsc_main_conf_t *mcf;
    ngx_pool_t               *pool;
    ngx_array_t              *entries;
    ngx_dir_t                 d;
    ngx_str_t                 data_dir, level1_dir;
    u_char                    l1_path[LSC_PATH_MAX];
    u_char                    l2_path[LSC_PATH_MAX];
    u_char                   *p, *l1_name;
    size_t                    nl;
    off_t                     total = 0;
    ngx_uint_t                i;
    lsc_evict_t              *list;

    if (++lsc_writes_since_check < LSC_EVICT_TRIGGER_EVERY) return;
    lsc_writes_since_check = 0;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (mcf == NULL || mcf->path.len == 0 || mcf->max_size <= 0) return;

    pool = ngx_create_pool(64 * 1024, r->connection->log);
    if (pool == NULL) return;

    entries = ngx_array_create(pool, 256, sizeof(lsc_evict_t));
    if (entries == NULL) goto out;

    if (mcf->path.len + sizeof("/data") >= sizeof(l1_path)) goto out;
    p = ngx_cpymem(l1_path, mcf->path.data, mcf->path.len);
    p = ngx_cpymem(p, "/data", 5);
    *p = '\0';
    data_dir.data = l1_path;
    data_dir.len  = p - l1_path;

    if (ngx_open_dir(&data_dir, &d) != NGX_OK) goto out;
    for (;;) {
        ngx_set_errno(0);
        if (ngx_read_dir(&d) != NGX_OK) break;
        nl = ngx_de_namelen(&d);
        if (nl != 2) continue;
        l1_name = ngx_de_name(&d);
        if (!isxdigit(l1_name[0]) || !isxdigit(l1_name[1])) continue;

        /* descend into <root>/data/<HH>/ */
        if (data_dir.len + 1 + 2 >= sizeof(l1_path)) continue;
        ngx_memcpy(l1_path + data_dir.len + 1, l1_name, 2);
        l1_path[data_dir.len] = '/';
        l1_path[data_dir.len + 3] = '\0';
        level1_dir.data = l1_path;
        level1_dir.len  = data_dir.len + 3;

        {
            ngx_dir_t  d2;
            u_char    *l2_name;
            size_t     nl2;
            if (ngx_open_dir(&level1_dir, &d2) != NGX_OK) continue;
            for (;;) {
                ngx_set_errno(0);
                if (ngx_read_dir(&d2) != NGX_OK) break;
                nl2 = ngx_de_namelen(&d2);
                if (nl2 != 2) continue;
                l2_name = ngx_de_name(&d2);
                if (!isxdigit(l2_name[0]) || !isxdigit(l2_name[1])) continue;

                if (level1_dir.len + 1 + 2 >= sizeof(l2_path)) continue;
                ngx_memcpy(l2_path, level1_dir.data, level1_dir.len);
                l2_path[level1_dir.len] = '/';
                ngx_memcpy(l2_path + level1_dir.len + 1, l2_name, 2);
                l2_path[level1_dir.len + 3] = '\0';

                lsc_walk_data_shard(l2_path, pool, entries, r->connection->log);
            }
            ngx_close_dir(&d2);
        }
    }
    ngx_close_dir(&d);

    if (entries->nelts == 0) goto out;

    list = entries->elts;
    for (i = 0; i < entries->nelts; i++) total += list[i].size;

    if (total <= mcf->max_size) goto out;

    qsort(list, entries->nelts, sizeof(lsc_evict_t), lsc_evict_cmp_mtime);

    for (i = 0; i < entries->nelts && total > mcf->max_size; i++) {
        if (lsc_unlink_entry(r, list[i].hex, -1, NULL) == NGX_OK) {
            total -= list[i].size;
        }
    }

out:
    ngx_destroy_pool(pool);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Mark one entry stale: flip the LSC_FF_STALE bit in the 24-byte header.
 *
 * Honors the same is_private filter as lsc_unlink_entry. Open the data
 * file O_RDWR, read the header, set the flag, write the header back.
 * Cheap on-disk operation (one read + one write of 24 bytes). The body
 * stays intact, so the entry remains readable in fallback paths until
 * the next request rebuilds it.
 *
 * Returns NGX_OK if the entry was marked, NGX_DECLINED if filter
 * rejected, NGX_ERROR on I/O failure.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_mark_stale(ngx_http_request_t *r, u_char *hex_key, int want_private,
    ngx_str_t *host_filter)
{
    ngx_http_lsc_main_conf_t *mcf;
    ngx_str_t                 data_path, meta_path;
    ngx_fd_t                  fd;
    u_char                   *meta_buf;
    ssize_t                   nread = 0;
    u_char                   *line, *end, *eol;
    int                       entry_private = 0;
    int                       host_matches  = (host_filter == NULL);
    u_char                    hdr[24];
    uint16_t                  flags;
    struct stat               mst;
    size_t                    to_read;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (mcf->path.len == 0) return NGX_ERROR;

    if (lsc_data_path(r->pool, &mcf->path, hex_key, &data_path) != NGX_OK
        || lsc_meta_path(r->pool, &mcf->path, hex_key, &meta_path) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* meta lookup for privacy + host filter */
    if (want_private != -1 || host_filter != NULL) {
        meta_buf = NULL;
        fd = ngx_open_file(meta_path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
        if (fd != NGX_INVALID_FILE) {
            to_read = 0;
            if (fstat(fd, &mst) == 0 && mst.st_size > 0) {
                to_read = (size_t) mst.st_size;
            }
            if (to_read > LSC_META_MAX) to_read = LSC_META_MAX;
            if (to_read > 0) {
                meta_buf = ngx_pnalloc(r->pool, to_read + 1);
                if (meta_buf != NULL) {
                    nread = ngx_read_fd(fd, meta_buf, to_read);
                    if (nread <= 0) nread = 0;
                    meta_buf[nread] = '\0';
                }
            }
            ngx_close_file(fd);
            if (meta_buf != NULL && nread > 0) {
                line = meta_buf;
                end  = meta_buf + nread;
                while (line < end) {
                    eol = (u_char *)ngx_strlchr(line, end, '\n');
                    if (eol == NULL) eol = end;
                    if (eol - line >= 12
                        && ngx_strncmp(line, "is_private ", 11) == 0
                        && line[11] == '1')
                    {
                        entry_private = 1;
                    } else if (host_filter != NULL
                               && eol - line > 5
                               && ngx_strncmp(line, "host ", 5) == 0)
                    {
                        u_char *hv = line + 5;
                        size_t  hl = eol - hv;
                        while (hl > 0 && (hv[hl - 1] == '\r'
                                          || hv[hl - 1] == ' '))
                            hl--;
                        if (hl == host_filter->len
                            && ngx_strncasecmp(hv, host_filter->data, hl) == 0)
                        {
                            host_matches = 1;
                        }
                    }
                    line = eol + 1;
                }
            }
        }
        if (want_private == 0 && entry_private != 0) return NGX_DECLINED;
        if (want_private == 1 && entry_private == 0) return NGX_DECLINED;
        if (!host_matches) return NGX_DECLINED;
    }

    /* open data file for read+write, flip the flag, write header back */
    fd = open((char *)data_path.data, O_RDWR);
    if (fd < 0) return NGX_DECLINED;

    if (read(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)
        || hdr[0] != 'L' || hdr[1] != 'S'
        || hdr[2] != 'C' || hdr[3] != '1')
    {
        close(fd);
        return NGX_DECLINED;
    }
    flags = (uint16_t)hdr[22] | ((uint16_t)hdr[23] << 8);
    flags |= LSC_FF_STALE;
    hdr[22] = (u_char)( flags        & 0xFF);
    hdr[23] = (u_char)((flags >> 8)  & 0xFF);

    if (lseek(fd, 0, SEEK_SET) != 0
        || write(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
    {
        close(fd);
        return NGX_ERROR;
    }
    close(fd);
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Walk a back-reference directory and mark every entry stale.
 * Mirror of lsc_walk_unlink for the stale path.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_walk_mark_stale(ngx_http_request_t *r, ngx_str_t *dir, int want_private,
    ngx_str_t *host_filter, ngx_uint_t *count)
{
    ngx_dir_t   d;
    ngx_str_t   p;
    ngx_uint_t  i;
    u_char      name[LSC_KEY_HEX_LEN + 1];
    size_t      nl;
    u_char     *raw;

    p = *dir;
    if (ngx_open_dir(&p, &d) != NGX_OK) return NGX_DECLINED;

    for (;;) {
        ngx_set_errno(0);
        if (ngx_read_dir(&d) != NGX_OK) break;
        nl = ngx_de_namelen(&d);
        if (nl != LSC_KEY_HEX_LEN) continue;
        raw = ngx_de_name(&d);

        for (i = 0; i < LSC_KEY_HEX_LEN; i++) {
            u_char c = raw[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) break;
        }
        if (i != LSC_KEY_HEX_LEN) continue;

        ngx_memcpy(name, raw, LSC_KEY_HEX_LEN);
        name[LSC_KEY_HEX_LEN] = '\0';

        if (lsc_mark_stale(r, name, want_private, host_filter) == NGX_OK) {
            (*count)++;
        }
    }
    ngx_close_dir(&d);
    return NGX_OK;
}


ngx_int_t
lsc_walk_unlink(ngx_http_request_t *r, ngx_str_t *dir, int want_private,
    ngx_str_t *host_filter, ngx_uint_t *count)
{
    ngx_dir_t   d;
    ngx_str_t   p;
    ngx_uint_t  i;
    u_char      name[LSC_KEY_HEX_LEN + 1];
    size_t      nl;
    u_char     *raw;

    p = *dir;
    if (ngx_open_dir(&p, &d) != NGX_OK) return NGX_DECLINED;

    for (;;) {
        ngx_set_errno(0);
        if (ngx_read_dir(&d) != NGX_OK) break;
        nl = ngx_de_namelen(&d);
        if (nl != LSC_KEY_HEX_LEN) continue;
        raw = ngx_de_name(&d);

        for (i = 0; i < LSC_KEY_HEX_LEN; i++) {
            u_char c = raw[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) break;
        }
        if (i != LSC_KEY_HEX_LEN) continue;

        ngx_memcpy(name, raw, LSC_KEY_HEX_LEN);
        name[LSC_KEY_HEX_LEN] = '\0';

        if (lsc_unlink_entry(r, name, want_private, host_filter) == NGX_OK) {
            (*count)++;
        }
    }
    ngx_close_dir(&d);
    return NGX_OK;
}
