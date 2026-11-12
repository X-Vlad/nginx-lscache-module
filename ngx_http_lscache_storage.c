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
 * Key: see lsc_compute_key_full. The host is the one nginx routed by.
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
 * The request's host: the name nginx picked the server by.
 * ═══════════════════════════════════════════════════════════════════════ */

void
lsc_request_host(ngx_http_request_t *r, ngx_str_t *out)
{
    /* headers_in.server is set from the request line when that is
     * absolute, else from the Host header; nginx has validated and
     * lowercased it and cut the port. */
    *out = r->headers_in.server;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Compute the SHA-1 cache key.
 *
 * scheme "\n" host "\n" <len(uri)> ":" uri "\n" args "\n" vary_string
 *        "\n" client_id "\n" default_vary
 *
 * The uri is the decoded one and may hold a "\n" (%0A) from the client,
 * so its length goes in front of it: two different requests can then
 * never give the same byte string.
 *
 * lsc_compute_key_full is the explicit-input form (used by the purge
 * executor when only a URL is known). lsc_compute_key wraps it with
 * inputs from the current request.
 * ═══════════════════════════════════════════════════════════════════════ */

void
lsc_compute_key_full(int is_https,
    ngx_str_t *host, ngx_str_t *uri, ngx_str_t *args,
    ngx_str_t *vary_string, ngx_str_t *client_id, ngx_str_t *default_vary,
    u_char out_bin[LSC_KEY_BIN_LEN])
{
    ngx_sha1_t  sha;
    u_char      c;
    size_t      i;
    static const u_char nl = '\n';

    ngx_sha1_init(&sha);

    if (is_https) ngx_sha1_update(&sha, (u_char *)"https", 5);
    else          ngx_sha1_update(&sha, (u_char *)"http",  4);
    ngx_sha1_update(&sha, &nl, 1);

    if (host && host->len > 0) {
        for (i = 0; i < host->len; i++) {
            c = ngx_tolower(host->data[i]);
            ngx_sha1_update(&sha, &c, 1);
        }
    }
    ngx_sha1_update(&sha, &nl, 1);

    {
        u_char lenbuf[NGX_SIZE_T_LEN + 1], *le;
        le = ngx_sprintf(lenbuf, "%uz:", uri ? uri->len : (size_t) 0);
        ngx_sha1_update(&sha, lenbuf, le - lenbuf);
    }
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
    ngx_sha1_update(&sha, &nl, 1);

    if (default_vary && default_vary->len > 0) {
        ngx_sha1_update(&sha, default_vary->data, default_vary->len);
    }

    ngx_sha1_final(out_bin, &sha);
}


void
lsc_compute_key(ngx_http_request_t *r, ngx_str_t *vary_string,
    ngx_str_t *client_id, int with_default_vary,
    u_char out_bin[LSC_KEY_BIN_LEN])
{
    ngx_str_t host;
    ngx_str_t dv = ngx_null_string;
    int       is_https = 0;

#if (NGX_HTTP_SSL)
    if (r->connection->ssl) is_https = 1;
#endif

    lsc_request_host(r, &host);
    if (with_default_vary && lsc_default_vary(r, &dv) != NGX_OK) {
        /* out of memory: a key no healthy request computes */
        ngx_str_set(&dv, "\x01unknown");
    }

    lsc_compute_key_full(is_https, &host, &r->uri, &r->args,
                         vary_string, client_id, &dv, out_bin);
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

/* Remove one index marker and, when that emptied its folder, the folder
 * (rmdir of a folder still in use just fails). `path` is NUL-terminated
 * and is put back as it was. */
static void
lsc_drop_ref(ngx_str_t *path)
{
    u_char *slash;

    (void) ngx_delete_file(path->data);
    slash = path->data + path->len;
    while (slash > path->data && *slash != '/') slash--;
    if (slash == path->data) return;
    *slash = '\0';
    (void) rmdir((char *) path->data);
    *slash = '/';
}


/* Create an empty index marker, making its folder when missing. A
 * purge may remove the emptied folder between our mkdir and our open,
 * so the pair is tried a few times. `path` is NUL-terminated. */
ngx_int_t
lsc_touch_ref(u_char *path, size_t len, ngx_log_t *log)
{
    u_char     *slash;
    ngx_fd_t    fd;
    ngx_uint_t  attempt;

    slash = path + len;
    while (slash > path && *slash != '/') slash--;
    if (slash == path) return NGX_ERROR;

    for (attempt = 0; attempt < 3; attempt++) {
        *slash = '\0';
        (void) lsc_mkpath(path, 0750, log);
        *slash = '/';
        fd = open((char *) path, O_WRONLY | O_CREAT | O_CLOEXEC, 0640);
        if (fd >= 0) {
            close(fd);
            return NGX_OK;
        }
        if (errno != ENOENT) break;
    }
    ngx_log_error(NGX_LOG_ERR, log, errno,
        "lscache: index marker \"%s\" not created", path);
    return NGX_ERROR;
}


/* Shared size counter. */
void
lsc_account(ngx_http_request_t *r, off_t delta)
{
    ngx_http_lsc_main_conf_t *mcf;
    lsc_shared_t             *sh;

    if (delta == 0) return;
    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (mcf == NULL || mcf->stat_zone == NULL) return;
    sh = mcf->stat_zone->data;
    if (sh == NULL) return;
    (void) ngx_atomic_fetch_add(&sh->bytes, (ngx_atomic_int_t) delta);
}


static ngx_int_t
lsc_unlink_entry_in(ngx_http_request_t *r, ngx_pool_t *pool, u_char *hex_key,
    int want_private, ngx_str_t *host_filter)
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

    if (lsc_data_path(pool, &mcf->path, hex_key, &data_path) != NGX_OK
        || lsc_meta_path(pool, &mcf->path, hex_key, &meta_path) != NGX_OK)
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
            meta_buf = ngx_pnalloc(pool, to_read + 1);
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
                    && lsc_tag_path(pool, &mcf->path, &tag, hex_key,
                                    &side_path) == NGX_OK)
                {
                    lsc_drop_ref(&side_path);
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
                    && lsc_host_path(pool, &mcf->path, &host, hex_key,
                                     &side_path) == NGX_OK)
                {
                    lsc_drop_ref(&side_path);
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
                        && lsc_vary_path(pool, &mcf->path, base,
                                         hex_key, &side_path) == NGX_OK)
                    {
                        lsc_drop_ref(&side_path);
                    }
                }
            }

            line = eol + 1;
        }
    }

    {
        struct stat dst;
        off_t       dsize = 0;
        if (stat((char *) data_path.data, &dst) == 0) dsize = dst.st_size;
        if (ngx_delete_file(data_path.data) == 0) {
            rc = NGX_OK;
            lsc_account(r, -dsize);
        }
    }
    (void) ngx_delete_file(meta_path.data);
    return rc;
}


/* Runs with a pool of its own: purges and sweeps call this for
 * thousands of entries within one request. */
ngx_int_t
lsc_unlink_entry(ngx_http_request_t *r, u_char *hex_key, int want_private,
    ngx_str_t *host_filter)
{
    ngx_pool_t *pool;
    ngx_int_t   rc;

    pool = ngx_create_pool(4096, r->connection->log);
    if (pool == NULL) return NGX_ERROR;
    rc = lsc_unlink_entry_in(r, pool, hex_key, want_private, host_filter);
    ngx_destroy_pool(pool);
    return rc;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Is this entry no longer servable (missing, damaged, or expired)?
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_uint_t
lsc_entry_dead(u_char *data_path, off_t *size_out)
{
    ngx_fd_t     fd;
    u_char       hdr[LSC_FILE_HEADER_BYTES];
    struct stat  st;
    uint64_t     expires = 0;
    uint32_t     body_len;
    ngx_uint_t   i, dead = 0;

    if (size_out) *size_out = 0;
    fd = open((char *) data_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    if (fstat(fd, &st) != 0
        || read(fd, hdr, sizeof(hdr)) != (ssize_t) sizeof(hdr)
        || hdr[0] != 'L' || hdr[1] != 'S' || hdr[2] != 'C' || hdr[3] != '1')
    {
        close(fd);
        return 1;
    }
    close(fd);
    if (size_out) *size_out = st.st_size;

    body_len = (uint32_t) hdr[4] | ((uint32_t) hdr[5] << 8)
             | ((uint32_t) hdr[6] << 16) | ((uint32_t) hdr[7] << 24);
    for (i = 0; i < 8; i++) expires |= ((uint64_t) hdr[12 + i]) << (i * 8);

    if ((off_t) body_len + LSC_FILE_HEADER_BYTES != st.st_size) dead = 1;
    if ((time_t) expires <= ngx_time()) dead = 1;
    return dead;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * May one more variant of this URL be stored?
 *
 * A URL's variants (vary values, private copies) are index markers in
 * vary/<base>/, and every miss walks them, so their number is capped
 * (lscache_max_variants). At the cap the expired ones are removed
 * first. NGX_OK: room (or `key_hex` is already one of them).
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
lsc_variant_room(ngx_http_request_t *r, u_char *base_hex, u_char *key_hex,
    ngx_uint_t max)
{
    ngx_http_lsc_main_conf_t *mcf;
    ngx_str_t                 dir, dpath;
    ngx_dir_t                 d;
    u_char                    names[256][LSC_KEY_HEX_LEN + 1];
    ngx_uint_t                n = 0, i, j, live;
    u_char                   *raw;

    if (max > 256) max = 256;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    dir.len  = mcf->path.len + sizeof("/vary/") - 1 + LSC_KEY_HEX_LEN;
    dir.data = ngx_pnalloc(r->pool, dir.len + 1);
    if (dir.data == NULL) return NGX_ERROR;
    raw = ngx_cpymem(dir.data, mcf->path.data, mcf->path.len);
    raw = ngx_cpymem(raw, "/vary/", 6);
    raw = ngx_cpymem(raw, base_hex, LSC_KEY_HEX_LEN);
    *raw = '\0';

    if (ngx_open_dir(&dir, &d) != NGX_OK) return NGX_OK;   /* no variants */
    for (;;) {
        ngx_set_errno(0);
        if (ngx_read_dir(&d) != NGX_OK) break;
        if (ngx_de_namelen(&d) != LSC_KEY_HEX_LEN) continue;
        raw = ngx_de_name(&d);
        for (j = 0; j < LSC_KEY_HEX_LEN; j++) {
            u_char c = raw[j];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) break;
        }
        if (j != LSC_KEY_HEX_LEN) continue;
        if (ngx_memcmp(raw, key_hex, LSC_KEY_HEX_LEN) == 0) {
            ngx_close_dir(&d);
            return NGX_OK;
        }
        if (n < 256) {
            ngx_memcpy(names[n], raw, LSC_KEY_HEX_LEN);
            names[n][LSC_KEY_HEX_LEN] = '\0';
        }
        n++;
    }
    ngx_close_dir(&d);

    if (n < max) return NGX_OK;

    live = n;
    for (i = 0; i < n && i < 256; i++) {
        if (lsc_data_path(r->pool, &mcf->path, names[i], &dpath) != NGX_OK) {
            continue;
        }
        if (lsc_entry_dead(dpath.data, NULL)) {
            (void) lsc_unlink_entry(r, names[i], -1, NULL);
            /* a marker whose entry is gone has no meta to find it by */
            if (lsc_vary_path(r->pool, &mcf->path, base_hex, names[i],
                              &dpath) == NGX_OK)
            {
                lsc_drop_ref(&dpath);
            }
            live--;
        }
    }
    return live < max ? NGX_OK : NGX_DECLINED;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Background sweep (driven by stores; lscache_max_size).
 *
 * The total size of the data files lives in shared memory and is kept
 * by the store and unlink paths; a full recount runs once after start
 * and then hourly, to correct drift. Every LSC_SWEEP_EVERY stores of a
 * worker, one worker at a time walks the next first-level folder of
 * data/ (a cursor in shared memory goes round all 256) and removes what
 * is expired or damaged. While the cache is over lscache_max_size the
 * walk goes on through the following folders and removes live entries
 * too, until the size is 10% under the limit or LSC_SWEEP_UNLINKS
 * entries are gone (the next call goes on from there; one call removes
 * far more than the stores between two calls can add). Which live
 * entries go is decided by where the cursor is, not by age.
 * ═══════════════════════════════════════════════════════════════════════ */

#define LSC_SWEEP_EVERY        64
#define LSC_SWEEP_UNLINKS      2048    /* per call                      */
#define LSC_RECOUNT_INTERVAL   3600
#define LSC_SWEEP_LOCK_STALE   120

static ngx_uint_t lsc_stores_since_sweep = 0;


/* Walk one shard. mode 0: add sizes to *total. mode 1: remove dead
 * entries, and live ones while the shared size is above `target`. */
static void
lsc_sweep_shard(ngx_http_request_t *r, ngx_http_lsc_main_conf_t *mcf,
    lsc_shared_t *sh, ngx_uint_t shard, int mode, off_t target,
    off_t *total, ngx_uint_t *unlinks)
{
    u_char      path[LSC_PATH_MAX], file[LSC_PATH_MAX];
    u_char      name[LSC_KEY_HEX_LEN + 1];
    ngx_str_t   dir;
    ngx_dir_t   d;
    u_char     *raw;
    size_t      dl;
    ngx_uint_t  j;
    off_t       size;
    struct stat st;

    /* <root>/data/HH/HH */
    raw = ngx_cpymem(path, mcf->path.data, mcf->path.len);
    raw = ngx_cpymem(raw, "/data/", 6);
    *raw++ = lsc_hex_chars[(shard >> 12) & 0xF];
    *raw++ = lsc_hex_chars[(shard >> 8) & 0xF];
    *raw++ = '/';
    *raw++ = lsc_hex_chars[(shard >> 4) & 0xF];
    *raw++ = lsc_hex_chars[shard & 0xF];
    *raw = '\0';
    dir.data = path;
    dir.len  = raw - path;
    dl = dir.len;
    if (ngx_open_dir(&dir, &d) != NGX_OK) return;

    for (;;) {
        ngx_set_errno(0);
        if (ngx_read_dir(&d) != NGX_OK) break;
        if (ngx_de_namelen(&d) != LSC_KEY_HEX_LEN) continue;
        raw = ngx_de_name(&d);
        for (j = 0; j < LSC_KEY_HEX_LEN; j++) {
            u_char c = raw[j];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) break;
        }
        if (j != LSC_KEY_HEX_LEN) continue;
        ngx_memcpy(name, raw, LSC_KEY_HEX_LEN);
        name[LSC_KEY_HEX_LEN] = '\0';

        ngx_memcpy(file, path, dl);
        file[dl] = '/';
        ngx_memcpy(file + dl + 1, name, LSC_KEY_HEX_LEN);
        file[dl + 1 + LSC_KEY_HEX_LEN] = '\0';

        if (mode == 0) {
            if (stat((char *) file, &st) == 0 && S_ISREG(st.st_mode)) {
                *total += st.st_size;
            }
            continue;
        }

        if (*unlinks >= LSC_SWEEP_UNLINKS) break;
        if (lsc_entry_dead(file, &size)
            || (target >= 0 && (off_t) sh->bytes > target))
        {
            (void) lsc_unlink_entry(r, name, -1, NULL);
            (*unlinks)++;
        }
    }
    ngx_close_dir(&d);
}


/* Walk the shards that exist under one first-level folder (data/HH). */
static void
lsc_sweep_level1(ngx_http_request_t *r, ngx_http_lsc_main_conf_t *mcf,
    lsc_shared_t *sh, ngx_uint_t l1, int mode, off_t target,
    off_t *total, ngx_uint_t *unlinks)
{
    u_char      path[LSC_PATH_MAX], *p, *raw;
    ngx_str_t   dir;
    ngx_dir_t   d;
    ngx_int_t   l2;

    p = ngx_cpymem(path, mcf->path.data, mcf->path.len);
    p = ngx_cpymem(p, "/data/", 6);
    *p++ = lsc_hex_chars[(l1 >> 4) & 0xF];
    *p++ = lsc_hex_chars[l1 & 0xF];
    *p = '\0';
    dir.data = path;
    dir.len  = p - path;
    if (ngx_open_dir(&dir, &d) != NGX_OK) return;

    for (;;) {
        ngx_set_errno(0);
        if (ngx_read_dir(&d) != NGX_OK) break;
        if (ngx_de_namelen(&d) != 2) continue;
        raw = ngx_de_name(&d);
        l2 = ngx_hextoi(raw, 2);
        if (l2 == NGX_ERROR) continue;
        if (mode == 1 && *unlinks >= LSC_SWEEP_UNLINKS) break;
        lsc_sweep_shard(r, mcf, sh, (l1 << 8) | (ngx_uint_t) l2, mode,
                        target, total, unlinks);
    }
    ngx_close_dir(&d);
}


void
lsc_maintain(ngx_http_request_t *r)
{
    ngx_http_lsc_main_conf_t *mcf;
    lsc_shared_t             *sh;
    ngx_atomic_uint_t         held;
    time_t                    now;
    ngx_uint_t                l1, n, unlinks = 0;
    off_t                     total = 0, target;

    if (++lsc_stores_since_sweep < LSC_SWEEP_EVERY) return;
    lsc_stores_since_sweep = 0;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_lscache_module);
    if (mcf == NULL || mcf->path.len == 0 || mcf->stat_zone == NULL) return;
    if (mcf->path.len + sizeof("/data/xx/xx/") + LSC_KEY_HEX_LEN
        >= LSC_PATH_MAX)
    {
        return;
    }
    sh = mcf->stat_zone->data;
    if (sh == NULL) return;

    /* one worker at a time; a lock left by a dead worker times out */
    now  = ngx_time();
    held = sh->busy;
    if (held != 0 && now - (time_t) held < LSC_SWEEP_LOCK_STALE) return;
    if (!ngx_atomic_cmp_set(&sh->busy, held, (ngx_atomic_uint_t) now)) return;

    if (!sh->counted
        || now - (time_t) sh->last_recount > LSC_RECOUNT_INTERVAL)
    {
        total = 0;
        for (l1 = 0; l1 < 256; l1++) {
            lsc_sweep_level1(r, mcf, sh, l1, 0, -1, &total, &unlinks);
        }
        sh->bytes        = (ngx_atomic_uint_t) total;
        sh->last_recount = (ngx_atomic_uint_t) now;
        sh->counted      = 1;
    }

    /* the counter is unsigned and two workers may undercount briefly */
    if ((ngx_atomic_int_t) sh->bytes < 0) sh->bytes = 0;

    target = -1;
    if (mcf->max_size > 0 && (off_t) sh->bytes > mcf->max_size) {
        target = mcf->max_size - mcf->max_size / 10;
    }

    /* one folder when within the limit; when over it, as many as it
     * takes (at most once round, and at most LSC_SWEEP_UNLINKS) */
    l1 = (ngx_uint_t) sh->cursor & 0xFF;
    for (n = 0; n < 256; n++) {
        lsc_sweep_level1(r, mcf, sh, l1, 1, target, &total, &unlinks);
        l1 = (l1 + 1) & 0xFF;
        if (unlinks >= LSC_SWEEP_UNLINKS) break;
        if (target < 0 || (off_t) sh->bytes <= target) break;
    }
    sh->cursor = l1;
    sh->busy   = 0;
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

static ngx_int_t
lsc_mark_stale_in(ngx_http_request_t *r, ngx_pool_t *pool, u_char *hex_key,
    int want_private, ngx_str_t *host_filter)
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

    if (lsc_data_path(pool, &mcf->path, hex_key, &data_path) != NGX_OK
        || lsc_meta_path(pool, &mcf->path, hex_key, &meta_path) != NGX_OK)
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
                meta_buf = ngx_pnalloc(pool, to_read + 1);
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


/* Runs with a pool of its own: purges and sweeps call this for
 * thousands of entries within one request. */
ngx_int_t
lsc_mark_stale(ngx_http_request_t *r, u_char *hex_key, int want_private,
    ngx_str_t *host_filter)
{
    ngx_pool_t *pool;
    ngx_int_t   rc;

    pool = ngx_create_pool(4096, r->connection->log);
    if (pool == NULL) return NGX_ERROR;
    rc = lsc_mark_stale_in(r, pool, hex_key, want_private, host_filter);
    ngx_destroy_pool(pool);
    return rc;
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
