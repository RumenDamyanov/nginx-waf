/*
 * nginx-waf - Web Application Firewall module for nginx
 *
 * Copyright (c) 2025-2026 Rumen Damyanov
 * BSD 3-Clause License - see LICENSE.md
 *
 * https://github.com/RumenDamyanov/nginx-waf
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_waf_module.h"


/*
 * Forward declarations
 */
static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf);
static void *ngx_http_waf_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r);

static char *ngx_http_waf_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_waf_enable_lists(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_disable_lists(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_waf_load_list(ngx_conf_t *cf,
    ngx_http_waf_list_t *list);
static ngx_int_t ngx_http_waf_parse_cidr(ngx_conf_t *cf, ngx_str_t *value,
    ngx_cidr_t *cidr);
static void ngx_http_waf_check_ip(ngx_http_request_t *r,
    ngx_http_waf_main_conf_t *wmcf, ngx_http_waf_loc_conf_t *wlcf,
    ngx_http_waf_check_result_t *result);
static ngx_int_t ngx_http_waf_list_has_tag(ngx_http_waf_list_t *list,
    ngx_str_t *tag);
static ngx_int_t ngx_http_waf_is_list_enabled(ngx_http_waf_list_t *list,
    ngx_http_waf_loc_conf_t *wlcf);
static ngx_int_t ngx_http_waf_is_list_disabled(ngx_http_waf_list_t *list,
    ngx_http_waf_loc_conf_t *wlcf);
static u_char *ngx_http_waf_get_client_ip(ngx_http_request_t *r,
    u_char *buf, size_t len);
static ngx_int_t ngx_http_waf_validate_name(ngx_str_t *name);


/*
 * Enum values for waf_mode directive
 */
static ngx_conf_enum_t ngx_http_waf_mode_enum[] = {
    { ngx_string("blacklist"), NGX_HTTP_WAF_MODE_BLACKLIST },
    { ngx_string("whitelist"), NGX_HTTP_WAF_MODE_WHITELIST },
    { ngx_null_string, 0 }
};


/*
 * Configuration directives
 */
static ngx_command_t ngx_http_waf_commands[] = {

    { ngx_string("waf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, enabled),
      NULL },

    { ngx_string("waf_mode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, mode),
      &ngx_http_waf_mode_enum },

    { ngx_string("waf_log_prefix"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, log_prefix),
      NULL },

    { ngx_string("waf_list"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE23,
      ngx_http_waf_list,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_enable_lists"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_enable_lists,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_disable_lists"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_disable_lists,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


/*
 * Module context
 */
static ngx_http_module_t ngx_http_waf_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_waf_init,                     /* postconfiguration */

    ngx_http_waf_create_main_conf,         /* create main configuration */
    ngx_http_waf_init_main_conf,           /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_waf_create_loc_conf,          /* create location configuration */
    ngx_http_waf_merge_loc_conf            /* merge location configuration */
};


/*
 * Module definition
 */
ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,              /* module context */
    ngx_http_waf_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/*
 * Create main configuration
 */
static void *
ngx_http_waf_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_main_conf_t));
    if (wmcf == NULL) {
        return NULL;
    }

    return wmcf;
}


/*
 * Initialize main configuration
 *
 * Load all defined IP lists.
 */
static char *
ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;
    ngx_http_waf_list_t       *list;
    ngx_uint_t                 i;

    if (wmcf->lists == NULL) {
        return NGX_CONF_OK;
    }

    /* Load all defined lists */
    list = wmcf->lists->elts;
    for (i = 0; i < wmcf->lists->nelts; i++) {
        if (ngx_http_waf_load_list(cf, &list[i]) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "waf: failed to load list \"%V\" from \"%V\"",
                          &list[i].name, &list[i].path);
            /* Continue loading other lists */
        }
    }

    return NGX_CONF_OK;
}


/*
 * Create location configuration
 */
static void *
ngx_http_waf_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_loc_conf_t));
    if (wlcf == NULL) {
        return NULL;
    }

    wlcf->enabled = NGX_CONF_UNSET;
    wlcf->mode = NGX_CONF_UNSET_UINT;
    wlcf->enable_all = NGX_CONF_UNSET;

    return wlcf;
}


/*
 * Merge location configurations
 */
static char *
ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_waf_loc_conf_t  *prev = parent;
    ngx_http_waf_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_uint_value(conf->mode, prev->mode,
                               NGX_HTTP_WAF_MODE_BLACKLIST);
    ngx_conf_merge_str_value(conf->log_prefix, prev->log_prefix, "waf");
    ngx_conf_merge_value(conf->enable_all, prev->enable_all, 0);

    if (conf->enable_lists == NULL) {
        conf->enable_lists = prev->enable_lists;
    }

    if (conf->disable_lists == NULL) {
        conf->disable_lists = prev->disable_lists;
    }

    return NGX_CONF_OK;
}


/*
 * Validate list/tag name
 *
 * Valid names contain only: a-z, A-Z, 0-9, underscore, hyphen
 * Must start with a letter or underscore
 * Maximum length: 64 characters
 */
static ngx_int_t
ngx_http_waf_validate_name(ngx_str_t *name)
{
    u_char  *p;
    size_t   i;

    if (name->len == 0 || name->len > 64) {
        return NGX_ERROR;
    }

    p = name->data;

    /* First character must be letter or underscore */
    if (!((*p >= 'a' && *p <= 'z')
          || (*p >= 'A' && *p <= 'Z')
          || *p == '_'))
    {
        return NGX_ERROR;
    }

    /* Rest can be alphanumeric, underscore, or hyphen */
    for (i = 1; i < name->len; i++) {
        if (!((p[i] >= 'a' && p[i] <= 'z')
              || (p[i] >= 'A' && p[i] <= 'Z')
              || (p[i] >= '0' && p[i] <= '9')
              || p[i] == '_'
              || p[i] == '-'))
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/*
 * waf_list directive handler
 *
 * Syntax: waf_list name path [tags]
 * Context: http
 *
 * Example:
 *   waf_list tor "/etc/nginx/waf/tor.txt" "anonymizers,privacy";
 */
static char *
ngx_http_waf_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t  *wmcf = conf;
    ngx_http_waf_list_t       *list;
    ngx_str_t                 *value;
    ngx_str_t                 *tag;
    u_char                    *p, *start, *end;

    value = cf->args->elts;

    /* Validate list name */
    if (ngx_http_waf_validate_name(&value[1]) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid waf_list name \"%V\" "
                           "(must be 1-64 chars, start with letter/underscore, "
                           "contain only alphanumeric, underscore, hyphen)",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    /* Allocate lists array if first list */
    if (wmcf->lists == NULL) {
        wmcf->lists = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_waf_list_t));
        if (wmcf->lists == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: failed to allocate lists array");
            return NGX_CONF_ERROR;
        }
    }

    /* Check for duplicate list name */
    list = wmcf->lists->elts;
    for (ngx_uint_t i = 0; i < wmcf->lists->nelts; i++) {
        if (list[i].name.len == value[1].len
            && ngx_strncmp(list[i].name.data, value[1].data, value[1].len) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate waf_list name \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    /* Create new list entry */
    list = ngx_array_push(wmcf->lists);
    if (list == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: failed to allocate list entry");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(list, sizeof(ngx_http_waf_list_t));

    /* Set name */
    list->name = value[1];

    /* Set path - validate it's not empty */
    if (value[2].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_list path cannot be empty for \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }
    list->path = value[2];

    /* Parse optional tags (comma-separated) */
    if (cf->args->nelts > 3 && value[3].len > 0) {
        list->tags = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (list->tags == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: failed to allocate tags array");
            return NGX_CONF_ERROR;
        }

        start = value[3].data;
        end = value[3].data + value[3].len;

        while (start < end) {
            /* Find comma or end */
            p = start;
            while (p < end && *p != ',') {
                p++;
            }

            /* Skip empty tags */
            if (p > start) {
                ngx_str_t temp_tag;
                temp_tag.data = start;
                temp_tag.len = p - start;

                /* Validate tag name */
                if (ngx_http_waf_validate_name(&temp_tag) != NGX_OK) {
                    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                       "waf: invalid tag \"%*s\" in list \"%V\" "
                                       "(skipping)", temp_tag.len, temp_tag.data,
                                       &list->name);
                    start = p + 1;
                    continue;
                }

                tag = ngx_array_push(list->tags);
                if (tag == NULL) {
                    return NGX_CONF_ERROR;
                }

                *tag = temp_tag;
            }

            start = p + 1;
        }
    }

    ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                  "waf: defined list \"%V\" from \"%V\" (%ui tags)",
                  &list->name, &list->path,
                  list->tags ? list->tags->nelts : 0);

    return NGX_CONF_OK;
}


/*
 * waf_enable_lists directive handler
 *
 * Syntax: waf_enable_lists name1 [name2] ... | tag:tagname | all
 * Context: http, server, location
 */
static char *
ngx_http_waf_enable_lists(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;
    ngx_str_t                *entry;
    ngx_uint_t                i;

    value = cf->args->elts;

    /* Check for "all" */
    if (cf->args->nelts == 2
        && value[1].len == 3
        && ngx_strncmp(value[1].data, "all", 3) == 0)
    {
        wlcf->enable_all = 1;
        return NGX_CONF_OK;
    }

    /* Allocate enable_lists array */
    if (wlcf->enable_lists == NULL) {
        wlcf->enable_lists = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                               sizeof(ngx_str_t));
        if (wlcf->enable_lists == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Add each argument to enable_lists */
    for (i = 1; i < cf->args->nelts; i++) {
        entry = ngx_array_push(wlcf->enable_lists);
        if (entry == NULL) {
            return NGX_CONF_ERROR;
        }

        *entry = value[i];
    }

    return NGX_CONF_OK;
}


/*
 * waf_disable_lists directive handler
 *
 * Syntax: waf_disable_lists name1 [name2] ... | tag:tagname
 * Context: http, server, location
 *
 * Disables specific lists even if they were enabled in parent context.
 */
static char *
ngx_http_waf_disable_lists(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;
    ngx_str_t                *entry;
    ngx_uint_t                i;

    value = cf->args->elts;

    /* Allocate disable_lists array */
    if (wlcf->disable_lists == NULL) {
        wlcf->disable_lists = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                                sizeof(ngx_str_t));
        if (wlcf->disable_lists == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Add each argument to disable_lists */
    for (i = 1; i < cf->args->nelts; i++) {
        entry = ngx_array_push(wlcf->disable_lists);
        if (entry == NULL) {
            return NGX_CONF_ERROR;
        }

        *entry = value[i];
    }

    return NGX_CONF_OK;
}


/*
 * Load IP list from file
 */
static ngx_int_t
ngx_http_waf_load_list(ngx_conf_t *cf, ngx_http_waf_list_t *list)
{
    ngx_file_t      file;
    ngx_buf_t      *buf;
    u_char         *line_start, *line_end, *p;
    ssize_t         n;
    size_t          len;
    ngx_cidr_t      cidr;
    ngx_int_t       rc;
    off_t           file_size;
    ngx_file_info_t fi;

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.name = list->path;
    file.log = cf->log;

    file.fd = ngx_open_file(list->path.data, NGX_FILE_RDONLY,
                             NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, cf->log, ngx_errno,
                      "waf: failed to open \"%V\"", &list->path);
        return NGX_ERROR;
    }

    /* Get file size */
    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, cf->log, ngx_errno,
                      "waf: failed to stat \"%V\"", &list->path);
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    file_size = ngx_file_size(&fi);
    if (file_size == 0) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "waf: list file \"%V\" is empty", &list->path);
        ngx_close_file(file.fd);
        list->loaded = 1;
        return NGX_OK;
    }

    /* Limit file size (10MB max) */
    if (file_size > 10 * 1024 * 1024) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                      "waf: list file \"%V\" too large (%O bytes)",
                      &list->path, file_size);
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    /* Allocate buffer for file content */
    buf = ngx_create_temp_buf(cf->pool, (size_t) file_size + 1);
    if (buf == NULL) {
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    /* Read entire file */
    n = ngx_read_file(&file, buf->pos, (size_t) file_size, 0);
    ngx_close_file(file.fd);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, cf->log, ngx_errno,
                      "waf: failed to read \"%V\"", &list->path);
        return NGX_ERROR;
    }

    buf->last = buf->pos + n;
    *buf->last = '\0';

    /* Create radix trees */
    list->tree4 = ngx_radix_tree_create(cf->pool, -1);
    if (list->tree4 == NULL) {
        return NGX_ERROR;
    }

#if (NGX_HAVE_INET6)
    list->tree6 = ngx_radix_tree_create(cf->pool, -1);
    if (list->tree6 == NULL) {
        return NGX_ERROR;
    }
#endif

    list->count4 = 0;
    list->count6 = 0;

    /* Parse file line by line */
    line_start = buf->pos;
    while (line_start < buf->last) {
        /* Find end of line */
        line_end = line_start;
        while (line_end < buf->last && *line_end != '\n' && *line_end != '\r') {
            line_end++;
        }

        /* Skip leading whitespace */
        p = line_start;
        while (p < line_end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        len = line_end - p;

        /* Skip empty lines and comments */
        if (len == 0 || *p == '#') {
            goto next_line;
        }

        /* Trim trailing whitespace */
        while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) {
            len--;
        }

        if (len == 0) {
            goto next_line;
        }

        /* Create temporary string for parsing */
        ngx_str_t ip_str;
        ip_str.data = p;
        ip_str.len = len;

        /* Parse IP/CIDR */
        rc = ngx_http_waf_parse_cidr(cf, &ip_str, &cidr);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "waf: invalid IP/CIDR in \"%V\": \"%*s\"",
                          &list->path, len, p);
            goto next_line;
        }

        /* Add to appropriate tree */
        if (cidr.family == AF_INET) {
            rc = ngx_radix32tree_insert(list->tree4,
                                        cidr.u.in.addr,
                                        cidr.u.in.mask,
                                        NGX_HTTP_WAF_RADIX_MATCH);
            if (rc == NGX_OK) {
                list->count4++;
            } else if (rc == NGX_BUSY) {
                /* Duplicate entry, ignore */
            } else {
                ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                              "waf: failed to insert IPv4 entry");
            }
        }
#if (NGX_HAVE_INET6)
        else if (cidr.family == AF_INET6) {
            rc = ngx_radix128tree_insert(list->tree6,
                                         cidr.u.in6.addr.s6_addr,
                                         cidr.u.in6.mask.s6_addr,
                                         NGX_HTTP_WAF_RADIX_MATCH);
            if (rc == NGX_OK) {
                list->count6++;
            } else if (rc == NGX_BUSY) {
                /* Duplicate entry, ignore */
            } else {
                ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                              "waf: failed to insert IPv6 entry");
            }
        }
#endif

next_line:
        /* Move to next line */
        line_start = line_end;
        while (line_start < buf->last
               && (*line_start == '\n' || *line_start == '\r'))
        {
            line_start++;
        }
    }

    list->loaded = 1;

    ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                  "waf: loaded list \"%V\": %ui IPv4, %ui IPv6 entries",
                  &list->name, list->count4, list->count6);

    return NGX_OK;
}


/*
 * Parse IP address or CIDR range
 */
static ngx_int_t
ngx_http_waf_parse_cidr(ngx_conf_t *cf, ngx_str_t *value, ngx_cidr_t *cidr)
{
    ngx_int_t  rc;
    u_char    *p;
    size_t     len;
    ngx_str_t  addr;

    /* Create null-terminated copy for parsing */
    len = value->len;
    p = ngx_pnalloc(cf->pool, len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, value->data, len);
    p[len] = '\0';

    addr.data = p;
    addr.len = len;

    /* Try to parse as CIDR first */
    rc = ngx_ptocidr(&addr, cidr);

    if (rc == NGX_ERROR) {
        /* Not a valid CIDR, try as plain IP */
        cidr->family = AF_INET;

        cidr->u.in.addr = ngx_inet_addr(p, len);
        if (cidr->u.in.addr != INADDR_NONE) {
            cidr->u.in.mask = 0xffffffff;
            return NGX_OK;
        }

#if (NGX_HAVE_INET6)
        /* Try IPv6 */
        cidr->family = AF_INET6;

        if (ngx_inet6_addr(p, len, cidr->u.in6.addr.s6_addr) == NGX_OK) {
            ngx_memset(cidr->u.in6.mask.s6_addr, 0xff, 16);
            return NGX_OK;
        }
#endif

        return NGX_ERROR;
    }

    if (rc == NGX_DONE) {
        /* Host address (CIDR with full mask) */
        return NGX_OK;
    }

    /* Valid CIDR with network mask */
    return NGX_OK;
}


/*
 * Check if list has a specific tag
 */
static ngx_int_t
ngx_http_waf_list_has_tag(ngx_http_waf_list_t *list, ngx_str_t *tag)
{
    ngx_str_t  *t;
    ngx_uint_t  i;

    if (list->tags == NULL) {
        return 0;
    }

    t = list->tags->elts;
    for (i = 0; i < list->tags->nelts; i++) {
        if (t[i].len == tag->len
            && ngx_strncmp(t[i].data, tag->data, tag->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


/*
 * Check if a list is explicitly disabled for this location
 */
static ngx_int_t
ngx_http_waf_is_list_disabled(ngx_http_waf_list_t *list,
    ngx_http_waf_loc_conf_t *wlcf)
{
    ngx_str_t  *entry;
    ngx_uint_t  i;

    if (wlcf->disable_lists == NULL || wlcf->disable_lists->nelts == 0) {
        return 0;
    }

    entry = wlcf->disable_lists->elts;
    for (i = 0; i < wlcf->disable_lists->nelts; i++) {
        /* Check for tag: prefix */
        if (entry[i].len > 4
            && ngx_strncmp(entry[i].data, "tag:", 4) == 0)
        {
            ngx_str_t tag;
            tag.data = entry[i].data + 4;
            tag.len = entry[i].len - 4;

            if (ngx_http_waf_list_has_tag(list, &tag)) {
                return 1;
            }
        } else {
            /* Check by name */
            if (entry[i].len == list->name.len
                && ngx_strncmp(entry[i].data, list->name.data, list->name.len) == 0)
            {
                return 1;
            }
        }
    }

    return 0;
}


/*
 * Check if a list is enabled for this location
 *
 * A list is enabled if:
 *   - enable_all is set, OR
 *   - It matches enable_lists by name or tag
 * AND:
 *   - It is NOT in disable_lists
 */
static ngx_int_t
ngx_http_waf_is_list_enabled(ngx_http_waf_list_t *list,
    ngx_http_waf_loc_conf_t *wlcf)
{
    ngx_str_t  *entry;
    ngx_uint_t  i;
    ngx_int_t   enabled = 0;

    /* Check if explicitly disabled first */
    if (ngx_http_waf_is_list_disabled(list, wlcf)) {
        return 0;
    }

    /* If enable_all is set, all lists are enabled */
    if (wlcf->enable_all) {
        return 1;
    }

    /* If no enable_lists configured, no lists are enabled */
    if (wlcf->enable_lists == NULL || wlcf->enable_lists->nelts == 0) {
        return 0;
    }

    entry = wlcf->enable_lists->elts;
    for (i = 0; i < wlcf->enable_lists->nelts; i++) {
        /* Check for tag: prefix */
        if (entry[i].len > 4
            && ngx_strncmp(entry[i].data, "tag:", 4) == 0)
        {
            ngx_str_t tag;
            tag.data = entry[i].data + 4;
            tag.len = entry[i].len - 4;

            if (ngx_http_waf_list_has_tag(list, &tag)) {
                enabled = 1;
                break;
            }
        } else {
            /* Check by name */
            if (entry[i].len == list->name.len
                && ngx_strncmp(entry[i].data, list->name.data, list->name.len) == 0)
            {
                enabled = 1;
                break;
            }
        }
    }

    return enabled;
}


/*
 * Format client IP address for logging
 */
static u_char *
ngx_http_waf_get_client_ip(ngx_http_request_t *r, u_char *buf, size_t len)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        return ngx_inet_ntop(AF_INET, &sin->sin_addr, buf, len);

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        return ngx_inet_ntop(AF_INET6, &sin6->sin6_addr, buf, len);
#endif

    default:
        return ngx_cpymem(buf, "unknown", 7);
    }
}


/*
 * Check client IP against enabled lists
 *
 * Sets result->matched to:
 *   1 - IP found in a list
 *   0 - IP not found
 *  -1 - Error
 *
 * Sets result->list_name to matched list name (if matched)
 */
static void
ngx_http_waf_check_ip(ngx_http_request_t *r, ngx_http_waf_main_conf_t *wmcf,
    ngx_http_waf_loc_conf_t *wlcf, ngx_http_waf_check_result_t *result)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
    ngx_http_waf_list_t  *list;
    ngx_uint_t            i;
    uintptr_t             value;

    result->matched = 0;
    result->list_name = NULL;

    if (wmcf->lists == NULL || wmcf->lists->nelts == 0) {
        return;
    }

    list = wmcf->lists->elts;

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;

        for (i = 0; i < wmcf->lists->nelts; i++) {
            if (!list[i].loaded || list[i].tree4 == NULL) {
                continue;
            }

            if (!ngx_http_waf_is_list_enabled(&list[i], wlcf)) {
                continue;
            }

            value = ngx_radix32tree_find(list[i].tree4,
                                          ntohl(sin->sin_addr.s_addr));

            if (value == NGX_HTTP_WAF_RADIX_MATCH) {
                result->matched = 1;
                result->list_name = &list[i].name;
                return;
            }
        }
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;

        for (i = 0; i < wmcf->lists->nelts; i++) {
            if (!list[i].loaded || list[i].tree6 == NULL) {
                continue;
            }

            if (!ngx_http_waf_is_list_enabled(&list[i], wlcf)) {
                continue;
            }

            value = ngx_radix128tree_find(list[i].tree6,
                                           sin6->sin6_addr.s6_addr);

            if (value == NGX_HTTP_WAF_RADIX_MATCH) {
                result->matched = 1;
                result->list_name = &list[i].name;
                return;
            }
        }
        break;
#endif

    default:
        /* Unknown address family */
        break;
    }
}


/*
 * Access phase handler
 */
static ngx_int_t
ngx_http_waf_handler(ngx_http_request_t *r)
{
    ngx_http_waf_main_conf_t    *wmcf;
    ngx_http_waf_loc_conf_t     *wlcf;
    ngx_http_waf_check_result_t  result;
    u_char                       ip_buf[NGX_INET6_ADDRSTRLEN];

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    /* If WAF is disabled, decline */
    if (!wlcf->enabled) {
        return NGX_DECLINED;
    }

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);

    /* Format client IP for logging */
    ngx_http_waf_get_client_ip(r, ip_buf, sizeof(ip_buf));

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "%V: checking %s (mode=%s)",
                   &wlcf->log_prefix, ip_buf,
                   wlcf->mode == NGX_HTTP_WAF_MODE_WHITELIST
                       ? "whitelist" : "blacklist");

    /* Check IP against lists */
    ngx_http_waf_check_ip(r, wmcf, wlcf, &result);

    if (result.matched < 0) {
        /* Error during check */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%V: error checking IP %s", &wlcf->log_prefix, ip_buf);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (wlcf->mode == NGX_HTTP_WAF_MODE_BLACKLIST) {
        /* Blacklist mode: block if matched */
        if (result.matched) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "%V: blocked %s (matched list \"%V\")",
                          &wlcf->log_prefix, ip_buf, result.list_name);
            return NGX_HTTP_FORBIDDEN;
        }
        /* Not matched, allow */
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "%V: allowed %s (no match)", &wlcf->log_prefix, ip_buf);
        return NGX_DECLINED;

    } else {
        /* Whitelist mode: allow only if matched */
        if (result.matched) {
            /* Matched whitelist, allow */
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "%V: allowed %s (matched whitelist \"%V\")",
                           &wlcf->log_prefix, ip_buf, result.list_name);
            return NGX_DECLINED;
        }

        /* Not in whitelist, block */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "%V: blocked %s (not in whitelist)",
                      &wlcf->log_prefix, ip_buf);
        return NGX_HTTP_FORBIDDEN;
    }
}


/*
 * Module initialization
 */
static ngx_int_t
ngx_http_waf_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_uint_t                  total_ips = 0;
    ngx_http_waf_list_t        *list;
    ngx_uint_t                  i;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_waf_handler;

    /* Count total IPs loaded */
    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    if (wmcf->lists != NULL) {
        list = wmcf->lists->elts;
        for (i = 0; i < wmcf->lists->nelts; i++) {
            total_ips += list[i].count4 + list[i].count6;
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "nginx-waf %s: %ui lists, %ui IPs loaded",
                  NGX_HTTP_WAF_VERSION,
                  wmcf->lists ? wmcf->lists->nelts : 0,
                  total_ips);

    return NGX_OK;
}
