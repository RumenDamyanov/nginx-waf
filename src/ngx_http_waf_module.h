/*
 * nginx-waf - Web Application Firewall module for nginx
 *
 * Copyright (c) 2025-2026 Rumen Damyanov
 * BSD 3-Clause License - see LICENSE.md
 *
 * https://github.com/RumenDamyanov/nginx-waf
 */

#ifndef _NGX_HTTP_WAF_MODULE_H_INCLUDED_
#define _NGX_HTTP_WAF_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_WAF_VERSION      "0.2.1"
#define NGX_HTTP_WAF_VERSION_NUM  000201


/*
 * Operation modes
 */
#define NGX_HTTP_WAF_MODE_BLACKLIST  0
#define NGX_HTTP_WAF_MODE_WHITELIST  1


/*
 * Radix tree marker values
 * Used to distinguish matched/unmatched entries
 */
#define NGX_HTTP_WAF_RADIX_EMPTY   (uintptr_t) 0
#define NGX_HTTP_WAF_RADIX_MATCH   (uintptr_t) 1


/*
 * IP list definition
 *
 * Represents a named IP list loaded from a file.
 * Tags allow grouping lists for bulk operations.
 */
typedef struct {
    ngx_str_t                   name;        /* list identifier */
    ngx_str_t                   path;        /* file path */
    ngx_array_t                *tags;        /* array of ngx_str_t */
    ngx_radix_tree_t           *tree4;       /* IPv4 radix tree */
#if (NGX_HAVE_INET6)
    ngx_radix_tree_t           *tree6;       /* IPv6 radix tree */
#endif
    ngx_uint_t                  count4;      /* IPv4 entry count */
    ngx_uint_t                  count6;      /* IPv6 entry count */
    ngx_flag_t                  loaded;      /* successfully loaded? */
} ngx_http_waf_list_t;


/*
 * Main configuration (http context)
 *
 * Stores global settings and all defined IP lists.
 * Lists are defined only at http level.
 */
typedef struct {
    ngx_array_t                *lists;       /* array of ngx_http_waf_list_t */
} ngx_http_waf_main_conf_t;


/*
 * Location configuration (http, server, location contexts)
 *
 * Settings that can be overridden per-context.
 * Uses NGX_CONF_UNSET for proper inheritance.
 */
typedef struct {
    ngx_flag_t                  enabled;        /* waf on|off */
    ngx_uint_t                  mode;           /* blacklist or whitelist */
    ngx_str_t                   log_prefix;     /* custom log prefix */
    ngx_array_t                *enable_lists;   /* list names/tags to enable */
    ngx_array_t                *disable_lists;  /* list names/tags to disable */
    ngx_flag_t                  enable_all;     /* enable all lists */
} ngx_http_waf_loc_conf_t;


/*
 * IP check result with matched list info
 */
typedef struct {
    ngx_int_t                   matched;       /* 1=found, 0=not found, -1=error */
    ngx_str_t                  *list_name;     /* name of matched list */
} ngx_http_waf_check_result_t;


/*
 * Module declaration
 */
extern ngx_module_t  ngx_http_waf_module;


#endif /* _NGX_HTTP_WAF_MODULE_H_INCLUDED_ */
