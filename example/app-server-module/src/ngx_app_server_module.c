#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_trie.h"
#include "ngx_app_server_module.h"
#include "ngx_file_group_module.h"

ngx_module_t  ngx_app_server_module;
extern ngx_module_t ngx_fgroup_module;

static ngx_int_t ngx_app_server_handler(ngx_http_request_t *r);
static ngx_int_t ngx_app_server_reload_handler(ngx_http_request_t *r);


static ngx_int_t ngx_app_server_module_init(ngx_cycle_t *cycle);

static char *ngx_app_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_app_server_reload(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

int app_finalize_req(ngx_http_request_t *r, ngx_str_t *response)
{  
    int body_len;

    ngx_buf_t *b;
    if(response) {
        b = ngx_create_temp_buf(r->pool, response->len);
        ngx_snprintf(b->pos, response->len, (char *)"%V", response);
        body_len = response->len;
    }

    r->headers_out.content_length_n = body_len;
    b->last = b->pos + body_len;
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    static ngx_str_t type = ngx_string("text/plain");
    r->headers_out.content_type = type;
    r->headers_out.status = NGX_HTTP_OK;

    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    ngx_int_t ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r, &out);

    return ret;
}


static char *
ngx_app_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_app_server_handler;

    return NGX_CONF_OK;
}


ngx_int_t app_reload_aio_cb(void *arg, int aio_result)
{
    int body_len;
    ngx_http_request_t *r = (ngx_http_request_t *)arg; 
    ngx_str_t response = ngx_string("ok");
    
    ngx_buf_t *b;
   
    if (aio_result == RELOAD_FGROUP_BUSY) {
        ngx_str_set(&response, "busy\n");
    }
    else if (aio_result == RELOAD_FGROUP_FAIL) {
        ngx_str_set(&response, "fail\n");
    }
    
    //must restore
    r->main->blocked--;
    r->aio = 0;

    //暂不考虑返回码r->headers_out.status
    b = ngx_create_temp_buf(r->pool, response.len);
    ngx_snprintf(b->pos, response.len, (char *)"%V", &response);
    body_len = response.len;

    r->headers_out.content_length_n = body_len;
    b->last = b->pos + body_len;
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    static ngx_str_t type = ngx_string("text/plain");
    r->headers_out.content_type = type;
    r->headers_out.status = NGX_HTTP_OK;

    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    ngx_int_t ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r, &out);

    return ret;
}


static char *
ngx_app_server_reload(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_app_server_reload_handler;

    return NGX_CONF_OK;
}


static ngx_command_t ngx_app_server_commands[] = {
    { ngx_string("srv_app"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_app_server,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("srv_reload"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_app_server_reload,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command 
};


/*
 * conf相关函数 
 *
*/
static void * ngx_app_server_create_srv_conf(ngx_conf_t *cf)
{
    ngx_app_server_conf_t *mycf;
    
    mycf = (ngx_app_server_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_app_server_conf_t));
    
    if(mycf == NULL) {
        return NULL;
    }

    ngx_str_null(&mycf->log_file); //"service.log"
    ngx_str_null(&mycf->log_level); //"INFO"
    mycf->max_log_file_size = NGX_CONF_UNSET_UINT;//1024000000

    mycf->conf = cf->cycle;
    return mycf;
}

static char *ngx_app_server_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}

static ngx_trie_t  *reload_arg_trie;
const struct app_arg_item reload_args[] = {
    arg_len("group=", 0),
    arg_len("name1=", 0),
    arg_len("name2=", 0),
    arg_len("name3=", 0),
    arg_len("name4=", 0),
    arg_len("name5=", 0),
    arg_len("name6=", 0),
    arg_len("name7=", 0),
    arg_len("name8=", 0),
    arg_len("name9=", 0),
    arg_len("name10=", 0),
    arg_len("name11=", 0),
    arg_len("name12=", 0),
    arg_len("name13=", 0),
    arg_len("name14=", 0),
    arg_len("name15=", 0),
    arg_len("name16=", 0),
    //    
};

static ngx_trie_t  *query_arg_trie;
const struct app_arg_item query_args[] = {
    arg_len("query=", 0),
};

static ngx_int_t ngx_app_server_module_init(ngx_cycle_t *cycle)
{
    ngx_uint_t i;

    ngx_http_core_main_conf_t *cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    ngx_http_core_srv_conf_t   **cscfp = cmcf->servers.elts;;
    ngx_app_server_conf_t *mycf;
    
    reload_arg_trie = ngx_trie_create(cycle->pool);
    if(reload_arg_trie == NULL)
        return NGX_ERROR;
    
    for(i=0; i<sizeof(reload_args)/sizeof(struct app_arg_item); i++) {
        ngx_str_t tmp;
        if(reload_args[i].str == NULL)
            continue;
        tmp.data = (u_char *)reload_args[i].str;
        tmp.len = reload_args[i].len;
        ngx_trie_node_t *node = reload_arg_trie->insert(reload_arg_trie, &tmp, 0);
        if (node == NULL) {
            return NGX_ERROR;
        }
        node->value = (void *)(i+1);
    }
    if( reload_arg_trie->build_clue(reload_arg_trie) != NGX_OK)
        return NGX_ERROR;

    query_arg_trie = ngx_trie_create(cycle->pool);
    if(query_arg_trie == NULL)
        return NGX_ERROR;
    
    for(i=0; i<sizeof(query_args)/sizeof(struct app_arg_item); i++) {
        ngx_str_t tmp;
        if(query_args[i].str == NULL)
            continue;
        tmp.data = (u_char *)query_args[i].str;
        tmp.len = query_args[i].len;
        ngx_trie_node_t *node = query_arg_trie->insert(query_arg_trie, &tmp, 0);
        if (node == NULL) {
            return NGX_ERROR;
        }
        node->value = (void *)(i+1);
    }
    if(query_arg_trie->build_clue(query_arg_trie) != NGX_OK)
        return NGX_ERROR;
    
    return NGX_OK;
}


size_t trim_all(char *str, size_t len)
{
    int left_space = 1;
    size_t idx = 0;
    char *start = str;
    while( idx < len ) {
        if(isspace(str[idx])) {
            if(!left_space) {
                *start = str[idx];
                ++start;
            }
            left_space = 1;
        }
        else {
            *start = str[idx];
            ++start;
            left_space = 0;
        }
        ++idx;
    }
    if(start > str && isspace(*(start - 1)))
        --start;
    *start = '\0';
    return start - str;
}

static ngx_int_t ngx_app_server_reload_handler(ngx_http_request_t *r)
{
    ngx_str_t args[sizeof(reload_args)/sizeof(struct app_arg_item)];
    
    ngx_int_t rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }
    ngx_memzero(args, sizeof(args)); 
    ngx_str_t fail_str = ngx_string("ok\n");
    void *group = NULL;
    
    ngx_array_t argarray;
#if 1 
    //如果没有参数，只reload第一个group
    if (r->args.len == 0) {
	    argarray.nelts = 0;
	    argarray.size = sizeof(ngx_str_t);
	    argarray.nalloc = 0;
	    argarray.pool = r->pool;
	    argarray.elts = &args[1];
    }
    else 
    {
        //提取args中的各个参数到userInfo中
        ngx_extract_args(reload_arg_trie, reload_args, &r->args, (ngx_str_t *)&args[0]);
        if(args[0].len == 0) {
            //如果没有指定group,则认为在全局group里
            args[0].data = (u_char *)"";
        }
	argarray.size = sizeof(ngx_str_t);
	argarray.nalloc = sizeof(reload_args)/sizeof(struct app_arg_item) - 1;
	argarray.nelts = argarray.nalloc;
	argarray.pool = r->pool;
	argarray.elts = &args[1];
    }
#endif
    

    ngx_int_t ret = ngx_fgroup_batch_reload(&args[0], &argarray, app_reload_aio_cb, r, r->pool);
    
    if(ret == RELOAD_FGROUP_AGAIN) {
	    r->main->blocked++;
        r->aio = 0;
        return NGX_AGAIN;
    }
    else if (ret == RELOAD_FGROUP_BUSY) {
	ngx_str_set(&fail_str, "busy\n");
    }
    else if (ret == RELOAD_FGROUP_FAIL) {
    	ngx_str_set(&fail_str, "fail\n");
    }
		
    return app_finalize_req((void *)r, &fail_str);
}

static ngx_int_t
ngx_app_server_handler(ngx_http_request_t *r)
{
    static ngx_str_t group_name = ngx_string("test");
    static ngx_str_t file_name = ngx_string("nginx_conf");
    ngx_str_t args[sizeof(query_args)/sizeof(struct app_arg_item)];


    ngx_int_t rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(args, sizeof(args));

    //提取args中的各个参数到userInfo中
    ngx_extract_args(query_arg_trie, query_args, &r->args, (ngx_str_t *)&args[0]);

    ngx_str_t res = ngx_fgroup_get_file(fgroup_get_cur_conf(), &group_name, &file_name);

    if(res.len == 0 || args[0].len == 0) {
        ngx_str_t res = ngx_string("NULL\n");
        rc = app_finalize_req((void *)r, &res);
        return rc;
    }

    //search query in file
    args[0].data[args[0].len] = '\0';
    u_char * pp = ngx_strnstr(res.data, args[0].data, res.len);

    char tmp[128];
    if(pp != NULL)
        sprintf(tmp, "found %s at %d\n",args[0].data, (pp - res.data));
    else
        sprintf(tmp, "cannot found %s\n",args[0].data);
    res.data = tmp;
    res.len = strlen(tmp);
    rc = app_finalize_req((void *)r, &res);

    return rc;
}

static ngx_http_module_t ngx_app_server_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    ngx_app_server_create_srv_conf,          /* create server configuration */
    ngx_app_server_merge_srv_conf,           /* merge server configuration */   
    NULL,                                     /* create location configuration */
    NULL                                      /* merge location configuration */
};

ngx_module_t ngx_app_server_module = {
    NGX_MODULE_V1,
    &ngx_app_server_module_ctx,        /* module context */
    ngx_app_server_commands,           /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    ngx_app_server_module_init,        /* init module */
    NULL,                              /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING    
};

