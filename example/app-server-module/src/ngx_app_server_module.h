#ifndef H_NGX_APP_SERVER_MODULE_H
#define H_NGX_APP_SERVER_MODULE_H
/* 模块配置结构  */
typedef struct {
    ngx_str_t log_file;
    ngx_str_t log_level;
    ngx_uint_t max_log_file_size;

    //conf
    ngx_cycle_t *conf;
}ngx_app_server_conf_t;

#endif
