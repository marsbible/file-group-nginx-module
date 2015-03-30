#include "ngx_file_group_module.h"
/* buffer set for internal use*/
typedef struct {
    void *shm_mem; //指向共享内存中的数据
    ngx_array_t ptrs; //指向各个buffer的指针
    uintptr_t set_version; //本地存储的bufferset版本号
    void *pool; //内存池,添加元素使用
} ngx_fgroup_bufferset_internal_t;

/* ngx file group undo log */
typedef struct {
    uint32_t undo_idx;
    u_char *ptr;
}ngx_fgroup_file_undo_log_t;

/* ngx file group */
typedef struct {
    uint32_t  group_id; //hash of group_name,must unique 
    int32_t error_idx; //file index which triggers the first error
    ngx_str_t group_name;
    ngx_str_t group_dir;
    ngx_array_t group_files; //array of ngx_file_node_t 
    ngx_shm_zone_t *shm_zone;
    ngx_slab_pool_t *shpool;
    ngx_array_t undo_log;
    ngx_fgroup_bufferset_internal_t bs;
}ngx_fgroup_file_group_t;

/* ngx file node */
typedef struct {
    ngx_rbtree_node_t     node;
    ngx_uint_t            group_idx; //group index in file_groups 
    ngx_str_t             name;
    ngx_str_t             filepath;
    ngx_str_t             fullpath;//完整路径
    ngx_uint_t            arr_index; //buf index in bufferset
    ngx_file_t            file; //onloading file info if any 
}ngx_fgroup_file_node_t;


typedef struct {
    uint32_t buf_key; //unique ipc key 
    uint32_t next_elem; //next elem idx, count from 1, 0 means no next
    int32_t buf_id; //-1 is invalid
    uint32_t reserved;
}ngx_fgroup_shm_buffer_version_t;

#define NGX_FGROUP_IN_UPDATE 0x8000000000000000ul
typedef struct {
    uint32_t group_id; //unique group id
    uint32_t elem_num;
    uint64_t set_version; //version number of this bufferset
    uint32_t updated_idx; //first updated element index, count from 1, 0 means no updated item，-1 means need all update 
    uint32_t reserverd;
    ngx_shmtx_sh_t lock; //share memory lock between process
    ngx_fgroup_shm_buffer_version_t buffer_version[0]; //version number of buffers
}ngx_fgroup_shm_bufferset_t;

ngx_fgroup_file_node_t *ngx_fgroup_file_rbtree_lookup(ngx_rbtree_t *rbtree, ngx_str_t *group_name, ngx_str_t *file_name);

//file shm api
u_char *ngx_fgroup_shm_get_by_name(void *conf, ngx_str_t *group_name, ngx_str_t *name);
u_char *ngx_fgroup_shm_get_by_id(int id);
void ngx_fgroup_shm_free(u_char *addr);
u_char *ngx_fgroup_shm_new_by_name(void *conf, ngx_str_t *group_name, ngx_str_t *name, size_t size, int *mid);
u_char *ngx_fgroup_shm_new_by_key(uint32_t key, size_t size, int *mid);
ngx_fgroup_shm_header_t *ngx_fgroup_shm_get_header(u_char *addr);

//bufferset api
ngx_fgroup_bufferset_t *ngx_fgroup_bufferset_init(ngx_fgroup_bufferset_t *bs, void *bs_shm, size_t init_size, void *conf);
uint32_t ngx_fgroup_bufferset_add_buffer(ngx_fgroup_bufferset_t *bs, u_char *buf);
u_char *ngx_fgroup_bufferset_del_buffer(ngx_fgroup_bufferset_t *bs, size_t idx);
u_char *ngx_fgroup_bufferset_get_buffer(ngx_fgroup_bufferset_t *bs, size_t idx);
u_char *ngx_fgroup_bufferset_set_buffer_locked(ngx_fgroup_bufferset_t *bs, u_char *buf, size_t idx);
unsigned int ngx_fgroup_bufferset_get_changed(ngx_fgroup_bufferset_t *bs, uint64_t *g_version);
void ngx_fgroup_bufferset_set_local_version(ngx_fgroup_bufferset_t *bs,uint64_t g_version);
void ngx_fgroup_bufferset_restore_buffer_locked(ngx_fgroup_bufferset_t *bs, u_char *buf, size_t idx);
uint64_t ngx_fgroup_bufferset_inc_version_locked(ngx_fgroup_bufferset_t *bs);
