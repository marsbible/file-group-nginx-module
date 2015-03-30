#include <sys/ipc.h>
#include <sys/shm.h>

enum reload_return {
  RELOAD_FGROUP_OK = NGX_OK,
  RELOAD_FGROUP_FAIL = NGX_ERROR,
  RELOAD_FGROUP_AGAIN = NGX_AGAIN,
  RELOAD_FGROUP_BUSY = NGX_BUSY
};

typedef struct {
    ngx_array_t  file_groups; //array of ngx_file_group_t
    ngx_rbtree_t file_tree; //index all file by (group name+file name)
    ngx_rbtree_node_t file_tree_sentinel;
    ngx_cycle_t *conf;
} ngx_fgroup_conf_t;

/* shared memory header,all shm of file group has this header  */
typedef struct {
    uint32_t     key; //store ipc key_t
    int          id; //shm id 
    size_t       size;
    uintptr_t    ipc_arg2;//-1 for invalid
} ngx_fgroup_shm_header_t;

/* buffer set*/
typedef struct {
    void *shm_mem; //point to shared metadata 
    ngx_array_t ptrs; //local pointers to data
    uintptr_t set_version; //local version number
    void *pool; //memory pool 
} ngx_fgroup_bufferset_t;

//murmurhash2a incremental implementation
typedef struct {
    unsigned int m_hash;
    unsigned int m_tail;
    unsigned int m_count;
    size_t m_size;
}murmurhash2a_t;

typedef ngx_int_t (*ngx_fgroup_reload_aio_cb)(void *arg, int aio_result);

typedef struct {
    int aio_issued;
    ngx_fgroup_reload_aio_cb cb; //callback set by user when aio is done
    void *arg; //argument for cb above
    void *fgroup;
    ngx_fgroup_conf_t *conf;
    ngx_pool_t *pool;
}ngx_fgroup_aio_handler_t;

void murmurhash2a_begin(murmurhash2a_t *mmh, unsigned int seed);
void murmurhash2a_add(murmurhash2a_t *mmh, u_char * data, size_t len);
unsigned int murmurhash2a_end(murmurhash2a_t *mmh);

ngx_str_t ngx_fgroup_get_file(void *conf, ngx_str_t *group_name, ngx_str_t *fname);
void *ngx_fgroup_get_file_idx(void *conf, ngx_str_t *group_name, ngx_str_t *fname, size_t *idx);
void *ngx_fgroup_get_group(void *conf, ngx_str_t *group_name);
ngx_array_t *ngx_fgroup_get_ptrs(void *group);
ngx_str_t ngx_fgroup_get_group_name(void *group);
ngx_str_t ngx_fgroup_get_file_name(void *group, size_t idx);
u_char *ngx_fgroup_get_file_ptr(void *group, size_t idx);
void ngx_fgroup_worker_init(void *conf);
int ngx_fgroup_reload(void *conf, void *fgroup, ngx_str_t *key);
int ngx_fgroup_reload_aio(void *conf, void *fgroup, ngx_str_t *key, ngx_fgroup_aio_handler_t *aio_st);
void ngx_fgroup_lock(void *group);
unsigned int ngx_fgroup_trylock(void *group);
void ngx_fgroup_unlock(void *group);

ngx_fgroup_conf_t *fgroup_get_cur_conf();
ngx_int_t ngx_fgroup_batch_reload(ngx_str_t *group_name, ngx_array_t *args, ngx_fgroup_reload_aio_cb cb, void *arg, ngx_pool_t *pool);
