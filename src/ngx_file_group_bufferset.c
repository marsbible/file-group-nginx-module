#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_file_group_module_internal.h"

/*
 * shm API
 *
*/
u_char *ngx_fgroup_shm_get_by_name(void *conf, ngx_str_t *group_name, ngx_str_t *name)
{
    int  id;
    u_char *p;
    ngx_fgroup_conf_t *clcf = (ngx_fgroup_conf_t *)conf;
    static ngx_str_t null_group = ngx_string("");

    if(conf == NULL || name == NULL)
        return NULL;

    ngx_fgroup_file_node_t *node =  ngx_fgroup_file_rbtree_lookup(&clcf->file_tree, group_name?(ngx_str_t *)group_name:&null_group, (ngx_str_t *)name);

    if(node == NULL) {

        return NULL;
    }

    id = shmget(node->node.key, 0, (SHM_R));
    if(id == -1) {
        return NULL;
    }

    p = shmat(id, NULL, 0);

    if (p == (void *) -1) {
        return NULL;
    }

    //bypass the header
    return p+sizeof(ngx_fgroup_shm_header_t);
}

u_char *ngx_fgroup_shm_get_by_id(int id)
{
    u_char *p = shmat(id, NULL, 0);

    if (p == (void *) -1) {
        return NULL;
    }

    //bypass the header
    return p+sizeof(ngx_fgroup_shm_header_t);
}

void ngx_fgroup_shm_free(u_char *addr)
{
    if(addr == NULL) {
        return;
    }
    if (shmdt(addr-sizeof(ngx_fgroup_shm_header_t)) == -1) {
        //assert(0);
    }
}

u_char *ngx_fgroup_shm_new_by_name(void *conf, ngx_str_t *group_name, ngx_str_t *name, size_t size, int *mid)
{
    int  id;
    u_char *p;
    ngx_fgroup_conf_t *clcf = (ngx_fgroup_conf_t *)conf;
    static ngx_str_t null_group = ngx_string("");

    if(conf == NULL || name == NULL)
        return NULL;

    ngx_fgroup_file_node_t *node =  ngx_fgroup_file_rbtree_lookup(&clcf->file_tree, group_name?(ngx_str_t *)group_name:&null_group, (ngx_str_t *)name);

    if(node == NULL) {
        return NULL;
    }

    id = shmget(node->node.key, size+sizeof(ngx_fgroup_shm_header_t), (SHM_R|SHM_W|IPC_CREAT|IPC_EXCL));

    if (id == -1) {
        return NULL;
    }

    p = shmat(id, NULL, 0);

    if (p == (void *) -1) {
        p = NULL;
    }

    if (shmctl(id, IPC_RMID, NULL) == -1) {
        //ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
        //                              "shmctl(IPC_RMID) failed");
    }

    if(p) {
        ngx_fgroup_shm_header_t *sh = (ngx_fgroup_shm_header_t *)p;
        sh->key = node->node.key;
        sh->id = id;
        sh->size = size+sizeof(ngx_fgroup_shm_header_t);
        sh->ipc_arg2 = 0;
        if(mid) *mid = id;
        p = p + sizeof(ngx_fgroup_shm_header_t);
    }

    return p;
}

u_char *ngx_fgroup_shm_new_by_key(uint32_t key, size_t size, int *mid)
{
    int  id;
    u_char *p;

    id = shmget(key, size+sizeof(ngx_fgroup_shm_header_t), (SHM_R|SHM_W|IPC_CREAT|IPC_EXCL));

    if (id == -1) {
        return NULL;
    }

    p = shmat(id, NULL, 0);

    if (p == (void *) -1) {
        p = NULL;
    }

    if (shmctl(id, IPC_RMID, NULL) == -1) {
        //ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
        //                              "shmctl(IPC_RMID) failed");
    }

    if(p) {
        ngx_fgroup_shm_header_t *sh = (ngx_fgroup_shm_header_t *)p;
        sh->key = key;
        sh->id = id;
        sh->size = size+sizeof(ngx_fgroup_shm_header_t);
        sh->ipc_arg2 = 0;
        if(mid) *mid = id;
        p = p + sizeof(ngx_fgroup_shm_header_t);
    }

    return p;
}

ngx_fgroup_shm_header_t *ngx_fgroup_shm_get_header(u_char *addr)
{
    return (ngx_fgroup_shm_header_t *)(addr - sizeof(ngx_fgroup_shm_header_t));
}


/*
 * bufferset API
 * 
*/

ngx_fgroup_bufferset_t *ngx_fgroup_bufferset_init(ngx_fgroup_bufferset_t *bs, void *bs_shm, size_t init_size, void *conf)
{
    ngx_fgroup_shm_bufferset_t *bs_sh = (ngx_fgroup_shm_bufferset_t *)bs_shm;
    ngx_fgroup_bufferset_internal_t *bs_ = (ngx_fgroup_bufferset_internal_t *)bs;

    ngx_cycle_t *cycle = ((ngx_fgroup_conf_t *)conf)->conf;

    if(bs_sh == NULL)
        return NULL;

    ngx_memzero(bs_sh, sizeof(ngx_fgroup_shm_bufferset_t) + sizeof(ngx_fgroup_shm_buffer_version_t)*init_size);
    size_t i;
    for(i=0; i<init_size; i++) {
        bs_sh->buffer_version[i].buf_id = -1;
    }

    bs_sh->elem_num = init_size;

    bs_->shm_mem = bs_sh;
    bs_->pool = cycle->pool;
    bs_->set_version = 0;
    ngx_array_init((ngx_array_t *)&bs_->ptrs, cycle->pool, init_size, sizeof(u_char *));

    u_char **pp = bs_->ptrs.elts;
    for(i=0; i<init_size; i++) {
        pp[i] = NULL;
    }
    bs_->ptrs.nelts = init_size;

    return bs;
}

uint32_t ngx_fgroup_bufferset_add_buffer(ngx_fgroup_bufferset_t *bs, u_char *buf)
{
    u_char **ptr;
    ptr = ngx_array_push((ngx_array_t *)(&bs->ptrs));
    if(ptr) {
        *ptr = buf;
        return bs->ptrs.nelts;
    }
    return 0;
}

u_char *ngx_fgroup_bufferset_del_buffer(ngx_fgroup_bufferset_t *bs, size_t idx)
{
    u_char **var = bs->ptrs.elts;
    u_char *del = NULL;
    size_t i;

    if(bs->ptrs.nelts == 0) return NULL;

    for (i = idx; i < bs->ptrs.nelts - 1; i++) {
        if(i==idx) del = var[i];
        var[i] = var[i+1];
    }

    if(i == bs->ptrs.nelts - 1) {
        bs->ptrs.nelts -= 1;
    }

    return del;
}

u_char *ngx_fgroup_bufferset_get_buffer(ngx_fgroup_bufferset_t *bs, size_t idx)
{
    u_char **var = bs->ptrs.elts;

    if(bs->ptrs.nelts == 0 || idx >= bs->ptrs.nelts) return NULL;

    return var[idx];
}

//the bufferset must under lock
u_char *ngx_fgroup_bufferset_set_buffer_locked(ngx_fgroup_bufferset_t *bs, u_char *buf, size_t idx)
{
    u_char **var = bs->ptrs.elts;
    u_char *old;

    if(bs->ptrs.nelts == 0 || idx >= bs->ptrs.nelts) return NULL;

    old = var[idx];
    var[idx] = buf;
    if(buf != NULL) {
        ngx_fgroup_shm_header_t *h = ngx_fgroup_shm_get_header(buf);
        ngx_fgroup_shm_bufferset_t *bs_sh = (ngx_fgroup_shm_bufferset_t *)bs->shm_mem;

        //put the buffer to the change list
        bs_sh->buffer_version[idx].next_elem = bs_sh->updated_idx;
        bs_sh->updated_idx = idx+1;
        bs_sh->buffer_version[idx].buf_id = h->id;
    }
    return old;
}

void ngx_fgroup_bufferset_restore_buffer_locked(ngx_fgroup_bufferset_t *bs, u_char *buf, size_t idx)
{
    u_char **var = bs->ptrs.elts;
    u_char *new;
    int32_t id;

    if(bs->ptrs.nelts == 0 || idx >= bs->ptrs.nelts) return;

    new = var[idx];
    var[idx] = buf;
    if(buf != NULL) {
        ngx_fgroup_shm_header_t *h = ngx_fgroup_shm_get_header(buf);
        id = h->id;
    }
    else {
        id = 0;
    }

    ngx_fgroup_shm_bufferset_t *bs_sh = (ngx_fgroup_shm_bufferset_t *)bs->shm_mem;

    //restore to old value
    bs_sh->updated_idx = bs_sh->buffer_version[idx].next_elem;
    bs_sh->buffer_version[idx].buf_id = id;
    ngx_fgroup_shm_free(new);
}

unsigned int ngx_fgroup_bufferset_get_changed(ngx_fgroup_bufferset_t *bs, uint64_t *g_version)
{
    *g_version = ((ngx_fgroup_shm_bufferset_t *)bs->shm_mem)->set_version;
    //if version changed and not in update currently, we should sync data later    
    return bs->set_version != *g_version && (*g_version & NGX_FGROUP_IN_UPDATE) == 0;
}

void ngx_fgroup_bufferset_set_local_version(ngx_fgroup_bufferset_t *bs,uint64_t g_version)
{
    bs->set_version = g_version & ~NGX_FGROUP_IN_UPDATE;
}

//bufferset must under lock
uint64_t ngx_fgroup_bufferset_inc_version_locked(ngx_fgroup_bufferset_t *bs)
{
    ngx_fgroup_shm_bufferset_t *bs_sh = (ngx_fgroup_shm_bufferset_t *)bs->shm_mem;
    bs_sh->set_version = (bs_sh->set_version & ~NGX_FGROUP_IN_UPDATE) + 1;
    return bs_sh->set_version;
}
