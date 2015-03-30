#include <assert.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include "ngx_file_group_module_internal.h"

typedef int (*ngx_fgroup_timer_cb)(void *arg,void *conf); //return 1: continue,others：stop the timer

struct _cb_arg {
    void *arg;
    ngx_fgroup_timer_cb cb;
    ngx_uint_t msecs;
    void *conf;
};

static void
ngx_fgroup_timer_handler(ngx_event_t *ev)
{
    struct _cb_arg * ca = (struct _cb_arg *)ev->data;
    int r = ca->cb(ca->arg, ca->conf);

    if(r == 1) {
        ngx_add_timer(ev, ca->msecs);
    }
    else { //error occur
        free(ca);
        free(ev);
    }
}

void *ngx_fgroup_add_timer(ngx_fgroup_timer_cb cb,void *arg,unsigned int seconds, void *conf)
{
    ngx_event_t *ev;
    struct _cb_arg *ca;
    ngx_fgroup_conf_t *mycf = (ngx_fgroup_conf_t *)conf;

    ev = (ngx_event_t *)calloc(sizeof(ngx_event_t), 1);
    ca = (struct _cb_arg *)malloc(sizeof(struct _cb_arg));
    if(ev == NULL || ca == NULL) {
        free(ev);
        free(ca);
        return NULL;
    }
    ca->arg = arg;
    ca->cb = cb;
    ca->msecs = 1000*seconds;
    ca->conf = conf;

    ev->handler = ngx_fgroup_timer_handler;
    ev->log = (ngx_log_t *)(mycf->conf->log);
    ev->data = (void *)ca;
    ngx_add_timer(ev, ca->msecs);

    return ev;
}

void ngx_fgroup_del_timer(void *ev)
{
    if(ev == NULL) return;
    free(((ngx_event_t *)ev)->data);
    ngx_del_timer((ngx_event_t *)ev);
    free(ev);
}

//highlevel api
ngx_str_t ngx_fgroup_get_file(void *conf, ngx_str_t *group_name, ngx_str_t *fname)
{
    ngx_fgroup_conf_t *mycf = (ngx_fgroup_conf_t *)conf;
    ngx_str_t ret = ngx_null_string;

    ngx_fgroup_file_node_t *fn = ngx_fgroup_file_rbtree_lookup(&mycf->file_tree, (ngx_str_t *)group_name, (ngx_str_t *)fname);

    if(fn == NULL) {
        return ret;
    }

    ngx_fgroup_file_group_t *groups = mycf->file_groups.elts;
    ngx_array_t *bs_ = &groups[fn->group_idx].bs.ptrs;

    assert(fn->arr_index < bs_->nelts);

    ret.data = ((u_char **)bs_->elts)[fn->arr_index];
    if(ret.data == NULL) {
        return ret;
    }
    ngx_fgroup_shm_header_t *tt = ngx_fgroup_shm_get_header(ret.data);
    ret.len = tt->size - sizeof(ngx_fgroup_shm_header_t);

    return ret;
}

//lowlevel api
void *ngx_fgroup_get_group(void *conf, ngx_str_t *group_name)
{
    ngx_fgroup_conf_t *mycf = (ngx_fgroup_conf_t *)conf;
    ngx_fgroup_file_group_t *groups;

    groups = mycf->file_groups.elts;
    
    size_t n;
    for (n = 0; n < mycf->file_groups.nelts; n++) {
        if(groups[n].group_name.len == group_name->len && ngx_strncmp(groups[n].group_name.data, group_name->data, group_name->len) == 0)
            break;
    }

    if(n == mycf->file_groups.nelts) {
        return NULL;
    }
    return &groups[n];
}

void *ngx_fgroup_get_file_idx(void *conf, ngx_str_t *group_name, ngx_str_t *fname, size_t *idx)
{
    ngx_fgroup_conf_t *mycf = (ngx_fgroup_conf_t *)conf;

    ngx_fgroup_file_node_t *fn = ngx_fgroup_file_rbtree_lookup(&mycf->file_tree, (ngx_str_t *)group_name, (ngx_str_t *)fname);

    if(fn == NULL) {
        return NULL;
    }

    ngx_fgroup_file_group_t *groups = mycf->file_groups.elts;
    ngx_array_t *bs_ = &groups[fn->group_idx].bs.ptrs;

    assert(fn->arr_index < bs_->nelts);

    *idx = fn->arr_index;
    return &groups[fn->group_idx];
}

ngx_str_t ngx_fgroup_get_group_name(void *group)
{
    return ((ngx_fgroup_file_group_t *)group)->group_name;
}

ngx_array_t *ngx_fgroup_get_ptrs(void *group)
{
    if(group == NULL) return NULL;
    return &((ngx_fgroup_file_group_t *)group)->bs.ptrs;
}

ngx_str_t ngx_fgroup_get_file_name(void *group, size_t idx)
{
    ngx_fgroup_file_node_t *nodes = ((ngx_fgroup_file_group_t *)group)->group_files.elts;

    assert(idx < ((ngx_fgroup_file_group_t *)group)->group_files.nelts);

    return nodes[idx].name;
}

u_char *ngx_fgroup_get_file_ptr(void *group, size_t idx)
{
    u_char **ptrs = ((ngx_fgroup_file_group_t *)group)->bs.ptrs.elts;
    assert(idx < ((ngx_fgroup_file_group_t *)group)->bs.ptrs.nelts);
    return ptrs[idx];
}

//lock guard
void ngx_fgroup_lock(void *group)
{
    ngx_slab_pool_t *shpool = ((ngx_fgroup_file_group_t *)group)->shpool;
    ngx_shmtx_lock(&shpool->mutex);
}

unsigned int ngx_fgroup_trylock(void *group)
{
    ngx_slab_pool_t *shpool = ((ngx_fgroup_file_group_t *)group)->shpool;
    return ngx_shmtx_trylock(&shpool->mutex);
}

void ngx_fgroup_unlock(void *group)
{
    ngx_slab_pool_t *shpool = ((ngx_fgroup_file_group_t *)group)->shpool;
    ngx_shmtx_unlock(&shpool->mutex);
}

static int ngx_fgroup_checker(void *arg, void *conf)
{
    uint32_t i,j;
    ngx_fgroup_file_group_t *ctx = (ngx_fgroup_file_group_t *)arg;
    ngx_fgroup_conf_t *cf = (ngx_fgroup_conf_t *)conf;   
    uint64_t g_v;

    //nginx is shutting down
    if(ngx_quit || ngx_exiting) {
        ngx_log_error(NGX_LOG_NOTICE, cf->conf->log, 0, "nginx is shutting down, won't add fgroup timer!");
        return 0;
    }

    //no change
    if(!ngx_fgroup_bufferset_get_changed((ngx_fgroup_bufferset_t *)(&ctx->bs), &g_v))
        return 1;

    u_char **key = ctx->bs.ptrs.elts;
    ngx_fgroup_shm_header_t *h;
    ngx_fgroup_shm_bufferset_t *bs_sh = (ngx_fgroup_shm_bufferset_t *)ctx->bs.shm_mem;

    //trylock failed 
    if(!ngx_fgroup_trylock(arg)) {
        ngx_log_error(NGX_LOG_NOTICE, cf->conf->log, 0, "file fgroup %V try lock failed!", &ctx->group_name);
        return 1;
    }
    ngx_log_error(NGX_LOG_DEBUG, cf->conf->log, 0, "file fgroup %V try lock ok!", &ctx->group_name);
    //double check 
    if(!ngx_fgroup_bufferset_get_changed((ngx_fgroup_bufferset_t *)(&ctx->bs), &g_v)) {
        ngx_fgroup_unlock(arg);
        return 1;
    }

    //if version number only diff by 1, we can sync data by change list
    if(g_v == ctx->bs.set_version + 1) {
        for (i = bs_sh->updated_idx; i != 0; i = bs_sh->buffer_version[i-1].next_elem) {
            j = i-1;
            h = (ngx_fgroup_shm_header_t *)(key[j] - sizeof(ngx_fgroup_shm_header_t));
            //no change for this buffer
            if(key[j] == NULL || h->id == bs_sh->buffer_version[j].buf_id )
                continue;

            u_char *p = shmat(bs_sh->buffer_version[j].buf_id, NULL, 0);
            if (p == (void *) -1) {
                ngx_log_error(NGX_LOG_ERR, cf->conf->log, 0, "ngx_fgroup_checker shmat() %d failed", bs_sh->buffer_version[j].buf_id);
                break;
            }
            //save old value
            ngx_fgroup_file_undo_log_t *u = ngx_array_push(&ctx->undo_log);
            u->undo_idx = j;
            u->ptr = key[j];

            key[j] = p+sizeof(ngx_fgroup_shm_header_t);
        }
        ngx_log_error(NGX_LOG_NOTICE, cf->conf->log, 0, "file fgroup \"%V\" incr-update to version %L", &ctx->group_name, g_v);
    }
    else { //multiple update, need full reload
        for (i = ctx->bs.ptrs.nelts; i != 0; i--) {
            j = i-1;
            h = (ngx_fgroup_shm_header_t *)(key[j] - sizeof(ngx_fgroup_shm_header_t));
            //no change for this buffer
            if(key[j] == NULL || h->id == bs_sh->buffer_version[j].buf_id )
                continue;

            u_char *p = shmat(bs_sh->buffer_version[j].buf_id, NULL, 0);
            if (p == (void *) -1) {
                ngx_log_error(NGX_LOG_ERR, cf->conf->log, 0, "ngx_fgroup_checker shmat() %d failed", bs_sh->buffer_version[j].buf_id);
                break;
            }
            //save old value
            ngx_fgroup_file_undo_log_t *u = ngx_array_push(&ctx->undo_log);
            u->undo_idx = j;
            u->ptr = key[j];

            key[j] = p+sizeof(ngx_fgroup_shm_header_t);
        }
        ngx_log_error(NGX_LOG_NOTICE, cf->conf->log, 0, "file fgroup \"%V\" full-update to version %L", &ctx->group_name, g_v);
    }

    if(i == 0) {
        ngx_fgroup_file_undo_log_t *logs;

        logs = ctx->undo_log.elts;
        size_t n;
        for (n = ctx->undo_log.nelts; n > 0; n--) {
            ngx_fgroup_shm_free(logs[n-1].ptr);
        }
        ngx_fgroup_bufferset_set_local_version((ngx_fgroup_bufferset_t *)(&ctx->bs), g_v);
    }
    else {
        //error occured, rollback  
        ngx_fgroup_file_undo_log_t *logs;

        logs = ctx->undo_log.elts;
        size_t n;
        uint32_t idx;
        //restore local pointers
        for (n = ctx->undo_log.nelts; n > 0; n--) {
            idx = logs[n-1].undo_idx;
            ngx_fgroup_shm_free(key[idx]);
            key[idx] = logs[n-1].ptr;
        }
        //restore shared metadata, if shared version and local version only diff by 1, rollback  
        if(g_v == ctx->bs.set_version + 1) {
            for (i = bs_sh->updated_idx; i != 0; i = bs_sh->buffer_version[i-1].next_elem) {
                j = i - 1;
                h = (ngx_fgroup_shm_header_t *)(key[j] - sizeof(ngx_fgroup_shm_header_t));
                //当前buffer没有变化
                if(key[j] == NULL) {
                    bs_sh->updated_idx = bs_sh->buffer_version[j].next_elem;
                    continue;
                }
                bs_sh->buffer_version[j].buf_id = h->id;
                bs_sh->updated_idx = bs_sh->buffer_version[j].next_elem;
            }
            //rollback done, consensus  
            bs_sh->set_version = ctx->bs.set_version;
        }
        //intermediate change lost, cannot rollback, mark and restore in next reload
        else
            bs_sh->set_version |= NGX_FGROUP_IN_UPDATE;
    }
    //undolog清理
    ctx->undo_log.nelts = 0;
    ngx_fgroup_unlock(arg);
    return 1;
}

//conf: current conf 
//fgroup: file group to be reload
//key: name in file group config 
int ngx_fgroup_reload(void *conf, void *fgroup, ngx_str_t *key)
{
    ngx_fgroup_conf_t *mycf = (ngx_fgroup_conf_t *)conf;
    ngx_fgroup_file_group_t *group = (ngx_fgroup_file_group_t *)fgroup;
    ngx_fgroup_file_node_t *node = NULL, *node_end;
    ssize_t n; 
    
    if(key != NULL) {
        node = ngx_fgroup_file_rbtree_lookup(&mycf->file_tree, &group->group_name, (ngx_str_t *)key);
        if(node == NULL) {
            ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0, "file group reload failed, cannnot find file node \"%V\":\"%V\"", &group->group_name, key);
            goto fail;
        }
        else {
            if(group != (ngx_fgroup_file_group_t *)(mycf->file_groups.elts) + node->group_idx) {
                ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0, "file group reload failed, file group error \"%V\":\"%V\"", &group->group_name, key);
                goto fail;
            }
            node_end = node + 1;
            ngx_log_error(NGX_LOG_DEBUG, mycf->conf->log, 0, "file group found node \"%V\":\"%V\"", &group->group_name, key);
        }
    }
    //key is null, reload all files in the group
    else {
        ngx_fgroup_file_node_t *tmp_node = group->group_files.elts;
        node = &tmp_node[0];
        node_end = node +  group->group_files.nelts;
    }
    
    ngx_str_t fname;
    //iterate all nodes
    for(; node != node_end; node++) {
        
        ngx_memzero(&node->file, sizeof(ngx_file_t));
        
        fname = node->filepath; //must null terminated 
        
        //absolute path, use it directly
        if(fname.data[0] == '/') { 
            if(node->fullpath.len < fname.len + 1) {//add '\0'
                node->fullpath.data = ngx_palloc(mycf->conf->pool, fname.len + 1);
            }
            ngx_sprintf(node->fullpath.data,"%V%Z", &fname);
            node->fullpath.len = fname.len;
        }
        else {
            //combine group dir and fname
            if(node->fullpath.len < fname.len + group->group_dir.len + 1 + 1) {//add '/' and '\0'
                node->fullpath.data = ngx_palloc(mycf->conf->pool, fname.len + group->group_dir.len + 1 + 1);
            }
            ngx_sprintf(node->fullpath.data,"%V/%V%Z", &group->group_dir, &fname);
            node->fullpath.len = fname.len + group->group_dir.len + 1;
        }
        
        node->file.name = node->fullpath;
        node->file.log = mycf->conf->log;
        //get basic file info 
        ngx_fd_t    fd;
        fd = ngx_open_file(node->file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0); 
        if (fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0, 
                    "file group open() \"%V\" failed",
                    &node->file.name);
            goto fail;
        }

        if (ngx_fd_info(fd, &node->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0,
                    "file group fstat() \"%V\" failed", &node->file.name);
            ngx_close_file(fd);
            goto fail;     
        }

        //create shared memory  
        int mid = -1;
        off_t      file_size; 

        file_size = ngx_file_size(&node->file.info);
        u_char *nbuf = ngx_fgroup_shm_new_by_key(node->node.key, file_size, &mid);

        if(nbuf == NULL) {
            ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0,
                    "file group shm_new  \"%V\",%z failed", &node->name, file_size);
            ngx_close_file(fd);
            goto fail;
        }

        ngx_log_error(NGX_LOG_DEBUG, mycf->conf->log, 0,
                "file group shm_new  \"%V\",%z ok", &node->name, file_size);

        //shm is ready to read file
        node->file.fd = fd; 
        n = ngx_read_file(&node->file, nbuf, (size_t)file_size, 0);

        if (n == NGX_ERROR || (size_t) n != (size_t)file_size) {
            node->file.fd = NGX_INVALID_FILE; 
            ngx_close_file(fd);
            ngx_fgroup_shm_free(nbuf); 
            ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0,
                    "file group read file \"%V\" returned %z bytes instead of %z",
                    &node->file.name, n, file_size);
            goto fail;         
        }
        
        u_char *old = ngx_fgroup_bufferset_set_buffer_locked((ngx_fgroup_bufferset_t *)(&group->bs), nbuf, node->arr_index);

        //add to undo log
        ngx_fgroup_file_undo_log_t *u = ngx_array_push(&group->undo_log);
        u->undo_idx = node->arr_index;
        u->ptr = old;

        //read file complete，set fd to invalid
        ngx_close_file(fd);
        node->file.fd = NGX_INVALID_FILE;
        ngx_log_error(NGX_LOG_DEBUG, mycf->conf->log, 0, "file group reload file %V,name %V ok",&node->file.name,&node->name);
    }
    return 0;

fail:
    {
        //rollback
        ngx_fgroup_file_undo_log_t *logs;

        logs = group->undo_log.elts;
        uint32_t idx;
        for (n = group->undo_log.nelts; n > 0; n--) {
            idx = logs[n-1].undo_idx;
            ngx_fgroup_bufferset_restore_buffer_locked((ngx_fgroup_bufferset_t *)(&group->bs), logs[n-1].ptr, idx);
            ngx_log_error(NGX_LOG_NOTICE, mycf->conf->log, 0, "file group restore file %V",&((ngx_fgroup_file_node_t *)group->group_files.elts)[idx].name);
        }
        group->undo_log.nelts = 0;
    }

    return -1;
}

#if (NGX_HAVE_FILE_AIO)

static void ngx_fgroup_aio_event_handler(ngx_event_t *ev)
{
    ngx_fgroup_aio_handler_t  *aio_st;

    aio_st = ((ngx_event_aio_t *)ev->data)->data;

    --aio_st->aio_issued;

    if(aio_st->aio_issued > 0) {
        return;
    }
    //aio all done
    int aio = 0;
    int load_all = 1;
    uint32_t i;
    ngx_fgroup_file_group_t *fgroup = (ngx_fgroup_file_group_t *)(aio_st->fgroup);
    
    //update all nodes 
    aio = ngx_fgroup_reload_aio(aio_st->conf, fgroup, NULL, aio_st);

    if(fgroup->error_idx < 0) {
        uint64_t vv = ngx_fgroup_bufferset_inc_version_locked((ngx_fgroup_bufferset_t *)&fgroup->bs);
        ngx_fgroup_bufferset_set_local_version((ngx_fgroup_bufferset_t *)&fgroup->bs, vv);
    }
    else {//reload中发生了错误 
        ((ngx_fgroup_bufferset_t *)fgroup->bs.shm_mem)->set_version &= ~NGX_FGROUP_IN_UPDATE;
        aio = -1;
    }
    fgroup->error_idx = -1;

    //释放老的buffer如果还有的话
    ngx_fgroup_file_undo_log_t *logs;

    logs = fgroup->undo_log.elts;
    size_t n;
    for (n = fgroup->undo_log.nelts; n > 0; n--) {
        ngx_fgroup_shm_free(logs[n-1].ptr);
    }
    fgroup->undo_log.nelts = 0;
    //generally we should have locked group before call ngx_fgroup_reload_aio, 
    //if not this unlock has no sideeffect
    ngx_fgroup_unlock(fgroup);

    if(aio < 0)  {
        aio_st->cb(aio_st->arg, RELOAD_FGROUP_FAIL);
    }
    else { 
        aio_st->cb(aio_st->arg, RELOAD_FGROUP_OK);
    }
}


//conf: current conf 
//fgroup: file group to be reload
//key: name in file group config 
//return value: AIO number issued, 0 means no AIO issued
int ngx_fgroup_reload_aio(void *conf, void *fgroup, ngx_str_t *key, ngx_fgroup_aio_handler_t *aio_st)
{
    ngx_fgroup_conf_t *mycf = (ngx_fgroup_conf_t *)conf;

    ngx_fgroup_file_group_t *group = (ngx_fgroup_file_group_t *)fgroup;
    ssize_t n;
    ngx_fgroup_file_node_t *node = NULL, *node_base, *node_end;
    int aio_num = 0;
    int sync_num = 0;
    ngx_str_t fname;
    
    
    if(key != NULL) {
        node_base = node = ngx_fgroup_file_rbtree_lookup(&mycf->file_tree, &group->group_name, (ngx_str_t *)key);
        if(node == NULL) {
            ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0, "file group reload failed, cannnot find file node \"%V\":\"%V\"", &group->group_name, key);
            goto fail;
        }
        else {
            if(group != (ngx_fgroup_file_group_t *)(mycf->file_groups.elts) + node->group_idx) {
                ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0, "file group reload failed, file group error \"%V\":\"%V\"", &group->group_name, key);
                goto fail;
            }
            node_end = node + 1;
            ngx_log_error(NGX_LOG_DEBUG, mycf->conf->log, 0, "file group found node \"%V\":\"%V\"", &group->group_name, key);
        }
    }
    //key is null, reload all files in the group
    else {
        ngx_fgroup_file_node_t *tmp_node = group->group_files.elts;
        node_base = node = &tmp_node[0];
        node_end = node +  group->group_files.nelts;
    }
    
    //iterate all nodes
    for(; node != node_end; node++) {
        u_char *nbuf = NULL;
        off_t   file_size = 0; 
       
        //if this file has not issued aio, skip 
        if(group->error_idx >= 0 && node->file.fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_DEBUG, mycf->conf->log, 0, "file group \"%V\" has error, ignore node \"%V\"", &group->group_name, &node->name);
            continue;
        }
        
        if(node->file.fd == 0) {
            ngx_log_error(NGX_LOG_DEBUG, mycf->conf->log, 0, "file group file node \"%V\" previously loaded", &node->name);
            node->file.fd = NGX_INVALID_FILE;
            continue;
        }

        if(node->file.fd == NGX_INVALID_FILE) {
            ngx_memzero(&node->file, sizeof(ngx_file_t));

            fname = node->filepath; //must null terminated 

            //absolute path, use it directly
            if(fname.data[0] == '/') { 
                if(node->fullpath.len < fname.len + 1) {//add '\0'
                    node->fullpath.data = ngx_palloc(mycf->conf->pool, fname.len + 1);
                }
                ngx_sprintf(node->fullpath.data,"%V%Z", &fname);
                node->fullpath.len = fname.len;
            }
            else {
                //combine group dir and fname
                if(node->fullpath.len < fname.len + group->group_dir.len + 1 + 1) {//add '/' and '\0'
                    node->fullpath.data = ngx_palloc(mycf->conf->pool, fname.len + group->group_dir.len + 1 + 1);
                }
                ngx_sprintf(node->fullpath.data,"%V/%V%Z", &group->group_dir, &fname);
                node->fullpath.len = fname.len + group->group_dir.len + 1;
            }

            node->file.name = node->fullpath;
            node->file.log = mycf->conf->log;
            //get basic file info
            ngx_fd_t    fd;
            fd = ngx_open_file(node->file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0); 
            if (fd == NGX_INVALID_FILE) {
                ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0, 
                        "file group open() \"%V\" failed",
                        &node->file.name);
                goto fail;
            }

            if (ngx_fd_info(fd, &node->file.info) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0,
                        "file group fstat() \"%V\" failed", &node->file.name);
                ngx_close_file(fd);
                goto fail;
            }

            //create shared memory
            int mid = -1;

            file_size = ngx_file_size(&node->file.info);
            nbuf = ngx_fgroup_shm_new_by_key(node->node.key, file_size, &mid);

            if(nbuf == NULL) {
                ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0,
                        "file group shm_new  \"%V\",%z failed", &node->name, file_size);
                ngx_close_file(fd);
                goto fail;
            }

            ngx_log_error(NGX_LOG_DEBUG, mycf->conf->log, 0,
                    "file group shm_new  \"%V\",%z ok", &node->name, file_size);

            //shm is ready to read file 
            node->file.fd = fd;
        }
        
        if(nbuf == NULL) {
            nbuf = (u_char *)node->file.aio->aiocb.aio_buf;
            file_size =  node->file.aio->aiocb.aio_nbytes;
        }
        
        if(file_size == 0) 
            n = 0;
        else 
            n = ngx_file_aio_read(&node->file, nbuf, file_size, 0, aio_st->pool);
        
        if(n == NGX_AGAIN) {
            aio_num++;
            aio_st->aio_issued = aio_num;
            node->file.aio->data = aio_st;
            node->file.aio->handler = ngx_fgroup_aio_event_handler;
            continue;
        }

        if(n < 0 || n != file_size) {
            //load fail
            ngx_close_file(node->file.fd);
            node->file.fd = NGX_INVALID_FILE; 
            ngx_fgroup_shm_free(nbuf); 
            ngx_log_error(NGX_LOG_ERR, mycf->conf->log, 0,
                    "file group read file aio \"%V\" returned %z bytes instead of %z",
                    &node->file.name, n, file_size);
            goto fail;
        }
        
        //previous has error, ignore
        if(group->error_idx >= 0) {
            ngx_close_file(node->file.fd);
            node->file.fd = NGX_INVALID_FILE;
            ngx_fgroup_shm_free(nbuf);
            continue;
        }
        
        //load ok
        u_char *old = ngx_fgroup_bufferset_set_buffer_locked((ngx_fgroup_bufferset_t *)(&group->bs), nbuf, node->arr_index);
        
        //add to undo log
        ngx_fgroup_file_undo_log_t *u = ngx_array_push(&group->undo_log);
        u->undo_idx = node->arr_index;
        u->ptr = old;

        //read completely, set fd to invalid
        ngx_close_file(node->file.fd);
        node->file.fd = NGX_INVALID_FILE;
        //mark if this is sync readed, avoid duplicate load
        if(node->file.aio == NULL || node->file.aio->res == 0) {
            node->file.fd = 0;
            sync_num++;
        }
        node->file.aio = NULL;
        ngx_log_error(NGX_LOG_DEBUG, mycf->conf->log, 0, "file group reload file %V,name %V ok",&node->file.name,&node->name);
    }

    //no aio issued，set all node's fd to be invalid 
    if(aio_num == 0 && sync_num > 0) {
        for(node=node_base; node != node_end; node++) {
           node->file.fd = NGX_INVALID_FILE; 
        }
    }
    return aio_num;
fail:
    //error occured 
    group->error_idx = node - node_base;
    
    //rollback
    ngx_fgroup_file_undo_log_t *logs;

    logs = group->undo_log.elts;
    uint32_t idx;
    for (n = group->undo_log.nelts; n > 0; n--) {
        idx = logs[n-1].undo_idx;
        ngx_fgroup_bufferset_restore_buffer_locked((ngx_fgroup_bufferset_t *)(&group->bs), logs[n-1].ptr, idx);
        ngx_log_error(NGX_LOG_NOTICE, mycf->conf->log, 0, "file group restore file %V",&((ngx_fgroup_file_node_t *)group->group_files.elts)[idx].name);
    }
    group->undo_log.nelts = 0;
    //previously issued aio, even if error occured, we should take care of it after all aio complete 
    return aio_num?aio_num:-1;
}
#else
int ngx_fgroup_reload_aio(void *conf, void *fgroup, ngx_str_t *key, ngx_fgroup_aio_handler_t *aio_st)
{
    return ngx_fgroup_reload(conf, fgroup, key);
}
#endif

void ngx_fgroup_worker_init(void *conf)
{
    ngx_fgroup_conf_t *mycf = (ngx_fgroup_conf_t *)conf;
    ngx_fgroup_file_group_t *groups;

    groups = mycf->file_groups.elts;
    size_t n,i;
    for (n = 0; n < mycf->file_groups.nelts; n++) {
        u_char **key = groups[n].bs.ptrs.elts;
        ngx_fgroup_shm_bufferset_t *bs_sh = (ngx_fgroup_shm_bufferset_t *)groups[n].bs.shm_mem;

        if(groups[n].group_files.nelts == 0)
            continue;
        //one timer per file group  
        ngx_fgroup_add_timer(ngx_fgroup_checker, (void *)(&groups[n]), 1, mycf);

        if(groups[n].bs.set_version > 0)
            continue;

        //avoid other instance is accessing the metadata
        ngx_fgroup_lock(&groups[n]);

        //last update not finished, error occured, we need full reload
        if(bs_sh->set_version & NGX_FGROUP_IN_UPDATE) {
            goto full_reload;
        }

        for (i = 0; i < groups[n].bs.ptrs.nelts; i++) {
            if(key[i] != NULL)
            {
                continue;
            }
            u_char *p = ngx_fgroup_shm_get_by_id(bs_sh->buffer_version[i].buf_id);
            if (p == NULL || ngx_fgroup_shm_get_header(p)->key != bs_sh->buffer_version[i].buf_key) {
                ngx_fgroup_shm_free(p);
                goto full_reload;
            }
            else {
                key[i] = p;
            }
        }
        groups[n].bs.set_version = bs_sh->set_version;
        ngx_fgroup_unlock(&groups[n]);
        continue;
full_reload:
        bs_sh->set_version |= NGX_FGROUP_IN_UPDATE;
        bs_sh->updated_idx = 0;
        if(ngx_fgroup_reload(conf, &groups[n], NULL) == 0) {
            uint64_t vv = ngx_fgroup_bufferset_inc_version_locked((ngx_fgroup_bufferset_t *)&groups[n].bs);
            ngx_fgroup_bufferset_set_local_version((ngx_fgroup_bufferset_t *)&groups[n].bs, vv);
        }
        else {
            ngx_log_error(NGX_LOG_ALERT, mycf->conf->log, 0, "worker init file group \"%V\" reload failed", &groups[n].group_name);
        }

        ngx_fgroup_file_undo_log_t *logs;

        logs = groups[n].undo_log.elts;
        for (n = groups[n].undo_log.nelts; n > 0; n--) {
            ngx_fgroup_shm_free(logs[n-1].ptr);
        }
        groups[n].undo_log.nelts = 0;

        ngx_fgroup_unlock(&groups[n]);
    }
}
