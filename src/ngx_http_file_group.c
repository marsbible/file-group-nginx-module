#include <assert.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include "ngx_file_group_module_internal.h"

/* batch reload of several files, support transaction */
/* args is argument array of ngx_str_t */
ngx_int_t ngx_fgroup_batch_reload(ngx_str_t *group_name, ngx_array_t *args, ngx_fgroup_reload_aio_cb cb, void *arg, ngx_pool_t *pool)
{
    ngx_str_t *elems;
    void *group;
    ngx_fgroup_conf_t *conf = fgroup_get_cur_conf();    

    group = ngx_fgroup_get_group(conf, group_name);

    if(group == NULL) {
        return RELOAD_FGROUP_FAIL; 
    }
     
    //group under reload，client need to retry later 
    if(!ngx_fgroup_trylock(group)) {
        return RELOAD_FGROUP_BUSY;
    }
    
    uint64_t g_v;
    ngx_fgroup_file_group_t *fgroup = (ngx_fgroup_file_group_t *)group;
    ngx_fgroup_bufferset_get_changed((ngx_fgroup_bufferset_t *)(&fgroup->bs), &g_v);
    ngx_fgroup_shm_bufferset_t *bs_sh = (ngx_fgroup_shm_bufferset_t *)fgroup->bs.shm_mem;
    
    //inconsistent, need recover
    if(g_v & NGX_FGROUP_IN_UPDATE) {
        g_v &= ~NGX_FGROUP_IN_UPDATE;
        //cannot rollback to local version，do full-reload later
        if(g_v != fgroup->bs.set_version) {
            //full reload
            bs_sh->updated_idx = 0;
        }
    }
    //global version larger than local version, cannot reload until synced
    else if(g_v > fgroup->bs.set_version) {
        ngx_fgroup_unlock(group);
        return RELOAD_FGROUP_BUSY;
    }
    
    uint32_t i,j;
    ngx_fgroup_shm_header_t *h;
    u_char **key = fgroup->bs.ptrs.elts; 
    
    if(g_v == fgroup->bs.set_version) {
        //same version, need to check update list
        for (i = bs_sh->updated_idx; i != 0; i = bs_sh->buffer_version[i-1].next_elem) {
            j = i-1;
            h = (ngx_fgroup_shm_header_t *)(key[j] - sizeof(ngx_fgroup_shm_header_t));
            //buffer no change
            if(key[j] == NULL || h->id == bs_sh->buffer_version[j].buf_id )
                continue;
            bs_sh->buffer_version[j].buf_id = h->id;
        }
        bs_sh->updated_idx = 0;
    }

    //begin reload
    int aio = 0;
    int load_all = 1;
    ngx_str_t *str_arg = args->elts;
    
    ngx_fgroup_aio_handler_t *aio_st = NULL;
    
#if (NGX_HAVE_FILE_AIO)
    if(cb != NULL) {
        aio_st = ngx_palloc(pool, sizeof(ngx_fgroup_aio_handler_t));
        aio_st->aio_issued = 0;
        aio_st->cb = cb;
        aio_st->arg = arg;
        aio_st->fgroup = fgroup;
        aio_st->conf = conf; 
        aio_st->pool = pool;
    }
#endif

    //mark updating
    bs_sh->set_version = bs_sh->set_version | NGX_FGROUP_IN_UPDATE;

    for(i=0; i<args->nelts; i++) {
        if(str_arg[i].len > 0) {
            int ret = ngx_fgroup_reload_aio(conf, group, &str_arg[i], aio_st);
            load_all = 0;
            if(ret < 0) {
                aio = -1;
                break;
            }
            aio += ret;
        }
    }
    
    if(load_all) {
        aio = ngx_fgroup_reload_aio(conf, group, NULL, aio_st);
    }
    
    if(aio > 0) {
        return RELOAD_FGROUP_AGAIN;    
    }
    
    if(aio == 0) {
        uint64_t vv = ngx_fgroup_bufferset_inc_version_locked((ngx_fgroup_bufferset_t *)&fgroup->bs);
        ngx_fgroup_bufferset_set_local_version((ngx_fgroup_bufferset_t *)&fgroup->bs, vv);
    }
    else {
        //rollback done, restore version number
        bs_sh->set_version &= ~NGX_FGROUP_IN_UPDATE;  
    }
    //free old bufferset if any
    ngx_fgroup_file_undo_log_t *logs;

    logs = fgroup->undo_log.elts;
    size_t n;
    for (n = fgroup->undo_log.nelts; n > 0; n--) {
        ngx_fgroup_shm_free(logs[n-1].ptr);
    }
    fgroup->undo_log.nelts = 0;
    fgroup->error_idx = -1;
    ngx_fgroup_unlock(group);
    
    if(aio < 0) {
        return RELOAD_FGROUP_FAIL; 
    }
     
    return RELOAD_FGROUP_OK;
}
