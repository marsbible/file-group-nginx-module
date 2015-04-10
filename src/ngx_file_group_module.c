#include <ngx_config.h>
#include <ngx_core.h>
#include <libgen.h>
#include "ngx_file_group_module_internal.h"

#define FILE_META_SHM_NAME "/_fgroup_file_meta_"
#define NULL_FILE_GROUP_ID 0xFFFFFFFF 

static void *file_meta_shm = NULL;
static size_t file_meta_size = 0;
static char meta_name[sizeof(FILE_META_SHM_NAME)+16];

typedef struct {
    ngx_fgroup_conf_t *conf; 
    ngx_fgroup_file_group_t *group;
}file_parse_arg_t;

static char * ngx_fgroup_group_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_fgroup_module_init(ngx_cycle_t *cycle);
static ngx_int_t worker_init(ngx_cycle_t *cycle);
static ngx_int_t  master_init(ngx_cycle_t *cycle);
static void  master_exit(ngx_cycle_t *cycle);

static ngx_command_t  ngx_conf_commands[] = {
   { ngx_string("file_group"),
        NGX_ANY_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
        ngx_fgroup_group_conf,
        0,
        0,
        NULL },
    ngx_null_command
};

ngx_module_t  ngx_fgroup_module = {
    NGX_MODULE_V1,
    NULL,                                  /* module context */
    ngx_conf_commands,                     /* module directives */
    NGX_CONF_MODULE,                       /* module type */
    master_init,                           /* init master */
    ngx_fgroup_module_init,                /* init module */
    worker_init,                           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    master_exit,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static int fgroup_str_cmp(ngx_str_t *s1, const char *s2, size_t s2_len)
{
    if(s1->len != s2_len) return s1->len - s2_len;
    return ngx_strncmp(s1->data, (u_char *)s2, s2_len);
}

/* murmurhash2a, by Austin Appleby */
#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }
static const unsigned int m = 0x5bd1e995;
static const int r = 24;

void murmurhash2a_begin(murmurhash2a_t *mmh,unsigned int seed)
{
    mmh->m_hash  = seed;
    mmh->m_tail  = 0;
    mmh->m_count = 0;
    mmh->m_size  = 0;
}

void murmurhash2a_add(murmurhash2a_t *mmh, u_char *data, size_t len)
{
    mmh->m_size += len;

    while( len && ((len<4) || mmh->m_count) )
    {
        mmh->m_tail |= (*data++) << (mmh->m_count * 8);

        mmh->m_count++;
        len--;

        if(mmh->m_count == 4)
        {
            mmix(mmh->m_hash,mmh->m_tail);
            mmh->m_tail = 0;
            mmh->m_count = 0;
        }
    }

    while(len >= 4)
    {
        unsigned int k = *(unsigned int*)data;

        mmix(mmh->m_hash,k);

        data += 4;
        len -= 4;
    }

    while( len && ((len<4) || mmh->m_count) )
    {
        mmh->m_tail |= (*data++) << (mmh->m_count * 8);

        mmh->m_count++;
        len--;

        if(mmh->m_count == 4)
        {
            mmix(mmh->m_hash,mmh->m_tail);
            mmh->m_tail = 0;
            mmh->m_count = 0;
        }
    }
}

unsigned int murmurhash2a_end(murmurhash2a_t *mmh)
{
    mmix(mmh->m_hash,mmh->m_tail);
    mmix(mmh->m_hash,mmh->m_size);

    mmh->m_hash ^= mmh->m_hash >> 13;
    mmh->m_hash *= m;
    mmh->m_hash ^= mmh->m_hash >> 15;

    return mmh->m_hash;
}


ngx_fgroup_file_node_t *
ngx_fgroup_file_rbtree_lookup(ngx_rbtree_t *rbtree, ngx_str_t *group_name, ngx_str_t *file_name)
{
    ngx_fgroup_file_node_t     *n;
    ngx_rbtree_node_t  *node, *sentinel;
    uint32_t hash;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    murmurhash2a_t mmh;
    murmurhash2a_begin(&mmh, 0);
    murmurhash2a_add(&mmh, group_name->data, group_name->len);
    murmurhash2a_add(&mmh, file_name->data, file_name->len);
    hash = murmurhash2a_end(&mmh);

    while (node != sentinel) {

        n = (ngx_fgroup_file_node_t *) node;

        if (hash != node->key) {
            node = (hash < node->key) ? node->left : node->right;
            continue;
        }

        return n;
    }

    return NULL;
}

static char *
ngx_fgroup_file_conf(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    file_parse_arg_t *t = (file_parse_arg_t *)conf;
    ngx_fgroup_conf_t *clcf = t->conf;
    ngx_fgroup_file_group_t *group = t->group;
    static ngx_str_t dir_token = ngx_string("group_dir");


    ngx_str_t       *value;
    ngx_uint_t       hash;
    ngx_fgroup_file_node_t  *key;
    value = cf->args->elts;

    if(cf->args->nelts != 2) {
        return NGX_CONF_ERROR;
    }

    if(fgroup_str_cmp((ngx_str_t *)(&dir_token), (char *)value[0].data, value[0].len) == 0) {
        group->group_dir = value[1];
        return NGX_CONF_OK;
    }

    //calc hash of group name+file name
    murmurhash2a_t mmh;
    murmurhash2a_begin(&mmh, 0);
    murmurhash2a_add(&mmh, group->group_name.data, group->group_name.len);
    murmurhash2a_add(&mmh, value[0].data, value[0].len);
    hash = murmurhash2a_end(&mmh);

    key = ngx_fgroup_file_rbtree_lookup(&clcf->file_tree, &group->group_name, &value[0]);

    if(key != NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "duplicate ipc key \"%uD\", "
                "ipc key name: \"%V\", "
                "previous ipc key name: \"%V\"",
                hash, &value[0], &key->name);
        return NGX_CONF_ERROR;
    }

    key = ngx_array_push(&group->group_files);
    if (key == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_fgroup_file_group_t *groups = clcf->file_groups.elts;


    key->node.key = hash;
    key->group_idx = group - groups;
    key->name = value[0];
    key->filepath = value[1];
    ngx_str_null(&key->fullpath);
    key->arr_index = group->group_files.nelts - 1;
    ngx_memzero(&key->file, sizeof(ngx_file_t));
    key->file.fd = NGX_INVALID_FILE;

    ngx_rbtree_insert(&clcf->file_tree, &key->node);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_fgroup_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t            *shpool;
    ngx_fgroup_file_group_t      *ctx;

    ctx = shm_zone->data;

    if (data) {
         return NGX_ERROR;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {

        return NGX_ERROR;
    }

    ctx->shpool = shpool;

    ngx_sprintf(shpool->log_ctx, " in fgroup shared memory \"%V\"%Z",
            &shm_zone->shm.name);

    return NGX_OK;
}

static char *
ngx_fgroup_group_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char        *rv;
    ngx_conf_t   save;
    ngx_str_t       *value;
    ngx_str_t       group_name = ngx_string("");
   
    ngx_fgroup_conf_t *clcf;

    /* the main mail context */
    if(*(ngx_fgroup_conf_t **)conf  == NULL) {
        clcf = ngx_pcalloc(cf->pool, sizeof(ngx_fgroup_conf_t));
        if (clcf == NULL) {
            return NGX_CONF_ERROR;
        }

        *(ngx_fgroup_conf_t **)conf = clcf;
    }
    else {
        clcf = *(ngx_fgroup_conf_t **)conf;
    }

    value = cf->args->elts;

    if(cf->args->nelts == 2) {
        group_name = value[1];
    }

    ngx_fgroup_file_group_t *groups;
    ngx_fgroup_file_group_t *group;
    size_t n;
    uint32_t hash;

    murmurhash2a_t mmh;
    murmurhash2a_begin(&mmh, 0);
    murmurhash2a_add(&mmh, group_name.data, group_name.len);
    hash = murmurhash2a_end(&mmh);

    groups = clcf->file_groups.elts;
    
    if(groups == NULL) {
        //file group init
        if (ngx_array_init(&clcf->file_groups, cf->pool, 8,
                    sizeof(ngx_fgroup_file_group_t))
                != NGX_OK)
        {
            return NULL;
        }
        ngx_rbtree_init(&clcf->file_tree, &clcf->file_tree_sentinel, ngx_rbtree_insert_value);
        clcf->conf = cf->cycle;
        groups = clcf->file_groups.elts;
    } 

    if(hash == NULL_FILE_GROUP_ID) {
        return "invalid group id";
    }

    //valid group id cannot be 0
    if(hash == 0) hash = NULL_FILE_GROUP_ID;

    for (n = 0; n < clcf->file_groups.nelts; n++) {
        if(hash == groups[n].group_id &&
          !(fgroup_str_cmp(&groups[n].group_name, (char *)group_name.data, group_name.len) == 0))
            break;
    }

    //same id with different name, hash conflict occurs
    if(n < clcf->file_groups.nelts) {
        return "group id conflict";
    }

    for (n = 0; n < clcf->file_groups.nelts; n++) {
        if(fgroup_str_cmp(&groups[n].group_name, (char *)group_name.data, group_name.len) == 0)
            break;
    }

    //cannot find,add group
    if(n == clcf->file_groups.nelts) {
        group = ngx_array_push(&clcf->file_groups);
        if(group == NULL)
            return "file_group push error";
        group->group_name = group_name;
        group->group_id = hash;
        group->error_idx = -1;
        ngx_str_set(&group->group_dir, "");
        if (ngx_array_init(&group->group_files, cf->pool, 8,
                           sizeof(ngx_fgroup_file_node_t))
            != NGX_OK)
        {
            return "group_files init error";
        }

        if (ngx_array_init(&group->undo_log, cf->pool, 8,
                    sizeof(ngx_fgroup_file_undo_log_t))
                != NGX_OK)
        {
            return "undo_log init error";
        }

        ngx_memzero(&group->bs, sizeof(ngx_fgroup_bufferset_internal_t));

        //alloc a slab for each group to utilize the mutex of slab as group lock, 
        //nginx could automatically sanitize inconsistent slab mutex of exited worker process 
        group->shm_zone = ngx_shared_memory_add(cf, &group_name, 1024, group);

        if (group->shm_zone == NULL) {
            return NGX_CONF_ERROR;
        }

        if (group->shm_zone->data) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "duplicate zone \"%V\"", &group_name);
            return NGX_CONF_ERROR;
        }

        group->shm_zone->init = ngx_fgroup_init_zone;
        group->shm_zone->data = group;
    }
    else {
        group = &groups[n];
    }

    file_parse_arg_t t = {clcf, group};
    save = *cf;
    cf->handler = ngx_fgroup_file_conf;
    cf->handler_conf = (void *)&t;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}

static ngx_cycle_t *cur_cycle;
static ngx_int_t worker_init(ngx_cycle_t *cycle)
{
    ngx_fgroup_conf_t    *mycf;
    
    mycf = (ngx_fgroup_conf_t *)ngx_get_conf(cycle->conf_ctx, ngx_fgroup_module);

    ngx_fgroup_worker_init((void *)mycf);      
    
    cur_cycle = cycle;
    return NGX_OK;
}

ngx_fgroup_conf_t *fgroup_get_cur_conf()
{
    ngx_fgroup_conf_t    *mycf;
    mycf = (ngx_fgroup_conf_t *)ngx_get_conf(cur_cycle->conf_ctx, ngx_fgroup_module);
    
    return mycf;
}


static ngx_int_t  master_init(ngx_cycle_t *cycle)
{
    ngx_uint_t j,k;
    ngx_array_t *arr;
    ngx_fgroup_conf_t    *mycf;

    mycf = (ngx_fgroup_conf_t *)ngx_get_conf(cycle->conf_ctx, ngx_fgroup_module);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
            "file group init_master called");

    ngx_fgroup_file_group_t *groups = mycf->file_groups.elts;
    for (j = 0; j < mycf->file_groups.nelts; j++) {
        arr = &groups[j].bs.ptrs;
        for(k=0; k<arr->nelts; k++) {
            if(((u_char **)arr->elts)[k] != NULL)
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                        "file group init_master free %xL", ((u_char **)arr->elts)[k]);
            ngx_fgroup_shm_free(((u_char **)arr->elts)[k]);
            ((u_char **)arr->elts)[k] = NULL;
        }
        groups[j].bs.set_version = 0;
    }
    return NGX_OK;
}

static void  master_exit(ngx_cycle_t *cycle)
{
    if(shm_unlink(meta_name) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                "shm_unlink \"%s\" failed", meta_name);
    }
}

static ngx_int_t ngx_fgroup_module_init(ngx_cycle_t *cycle)
{
    ngx_fgroup_conf_t    *mycf;
    ngx_fgroup_file_group_t *groups;
    size_t m;
    size_t n=0;
    uint32_t size = sizeof(ngx_fgroup_shm_bufferset_t); //dummy st at the end to indicate ending 
    

    mycf = (ngx_fgroup_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_fgroup_module);
    groups = mycf->file_groups.elts;
    for (n = 0; n < mycf->file_groups.nelts; n++) {
        size += sizeof(ngx_fgroup_shm_bufferset_t) + groups[n].group_files.nelts*sizeof(ngx_fgroup_shm_buffer_version_t);
    }

    u_char *old_meta = NULL;
    char exec_name[PATH_MAX];

    //add directory info to distinguish multiple instance on a single machine
    ssize_t len = readlink("/proc/self/exe", exec_name, PATH_MAX);
    if(len > 0) {
        uint32_t mhash;
        u_char *dir_name;
        exec_name[len] = '\0';
        dir_name = (u_char *)dirname(exec_name);
        mhash = ngx_murmur_hash2((u_char *)dir_name, ngx_strlen(dir_name));
        dir_name = ngx_sprintf((u_char *)meta_name, "%s", FILE_META_SHM_NAME);
        dir_name = ngx_hex_dump(dir_name, (u_char *)(&mhash), sizeof(uint32_t));
        *dir_name = '\0';
    }

    //try to use old metadata 
    if(file_meta_shm != NULL) {
        //old_meta = ngx_palloc(cycle->pool, file_meta_size);
        old_meta = malloc(file_meta_size);
    if(old_meta == NULL)  {
            return NGX_ERROR;
        }
        ngx_memcpy(old_meta, file_meta_shm, file_meta_size);

        if(shm_unlink(meta_name) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                    "shm_unlink \"%s\" failed", meta_name);
        }

        if(munmap((void*)file_meta_shm, file_meta_size) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                    "munmap \"%s\" failed", meta_name);
        }
        file_meta_shm = NULL;
    }

    //init metadata in shm 
    int fd = shm_open(meta_name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if(fd == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                "failed shm_open \"%s\"", meta_name);
        return NGX_ERROR;
    }

    ngx_file_info_t fi;
    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                ngx_fd_info_n " \"%s\" failed", meta_name);
        return NGX_ERROR;
    }

    //has metadata in another instance, try to use it 
    if((size_t)ngx_file_size(&fi) > 0) {
        u_char *tmp  = (u_char *)mmap(NULL, (size_t)ngx_file_size(&fi), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if(tmp != MAP_FAILED) {
            old_meta = tmp;
            if(-1 == shm_unlink(meta_name))
            {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                        "shm_unlink other fgroup_file_meta failed");
            }
            fd = shm_open(meta_name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
            if(fd == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                        "failed shm_open2 fgroup_file_meta");
                return NGX_ERROR;
            }
        }
    }

    if(ftruncate(fd, size) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                "failed ftruncate fgroup_file_meta %z", size);
        return NGX_ERROR;
    }

    file_meta_shm = (u_char *)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if(file_meta_shm == MAP_FAILED)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                "mmap fgroup_file_meta failed %z", size);
        return NGX_ERROR;
    }
    file_meta_size = size;
    u_char *pos = file_meta_shm;

    for (n = 0; n < mycf->file_groups.nelts; n++) {
        ngx_fgroup_shm_bufferset_t *t = NULL;
        ngx_fgroup_shm_bufferset_t *bst = (ngx_fgroup_shm_bufferset_t *)pos;
        ngx_fgroup_bufferset_init((ngx_fgroup_bufferset_t *)(&groups[n].bs), (void *)pos, groups[n].group_files.nelts, mycf);

        //change mutex's internal flag to shared meta data so that it can take effect to all processes attached the shared meta data 
        groups[n].shpool->mutex.lock = &bst->lock.lock;

        if(old_meta) {
            t = (ngx_fgroup_shm_bufferset_t *)old_meta;
            for(; t->group_id != 0; ) {
                if(t->group_id == groups[n].group_id) {
                    break;
                }
                t = (ngx_fgroup_shm_bufferset_t *)((u_char *)t + sizeof(ngx_fgroup_shm_bufferset_t) + t->elem_num*sizeof(ngx_fgroup_shm_buffer_version_t));
            }
            if(t->group_id == 0) t = NULL;
        }

        ngx_fgroup_file_node_t *ft =  groups[n].group_files.elts;
        size_t end;
        void *ated;
        ngx_shmtx_t mutex;
        ngx_memzero(&mutex, sizeof(ngx_shmtx_t));

        if(t == NULL)
            end=0;
        else {
            end = t->elem_num;
            end = ngx_min(end, groups[n].group_files.nelts);

            mutex.lock = &t->lock.lock;
            mutex.spin = 2048;

            int i = 0;
            while(!ngx_shmtx_trylock(&mutex)) {
                i++;
                if(i > 200) break;
                ngx_msleep(10);
            }

            //cannot lock after 2s，consider old_meta is abnormal，give up
            if(i > 200) {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "lock old fgroup %V failed in 2s", &groups[n].group_name);
                end = 0;
            }
            else if(t->set_version & NGX_FGROUP_IN_UPDATE) {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "lock old fgroup %V ok but it is not consistent", &groups[n].group_name);
                ngx_shmtx_unlock(&mutex);
                end = 0;
            }
            else
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "lock old fgroup %V ok, %z elems", &groups[n].group_name, end);
        }

        //copy old_meta
        for (m=0; m<end; m++) {
            //init buf_key
            bst->buffer_version[m].buf_key = ft[m].node.key;
            bst->buffer_version[m].buf_id = -1;
            //if key doesn't match，or buffer invalid, consider old_meta is abnormal 
            if(t->buffer_version[m].buf_key != ft[m].node.key || t->buffer_version[m].buf_id == -1)
                break;
            ated = ngx_fgroup_shm_get_by_id(t->buffer_version[m].buf_id);
            //invalid shm
            if(ated == NULL)
                break;

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "get %V from existed shared memorys", &ft[m].name);
            ((void **)groups[n].bs.ptrs.elts)[m] = ated;
            bst->buffer_version[m].buf_id = t->buffer_version[m].buf_id;
        }

        //cannot reuse, reload others from file 
        for(; m < groups[n].group_files.nelts; m++) {
            bst->buffer_version[m].buf_key = ft[m].node.key;
            bst->buffer_version[m].buf_id = -1;
            if(ngx_fgroup_reload(mycf, &groups[n], &ft[m].name) < 0)
                break;
        }

        //error occurs
        if(m < groups[n].group_files.nelts) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "file group reload %V failed", &ft[m].name);
            if(end) ngx_shmtx_unlock(&mutex);
            return NGX_ERROR;
        }
        groups[n].undo_log.nelts = 0;
        bst->group_id = groups[n].group_id;
        uint64_t vv = ngx_fgroup_bufferset_inc_version_locked((ngx_fgroup_bufferset_t *)&groups[n].bs);
        ngx_fgroup_bufferset_set_local_version((ngx_fgroup_bufferset_t *)&groups[n].bs, vv);

        if(end) ngx_shmtx_unlock(&mutex);

        pos += sizeof(ngx_fgroup_shm_bufferset_t) + groups[n].group_files.nelts*sizeof(ngx_fgroup_shm_buffer_version_t);
    }
    return NGX_OK;
}
