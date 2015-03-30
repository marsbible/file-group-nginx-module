# file-group-nginx-module
a nginx module can manage files in shared memory, support file group and online update,currently only support Linux.

# How to add this module to nginx?
1. put the module to nginx source root directory,e.g. /home/foo/nginx-1.7.0/

2. cd file-group-nginx-module/patch && ./patch.sh 

3. add "--add-module=./file-group-nginx-module/" to configure option,add "--with-file-aio" to configurre option if your want to use native file AIO

4. ./configure ... && make

# How to use this module?
1. Add "include file_groups.conf;" to nginx.conf at top level

2. Create file_groups.conf and add file-group configuration to it, keyword "file_group" with a name to create a file group,
   no name means the unique default group, keyword "group_dir" to set the default directory of a group.

   Other config line is free to define with a form "file_key file_name", within which file_key identify a file's key and file_name identify a file's 
   actual name,group_name+file_key must be unique. 
   
   a sample is like this:
```
   file_group {
   
       group_dir /home/foot/dict;
       
   }

   file_group test {
   
       group_dir /home/foo/dict;
       
       file1 file1.dat;
       
       file2 file2.dat;
       
   }
```   
3. 
   change your own module's config, e.g. 
       NGX_ADDON_DEPS="$NGX_ADDON_DEPS \
                       $ngx_addon_dir/../file-group-nginx-module/src/ngx_file_group_module.h"

       HTTP_INCS="$HTTP_INCS \
                  $ngx_addon_dir/../file-group-nginx-module/src" 


   add "extern ngx_module_t ngx_fgroup_module;" to your own module code
   
   get the file content when your need, e.g.
```
   
       ngx_str_t group_name = ngx_string("test");
       
       ngx_str_t file_name = ngx_string("file1");
       
       ngx_str_t res = ngx_fgroup_get_file(fgroup_get_cur_conf(), &group_name, &file_name);
       
       //res refer to the content of file1, do something with res1... 
```       

# How to online reload files
  a typical way is to add a http handler and bind it to a specific URL, then in the http handler,
  you can call the reload function when you got arguments ready,the interface is as below:
       
  ngx_int_t ngx_fgroup_batch_reload(ngx_str_t *group_name, ngx_array_t *args, ngx_fgroup_reload_aio_cb cb, void *arg, ngx_pool_t *pool);
  
  group_name is the file group you want to reload, args is an array of file keys you want to reload, if no file key if specified, all files of the group will be reloaded.
  
  The last 3 arguments is file AIO related, if you won't use AIO, just pass all these 3 arguments as NULL, otherwise cb is the callback 
  which will be called when AIO is done, arg is its argument,pool is temporary memory pool for internal use.
  
  In the typical way, cb is a callback which construct a response and send back to client, arg is the ngx_http_request_t processing the reload request, pool is the memory pool 
  of ngx_http_request_t so that is will be auto destroyed when request is finished.
  
  
  NOTICE:
  when reload in AIO mode, the caller is responsible to make sure the 3 AIO arguments will not be destroyed until AIO is done.In the typical way(process reload in a http handler), we should increase the referrence counter of ngx_http_request_t and set aio to 1 when aio issued,e.g.   
```  
     if(ret == RELOAD_FGROUP_AGAIN) {
     
        r->main->blocked++;
        
        r->aio = 1;
        
     }
```     
  and restore it at the end of ngx_fgroup_reload_aio_cb,e.g.
``` 
     if(aio_st->aio_issued) {
     
       r->main->blocked--;
       
       r->aio = 0;
       
     } 
```     

# Limitations
  This module is highly rely on Linux and doesn't have a plan to support other platforms.
  This module only support multi-process mode of nginx, doesn't support multi-thread.
  The module has a patch to add init_master callback, though it's simple and has no sideeffect to other functions,
  it should be noticed.
