#!/bin/bash

#nginx patch to support init_master() callback 


ngx_process_cycle_patch=`grep 'nginx_version' '../../src/core/nginx.h' | awk -F' ' '{if($3>=1007004) print "ngx_process_cycle.c.patch"; else print "ngx_process_cycle.c.patch.old"; }'`

cd ../../
patch -p0 < file-group-nginx-module/patch/$ngx_process_cycle_patch
patch -p0 < file-group-nginx-module/patch/ngx_conf_file.h.patch

