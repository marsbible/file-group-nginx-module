#!/bin/bash

CFLAGS="-Werror -g -O2 -I./pcre-8.35" \
./configure  --with-file-aio \
             --with-pcre=./pcre-8.35 \
	         --add-module=./file-group-nginx-module/ \
             --with-http_ssl_module --with-http_spdy_module --with-http_addition_module \
             --http-client-body-temp-path=temp_dir/client-body-temp \
             --http-proxy-temp-path=temp_dir/proxy-temp \
             --http-fastcgi-temp-path=temp_dir/fastcgi-temp \
             --http-uwsgi-temp-path=temp_dir/uwsgi-temp \
             --http-scgi-temp-path=temp_dir/scgi-temp \
