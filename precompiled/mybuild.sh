#! /bin/sh

# demo  由于意外， 我的编译脚本丢失了，而且也没有备份
# 导致现在的编译命令应该并不好用， 但是我也不想再去重新研究了， 以后再说吧
# 可以在使用的过程中，逐渐完善这个脚本
emcc openssl_func.c others.c -I ./include -L ./libs -lcrypto \
-s WASM=1 \
# -s MODULARIZE=1 \ # 这个好像不好用
-s EXPORTED_FUNCTIONS="['_malloc', '_free']"  \
-s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap", "ccall"]' \
-s ALLOW_MEMORY_GROWTH=1 \
-o openssl_func.js
