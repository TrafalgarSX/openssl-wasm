#! /bin/sh

NPROCESSORS=$(getconf NPROCESSORS_ONLN 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)

cd openssl || exit 1

# env \
#     CROSS_COMPILE="" \
#     AR="zig ar" \
#     RANLIB="zig ranlib" \
#     CC="zig cc --target=wasm32-wasi" \
#     CFLAGS="-Ofast" \
#     CPPFLAGS="-DUSE_TIMEGM=1 -Dgetpid=getpagesize -Dgetuid=getpagesize -Dgeteuid=getpagesize -Dgetgid=getpagesize -Dgetegid=getpagesize" \
#     LDFLAGS="-s" \
#     ./Configure \
#     --banner="wasm32-wasi port" \
#     no-asm \
#     no-async \
#     no-egd \
#     no-ktls \
#     no-module \
#     no-posix-io \
#     no-secure-memory \
#     no-shared \
#     no-sock \
#     no-stdio \
#     no-thread-pool \
#     no-threads \
#     no-ui-console \
#     no-weak-ssl-ciphers || exit 1

# wasiconfigure ./Configure gcc -no-sock -no-ui-console -DHAVE_FORK=0 -D_WASI_EMULATED_MMAN -D_WASI_EMULATED_SIGNAL -DOPENSSL_NO_SECURE_MEMORY -DNO_SYSLOG --with-rand-seed=getrandom

# linux-generic64 linux-x32
# demo  由于意外， 我的编译脚本丢失了，而且也没有备份
emconfigure ./Configure linux-x32 -no-asm -no-sock


emmake make "-j${NPROCESSORS}"
# emmake make -j 12 build_generated libssl.a libcrypto.a

cd - || exit 1

mkdir -p precompiled/lib
mv openssl/*.a precompiled/lib

mkdir -p precompiled/include
cp -r openssl/include/openssl precompiled/include
