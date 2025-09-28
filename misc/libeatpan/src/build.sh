#!/bin/sh

apt update -y && apt install git -y build-essential autoconf libtool m4 pkgconf patchelf
git clone https://github.com/dinhvh/libetpan.git
cd libetpan
sed -i '112s|/Users/hoa/tmp|/tmp|' tests/pgp.c
./autogen.sh
make -j8
cd ..
cp libetpan/src/.libs/libetpan.so.20.5.0 libetpan.so.20
cp libetpan/tests/.libs/pgp .
patchelf --set-rpath . pgp
rm -rf libetpan
