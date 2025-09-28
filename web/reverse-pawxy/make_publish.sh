#!/bin/sh

cp ./src/supervisord.conf supervisord.conf.bak
sed -i 's/skbdg{.*}/skbdg{test_flag}/' ./src/supervisord.conf
zip -r publish/reverse-pawxy.zip src/
mv supervisord.conf.bak src/supervisord.conf
