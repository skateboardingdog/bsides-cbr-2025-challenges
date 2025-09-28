#!/bin/sh

cp ./src/Dockerfile Dockerfile.bak
sed -i 's/skbdg{.*}/skbdg{test_flag}/' ./src/Dockerfile
zip -r publish/logbook.zip src/
mv Dockerfile.bak src/Dockerfile
