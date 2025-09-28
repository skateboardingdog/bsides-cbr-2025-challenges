#!/bin/sh

ln -s ../src/uppawcase.py publish/uppawcase.py
cp src/Dockerfile publish/Dockerfile
sed -i 's/skbdg{.*}/skbdg{testflag}/' ./publish/Dockerfile
