#!/bin/sh

cp ./src/flag.txt flag.txt.bak
echo 'skbdg{testflag}' > ./src/flag.txt
tar cvfz publish/libeatpan.tar.gz --transform 's|^src|libeatpan|' src/ 
mv flag.txt.bak ./src/flag.txt
