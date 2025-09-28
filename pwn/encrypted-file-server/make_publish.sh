#!/bin/sh

cp ./src/flag.txt flag.txt.bak
cp ./src/server_key.bin server_key.bin.bak
mv ./src/Makefile Makefile.bak
echo 'skbdg{testflag}' > ./src/flag.txt
echo -n 'fakekey_fakekey!' > ./src/server_key.bin
tar cvfz publish/encrypted-file-server.tar.gz --transform 's|^src|encrypted-file-server|' src/
mv flag.txt.bak ./src/flag.txt
mv server_key.bin.bak ./src/server_key.bin
mv Makefile.bak ./src/Makefile
