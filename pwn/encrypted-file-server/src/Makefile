all:
	gcc chall.c -o chall -lcrypto -g
	patchelf --set-rpath . --set-interpreter ./ld-2.35.so chall
