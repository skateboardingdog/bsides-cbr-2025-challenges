server:
	gcc server.c -o server

client:
	gcc client.c -lcurses -o client

all: client server

publish:
	mv flag.txt flag.txt.bak
	echo 'skbdg{test_flag}' > flag.txt
	tar chvfz chatroom2.tar.gz client server client.c server.c chatroom.h Dockerfile flag.txt
	mv flag.txt.bak flag.txt

clean:
	rm -f client server
