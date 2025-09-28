server:
	gcc server.c -o server

client: 	
	gcc client.c -lcurses -lssl -lcrypto -o client


all: client server

publish:
	cp run_bots.py run_bots.py.bak
	sed -i 's/skbdg{.*}/skbdg{test_flag}/g' run_bots.py
	tar chvfz chatroom1.tar.gz client server client.c server.c chatroom.h Dockerfile run_bots.py libchat.py
	mv run_bots.py.bak run_bots.py

clean:
	rm -f client server
