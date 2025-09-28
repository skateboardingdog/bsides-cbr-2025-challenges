all:
	gcc chall.c -o chall

publish:
	mv flag.txt flag.txt.bak
	echo skbdg{test_flag} > flag.txt
	tar cvfz wordgame.tar.gz chall chall.c Dockerfile flag.txt
	mv flag.txt.bak flag.txt
