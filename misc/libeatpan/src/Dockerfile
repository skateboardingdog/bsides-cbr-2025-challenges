FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-24.04

RUN apt update -y && apt install -y wget && rm -r /var/lib/apt/lists/*

ENV JAIL_CWD=/chal
ENV TMP_ENABLED=1

COPY ./nsjail.cfg /home/ctf/
COPY ./pgp ./libetpan.so.20 ./flag.txt /home/ctf/chal/
COPY ./server.sh /home/ctf/chal/pwn
