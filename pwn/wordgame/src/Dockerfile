FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV JAIL_CWD=/chal

COPY nsjail.cfg /home/ctf/nsjail.cfg

COPY ./flag.txt /home/ctf/chal
COPY ./chall /home/ctf/chal/pwn
