FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV JAIL_CWD=/chal
ENV TMP_PARAMS=", { \
    src: \"/etc/ssl/openssl.cnf\", \
    dst: \"/etc/ssl/openssl.cnf\", \
    is_bind: true, \
    rw: false \
  }, { \
    src: \"/home/ctf/chal/tmp\", \
    dst: \"/tmp\", \
    is_bind: true, \
    rw: true \
  }"

RUN mkdir -p /home/ctf/chal/tmp
RUN chown -R ctf /home/ctf/chal/tmp

COPY ./flag.txt /home/ctf/chal
COPY ./ld-2.35.so /home/ctf/chal
COPY ./libc.so.6 /home/ctf/chal
COPY ./libcrypto.so.3 /home/ctf/chal
COPY ./server_key.bin /home/ctf/chal
COPY ./chall /home/ctf/chal/pwn
