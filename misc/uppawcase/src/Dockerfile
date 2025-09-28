FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y gcc --fix-missing \
    && rm -r /var/lib/apt/lists/*

ENV FLAG=skbdg{did_you_know_that_printf_is_turing_complete!?}

ENV JAIL_CWD=/chal TMP_ENABLED=1
COPY ./uppawcase.py /home/ctf/chal/pwn
