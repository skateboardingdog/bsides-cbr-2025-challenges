FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-24.04

RUN pip install -t /lib/python3/dist-packages pycryptodome

ENV FLAG="skbdg{only_th3_f4st3st_hedged0g_can_bre4k_40_bits_in_30_s3conds!}"

COPY ./supersanic2.py /home/ctf/chal/pwn
