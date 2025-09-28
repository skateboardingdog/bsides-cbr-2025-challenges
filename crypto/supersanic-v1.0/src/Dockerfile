FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-24.04

RUN pip install -t /lib/python3/dist-packages pycryptodome

ENV FLAG="skbdg{y0u_went_v3ry_fas7_prepar3_t0_g0_3ven_f4st3r!}"

COPY ./supersanic1.py /home/ctf/chal/pwn
