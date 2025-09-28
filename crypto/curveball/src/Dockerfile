FROM ghcr.io/downunderctf/docker-vendor/sagemath:ubuntu-22.04

RUN pip install -t /lib/python3/dist-packages pycryptodome

ENV TIME_LIMIT=600
ENV FLAG=skbdg{a_bs1dh_param_chall3ng3_at_bs1d3s_canb3rra?}

ENV SAGE_STARTUP_FILE=/dev/null
ENV DOT_SAGE=/tmp/.sage

COPY ./chall.py /home/ctf/chal/pwn
COPY nsjail.cfg /home/ctf/
RUN chmod +x /home/ctf/chal/pwn
