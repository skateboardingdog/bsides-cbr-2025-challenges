FROM ghcr.io/downunderctf/docker-vendor/sagemath:ubuntu-22.04

ENV TIME_LIMIT=300
ENV FLAG=skbdg{th1s_i5_n4Cho_av3Rage_crYP7o_challenge_it_H45_way_t00_many_H0L35}

ENV DOT_SAGE=/tmp/

COPY nsjail.cfg /home/ctf/
COPY ./cheesecake_shop.sage /home/ctf/chal
RUN sage --preparse /home/ctf/chal/cheesecake_shop.sage
RUN echo "#!/usr/bin/env python3" > /home/ctf/chal/pwn
RUN cat /home/ctf/chal/cheesecake_shop.sage.py >> /home/ctf/chal/pwn
RUN chmod +x /home/ctf/chal/pwn
