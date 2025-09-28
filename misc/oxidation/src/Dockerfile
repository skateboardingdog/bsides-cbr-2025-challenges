FROM rust:latest

# install dependencies
RUN apt-get update && apt-get install -y \
  libpam0g-dev sudo vim git make socat \
  && rm -rf /var/lib/apt/lists/*

# copy setup files
COPY setup.sh /tmp/setup.sh
COPY env.patch /tmp/env.patch
COPY flag.txt /root/flag.txt

RUN chmod +x /tmp/setup.sh && /tmp/setup.sh && rm /tmp/setup.sh /tmp/env.patch

# create user
RUN useradd -m user -s /bin/bash
WORKDIR /home/user
USER user

ENTRYPOINT ["socat", "-dd", "TCP4-LISTEN:1337,fork,reuseaddr", "EXEC:\"timeout 300 setsid /bin/bash -i\",stderr,pty,raw,echo=0"]
