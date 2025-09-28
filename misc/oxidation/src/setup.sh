#!/bin/bash

set -euxo pipefail

# clone and patch sudo-rs
git clone https://github.com/trifectatechfoundation/sudo-rs /usr/src/sudo-rs
cd /usr/src/sudo-rs
git checkout 51f52353f395b04605ec87917110a722ed496cbc
cp /tmp/env.patch .
git apply env.patch

# build and install sudo-rs
cargo install --path .
mv /usr/local/cargo/bin/sudo /bin/sudo
mv /usr/local/cargo/bin/su /bin/su
chmod +s /bin/sudo
chmod +s /bin/su

# install vixie cron
git clone https://github.com/vixie/cron /usr/src/cron
cd /usr/src/cron
make install
mkdir -p /var/cron/tabs
touch /var/cron/cron.deny

# remove sources
rm -r /usr/src/*
