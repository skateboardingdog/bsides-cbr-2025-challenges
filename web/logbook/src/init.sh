#!/bin/bash

lol() {
  hi=`md5sum <(echo "$1") | cut -d' ' -f1`
  while [[ ! $hi == ff* ]]; do
    hi=`md5sum <(echo "$hi") | cut -d' ' -f1`
  done
}

uuid=`md5sum <(echo "$FLAG") | cut -d' ' -f1 | sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/'`
uuid="${uuid:0:14}4${uuid:15}"
file="data/$uuid"
mkdir -p data
chown 1000:1000 data
echo "$FLAG" > "$file"
chmod 444 "$file"
unset FLAG
lol "$uuid"
setpriv --reuid=1000 --regid=1000 --clear-groups ./run.sh "$file"
