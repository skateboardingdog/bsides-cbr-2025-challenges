#!/bin/bash
lol() {
  hi=`md5sum <(echo "$1") | cut -d' ' -f1`
  while [[ ! $hi == ff* ]]; do
    hi=`md5sum <(echo "$hi") | cut -d' ' -f1`
  done
}

lol "$1"
npm run start