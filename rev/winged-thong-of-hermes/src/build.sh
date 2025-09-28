#!/usr/bin/env sh


# // Add this to main.js me to change the flag
# // var text = "skbdg{fl33t_as_f3ath3rs_and_swift_0f_s0ng}";
# // var textBytes = aesjs.padding.pkcs7.pad(aesjs.utils.utf8.toBytes(text));
# // var aesCbc = new aesjs.ModeOfOperation.cbc(k, i);
# // var encryptedBytes = aesCbc.encrypt(textBytes);

set -e

# npm install javascript-obfuscator
npx javascript-obfuscator --config=config.json main.js

# https://github.com/facebook/hermes
hermesc -emit-binary -out main.hbc -fstrip-function-names -g0 -O0 main-obfuscated.js
hermes main.hbc
