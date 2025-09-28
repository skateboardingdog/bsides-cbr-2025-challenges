#!/bin/sh

conn_string=$1
mode=$2
jump_host=$(echo "$conn_string" | sed -n 's/.*-J \([^ ]*\).*/\1/p')
target_host=$(echo "$conn_string" | awk '{print $NF}')

if [[ $mode == "PROD" ]]; then
    scp -J "$jump_host" ./flag.txt "$target_host:/var/mobile/"
    ssh -J "$jump_host" "$target_host" "apt update -y && apt install -y socat"
else
    ssh -J "$jump_host" "$target_host" "echo 'skbdg{testflag}' > /var/mobile/flag.txt"
    ssh -J "$jump_host" "$target_host" "apt update -y && apt install -y lldb socat"
fi

scp -J "$jump_host" ./lucky_visitor "$target_host:/var/mobile/"
scp -J "$jump_host" ./dog.sk8boarding.lucky_visitor.plist "$target_host:/Library/LaunchDaemons/"
