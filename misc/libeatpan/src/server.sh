#!/bin/bash

echo "Send your .eml to maybe be encrypted (end with literal 'EOF'): "
TMPFILE=$(mktemp)
while IFS= read -r line; do
    if [[ "$line" == "EOF" ]]; then
        break
    fi
    echo "$line" >> "$TMPFILE"
done
./pgp "$TMPFILE"
rm $TMPFILE
