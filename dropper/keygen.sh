#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <payload_binary> [key_size_bytes]"
    echo "Example (Standard): $0 ../tests/payload"
    echo "Example (256-bit):  $0 ../tests/payload 32"
    exit 1
fi

PAYLOAD_IN="$1"
KEY_SIZE="${2:-16}"

if [ ! -f "$PAYLOAD_IN" ]; then
    echo "Error: File '$PAYLOAD_IN' not found."
    exit 1
fi

if ! [[ "$KEY_SIZE" =~ ^[0-9]+$ ]] || [ "$KEY_SIZE" -le 0 ]; then
    echo "Error: Key size must be a positive integer."
    exit 1
fi

RAW_BYTES=$(hexdump -n "$KEY_SIZE" -v -e '/1 "0x%02X, "' /dev/urandom | sed 's/, $//')

echo "[*] Generating key.h with $KEY_SIZE-byte ($((KEY_SIZE * 8))-bit) key..."

cat <<EOF > key.h
#ifndef KEY_H
#define KEY_H

// Auto-generated $((KEY_SIZE * 8))-bit XOR key
unsigned char xor_key[] = { $RAW_BYTES };
#define XOR_KEY_LEN $KEY_SIZE

#endif
EOF

echo "[*] Encrypting '$PAYLOAD_IN'..."

PYTHON_KEY_LIST="[${RAW_BYTES}]"

python3 -c "
k=${PYTHON_KEY_LIST}
d=open('${PAYLOAD_IN}','rb').read()
print('#ifndef PAYLOAD_DATA_H')
print('#define PAYLOAD_DATA_H')
print('unsigned char encrypted_payload[] = {' + ','.join([hex(b ^ k[i%len(k)]) for i,b in enumerate(d)]) + '};')
print('#endif')
" > payload_data.h

echo "[+] Done! Generated key.h and payload_data.h"