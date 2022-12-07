#!/bin/bash

set -e

gcc src/main.c lib/crypto.c -lssl -lcrypto -lcrypt -lsodium
./a.out < input/1.bin
