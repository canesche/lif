#!/bin/bash

set -e

gcc src/main.c lib/mee.c -lssl -lcrypto -lcrypt
./a.out < input/1.bin