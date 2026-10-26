#!/bin/sh
# TracePot fixture: writes a file larger than the configured file-size limit.
head -c 4194304 /dev/zero > large.bin
echo after-write
