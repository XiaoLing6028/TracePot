#!/bin/sh
# TracePot fixture: grows the workspace beyond a small disk limit, then idles.
for i in 1 2 3 4; do
    head -c 2097152 /dev/zero > "fill-$i.bin"
done
sleep 30
