#!/bin/sh
# TracePot fixture: reports whether the given host paths are visible inside the sandbox.
for p in "$@"; do
    if [ -e "$p" ]; then echo "visible $p"; else echo "absent $p"; fi
done > probe-result.txt
cat /etc/hostname >> probe-result.txt
