#!/bin/sh
# TracePot fixture: leaves a background process running when the script exits.
sleep 300 &
pid=$!
# Wait until the background child has actually executed sleep, so the test is not timing-dependent.
i=0
while [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" != "/usr/bin/sleep" ] && [ "$i" -lt 500 ]; do
    i=$((i + 1))
    sleep 0.01
done
echo started-background
