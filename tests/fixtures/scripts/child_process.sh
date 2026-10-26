#!/bin/sh
# TracePot fixture: runs child processes and exits with a distinctive status.
sh -c 'echo from-child' > child-output.txt
/usr/bin/env true
exit 4
