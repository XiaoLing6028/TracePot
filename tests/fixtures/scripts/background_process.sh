#!/bin/sh
# TracePot fixture: leaves a background process running when the script exits.
sleep 300 &
echo started-background
