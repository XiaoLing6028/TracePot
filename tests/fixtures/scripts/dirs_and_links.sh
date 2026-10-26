#!/bin/sh
# TracePot fixture: creates nested directories and a relative symlink.
mkdir -p nested/deeper
echo target > link-target.txt
ln -s ../link-target.txt nested/link
