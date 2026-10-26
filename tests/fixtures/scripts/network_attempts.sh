#!/bin/bash
# TracePot fixture: attempts name resolution and a TCP connection. Uses the reserved .invalid
# TLD and an RFC 5737 documentation address; under TracePot's isolated network policy neither
# can leave the sandbox.
getent hosts tracepot-fixture.invalid > /dev/null 2>&1 || true
(echo > /dev/tcp/198.51.100.7/443) > /dev/null 2>&1 || true
exit 0
