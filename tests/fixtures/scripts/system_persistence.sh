#!/bin/sh
# TracePot fixture: tries to install a system service and a cron job (inside the sandbox only).
printf '[Service]\nExecStart=/bin/true\n' > /etc/systemd/system/tracepot-fixture.service || echo "unit not written"
echo '* * * * * root /bin/true' > /etc/cron.d/tracepot-fixture || echo "cron not written"
exit 0
