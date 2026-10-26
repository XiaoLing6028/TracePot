#!/bin/sh
# TracePot fixture: creates user-level autostart and systemd user unit files and edits ~/.bashrc
# inside the sandbox's simulated home directory.
mkdir -p "$HOME/.config/autostart" "$HOME/.config/systemd/user"
printf '[Desktop Entry]\nType=Application\nName=TracePot Fixture\nExec=/bin/true\n' \
    > "$HOME/.config/autostart/tracepot-fixture.desktop"
printf '[Unit]\nDescription=TracePot fixture\n[Service]\nExecStart=/bin/true\n' \
    > "$HOME/.config/systemd/user/tracepot-fixture.service"
echo '# added by TracePot fixture' >> "$HOME/.bashrc"
