# TracePot

**What did this installer actually do?**

TracePot is a Linux-first, open-source tool that runs a shell-script or tar-archive installer
inside a disposable, isolated sandbox and reports what it observably did: the files it created,
modified and deleted, the processes it ran, the network connections it attempted, and the
startup/persistence locations it touched. It has a command-line interface (`tracepot`) and a Qt6
desktop application (TracePot) built on the same C++20 core library.

TracePot reports *observations*. It never declares an input safe: a quiet run only means nothing
suspicious was observed in one time-limited, network-isolated execution.

> **Status:** early MVP (version 0.1.0). Built and tested on Ubuntu 24.04 (GCC 13, Qt 6.4,
> bubblewrap 0.9, strace 6.8). Fedora is a primary target platform, but this version has not yet
> been built or tested on Fedora.

## Features

- **Inputs:** shell scripts (`#!` with sh/bash/dash/zsh/ksh/mksh/ash, or `.sh` files) and tar
  archives (uncompressed, gzip, bzip2, xz, zstd, lzip). Archives are extracted by TracePot with
  strict checks (no `..` or absolute paths, no device nodes/FIFOs, no escaping or write-through
  symlinks, entry-count and size limits) before an installer script inside them is run.
  ELF binaries, AppImages, RPM/DEB packages, ZIP files and non-shell scripts are rejected with an
  explanation; nothing is executed implicitly.
- **Sandbox:** [bubblewrap](https://github.com/containers/bubblewrap) with user, mount, PID, IPC,
  UTS and network namespaces (cgroup namespace when available), a minimal explicit filesystem view,
  a seccomp filter, no capabilities, `no_new_privs`, resource limits and a wall-clock timeout.
  The host's home directory, credentials, D-Bus/X11/Wayland sockets and network are not visible.
  TracePot refuses to run anything if the sandbox cannot be created.
- **Observation:**
  - syscall tracing with `strace` (process creation and `exec`, file mutations, permission and
    ownership changes, sensitive reads, socket/connect/bind/listen/send) with process ancestry;
  - before/after filesystem snapshots with SHA-256 hashes, permission/ownership/symlink/type
    changes and unified diffs of small text files;
  - a host integrity check comparing the real host's persistence locations before and after.
- **Classification:** persistence-related locations (shell startup files, XDG autostart, systemd
  units, cron, SysV init, sudoers, SSH, dynamic linker, udev, PAM, kernel modules, package
  repositories, persistence commands such as `systemctl enable`) and extra user-defined patterns.
  Classifications are labelled as *inferred*; observations as *observed*.
- **Network:** isolated by default (private network namespace with loopback only). DNS queries
  (decoded from the query packets), connection attempts and their errors, and URLs found in command
  lines (as *inferred* destinations) are reported. Nothing leaves the sandbox.
- **Reports:** versioned JSON ([schema](schemas/tracepot-report-1.schema.json)), self-contained
  HTML and a terminal summary.
- **GUI:** input selection and type detection, sandbox/limit configuration, dependency readiness
  checks, live progress with cancellation, sortable/filterable result tables with an evidence
  details panel, report loading and JSON/HTML export.

## Requirements

Runtime (both the CLI and the GUI):

- Linux with unprivileged user namespaces available to bubblewrap
- `bwrap` (bubblewrap; tested with 0.9.0 — optional features such as `--disable-userns`,
  `--clearenv` and tmpfs size limits are detected at runtime)
- `strace` (tested with 6.8; a version supporting `--pidns-translation` is needed for complete
  process ancestry, older versions work with parent processes reported as unknown)
- ptrace of child processes permitted (Yama `ptrace_scope` 0 or 1; 3 disables ptrace entirely)
- libarchive, OpenSSL (libcrypto), libseccomp; Qt 6 (Core, Gui, Widgets) for the GUI

Build:

| Purpose | Fedora | Debian / Ubuntu |
| --- | --- | --- |
| Toolchain | `gcc-c++ cmake ninja-build pkgconf` | `g++ cmake ninja-build pkg-config` |
| Core libraries | `libarchive-devel openssl-devel libseccomp-devel json-devel` | `libarchive-dev libssl-dev libseccomp-dev nlohmann-json3-dev` |
| GUI and tests | `qt6-qtbase-devel` | `qt6-base-dev` |
| AppImage packaging | `qt6-qtwayland librsvg2-tools curl` | `qt6-wayland librsvg2-bin curl` |
| Runtime tools | `bubblewrap strace` | `bubblewrap strace` |

The Debian/Ubuntu package names were used for the verified build; the Fedora names are the
corresponding packages but were not exercised in this version.

## Building

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel
```

Presets are available (`cmake --preset debug|release|asan|cli-only`). `-DTRACEPOT_BUILD_GUI=OFF`
builds only the core and CLI (Qt is then only needed when `BUILD_TESTING=ON`).

Build outputs are placed in `build/bin/`: `tracepot` (CLI), `tracepot-gui` (GUI) and
`tracepot-limits` (an internal helper that must stay next to the executables, or be installed in
`<prefix>/libexec/tracepot/`). `cmake --install build` installs all three plus the JSON schema, a
desktop entry and an icon.

## AppImage

The x86_64 AppImage contains the GUI, the CLI, the `tracepot-limits` helper, Qt 6 (X11 and Wayland)
and the core libraries (libarchive, OpenSSL, libseccomp):

```sh
chmod +x TracePot-0.1.0-x86_64.AppImage
./TracePot-0.1.0-x86_64.AppImage                                # GUI
./TracePot-0.1.0-x86_64.AppImage cli check                      # command-line interface
./TracePot-0.1.0-x86_64.AppImage cli analyze ./installer.sh
```

A symlink named `tracepot` that points to the AppImage also starts the command-line interface
(`ln -s ~/Applications/TracePot-0.1.0-x86_64.AppImage ~/.local/bin/tracepot`).

Host requirements:

- x86_64 Linux with glibc 2.38 or newer and libstdc++ from GCC 13.2 or newer, for example Fedora 39+,
  Ubuntu 24.04+, Debian 13+, RHEL 10, Arch Linux or openSUSE Tumbleweed. Debian 12 and RHEL 9 are
  too old.
- `bwrap` and `strace` installed from the distribution, plus the kernel requirements described in
  [Sandbox requirements](#sandbox-requirements). They are deliberately not bundled: the sandbox and
  the tracer have to match the host kernel and its security policy (for example Ubuntu's AppArmor
  profile for bwrap) and receive the distribution's security updates.
- FUSE to mount the AppImage (`fusermount3` from the `fuse3` package, normally installed on desktop
  systems). Without FUSE, run it with `--appimage-extract-and-run` or set
  `APPIMAGE_EXTRACT_AND_RUN=1`.
- For the GUI only: the libraries every desktop has (X11/xcb or the Wayland client library,
  EGL/GLX through libglvnd, fontconfig, FreeType, HarfBuzz). The CLI needs none of them.

AppImages do not install themselves: use an integration tool such as Gear Lever or
AppImageLauncher to get a menu entry and icon. Building the AppImage is described in
[docs/development.md](docs/development.md#appimage).

## Running the tests

```sh
ctest --test-dir build --output-on-failure
ctest --test-dir build -L unit           # no sandbox needed
ctest --test-dir build -L integration    # runs harmless fixtures inside the real sandbox
ctest --test-dir build -L gui            # Qt Test, offscreen platform
```

Integration tests are skipped (not failed) when `tracepot check` would report the host as not
ready. Tests never touch the real host's startup configuration, services, credentials or network:
fixtures run only inside the sandbox, use RFC 5737 documentation addresses and the reserved
`.invalid` domain, and the host-integrity check runs against a temporary fake home directory.

## Command-line usage

```text
tracepot check [--json]
tracepot analyze <input> [options] [-- <script arguments>...]
tracepot report <report.json> [--html <file>] [--json] [--details]
tracepot version | help
```

Examples:

```sh
tracepot check
tracepot analyze ./installer.sh
tracepot analyze ./package.tar.gz --timeout 60
tracepot analyze ./package.tar.gz --entry pkg-1.0/scripts/install.sh --as-root
tracepot analyze ./installer.sh --env PREFIX=/opt/demo -- --unattended
tracepot report ./tracepot-results/latest.json
tracepot report ./tracepot-results/latest.json --html report.html
```

`analyze` options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--timeout <s>` | 120 | Wall-clock limit; the whole sandbox is killed when it expires |
| `--entry <path>` | auto | Script inside a tar archive (auto-detects a single `install.sh`, `setup.sh`, `installer.sh` or `install`) |
| `--arg <value>` / `-- ...` | — | Script arguments, passed as an argument vector (never through a shell) |
| `--env NAME=VALUE` | — | Extra environment variables; only names appear in reports |
| `--as-root` | off | Simulate the root user inside the sandbox (system directories become writable *in the sandbox*) |
| `--memory <MiB>` | 2048 | Per-process address-space limit (`RLIMIT_AS`), 0 = none |
| `--max-processes <n>` | 256 | Additional processes allowed (`RLIMIT_NPROC`), 0 = none |
| `--max-file-size <MiB>` | 512 | Largest file the sample may write (`RLIMIT_FSIZE`), 0 = none |
| `--max-disk <MiB>` | 1024 | Maximum growth of the sandbox's files, 0 = none |
| `--persistence-pattern <glob>` | — | Extra location to classify as persistence (`~/` = any home) |
| `--output <dir>` | `./tracepot-results` | Where `<id>.json`, `<id>.html` and `latest.json` are written |
| `--no-html` | — | Skip the HTML report |
| `--keep-workspace` | — | Keep the analysis workspace for manual inspection |
| `--allow-untraced` | — | Run even if strace is unavailable (filesystem comparison only; recorded as missing evidence) |
| `--quiet` | — | No progress output |

Exit codes: `0` success · `1` usage error · `2` input rejected (unsupported, unsafe or damaged
archive, invalid report file) · `3` sandbox or tracer unavailable (also returned by `check` when
not ready) · `4` analysis failed · `5` interrupted (Ctrl-C; a partial report is written) · `6`
report written, but the sample was stopped by the timeout or a resource limit.

The exit status of the analyzed script itself is in the report (`execution.exitCode`), not in
TracePot's exit code.

## GUI

```sh
tracepot-gui                       # or: tracepot-gui ./installer.sh
tracepot-gui --report ./tracepot-results/latest.json
```

Select an input, review the detected type and the sandbox settings, check the dependency readiness
panel and press **Start Analysis** (F5). Progress shows the current stage, elapsed time and live
process/file/network event counts; **Cancel** (Shift+F5) kills the sandbox and produces a partial
report. Results appear in tabs (Summary, Filesystem, Processes, Events, Network, Persistence,
Warnings & Limitations) with filters, sortable columns and a details panel showing the evidence for
the selected row. Every report is also saved to `$XDG_DATA_HOME/tracepot/reports/`; File → Export
writes JSON or HTML. Settings are stored in `$XDG_CONFIG_HOME/tracepot/tracepot-gui.conf`.

## Reports

Each report contains the schema version, application name and version, analysis ID, input name and
SHA-256, timestamps, sandbox configuration and capabilities, network policy, exit status and
termination reason, process records, the syscall event timeline, filesystem changes, network
events, persistence classifications, resource-limit events, the host integrity check, statistics,
and warnings/limitations. Missing values are explicit `null`s. See
[docs/report-format.md](docs/report-format.md) and
[schemas/tracepot-report-1.schema.json](schemas/tracepot-report-1.schema.json).

## Sandbox requirements

Run `tracepot check` (or look at the GUI's readiness panel). It does not just look for binaries: it
starts a throwaway sandbox and a traced sandbox and reports what failed, with hints, for example
when user namespaces are disabled (`kernel.unprivileged_userns_clone=0`,
`user.max_user_namespaces=0`), restricted by AppArmor
(`kernel.apparmor_restrict_unprivileged_userns=1`, as on Ubuntu 24.04 without the bwrap AppArmor
profile), or when ptrace is disabled (`kernel.yama.ptrace_scope=3`). TracePot does not need root
and never calls `sudo`; running it as root is supported but discouraged (the report warns).

## Known limitations

- The sandbox shares the host kernel. Namespaces and seccomp reduce, but do not remove, the risk of
  kernel exploits. **Use a disposable virtual machine for high-risk samples.**
- Network access is blocked, so behavior that depends on downloads or remote responses is not
  exercised; only attempts are visible. There is no controlled gateway/proxy mode yet.
- One run is observed. Delayed, conditional, randomized or login/boot-triggered behavior may not
  happen. Code can detect the sandbox (hostname, PID namespace, missing `/sys`, missing services)
  and behave differently. Background processes still running when the entry script exits are killed.
- Only selected syscalls are traced. Writes through memory mappings or inherited descriptors appear
  only in the filesystem comparison; io_uring and other syscalls denied by the seccomp filter are
  not visible; ordinary file reads are counted, not listed.
- The sandbox can read the host path of its workspace (which contains the user name) from
  `/proc/self/mountinfo` and `/proc/1/cmdline`. `/usr` is visible read-only.
- Ownership changes cannot take effect inside the user namespace; attempts appear as failed
  syscalls. `/dev/shm` is not part of the filesystem comparison.
- Resource limits: `RLIMIT_NPROC` is not enforced when TracePot runs as root; the disk limit is
  enforced by polling once per second; memory is limited per process (address space), not per
  sandbox (no cgroup integration).
- Only shell scripts and tar archives are supported; binary installers are rejected.

See [docs/security-model.md](docs/security-model.md) for the full discussion.

## Responsible use

- Analyze only software you are permitted to analyze. TracePot is a defensive inspection tool.
- Treat every sample as hostile. Prefer a dedicated, disposable VM without access to sensitive
  networks or data; TracePot's sandbox is an additional layer, not a replacement.
- Do not upload samples or reports anywhere unless you intend to; TracePot itself has no
  telemetry, no remote uploads and no automatic sample submission.
- Reports contain host paths and captured program output; review them before sharing.
- Interpret findings in context: installers legitimately create services, modify shell
  configuration and download components. A finding is evidence to review, not a verdict.

## Documentation

- [docs/architecture.md](docs/architecture.md) — module boundaries and the event pipeline
- [docs/security-model.md](docs/security-model.md) — trust boundaries, isolation, limitations
- [docs/report-format.md](docs/report-format.md) — report fields and how to read them
- [docs/development.md](docs/development.md) — development setup, targets, tests, contributing

## License

Apache License 2.0 — see [LICENSE](LICENSE).
