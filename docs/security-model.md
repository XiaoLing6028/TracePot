# TracePot security model

TracePot executes untrusted installer code. This document states what the sandbox is designed to
guarantee, what it does not guarantee, and how to interpret the evidence it produces. When in
doubt, assume less isolation, not more: **analyze high-risk samples inside a disposable virtual
machine**, with TracePot as an additional layer.

## Trust boundaries

| Component | Trust |
| --- | --- |
| The analyzed input and everything it starts | **Untrusted.** Runs only inside the sandbox. |
| Files the sample writes in the workspace, its stdout/stderr | **Untrusted data.** Read by TracePot without following symlinks, with size limits, sanitized for display. |
| strace output | **Untrusted data.** File names, argv strings and buffers are sample-controlled; the parser relies only on strace's escaping guarantees. |
| Archives being extracted | **Untrusted data.** Extracted by TracePot's own hardened extractor before anything runs. |
| Saved reports loaded into the CLI/GUI | **Untrusted data.** Validated against the schema version; all content escaped in HTML and shown as plain text in the GUI. |
| TracePot, `tracepot-limits`, bubblewrap, strace, the host kernel | Trusted computing base. |

## Isolation layers

The installer runs as `strace → tracepot-limits → bwrap → <shell> /work/<script>`:

1. **Namespaces (bubblewrap).** New user, mount, PID, IPC, UTS and network namespaces (plus a cgroup
   namespace when available). Nested user namespaces are disabled (`--disable-userns` when
   supported, and always through seccomp).
2. **Minimal filesystem view.** Only these are visible:
   - `/usr` and the `/bin`, `/sbin`, `/lib*` links or directories, **read-only from the host**;
   - fresh `/proc` for the sandbox's PID namespace, a minimal `/dev` (null, zero, full, random,
     urandom, tty, pts) and a private 64 MiB tmpfs on `/dev/shm`;
   - `/etc`, `/home`, `/root`, `/var`, `/opt`, `/usr/local`, `/run`, `/tmp`, `/work` from TracePot's
     private workspace. `/etc` is a curated copy containing only world-readable, non-secret files
     (no shadow/sudoers/SSH keys, no package-manager or `/etc/environment` files that may carry
     proxy or repository credentials) plus synthesized `passwd`, `group`, `hosts`, `hostname`
     and a random `machine-id`.
   Not visible: the user's home directory, other users' files, `/sys`, D-Bus, X11/Wayland,
   PulseAudio/PipeWire, the Docker/Podman sockets, SSH agents, `/run/user/<uid>` of the host, and
   the host's `/usr/local`.
3. **Writable areas.** In the default (unprivileged) mode only `/tmp`, `/var/tmp`, `/work`,
   `/home/tracepot` and `/run/user/1000` are writable; system directories are read-only bind mounts,
   so attempts fail with `EROFS` and are recorded. With `--as-root` ("simulate root") the sandbox
   user is uid 0 *inside the user namespace only* and the workspace copies of the system
   directories become writable, so system-level changes can be observed. No host privileges are
   granted in either mode, and every writable path is inside the workspace
   (`sandbox.hostWritablePaths` in the report lists them).
4. **Privileges.** All capabilities dropped (`--cap-drop ALL`), `no_new_privs` (set by bubblewrap for
   seccomp), new session (no controlling terminal), sanitized environment (`--clearenv` plus explicit
   variables only).
5. **Seccomp filter** (deny-list, loaded by bubblewrap): kernel keyring, BPF, perf events,
   userfaultfd, module loading, kexec, mount/umount/pivot_root, `open_by_handle_at`, NUMA memory
   policy calls, `syslog`, `acct`, `quotactl` → `EPERM`; io_uring → `ENOSYS`; `clone3` → `ENOSYS`
   (so that `clone()` flags can be filtered); `unshare`/`clone` with `CLONE_NEWUSER` → `EPERM`;
   `TIOCSTI`/`TIOCLINUX` ioctls → `EPERM`; socket families other than UNIX, INET, INET6 and NETLINK
   → `EAFNOSUPPORT`. The same rules apply to the 32-bit x86 ABIs on x86-64.
6. **Network.** A private network namespace with only loopback. Nothing can reach the host network
   or the internet; there is no proxy or gateway mode in this version.
7. **Resource limits** (set by `tracepot-limits` just before it executes bubblewrap):
   `RLIMIT_AS` (per-process address space), `RLIMIT_FSIZE` (largest written file),
   `RLIMIT_NPROC` (current processes of the user plus the configured allowance), `RLIMIT_NOFILE`,
   `RLIMIT_CORE=0`. TracePot additionally enforces a wall-clock timeout, a disk-growth limit
   (polled every second over the workspace tree, with a filesystem free-space safety net), a
   file-count limit and a trace-size limit; on any of them the whole sandbox is killed.

## Lifecycle guarantees

- **Fail closed.** If bubblewrap cannot create the sandbox, nothing is executed. If strace is not
  usable, nothing is executed unless the user explicitly allows an untraced run, which is then
  recorded as missing evidence.
- **Termination.** On timeout, cancellation or a limit, TracePot sends `SIGKILL` to bubblewrap and
  to the PID-namespace init process; the kernel then kills every process in the namespace.
  Background processes still running when the entry script exits are killed the same way when
  bubblewrap's init exits.
- **TracePot crashes.** The launcher process has `PR_SET_PDEATHSIG=SIGKILL`; `tracepot-limits`
  arms `PR_SET_PDEATHSIG` again (it survives the exec into bubblewrap) and refuses to start if its
  tracer is no longer attached; bubblewrap runs with `--die-with-parent`. A killed TracePot
  therefore takes the sandbox down instead of leaving it running untraced (covered by an
  integration test that SIGKILLs the CLI during sandbox start-up). Residual risk: bubblewrap
  arms its own parent-death signal for its internal init process shortly after forking it; a
  crash of bubblewrap itself in that instant is outside TracePot's control.
- **Cleanup.** Workspaces are removed after each analysis without following symlinks, restoring
  permissions the sample removed and coping with arbitrarily deep trees. Each workspace is
  `flock`ed while in use; workspaces left behind by a killed analysis are removed by the next
  analysis (unless they were explicitly kept).

## Host-side hardening

- **Archives** are rejected as a whole — never partially extracted — if any member uses an absolute
  path or `..`, is a device node, FIFO or socket, is a symlink with an absolute or escaping target,
  is a hard link to anything but a previously extracted regular file, would be written through a
  symlink or non-directory (checked component by component with `O_NOFOLLOW`), duplicates another
  member, or exceeds entry-count, per-file, total-size, path-length or depth limits. Only
  permission bits (without setuid/setgid/sticky) are preserved.
  Symlink targets are checked lexically; chains of in-archive links could still point outside the
  extraction directory, but TracePot never follows links during extraction, snapshotting or
  cleanup, and inside the sandbox such a link can only reach the sandbox's own view.
- **Snapshots** use `openat`/`fstatat` with `O_NOFOLLOW`, never open non-regular files, re-verify the
  inode after opening, and limit entries, depth, hashing volume and captured text.
- **Process launching** uses `fork`/`execve` with absolute paths and argument vectors; no host
  shell ever interprets user or sample input. Environment variables are passed to the sandbox via
  bubblewrap, not to the host-side launcher. Only async-signal-safe calls run between `fork` and
  `execve`.
- **Parsing** of strace output relies on its escaping of quotes, angle brackets and control
  characters; lines have a maximum length, the number of events and buffered records is capped,
  and DNS payload decoding is bounds-checked. All sample-derived strings are sanitized (invalid
  UTF-8 and control characters escaped) before they reach reports, terminals or the GUI.
- **Output.** HTML reports escape all content and contain no scripts; GUI labels that can show
  sample- or report-derived text are forced to plain text. Environment variable *values* are never
  written to reports; credentials embedded in URLs are redacted.
- **Workspace** directories are created with mode 0700 under `$XDG_CACHE_HOME/tracepot/runs`; files
  are written with `O_NOFOLLOW` and restrictive modes.

## What the sandbox does not protect against

- **Kernel vulnerabilities.** Everything runs on the host kernel. User namespaces expose a larger
  kernel attack surface to unprivileged code; the seccomp filter reduces but does not eliminate it.
- **Information exposure.** The sample can read the read-only host `/usr` (installed software and
  versions), kernel version and CPU information from `/proc`, and the host path of the workspace
  (which includes the user name) from `/proc/self/mountinfo` and `/proc/1/cmdline`.
- **Resource exhaustion beyond the limits.** Memory is limited per process, not per sandbox; there is
  no cgroup integration. `RLIMIT_NPROC` is not enforced for root, so running TracePot as root
  weakens fork-bomb protection. The disk limit is enforced by polling, so short overshoots
  (bounded per file by `RLIMIT_FSIZE`) are possible.
- **Running TracePot as root** keeps the sandbox layers in place, but sandboxed processes then run
  under the host's root UID mapping and `RLIMIT_NPROC` is ineffective. It is supported for
  environments such as containers but discouraged; reports carry a warning.

## Observation limits (evidence interpretation)

Evidence in reports is labelled:

- **observed** — recorded directly: syscall trace events, process records, filesystem changes, host
  integrity results.
- **inferred** — produced by rules from observations: persistence classifications, destinations
  derived from URLs in command lines.
- **missing** — an observation that could not be made (for example no tracer); the report says so
  in its diagnostics instead of presenting an empty table as "nothing happened".
- **error** — a collection step failed.

What the trace cannot show:

- syscalls denied by seccomp (seccomp runs before ptrace stops), io_uring operations (blocked),
- writes through memory mappings or descriptors opened before a path change, beyond what the
  filesystem comparison captures,
- reads of ordinary files (counted, not listed); only reads of credential/secret locations are
  listed,
- anything that happens after the run (timers, cron jobs, login or boot hooks).

Network evidence is limited to what the isolated policy allows the sample to attempt: DNS query
names decoded from the query packets, connection attempts and their errors (typically
`ENETUNREACH` or `ECONNREFUSED`), and URLs seen in command lines. A successful `send()` or UDP
`connect()` is reported with outcome `unknown` because no packet left the sandbox and no response
was observed; `success` is reserved for completed TCP connections and local sockets, which can only
reach services inside the sandbox.

The filesystem comparison reports the net effect inside the sandbox; the syscall trace shows
transient and failed activity. A file created and removed during the run appears in the trace
(and, at a persistence location, as an `attempt-observed` finding) but not as a filesystem change.

A persistence-related location being modified is not, by itself, malicious: installers routinely
add shell `PATH` entries, desktop autostart files or services. Conversely, the absence of findings
does not mean an input is benign — it can detect the analysis environment, wait, require network
responses, or act through channels that were not observed. **TracePot never certifies an input as
safe.**

## Recommendations

- Run TracePot as an unprivileged user inside a disposable VM without access to sensitive data or
  networks when analyzing samples of unknown origin.
- Keep the host kernel, bubblewrap and strace up to date.
- Review `tracepot check` output and the report's limitations before relying on a result.
