# TracePot architecture

TracePot is split into a reusable C++20 core library and two thin front ends.

```
            ┌──────────────────────┐      ┌─────────────────────────────┐
            │ tracepot (CLI)       │      │ tracepot-gui (Qt6 Widgets)  │
            │ src/cli              │      │ src/gui                     │
            └──────────┬───────────┘      └──────────────┬──────────────┘
                       │  AnalysisConfig / Analyzer / reports (no duplicated logic)
                       ▼                                 ▼
            ┌────────────────────────────────────────────────────────────┐
            │ tracepot_core (src/core) — no Qt dependency                │
            │ models · util · archive · sandbox · observers · diff ·     │
            │ analysis · reporting                                       │
            └────────────────────────────────────────────────────────────┘
                       │ fork/exec (argument vectors only)
                       ▼
   strace ──► tracepot-limits (src/helper) ──► bwrap ──► installer script
```

## Modules

| Directory | Responsibility |
| --- | --- |
| `src/core/models` | Plain data types: `AnalysisConfig`, limits, `AnalysisReport` and its records, enums with stable string names, `Result<T>`/`Error`. |
| `src/core/util` | RAII file descriptors, non-following file operations (`removeTree`, bounded reads, secure writes), SHA-256 (OpenSSL EVP), path normalization and display sanitizing, glob matching, XDG directories, timestamps. |
| `src/core/archive` | Input type detection (`InputInspector`), hardened tar extraction (`SafeExtractor`, libarchive), entry-point selection. |
| `src/core/sandbox` | Workspace layout and cleanup, bubblewrap command construction, seccomp program generation (libseccomp), process supervision (`ProcessSupervisor`), dependency readiness probes, and the sandbox run loop (`SandboxRunner`). |
| `src/core/observers` | strace output parsing (`StraceParser`), the stateful `TraceCollector` (process tree, file events, network events), DNS/URL helpers and the network policy interface (`NetworkGateway`), |
| `src/core/diff` | Filesystem snapshots (`Snapshot`), snapshot comparison (`FsDiff`), unified text diffs (`TextDiff`). |
| `src/core/analysis` | The `Analyzer` pipeline, cancellation token, persistence classification. |
| `src/core/reporting` | JSON serialization/parsing (versioned schema), HTML and text rendering. |
| `src/helper` | `tracepot-limits`: sets resource limits and the parent-death signal, closes stray descriptors, then executes bubblewrap. |
| `src/cli` | Argument parsing (`CliOptions`) and the `tracepot` command. |
| `src/gui` | `MainWindow`, `AnalysisWorker` (runs the `Analyzer` on a worker thread), `ResultsView`, and a generic sortable/filterable table model. |

Front ends only build an `AnalysisConfig`, run `Analyzer::run()` and present the resulting
`AnalysisReport`; every analysis decision lives in the core.

## Analysis pipeline

`Analyzer::run()` executes these stages (reported through the progress callback):

1. **Validating** — run (or reuse) the readiness probe; refuse to continue if the sandbox or (unless
   explicitly allowed) the tracer is unavailable. Inspect the input by content; unsupported inputs
   are rejected before anything is copied or executed.
2. **Preparing workspace** — remove stale workspaces of killed analyses, create
   `$XDG_CACHE_HOME/tracepot/runs/<analysis-id>/` (mode 0700, locked with `flock`), copy the input
   (hashing it), build the sandbox root (curated `/etc`, home skeletons, standard directories), copy
   the script or safely extract the archive into `/work`, and resolve the entry point and shell.
3. **Capturing baseline** — snapshot the sandbox root and the host's persistence locations.
4. **Running** — build the seccomp program and the bubblewrap command and run
   `strace … -- tracepot-limits … -- bwrap … -- <shell> /work/<script> <args>`. The runner tails the
   trace file and feeds it to the `TraceCollector` while enforcing the timeout, cancellation, disk
   growth, file-count and trace-size limits.
5. **Collecting events** — finish parsing, build process records, attribute threads to processes,
   restore chronological order; read bounded stdout/stderr excerpts.
6. **Comparing filesystem state** — snapshot again and diff; attribute changes to the processes
   seen mutating those paths; diff the host persistence locations.
7. **Classifying observations** — persistence rules over filesystem changes, failed or transient
   write attempts and persistence commands.
8. **Writing report** — assemble diagnostics (limitations, warnings, errors), statistics and timing;
   remove the workspace unless it is to be kept.

The function returns an `Error` only when the input was never executed (invalid or unsafe input,
unavailable sandbox, cancellation before start). Once execution starts, a report is always
produced; timeouts, cancellations and limit hits become the report's termination reason.

## Event pipeline

```
strace -o <workspace>/trace/strace.log      (outside the sandbox, not visible to it)
        │  tail (TraceTail, bounded reads)
        ▼
TraceCollector::feed(chunk)
  ├─ line splitting with a maximum line length
  ├─ parseStraceLine()        kind: syscall / unfinished / resumed / signal / exit / kill
  ├─ StraceAssembler          merges "<unfinished ...>" with "<... resumed>" per PID
  ├─ entry detection          everything before the execve of the configured command is
  │                           bubblewrap's own setup and is ignored (those PIDs are remembered)
  ├─ PID bookkeeping          clone/fork/vfork results (translated with --pidns-translation)
  │                           create process records; CLONE_THREAD maps threads to processes;
  │                           records of not-yet-announced children are buffered and replayed
  └─ dispatch                 exec, open/creat (write intent, sensitive reads), path mutations,
                              socket/connect/bind/listen/send(+DNS decoding), chdir/fchdir
        ▼
TraceEvent / ProcessRecord / NetworkEvent / ResourceLimitEvent
```

Paths are resolved to absolute sandbox paths using strace's `-y` decorations (the kernel's view of
descriptors, including `AT_FDCWD</cwd>`) and a per-process working-directory model as a fallback.
All strings taken from the trace are sanitized for display (invalid UTF-8 and control characters
become escapes) before they are stored in records.

The filesystem comparison is independent of the trace: snapshots capture the final state even for
changes the trace cannot see (memory-mapped writes, writes through inherited descriptors), while
the trace shows transient activity (a file written and deleted) and failed attempts that leave no
filesystem change. Both kinds of evidence are kept and linked: filesystem changes carry the PIDs
that the trace saw modifying the same path.

## Process and thread model

- The CLI runs the analysis on its main thread; SIGINT/SIGTERM set the `CancellationToken`
  (a lock-free atomic) from a signal handler.
- The GUI moves an `AnalysisWorker` to a `QThread`. Progress, success and failure travel to the UI
  as queued signals; cancellation uses the same shared `CancellationToken`. Closing the window
  cancels and joins the worker. The readiness probe runs on its own short-lived thread.
- `ProcessSupervisor` prepares everything before `fork()` and uses only async-signal-safe calls in
  the child. The child starts a new session, sets `PR_SET_PDEATHSIG`, resets signal state, marks
  every inherited descriptor close-on-exec, and `execve`s an absolute path with an explicit
  environment. Waiting uses `pidfd` + `poll` where available.

## Extension points

- **Network policy:** `NetworkGateway` (in `observers/NetworkObserver.hpp`) describes the policy,
  can contribute sandbox arguments and can return events observed on the gateway side. Only
  `IsolatedNetwork` exists today. A controlled proxy would implement this interface (for example
  by binding a proxy socket into the sandbox) and add its own events to the report.
- **Persistence rules:** `builtinPersistenceRules()` in `analysis/Persistence.cpp`; users can add
  patterns with `--persistence-pattern` / `AnalysisConfig::extraPersistencePatterns`.
- **Input types:** `InputInspector` decides what can run; a new type needs a safe preparation step
  (like `SafeExtractor`) and an entry-point rule.

## Reports

`reporting/ReportJson` writes and reads the versioned JSON format (`schemas/tracepot-report-1.schema.json`);
`reporting/ReportRender` produces HTML (all content escaped, no scripts) and the CLI summary. The
GUI renders the same report model. See [report-format.md](report-format.md).
