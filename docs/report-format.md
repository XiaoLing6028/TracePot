# TracePot report format

Reports are JSON documents described by [`schemas/tracepot-report-1.schema.json`](../schemas/tracepot-report-1.schema.json)
(JSON Schema 2020-12). The CLI writes `<analysis-id>.json` (plus `latest.json` and optionally an HTML
rendering); the GUI saves every report under `$XDG_DATA_HOME/tracepot/reports/`.

## Versioning

- `"schema": "tracepot-report"` identifies the document type.
- `"schemaVersion": "MAJOR.MINOR"` — readers accept any `1.x` and must ignore unknown fields.
  Minor versions only add optional fields. A major version change means an incompatible format;
  `tracepot report` and the GUI refuse documents with an unknown major version.
- Missing values are explicit `null`s; absent optional sections (for example `input.archive` for a
  script) are `null`, never omitted.

## Top-level fields

| Field | Content |
| --- | --- |
| `application` | `name` (`"TracePot"`) and `version`. |
| `analysisId` | Unique ID, also the report file name. |
| `disclaimer` | States that the report describes observations and does not certify safety. |
| `timing` | `startedAt`, `finishedAt` (ISO 8601 UTC) and `durationSeconds` of the whole analysis. |
| `input` | File name, SHA-256, size, `kind` (`shell-script`, `tar-archive`), format, interpreter, executed `entryPoint` (sandbox path), arguments, names of extra environment variables (never values), and for archives the extracted member list. |
| `sandbox` | Backend and version, namespaces, simulated user and UID, seccomp rules, read-only and writable sandbox paths, the host paths writable by the sandbox (all inside the workspace), limits and how they are enforced, tracer name/version, whether TracePot ran as root. |
| `networkPolicy` | Mode (`isolated`), description, whether external connectivity / DNS resolution were possible (both `false`), how network activity was observed. |
| `execution` | `terminationReason` (`exited`, `signaled`, `timeout`, `cancelled`, `resource-limit`, `launch-failed`, `not-started`), `exitCode`, terminating `signal`, `detail`, execution time, and bounded, sanitized stdout/stderr excerpts (stderr also contains launcher diagnostics). |
| `processes` | One record per process: PID (as seen by the tracer), parent PID or `null`, start/end times (Unix epoch seconds), every `exec` with path, argv and outcome, exit code or signal, thread count, and `terminatedAtTeardown` for processes killed because the run ended. |
| `events` | Chronological syscall-level timeline: process spawn/exec, file writes (open with write intent), deletes, renames, directory creation/removal, symlinks, hard links, permission and ownership changes, truncation, sensitive reads, network connect/bind/listen. Each has `outcome` and the `error` name when it failed. |
| `filesystemChanges` | `created` / `modified` / `deleted` entries from the before/after comparison, with changed `aspects` (`content`, `size`, `permissions`, `ownership`, `link-target`, `type`, `timestamps`), before/after metadata (type, octal `mode`, uid/gid as seen in the sandbox, size, mtime, SHA-256 or the reason it is missing, link target), a unified `textDiff` for small text files, the PIDs the trace saw modifying the path, and the sandbox `area`. |
| `networkEvents` | `dns-query` (decoded name and type), `connect`, `datagram`, `bind`, `listen`, `local-socket`, and `inferred-destination` (URLs from command lines; credentials redacted), each with `evidence` and `source`. |
| `persistence` | Inferred classifications: category, scope (`user`/`system`), path, action, outcome (`applied-in-sandbox`, `attempt-failed (ERRNO)`, `attempt-observed`, `command-executed`, `command-failed`), rule, description, the observation sources it is based on, PIDs. |
| `resourceLimitEvents` | Limits that were hit: `wall-clock-timeout`, `disk`, `file-count`, `trace-size`, `file-size` (SIGXFSZ), `cpu-time`, `process-count` (fork failed with EAGAIN). |
| `hostIntegrity` | Host persistence locations compared before and after the run (host paths), number of entries compared, changes found, and a note. Changes are reported but not attributed to the sample. |
| `statistics` | Trace lines parsed/unparsed, trace bytes, recorded and dropped events, read-only opens, snapshot sizes, bytes hashed. |
| `diagnostics` | `severity` (`info`, `warning`, `error`) and `kind` (`limitation`, `warning`, `error`, `note`) with a stable `code` and message. Limitations describe what the analysis could not observe. |

## Reading outcomes

- `success` — the operation completed (for network events: a completed TCP connection or a local
  socket; under the isolated policy only services inside the sandbox are reachable).
- `failed` — the syscall returned an error, given in `error` (for example `EROFS`,
  `ENETUNREACH`).
- `unknown` — the result was not observable: DNS queries and datagrams handed to the kernel,
  UDP `connect()` associations, non-blocking connects still in progress, inferred destinations.

## Example (abridged)

```json
{
  "schema": "tracepot-report",
  "schemaVersion": "1.0",
  "application": { "name": "TracePot", "version": "0.1.0" },
  "input": { "fileName": "demo-installer.sh", "kind": "shell-script", "entryPoint": "/work/demo-installer.sh" },
  "execution": { "terminationReason": "exited", "exitCode": 3, "signal": null },
  "persistence": [
    { "category": "shell-startup", "scope": "user", "path": "/home/tracepot/.bashrc",
      "action": "modified", "outcome": "applied-in-sandbox", "evidence": "inferred",
      "basis": ["filesystem-diff", "syscall-trace"] },
    { "category": "cron", "scope": "system", "path": "/etc/cron.d/demo",
      "action": "write-attempt", "outcome": "attempt-failed (EROFS)", "evidence": "inferred",
      "basis": ["syscall-trace"] }
  ],
  "networkEvents": [
    { "kind": "dns-query", "hostname": "updates.example.invalid", "address": "127.0.0.1", "port": 53,
      "outcome": "unknown", "evidence": "observed" },
    { "kind": "connect", "protocol": "tcp", "address": "198.51.100.7", "port": 443,
      "outcome": "failed", "error": "ENETUNREACH", "evidence": "observed" }
  ]
}
```

A complete sample is in [`tests/fixtures/sample-report.json`](../tests/fixtures/sample-report.json).
