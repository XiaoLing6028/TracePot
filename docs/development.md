# Developing TracePot

## Setup

Install the build dependencies listed in the [README](../README.md#requirements), then:

```sh
cmake --preset debug          # build/debug, tests enabled
cmake --build --preset debug
ctest --preset debug
```

or without presets:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Check that the host can run analyses at all with `build/bin/tracepot check`.

## Build options and targets

| Option | Default | Effect |
| --- | --- | --- |
| `BUILD_TESTING` | `ON` (via CTest) | Build the Qt Test suites |
| `TRACEPOT_BUILD_GUI` | `ON` | Build `tracepot-gui` (needs Qt6 Widgets) |
| `TRACEPOT_ENABLE_SANITIZERS` | `OFF` | AddressSanitizer + UndefinedBehaviorSanitizer (`asan` preset) |
| `TRACEPOT_ENABLE_CLANG_TIDY` | `OFF` | Run clang-tidy with the repository's `.clang-tidy` during the build |
| `TRACEPOT_WARNINGS_AS_ERRORS` | `OFF` | Add `-Werror` |

| Target | Output |
| --- | --- |
| `tracepot_core` | Static core library (no Qt) |
| `tracepot_limits` | `bin/tracepot-limits`, the launcher helper (must sit next to the executables or in `libexec/tracepot`) |
| `tracepot_cli` | `bin/tracepot` |
| `tracepot_gui_lib`, `tracepot_gui` | GUI library (shared with tests) and `bin/tracepot-gui` |
| `tst_*` | Test executables in `bin/` |

All targets use `-Wall -Wextra -Wpedantic -Wshadow` and related warnings, `-fstack-protector-strong`
and `_FORTIFY_SOURCE=2` for optimized builds.

## Tests

Tests use Qt Test and are labelled:

- `unit` — pure logic, no sandbox: hashing, paths, globbing, snapshots and diffs, text diffs,
  input detection, hostile archives (generated in-test with libarchive), persistence rules, strace
  parsing (including hostile file names), trace collection on a recorded trace
  (`tests/fixtures/traces/`), DNS/URL decoding, report JSON/HTML and schema consistency, process
  supervision (timeouts, signals, group kills), bubblewrap command construction, workspaces, CLI
  options.
- `integration` — runs the fixtures in `tests/fixtures/scripts/` through the real pipeline and
  checks specific observations (file creation, modification, deletion, symlinks, permissions,
  child processes, network attempts, persistence files, timeouts, cancellation, teardown, disk and
  file-size limits, isolation from the host, malicious archives) plus the CLI's exit codes, report
  files and crash cleanup. Skipped when the host is not ready.
- `gui` — main window creation, input validation, start/cancel, progress and error presentation,
  report loading, filters/sorting, and that untrusted text is never rendered as HTML. Runs with
  `QT_QPA_PLATFORM=offscreen`.

```sh
ctest --test-dir build -L unit
ctest --test-dir build -R tst_trace_collector --output-on-failure
build/bin/tst_integration_analysis timeoutTerminatesSandbox   # a single Qt Test function
```

Sanitizers and static analysis:

```sh
cmake --preset asan && cmake --build --preset asan && ctest --preset asan
clang-tidy -p build src/core/observers/TraceCollector.cpp
```

### Fixture rules

Fixtures must be harmless and purpose-built: they may only act inside the sandbox, must use
documentation addresses (RFC 5737/3849) and reserved names (`.invalid`, `.example`) for network
attempts, and must not depend on timing in a way that makes tests flaky (wait for the observable
condition instead of sleeping). Never add real malware or exploit code to the repository, and never
write tests that modify the real host's startup configuration, services, credentials or network
settings; use temporary directories and `AnalysisConfig::hostHome` instead.

## Code layout and conventions

- C++20, namespace `tracepot` (`tracepot::gui`, `tracepot::cli` for front ends), headers next to
  sources, includes relative to `src/` (`#include "core/diff/Snapshot.hpp"`).
- `tracepot_core` must not depend on Qt; the GUI and CLI must not contain analysis logic.
- Errors are returned as `Result<T>` / `Status` with an `ErrorCode`, a message and, when possible,
  an actionable hint. Exceptions do not cross module boundaries.
- RAII for every resource (`UniqueFd`, `Workspace`, `ProcessSupervisor`); no owning raw pointers.
- Treat every byte coming from the sample (files, output, trace, archives, saved reports) as
  hostile: no symlink following, bounded reads, sanitized display, escaped HTML.
- Launch processes only through `ProcessSupervisor` with absolute paths and argument vectors.
- Never report something that was not observed: use `EvidenceKind::Inferred` for classifications,
  `Outcome::Unknown` when the result is not observable, and add a `Diagnostic` (limitation) when an
  observation is missing.

## Adding a persistence rule

Add an entry to `builtinPersistenceRules()` in `src/core/analysis/Persistence.cpp` (patterns are
globs over sandbox paths; `~/` expands to every home directory), extend the data-driven test in
`tests/unit/tst_persistence.cpp`, and, if the host should be checked too, add the location to
`hostPersistencePaths()`.

## Report schema changes

Adding optional fields is a minor version change: update `kReportSchemaMinor`, the serializer and
parser in `src/core/reporting/ReportJson.cpp`, and `schemas/tracepot-report-1.schema.json`
(`tst_report_json` checks that serializer and schema agree). Removing or changing the meaning of a
field requires a new major version and a new schema file.

## Contribution workflow

1. Create a branch, make focused changes with tests.
2. Build with warnings enabled and run `ctest`; for sandbox, parser or extraction changes also run
   the `asan` preset and the integration tests as an unprivileged user.
3. Update the documentation when behavior, limits or guarantees change — in particular
   `docs/security-model.md` must describe the actual guarantees.
4. Describe in the pull request what was tested and what could not be tested.
