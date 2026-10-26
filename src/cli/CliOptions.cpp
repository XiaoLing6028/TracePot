#include "cli/CliOptions.hpp"

#include "core/models/Limits.hpp"

#include <charconv>

namespace tracepot::cli {

namespace {

Result<std::uint64_t> parseUnsigned(const std::string& option, const std::string& text, std::uint64_t max)
{
    std::uint64_t value = 0;
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value);
    if (text.empty() || ec != std::errc() || ptr != end || value > max) {
        return makeError(ErrorCode::InvalidArgument,
                         "invalid value for " + option + ": '" + text + "' (expected 0.." + std::to_string(max) + ")");
    }
    return value;
}

}  // namespace

std::string usageText()
{
    return R"(Usage:
  tracepot check [--json]
  tracepot analyze <input> [options] [-- <script arguments>...]
  tracepot report <report.json> [--html <file>] [--json] [--details]
  tracepot version
  tracepot help

Analyze options:
  --timeout <seconds>           Wall-clock limit for the sandboxed run (default 120)
  --entry <path>                Script inside a tar archive to execute (default: auto-detect
                                install.sh, setup.sh, installer.sh or install)
  --arg <value>                 Argument passed to the script (repeatable)
  --env <NAME=VALUE>            Environment variable for the script (repeatable; only names are
                                written to reports)
  --as-root                     Simulate the root user inside the sandbox (no host privileges)
  --memory <MiB>                Address-space limit per process (default 2048, 0 = none)
  --max-processes <n>           Additional processes allowed (default 256, 0 = none)
  --max-file-size <MiB>         Maximum size of a single written file (default 512, 0 = none)
  --max-disk <MiB>              Maximum workspace growth (default 1024, 0 = none)
  --persistence-pattern <glob>  Extra path pattern to classify as persistence (repeatable;
                                '~/' matches any home directory)
  --output <dir>                Directory for reports (default ./tracepot-results)
  --no-html                     Do not write the HTML report
  --keep-workspace              Keep the analysis workspace for manual inspection
  --allow-untraced              Run even if strace is unavailable (filesystem diff only)
  --quiet                       Do not print progress

Exit codes:
  0 success   1 usage error   2 input rejected or invalid report   3 sandbox/tracer unavailable
  4 analysis failed   5 interrupted   6 report written but the sample was stopped by a limit
)";
}

Result<Options> parseCommandLine(const std::vector<std::string>& args)
{
    Options options;
    if (args.empty()) {
        options.command = Command::Help;
        return options;
    }
    const std::string& command = args.front();
    if (command == "help" || command == "--help" || command == "-h") {
        options.command = Command::Help;
        return options;
    }
    if (command == "version" || command == "--version") {
        options.command = Command::Version;
        return options;
    }
    std::vector<std::string> positional;
    auto& config = options.analysis;
    for (std::size_t i = 1; i < args.size(); ++i) {
        const std::string& arg = args[i];
        auto value = [&](const std::string& name) -> Result<std::string> {
            if (i + 1 >= args.size()) {
                return makeError(ErrorCode::InvalidArgument, "missing value for " + name);
            }
            return args[++i];
        };
        auto number = [&](const std::string& name, std::uint64_t max) -> Result<std::uint64_t> {
            auto text = value(name);
            if (!text) {
                return text.error();
            }
            return parseUnsigned(name, text.value(), max);
        };
#define TRACEPOT_TRY(var, expr)        \
    auto var = (expr);                 \
    if (!var) {                        \
        return var.error();            \
    }
        if (arg == "--") {
            if (command != "analyze") {
                return makeError(ErrorCode::InvalidArgument, "'--' is only valid for analyze");
            }
            config.arguments.insert(config.arguments.end(), args.begin() + static_cast<long>(i) + 1, args.end());
            break;
        }
        if (arg == "--json") {
            options.json = true;
        } else if (arg == "--details") {
            options.details = true;
        } else if (arg == "--quiet") {
            options.quiet = true;
        } else if (arg == "--html") {
            TRACEPOT_TRY(path, value(arg));
            options.htmlOutput = path.value();
        } else if (arg == "--timeout") {
            TRACEPOT_TRY(n, number(arg, 86400));
            if (n.value() == 0) {
                return makeError(ErrorCode::InvalidArgument, "--timeout must be at least 1 second");
            }
            config.limits.timeoutSeconds = static_cast<int>(n.value());
        } else if (arg == "--entry") {
            TRACEPOT_TRY(entry, value(arg));
            config.entryPoint = entry.value();
        } else if (arg == "--arg") {
            TRACEPOT_TRY(a, value(arg));
            config.arguments.push_back(a.value());
        } else if (arg == "--env") {
            TRACEPOT_TRY(kv, value(arg));
            const auto eq = kv.value().find('=');
            if (eq == std::string::npos || eq == 0) {
                return makeError(ErrorCode::InvalidArgument, "--env expects NAME=VALUE");
            }
            config.environment.emplace_back(kv.value().substr(0, eq), kv.value().substr(eq + 1));
        } else if (arg == "--as-root") {
            config.user = SandboxUser::SimulatedRoot;
        } else if (arg == "--memory") {
            TRACEPOT_TRY(n, number(arg, 1024ULL * 1024));
            config.limits.memoryBytes = n.value() * MiB;
        } else if (arg == "--max-processes") {
            TRACEPOT_TRY(n, number(arg, 100000));
            config.limits.maxProcesses = static_cast<std::uint32_t>(n.value());
        } else if (arg == "--max-file-size") {
            TRACEPOT_TRY(n, number(arg, 1024ULL * 1024));
            config.limits.maxFileSizeBytes = n.value() * MiB;
        } else if (arg == "--max-disk") {
            TRACEPOT_TRY(n, number(arg, 1024ULL * 1024));
            config.limits.maxDiskBytes = n.value() * MiB;
        } else if (arg == "--persistence-pattern") {
            TRACEPOT_TRY(p, value(arg));
            if (p.value().empty() || (p.value().front() != '/' && p.value().rfind("~/", 0) != 0)) {
                return makeError(ErrorCode::InvalidArgument, "--persistence-pattern must start with '/' or '~/'");
            }
            config.extraPersistencePatterns.push_back(p.value());
        } else if (arg == "--output") {
            TRACEPOT_TRY(dir, value(arg));
            options.outputDir = dir.value();
        } else if (arg == "--no-html") {
            options.writeHtml = false;
        } else if (arg == "--keep-workspace") {
            config.keepWorkspace = true;
        } else if (arg == "--allow-untraced") {
            config.requireTracing = false;
        } else if (!arg.empty() && arg.front() == '-' && arg != "-") {
            return makeError(ErrorCode::InvalidArgument, "unknown option " + arg);
        } else {
            positional.push_back(arg);
        }
#undef TRACEPOT_TRY
    }

    if (command == "check") {
        options.command = Command::Check;
        if (!positional.empty()) {
            return makeError(ErrorCode::InvalidArgument, "check takes no arguments");
        }
    } else if (command == "analyze") {
        options.command = Command::Analyze;
        if (positional.size() != 1) {
            return makeError(ErrorCode::InvalidArgument, "analyze expects exactly one input file");
        }
        config.inputPath = positional.front();
    } else if (command == "report") {
        options.command = Command::Report;
        if (positional.size() != 1) {
            return makeError(ErrorCode::InvalidArgument, "report expects exactly one report file");
        }
        options.reportPath = positional.front();
    } else {
        return makeError(ErrorCode::InvalidArgument, "unknown command '" + command + "'");
    }
    return options;
}

}  // namespace tracepot::cli
