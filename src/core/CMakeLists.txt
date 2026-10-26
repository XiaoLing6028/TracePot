configure_file(Version.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/generated/Version.hpp @ONLY)

add_library(tracepot_core STATIC
    models/Models.cpp
    util/FileUtil.cpp
    util/Glob.cpp
    util/PathUtil.cpp
    util/Sha256.cpp
    util/TimeUtil.cpp
    archive/EntryPoint.cpp
    archive/InputInspector.cpp
    archive/SafeExtractor.cpp
    diff/FsDiff.cpp
    diff/Snapshot.cpp
    diff/TextDiff.cpp
    sandbox/BwrapCommand.cpp
    sandbox/ProcessSupervisor.cpp
    sandbox/Readiness.cpp
    sandbox/SandboxRunner.cpp
    sandbox/SeccompFilter.cpp
    sandbox/Workspace.cpp
    observers/NetworkObserver.cpp
    observers/StraceParser.cpp
    observers/TraceCollector.cpp
    analysis/Analyzer.cpp
    analysis/Persistence.cpp
    reporting/ReportJson.cpp
    reporting/ReportRender.cpp
)

target_include_directories(tracepot_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}/generated)

# tracepot_core deliberately has no Qt dependency so the CLI and other front ends can reuse it.
target_link_libraries(tracepot_core
    PUBLIC
        nlohmann_json::nlohmann_json
    PRIVATE
        LibArchive::LibArchive
        OpenSSL::Crypto
        PkgConfig::LIBSECCOMP)

tracepot_configure_target(tracepot_core)
