set(CMAKE_AUTOMOC ON)

add_library(tracepot_test_support STATIC common/TestSupport.cpp)
target_include_directories(tracepot_test_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(tracepot_test_support PUBLIC
    TRACEPOT_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
    TRACEPOT_SCHEMA_FILE="${PROJECT_SOURCE_DIR}/schemas/tracepot-report-1.schema.json")
target_link_libraries(tracepot_test_support PUBLIC tracepot_core Qt6::Core Qt6::Test LibArchive::LibArchive)
tracepot_configure_target(tracepot_test_support)

# tracepot_add_test(<name> SOURCES <files...> [LIBS <libs...>] [LABELS <labels...>] [TIMEOUT <s>])
function(tracepot_add_test name)
    cmake_parse_arguments(T "" "TIMEOUT" "SOURCES;LIBS;LABELS" ${ARGN})
    add_executable(${name} ${T_SOURCES})
    target_link_libraries(${name} PRIVATE tracepot_test_support ${T_LIBS})
    tracepot_configure_target(${name})
    add_dependencies(${name} tracepot_limits)
    add_test(NAME ${name} COMMAND ${name})
    if(NOT T_TIMEOUT)
        set(T_TIMEOUT 120)
    endif()
    set_tests_properties(${name} PROPERTIES
        LABELS "${T_LABELS}"
        TIMEOUT ${T_TIMEOUT}
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endfunction()

# Unit tests: no sandbox required.
tracepot_add_test(tst_sha256 SOURCES unit/tst_sha256.cpp LABELS unit)
tracepot_add_test(tst_paths SOURCES unit/tst_paths.cpp LABELS unit)
tracepot_add_test(tst_glob SOURCES unit/tst_glob.cpp LABELS unit)
tracepot_add_test(tst_snapshot_diff SOURCES unit/tst_snapshot_diff.cpp LABELS unit)
tracepot_add_test(tst_text_diff SOURCES unit/tst_text_diff.cpp LABELS unit)
tracepot_add_test(tst_input_inspector SOURCES unit/tst_input_inspector.cpp LABELS unit)
tracepot_add_test(tst_archive SOURCES unit/tst_archive.cpp LABELS unit)
tracepot_add_test(tst_persistence SOURCES unit/tst_persistence.cpp LABELS unit)
tracepot_add_test(tst_strace_parser SOURCES unit/tst_strace_parser.cpp unit/strace_samples.cpp LABELS unit)
tracepot_add_test(tst_trace_collector SOURCES unit/tst_trace_collector.cpp LABELS unit)
tracepot_add_test(tst_network SOURCES unit/tst_network.cpp LABELS unit)
tracepot_add_test(tst_report_json SOURCES unit/tst_report_json.cpp LABELS unit)
tracepot_add_test(tst_process_supervisor SOURCES unit/tst_process_supervisor.cpp LABELS unit)
tracepot_add_test(tst_bwrap_command SOURCES unit/tst_bwrap_command.cpp LABELS unit)
tracepot_add_test(tst_workspace SOURCES unit/tst_workspace.cpp LABELS unit)
tracepot_add_test(tst_cli_options
    SOURCES unit/tst_cli_options.cpp ${PROJECT_SOURCE_DIR}/src/cli/CliOptions.cpp
    LABELS unit)

# Integration tests: execute purpose-built fixtures inside the real sandbox. They are skipped
# (not failed) when `tracepot check` would report the host as not ready.
tracepot_add_test(tst_integration_analysis
    SOURCES integration/tst_integration_analysis.cpp
    LABELS integration
    TIMEOUT 600)
tracepot_add_test(tst_integration_cli
    SOURCES integration/tst_integration_cli.cpp
    LABELS integration
    TIMEOUT 300)
add_dependencies(tst_integration_cli tracepot_cli)
target_compile_definitions(tst_integration_cli PRIVATE TRACEPOT_CLI_PATH="$<TARGET_FILE:tracepot_cli>")

if(TRACEPOT_BUILD_GUI)
    tracepot_add_test(tst_gui_mainwindow
        SOURCES gui/tst_gui_mainwindow.cpp
        LIBS tracepot_gui_lib Qt6::Widgets
        LABELS gui
        TIMEOUT 300)
endif()
