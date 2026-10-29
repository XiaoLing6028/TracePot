cmake_minimum_required(VERSION 3.22)

project(TracePot
    VERSION 0.1.0
    DESCRIPTION "Linux installer behavior analysis tool"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "TracePot only supports Linux (namespaces, ptrace and seccomp are required).")
endif()

option(TRACEPOT_BUILD_GUI "Build the TracePot Qt6 Widgets application" ON)
option(TRACEPOT_ENABLE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(TRACEPOT_ENABLE_CLANG_TIDY "Run clang-tidy during the build" OFF)
option(TRACEPOT_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

include(CTest)
include(GNUInstallDirs)
include(cmake/TracePotCompilerOptions.cmake)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSECCOMP REQUIRED IMPORTED_TARGET libseccomp)
find_package(LibArchive 3.3 REQUIRED)
find_package(OpenSSL 1.1 REQUIRED COMPONENTS Crypto)
find_package(nlohmann_json 3.9 REQUIRED)

if(TRACEPOT_BUILD_GUI OR BUILD_TESTING)
    set(TRACEPOT_QT_COMPONENTS Core)
    if(TRACEPOT_BUILD_GUI)
        list(APPEND TRACEPOT_QT_COMPONENTS Widgets)
    endif()
    if(BUILD_TESTING)
        list(APPEND TRACEPOT_QT_COMPONENTS Test)
    endif()
    find_package(Qt6 6.2 REQUIRED COMPONENTS ${TRACEPOT_QT_COMPONENTS})
endif()

if(TRACEPOT_ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
    set(TRACEPOT_CLANG_TIDY_COMMAND ${CLANG_TIDY_EXE})
endif()

add_subdirectory(src/core)
add_subdirectory(src/helper)
add_subdirectory(src/cli)
if(TRACEPOT_BUILD_GUI)
    add_subdirectory(src/gui)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

install(FILES schemas/tracepot-report-1.schema.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/tracepot/schemas)
install(FILES README.md LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
if(TRACEPOT_BUILD_GUI)
    install(FILES data/tracepot.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
    install(FILES data/tracepot.svg DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)
endif()
