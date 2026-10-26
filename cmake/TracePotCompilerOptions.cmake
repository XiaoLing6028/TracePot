# Shared compiler settings for TracePot targets.

add_library(tracepot_compiler_options INTERFACE)

target_compile_options(tracepot_compiler_options INTERFACE
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wnon-virtual-dtor
    -Woverloaded-virtual
    -Wformat=2
    -Wimplicit-fallthrough
    -Wnull-dereference
    -fstack-protector-strong)

if(TRACEPOT_WARNINGS_AS_ERRORS)
    target_compile_options(tracepot_compiler_options INTERFACE -Werror)
endif()

# Hardening for optimized builds. _FORTIFY_SOURCE requires optimization.
target_compile_definitions(tracepot_compiler_options INTERFACE
    $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>)

if(TRACEPOT_ENABLE_SANITIZERS)
    target_compile_options(tracepot_compiler_options INTERFACE
        -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    target_link_options(tracepot_compiler_options INTERFACE -fsanitize=address,undefined)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Applies project-wide settings to a TracePot target.
function(tracepot_configure_target target)
    target_link_libraries(${target} PRIVATE tracepot_compiler_options)
    if(TRACEPOT_CLANG_TIDY_COMMAND)
        set_target_properties(${target} PROPERTIES CXX_CLANG_TIDY "${TRACEPOT_CLANG_TIDY_COMMAND}")
    endif()
endfunction()
