add_executable(tracepot_cli main.cpp CliOptions.cpp)
set_target_properties(tracepot_cli PROPERTIES OUTPUT_NAME tracepot)
target_link_libraries(tracepot_cli PRIVATE tracepot_core)
tracepot_configure_target(tracepot_cli)
add_dependencies(tracepot_cli tracepot_limits)

install(TARGETS tracepot_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
