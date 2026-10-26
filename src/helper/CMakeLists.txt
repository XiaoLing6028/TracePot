add_executable(tracepot_limits limits_main.cpp)
set_target_properties(tracepot_limits PROPERTIES OUTPUT_NAME tracepot-limits)
tracepot_configure_target(tracepot_limits)

install(TARGETS tracepot_limits RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/tracepot)
