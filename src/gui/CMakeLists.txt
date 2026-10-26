set(CMAKE_AUTOMOC ON)

# Shared by the GUI executable and the GUI tests.
add_library(tracepot_gui_lib STATIC
    AnalysisWorker.cpp
    AnalysisWorker.hpp
    MainWindow.cpp
    MainWindow.hpp
    models/RecordTableModel.cpp
    models/RecordTableModel.hpp
    widgets/ResultsView.cpp
    widgets/ResultsView.hpp
)
target_link_libraries(tracepot_gui_lib PUBLIC tracepot_core Qt6::Widgets)
tracepot_configure_target(tracepot_gui_lib)

add_executable(tracepot_gui main.cpp)
set_target_properties(tracepot_gui PROPERTIES OUTPUT_NAME tracepot-gui)
target_link_libraries(tracepot_gui PRIVATE tracepot_gui_lib)
tracepot_configure_target(tracepot_gui)
add_dependencies(tracepot_gui tracepot_limits)

install(TARGETS tracepot_gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
