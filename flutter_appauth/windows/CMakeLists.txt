cmake_minimum_required(VERSION 3.15)
set(PROJECT_NAME "flutter_appauth")
project(${PROJECT_NAME} LANGUAGES CXX)

find_program(NUGET_EXE nuget)
if(NOT NUGET_EXE)
	message("NUGET.EXE not found.")
	message(FATAL_ERROR "Please install this executable, and run CMake again.")
endif()


exec_program(nuget
    ARGS install "Microsoft.Web.WebView2" -Version 0.9.579 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
exec_program(nuget
    ARGS install "Microsoft.Windows.ImplementationLibrary" -Version 1.0.200519.2 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)


# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "flutter_appauth_plugin")
if(APPLE)
	set(WEBVIEW_COMPILE_DEFS "-DWEBVIEW_MAC=1")
	find_library(COCOA_LIBRARY Cocoa)
	find_library(WEBKIT_LIBRARY Webkit)
	set(WEBVIEW_LIBS ${COCOA_LIBRARY} ${WEBKIT_LIBRARY})
	set(WEBVIEW_COMPILE_OPTS "-ObjC++")
elseif(WIN32)
	set(WEBVIEW_COMPILE_DEFS "-DWEBVIEW_WIN=1")
	#set(WEBVIEW_LIBS "WindowsApp.lib user32.lib kernel32.lib") 
else()
	set(WEBVIEW_COMPILE_DEFS "-DWEBVIEW_GTK=1")
	find_package(PkgConfig REQUIRED)
	pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
	pkg_check_modules(WEBKIT2 REQUIRED webkit2gtk-4.0)
	set(WEBVIEW_COMPILE_INCS ${GTK3_INCLUDE_DIRS} ${WEBKIT2_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR})
	set(WEBVIEW_LIBS ${GTK3_LIBRARIES} ${WEBKIT2_LIBRARIES})
endif()


add_library(${PLUGIN_NAME} SHARED
  "flutter_appauth_plugin.cpp"
   "webview/webview.hpp"
)
apply_standard_settings(${PLUGIN_NAME})
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)

target_link_libraries(${PLUGIN_NAME} PRIVATE ${CMAKE_BINARY_DIR}/packages/Microsoft.Web.WebView2/build/native/Microsoft.Web.WebView2.targets)
target_link_libraries(${PLUGIN_NAME} PRIVATE ${CMAKE_BINARY_DIR}/packages/Microsoft.Windows.ImplementationLibrary/build/native/Microsoft.Windows.ImplementationLibrary.targets)  

target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
target_compile_definitions(${PLUGIN_NAME} INTERFACE ${WEBVIEW_COMPILE_DEFS})
target_compile_features(${PLUGIN_NAME} INTERFACE cxx_std_17)
target_compile_options(${PLUGIN_NAME} INTERFACE ${WEBVIEW_COMPILE_OPTS})
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(${PLUGIN_NAME} INTERFACE ${PROJECT_SOURCE_DIR} ${WEBVIEW_COMPILE_INCS})
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin)
target_link_libraries(${PLUGIN_NAME} INTERFACE ${WEBVIEW_LIBS})

exec_program(nuget ARGS restore)

# List of absolute paths to libraries that should be bundled with the plugin
set(flutter_appauth_bundled_libraries
  ""
  PARENT_SCOPE
)
# set_property(TARGET flutter_appauth_plugin
#   PROPERTY VS_PACKAGE_REFERENCES "Microsoft.Web.WebView2.0.9.538"
# )
# set_property(TARGET flutter_appauth_plugin
#   PROPERTY VS_PACKAGE_REFERENCES "Microsoft.Windows.ImplementationLibrary.1.0.200519.2"
# )