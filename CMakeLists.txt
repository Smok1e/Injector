cmake_minimum_required (VERSION 3.22)

if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/ArgParser/CMakeLists.txt")
	message(FATAL_ERROR "external/ArgParser does not contains CMakeLists.txt; Perhaps you forgot to do git submodule init && git submodule update?")
endif ()

project(Injector)

set(CMAKE_CXX_STANDARD            20  )
set(CMAKE_CXX_STANDARD_REQUIRED   True)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON  )

add_executable(
	injector
	src/Main.cpp
)

add_subdirectory(external/ArgParser)
target_link_libraries(injector PRIVATE ArgParser)