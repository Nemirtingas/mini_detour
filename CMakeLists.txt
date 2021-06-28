project(mini_detour)
cmake_minimum_required(VERSION 3.0)

if(WIN32) # Setup some variables for Windows build
  if(MSVC) # If building with MSVC
	option(STATIC_MSVCRT "Static link the MSVC runtime" ON)
	
    if(STATIC_MSVCRT)
      set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
      foreach(CompilerFlag ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
      endforeach()
    endif()
  endif()

elseif(APPLE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
  
elseif(UNIX)

else()
  message(FATAL_ERROR "No CMake for other platforms")

endif()

set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(USE_SPDLOG "Enable logs with SPDLOG" OFF)
option(BUILD_TESTS "Build tests" OFF)
option(LOCAL_INSTALL "Install on local folder instead of system directories" ON)

if(LOCAL_INSTALL)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

add_library(
  ${PROJECT_NAME}
  src/mini_detour.cpp
)

target_link_libraries(
  ${PROJECT_NAME}
  PUBLIC
  $<$<BOOL:${USE_SPDLOG}>:spdlog::spdlog>
  
  # For library UNIX loading
  $<$<NOT:$<BOOL:${WIN32}>>:dl>
)

target_include_directories(
  ${PROJECT_NAME}
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_compile_definitions(
  ${PROJECT_NAME}
  PRIVATE
  $<$<BOOL:${USE_SPDLOG}>:USE_SPDLOG>
)


if(BUILD_TESTS)

add_executable(
  tests
  tests/test.cpp
)

target_link_libraries(
  tests
  PUBLIC
  ${PROJECT_NAME}
)

target_include_directories(
  tests
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

endif()

install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-targets
    RUNTIME DESTINATION "bin"
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib"
)

install(
    EXPORT
        ${PROJECT_NAME}-targets
    NAMESPACE
        ${PROJECT_NAME}::
    DESTINATION
        "lib/${PROJECT_NAME}"
)