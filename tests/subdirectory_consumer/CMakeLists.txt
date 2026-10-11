# Checks that adding mini_detour with add_subdirectory doesn't change the parent project settings.
#
#   cmake -S tests/subdirectory_consumer -B consumer_build
#   cmake --build consumer_build
cmake_minimum_required(VERSION 3.15)
project(mini_detour_subdirectory_consumer LANGUAGES C CXX)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../.. mini_detour)

add_executable(subdirectory_consumer main.cpp)
target_link_libraries(subdirectory_consumer PRIVATE Nemirtingas::MiniDetour)
