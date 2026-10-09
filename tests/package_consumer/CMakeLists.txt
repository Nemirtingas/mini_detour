# Checks that an installed mini_detour can be found and used with find_package (BUGS.md #42).
#
#   cmake -S . -B build -DCMAKE_INSTALL_PREFIX=<prefix>
#   cmake --build build --target install
#   cmake -S tests/package_consumer -B consumer_build -DCMAKE_PREFIX_PATH=<prefix>
#   cmake --build consumer_build
cmake_minimum_required(VERSION 3.15)
project(mini_detour_package_consumer LANGUAGES CXX)

find_package(MiniDetour 1.1 REQUIRED)

add_executable(package_consumer main.cpp)
target_link_libraries(package_consumer PRIVATE Nemirtingas::MiniDetour)
