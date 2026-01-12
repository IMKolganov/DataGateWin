cmake_minimum_required(VERSION 3.22)
project(DataGateWin LANGUAGES C CXX)

# Optional but recommended: do not build tests by default in superbuilds
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

add_subdirectory(openvpn3 EXCLUDE_FROM_ALL)
add_subdirectory(engine)
