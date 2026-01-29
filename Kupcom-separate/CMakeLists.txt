cmake_minimum_required(VERSION 3.10)
project(kupcom)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(extern/mcl)

add_executable(kupcom
    src/main.cpp
    src/commit.cpp
    src/poly_utils.cpp
    src/eval.cpp
    src/check.cpp
    src/kgen.cpp
    src/update.cpp
    src/verify_update.cpp
)

target_include_directories(kupcom PRIVATE
    extern/mcl/include
)

target_link_libraries(kupcom
    mcl
)
