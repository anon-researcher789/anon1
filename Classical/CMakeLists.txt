cmake_minimum_required(VERSION 3.10)
find_package(OpenSSL REQUIRED)
project(kupcom)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)

add_subdirectory(extern/mcl)

add_library(kzg
    src/crypto/kzg/kgen.cpp
    src/crypto/kzg/update.cpp
    src/crypto/kzg/verify_update.cpp
    src/crypto/kzg/commit.cpp
    src/crypto/kzg/eval.cpp
    src/crypto/kzg/check.cpp
    src/crypto/kzg/poly_utils.cpp
)

target_include_directories(kzg PUBLIC src)

target_link_libraries(kzg PRIVATE OpenSSL::Crypto mcl)

add_executable(kupcom src/main.cpp src/bench/benchmark.cpp)
target_link_libraries(kupcom kzg)
add_library(snark
    src/snark/iop/prover.cpp
    src/snark/iop/verifier.cpp
)

target_link_libraries(snark PUBLIC OpenSSL::Crypto kzg)

