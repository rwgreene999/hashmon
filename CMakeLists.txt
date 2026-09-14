cmake_minimum_required(VERSION 3.16)
project(hashmon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

set(HASHMON_SOURCES
    src/main.cpp
    src/cli.cpp
    src/hash_utils.cpp
    src/hashes/md5.cpp
    src/hashes/sha1.cpp
    src/hashes/sha256.cpp
    src/hashes/sha224.cpp
    src/hashes/sha384.cpp
    src/hashes/sha512.cpp
    src/hashes/crc32.cpp
    src/hashes/crc64.cpp
)

add_executable(hashmon ${HASHMON_SOURCES})
target_include_directories(hashmon PRIVATE src src/hashes)
target_link_libraries(hashmon PRIVATE crypto)
target_compile_features(hashmon PRIVATE cxx_std_17)

set(HASH_TEST_SOURCES
    tests/hash_tests.cpp
    src/hash_utils.cpp
    src/hashes/md5.cpp
    src/hashes/sha1.cpp
    src/hashes/sha256.cpp
    src/hashes/sha224.cpp
    src/hashes/sha384.cpp
    src/hashes/sha512.cpp
    src/hashes/crc32.cpp
    src/hashes/crc64.cpp
)

add_executable(hash_tests ${HASH_TEST_SOURCES})
target_include_directories(hash_tests PRIVATE src src/hashes)
target_link_libraries(hash_tests PRIVATE crypto)
target_compile_features(hash_tests PRIVATE cxx_std_17)

set(CLI_TEST_SOURCES
    tests/cli_tests.cpp
    src/cli.cpp
    src/hash_utils.cpp
    src/hashes/md5.cpp
    src/hashes/sha1.cpp
    src/hashes/sha256.cpp
    src/hashes/sha224.cpp
    src/hashes/sha384.cpp
    src/hashes/sha512.cpp
    src/hashes/crc32.cpp
    src/hashes/crc64.cpp
)

add_executable(cli_tests ${CLI_TEST_SOURCES})
target_include_directories(cli_tests PRIVATE src src/hashes)
target_link_libraries(cli_tests PRIVATE crypto)
target_compile_features(cli_tests PRIVATE cxx_std_17)

add_test(NAME hash_tests COMMAND hash_tests)
add_test(NAME cli_tests COMMAND cli_tests)
