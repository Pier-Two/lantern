cmake_minimum_required(VERSION 3.20)

project(lantern VERSION 0.1.0 LANGUAGES C)

set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

if(APPLE)
    set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "Target architecture for macOS builds" FORCE)
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include(cmake/Dependencies.cmake)

set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)


add_library(lantern STATIC
    src/consensus/containers.c
    src/consensus/signature.c
    src/consensus/state.c
    src/consensus/ssz.c
    src/core/client.c
    src/genesis/genesis.c
    src/encoding/snappy.c
    src/networking/enr.c
    src/networking/gossip.c
    src/networking/libp2p.c
    src/networking/messages.c
    src/encoding/rlp.c
    src/support/string_list.c
    src/support/strings.c
    src/internal/yaml_parser.c
    external/c-libp2p/src/multiformats/multibase/encoding/base64_url.c
    external/c-libp2p/external/wjcryptlib/lib/WjCryptLib_Sha256.c
)

target_include_directories(lantern
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/external/c-libp2p/external/secp256k1/include
        ${PROJECT_SOURCE_DIR}/external/c-libp2p/external/libtomcrypt/src/headers
        ${PROJECT_SOURCE_DIR}/external/c-libp2p/external/wjcryptlib/lib
)

lantern_configure_dependencies(lantern)
target_link_libraries(lantern PRIVATE secp256k1 libtomcrypt)

add_executable(lantern_cli src/core/main.c)
target_link_libraries(lantern_cli PRIVATE lantern)

option(LANTERN_BUILD_TESTS "Build lantern unit tests" ON)
if(LANTERN_BUILD_TESTS)
    enable_testing()
    add_executable(lantern_client_test tests/unit/test_client.c)
    target_link_libraries(lantern_client_test PRIVATE lantern)
    target_compile_definitions(lantern_client_test PRIVATE LANTERN_TEST_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures")
    add_test(NAME lantern_client COMMAND lantern_client_test)

    add_executable(lantern_rlp_test tests/unit/test_rlp.c)
    target_link_libraries(lantern_rlp_test PRIVATE lantern)
    add_test(NAME lantern_rlp COMMAND lantern_rlp_test)

    add_executable(lantern_enr_test tests/unit/test_enr.c)
    target_link_libraries(lantern_enr_test PRIVATE lantern)
    add_test(NAME lantern_enr COMMAND lantern_enr_test)

    add_executable(lantern_ssz_test tests/unit/test_ssz.c)
    target_link_libraries(lantern_ssz_test PRIVATE lantern)
    add_test(NAME lantern_ssz COMMAND lantern_ssz_test)

    add_executable(lantern_snappy_test tests/unit/test_snappy.c)
    target_link_libraries(lantern_snappy_test PRIVATE lantern)
    add_test(NAME lantern_snappy COMMAND lantern_snappy_test)

    add_executable(lantern_networking_messages_test tests/unit/test_networking_messages.c)
    target_link_libraries(lantern_networking_messages_test PRIVATE lantern)
    add_test(NAME lantern_networking_messages COMMAND lantern_networking_messages_test)
endif()
