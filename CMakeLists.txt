cmake_minimum_required(VERSION 3.20)

project(lantern VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include(cmake/Dependencies.cmake)

add_library(lantern STATIC
    src/client.c
    src/genesis.c
    src/enr.c
    src/rlp.c
    src/string_list.c
    src/internal/strings.c
    src/internal/yaml_parser.c
    external/c-libp2p/src/multiformats/multibase/encoding/base64_url.c
)

target_include_directories(lantern
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)

lantern_configure_dependencies(lantern)

add_executable(lantern_cli src/main.c)
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
endif()
