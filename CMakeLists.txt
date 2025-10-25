cmake_minimum_required(VERSION 3.20)

project(lantern VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include(cmake/Dependencies.cmake)

add_library(lantern STATIC
    src/client.c
)

target_include_directories(lantern
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

lantern_configure_dependencies(lantern)

add_executable(lantern_cli src/main.c)
target_link_libraries(lantern_cli PRIVATE lantern)

option(LANTERN_BUILD_TESTS "Build lantern unit tests" ON)
if(LANTERN_BUILD_TESTS)
    enable_testing()
    add_executable(lantern_client_test tests/unit/test_client.c)
    target_link_libraries(lantern_client_test PRIVATE lantern)
    add_test(NAME lantern_client COMMAND lantern_client_test)
endif()
