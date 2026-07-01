cmake_minimum_required(VERSION 3.15)
project(x2s C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

# libmicrohttpd does not ship a CMake config file, so we locate it with
# pkg-config. CMake 3.15+ always has FindPkgConfig available on Linux/macOS.
find_package(PkgConfig REQUIRED)
pkg_check_modules(MHD REQUIRED libmicrohttpd)

add_executable(x2s
    src/main.c
    src/obj_operations.c
    src/api_server.c
    src/auth.c
    src/obj_helpers.c
    src/api_helpers.c
    src/cli_setup.c
)

target_include_directories(x2s PRIVATE
    src
    ${MHD_INCLUDE_DIRS}
)

target_link_libraries(x2s PRIVATE
    OpenSSL::Crypto
    ${MHD_LIBRARIES}
)

# Propagate any pkg-config compile flags (e.g. -D_REENTRANT on some distros)
target_compile_options(x2s PRIVATE
    -Wall -Wextra -Wpedantic
    ${MHD_CFLAGS_OTHER}
)