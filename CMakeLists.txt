cmake_minimum_required(VERSION 3.15)
project(x2s C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(EXTERNAL_INSTALL_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/external")

set(_cjson_h "${EXTERNAL_INSTALL_LOCATION}/cJSON.h")
set(_cjson_c "${EXTERNAL_INSTALL_LOCATION}/cJSON.c")

if(NOT EXISTS "${_cjson_h}")
  file(DOWNLOAD
      "https://raw.githubusercontent.com/DaveGamble/cJSON/refs/heads/master/cJSON.h"
      "${_cjson_h}"
      SHOW_PROGRESS
      STATUS status
      INACTIVITY_TIMEOUT 60
  )
  list(GET status 0 status_code)
  if(NOT status_code EQUAL 0)
      message(FATAL_ERROR "Failed to download cJSON.h: ${status}")
  endif()
endif()

if(NOT EXISTS "${_cjson_c}")
  file(DOWNLOAD
      "https://raw.githubusercontent.com/DaveGamble/cJSON/refs/heads/master/cJSON.c"
      "${_cjson_c}"
      SHOW_PROGRESS
      STATUS status
      INACTIVITY_TIMEOUT 60
  )
  list(GET status 0 status_code)
  if(NOT status_code EQUAL 0)
      message(FATAL_ERROR "Failed to download cJSON.c: ${status}")
  endif()
endif()

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
    ${_cjson_c}
)

target_include_directories(x2s PRIVATE
    src
    ${EXTERNAL_INSTALL_LOCATION}
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