cmake_minimum_required(VERSION 3.15)
project(x2s C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(EXTERNAL_INSTALL_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/external")
file(MAKE_DIRECTORY "${EXTERNAL_INSTALL_LOCATION}")

# Pin cJSON to a specific release tag for reproducible builds
set(CJSON_VERSION "v1.7.19")
set(_cjson_h "${EXTERNAL_INSTALL_LOCATION}/cJSON.h")
set(_cjson_c "${EXTERNAL_INSTALL_LOCATION}/cJSON.c")

if(NOT EXISTS "${_cjson_h}")
  file(DOWNLOAD
      "https://raw.githubusercontent.com/DaveGamble/cJSON/${CJSON_VERSION}/cJSON.h"
      "${_cjson_h}"
      SHOW_PROGRESS
      STATUS status
      INACTIVITY_TIMEOUT 60
      # SHA256 hash for cJSON.h v1.7.19
      EXPECTED_HASH SHA256=25b0145150d500498e4d209cec69c18c42cf818bffcc54690be3b895a2a16dee
  )
  list(GET status 0 status_code)
  if(NOT status_code EQUAL 0)
      message(FATAL_ERROR "Failed to download cJSON.h: ${status}")
  endif()
endif()

if(NOT EXISTS "${_cjson_c}")
  file(DOWNLOAD
      "https://raw.githubusercontent.com/DaveGamble/cJSON/${CJSON_VERSION}/cJSON.c"
      "${_cjson_c}"
      SHOW_PROGRESS
      STATUS status
      INACTIVITY_TIMEOUT 60
      # SHA256 hash for cJSON.c v1.7.19
      EXPECTED_HASH SHA256=298581a04a36c0165da4b0aade235c23088cb2faa58651d720ea2f3706ed0b0d
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
    src/cli/main.c
    src/core/hex_utils.c
    src/server/api_server.c
    src/auth/auth.c
    src/config/cli_setup.c
    src/format/format_v1.c
    src/format/format_v2.c
    src/storage/object_repository.c
    src/storage/object_permissions.c
    src/storage/object_index.c
    src/storage/object_io.c
    src/crypto/object_crypto.c
    src/crypto/encryption.c
    src/storage/object_serialization.c
    src/server/http_utils.c
    src/server/mime_types.c
    src/server/rate_limiter.c
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

add_executable(x2s-migrate
    src/cli/migrate.c
    src/core/hex_utils.c
    src/auth/auth.c
    src/format/format_v1.c
    src/format/format_v2.c
    src/storage/object_io.c
    src/crypto/object_crypto.c
    src/crypto/encryption.c
    src/storage/object_serialization.c
    ${_cjson_c}
)

target_include_directories(x2s-migrate PRIVATE
    src
    ${EXTERNAL_INSTALL_LOCATION}
)

target_link_libraries(x2s-migrate PRIVATE
    OpenSSL::Crypto
)

target_compile_options(x2s-migrate PRIVATE
    -Wall -Wextra -Wpedantic
)

# Propagate any pkg-config compile flags (e.g. -D_REENTRANT on some distros)
target_compile_options(x2s PRIVATE
    -Wall -Wextra -Wpedantic
    ${MHD_CFLAGS_OTHER}
)