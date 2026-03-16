cmake_minimum_required(VERSION 3.20)

project(VMPilot-crypto)

set(CMAKE_CXX_STANDARD 20)

# Setup default variables
# Set default values for compile options
set(CRYPTO_LIB "Botan" CACHE STRING "The backend crypto library")
set_property(CACHE CRYPTO_LIB PROPERTY STRINGS "Botan" "OpenSSL" "libsodium")

set(CMAKE_LINKER "ld" CACHE STRING "The linker")
set_property(CACHE CMAKE_LINKER PROPERTY STRINGS "ld" "mold" "lld" "gold")

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -O0 -g --static)
endif ()

if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /WX /Od /Zi /EHsc")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX /Od /Zi /EHsc")
endif ()

include(cmake/CPM.cmake)

# Add subdirectories
add_subdirectory(src)

# Add test
add_subdirectory(test)

# Expose include directory to other subprojects through cache variable
set(CRYPTO_INCLUDE_DIR ${CRYPTO_INCLUDE_DIRS} CACHE INTERNAL "Directory of crypto include files")
