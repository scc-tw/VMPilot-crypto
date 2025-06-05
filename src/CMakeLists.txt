set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../)

if(NOT CRYPTO_LIB)
    message(FATAL_ERROR "CRYPTO_LIB is not defined")
endif()

function(add_blake3)
    CPMAddPackage(
        NAME BLAKE3-cmake
        GITHUB_REPOSITORY 25077667/BLAKE3-cmake
        GIT_TAG 1.4.0
    )
    set(BLAKE3_INCLUDE_DIR ${CMAKE_BINARY_DIR}/_deps/blake3-src/c/)
    if(MSVC)
        set(BLAKE3_LIBRARY ${CMAKE_BINARY_DIR}/_deps/blake3-build/blake3.lib)
    else()
        set(BLAKE3_LIBRARY ${CMAKE_BINARY_DIR}/_deps/blake3-build/libblake3.a)
    endif()

    # Instead of add_library, use add_library with IMPORTED STATIC option to specify static linking.
    add_library(blake3_staticlib STATIC IMPORTED)
    set_target_properties(blake3_staticlib PROPERTIES IMPORTED_LOCATION ${BLAKE3_LIBRARY})

    set(INCLUDE_DIRS ${INCLUDE_DIRS} ${BLAKE3_INCLUDE_DIR} PARENT_SCOPE)
    set(THIRD_PARTY_LIBS ${THIRD_PARTY_LIBS} blake3_staticlib PARENT_SCOPE)  # Use target name here instead of library path
endfunction(add_blake3)

function(add_botan)
    set(SOURCE_FILES botan.cpp PARENT_SCOPE)
    # Add botan as a dependency
    CPMAddPackage(
        NAME botan-cmake
        GIT_TAG 3.1.1
        GITHUB_REPOSITORY "25077667/botan-cmake"
    )
    # Set botan include directory variable, link botan library
    set(BOTAN_INCLUDE_DIR ${CMAKE_BINARY_DIR}/_deps/botan-src/build/include/)
    if (MSVC)
        set(BOTAN_LIBRARY ${CMAKE_BINARY_DIR}/_deps/botan-src/botan.lib)
    else()
        set(BOTAN_LIBRARY ${CMAKE_BINARY_DIR}/_deps/botan-src/libbotan-3.a)
    endif()

    # Instead of add_library, use add_library with IMPORTED STATIC option to specify static linking.
    add_library(botan_staticlib STATIC IMPORTED)
    set_target_properties(botan_staticlib PROPERTIES IMPORTED_LOCATION ${BOTAN_LIBRARY})

    set(INCLUDE_DIRS ${INCLUDE_DIRS} ${BOTAN_INCLUDE_DIR} PARENT_SCOPE)
    set(THIRD_PARTY_LIBS ${THIRD_PARTY_LIBS} botan_staticlib PARENT_SCOPE)
endfunction(add_botan)

function(add_openssl)
    find_package(OpenSSL REQUIRED)
    set(SOURCE_FILES openssl.cpp PARENT_SCOPE)
    set(INCLUDE_DIRS ${INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} PARENT_SCOPE)
    set(THIRD_PARTY_LIBS ${THIRD_PARTY_LIBS} ${OPENSSL_LIBRARIES} PARENT_SCOPE)
endfunction(add_openssl)

function(add_sodium)
    message(STATUS "Welcome to pull request to add libsodium support")
    message(FATAL_ERROR "libsodium is not supported now")
endfunction(add_sodium)

if(CRYPTO_LIB STREQUAL "Botan")
    add_botan()
elseif(CRYPTO_LIB STREQUAL "OpenSSL")
    add_openssl()
elseif(CRYPTO_LIB STREQUAL "libsodium")
    add_sodium()
else()
    message(FATAL_ERROR "CRYPTO_LIB is not defined")
endif()

add_blake3()

include_directories(${INCLUDE_DIRS})

# Add BLAKE3 source file
set(SOURCE_FILES ${SOURCE_FILES} blake3.cpp)

# Add the library static linked to the source file
add_library(crypto STATIC ${SOURCE_FILES})

# Link third party libraries together first
# like ar rcs ${THIRD_PARTY_LIBS}
target_link_libraries(crypto PRIVATE ${THIRD_PARTY_LIBS})

# Copy crypto library to CMAKE_BINARY_DIR
add_custom_command(TARGET crypto POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:crypto> ${CMAKE_BINARY_DIR}
)

# Expose include directory to parent scope
set(CRYPTO_INCLUDE_DIRS ${INCLUDE_DIRS} PARENT_SCOPE)