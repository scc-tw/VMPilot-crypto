set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../)

if(NOT CRYPTO_LIB)
    message(FATAL_ERROR "CRYPTO_LIB is not defined")
endif()

function(add_blake3)
    # Use local BLAKE3 submodule (third_party/BLAKE3)
    set(BLAKE3_SOURCE_DIR ${CMAKE_SOURCE_DIR}/third_party/BLAKE3/c)
    set(BLAKE3_INCLUDE_DIR ${BLAKE3_SOURCE_DIR})

    # Strip MSVC-specific C/CXX flags before entering BLAKE3 so they don't
    # leak into the MASM assembler (ml64.exe doesn't understand /Od, /EHsc, etc.)
    if(MSVC)
        set(_saved_C_FLAGS "${CMAKE_C_FLAGS}")
        set(_saved_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        set(CMAKE_C_FLAGS "")
        set(CMAKE_CXX_FLAGS "")
    endif()

    # Add BLAKE3 as subdirectory when vendored, otherwise fetch it.
    if(EXISTS ${BLAKE3_SOURCE_DIR}/CMakeLists.txt)
        add_subdirectory(${BLAKE3_SOURCE_DIR} ${CMAKE_BINARY_DIR}/blake3-build EXCLUDE_FROM_ALL)
    else()
        CPMAddPackage(
            NAME blake3
            GITHUB_REPOSITORY BLAKE3-team/BLAKE3
            GIT_TAG 1.8.4
            SOURCE_SUBDIR c
        )

        set(BLAKE3_INCLUDE_DIR ${blake3_SOURCE_DIR}/c)
    endif()

    if(MSVC)
        set(CMAKE_C_FLAGS "${_saved_C_FLAGS}")
        set(CMAKE_CXX_FLAGS "${_saved_CXX_FLAGS}")
    endif()

    if(TARGET BLAKE3::blake3)
        set(BLAKE3_TARGET BLAKE3::blake3)
    elseif(TARGET blake3)
        set(BLAKE3_TARGET blake3)
    else()
        message(FATAL_ERROR "BLAKE3 source is available but no BLAKE3 target was created")
    endif()

    set(INCLUDE_DIRS ${INCLUDE_DIRS} ${BLAKE3_INCLUDE_DIR} PARENT_SCOPE)
    set(THIRD_PARTY_LIBS ${THIRD_PARTY_LIBS} ${BLAKE3_TARGET} PARENT_SCOPE)
endfunction(add_blake3)

function(add_botan)
    set(SOURCE_FILES botan.cpp PARENT_SCOPE)

    include(ExternalProject)

    set(BOTAN_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/botan)
    set(BOTAN_BUILD_DIR ${CMAKE_BINARY_DIR}/botan-build)
    set(BOTAN_INSTALL_DIR ${BOTAN_BUILD_DIR}/install)

    # Common configure arguments
    set(BOTAN_CONFIGURE_ARGS
        --minimized-build
        --enable-modules=aes,sha2_64,sha2_32,cbc,hex,mode_pad,ed25519,pubkey,asn1,pem,rng,auto_rng,system_rng
        --disable-shared-library
        --without-documentation
        --no-install-python-module
        --with-build-dir=${BOTAN_BUILD_DIR}
        --prefix=${BOTAN_INSTALL_DIR}
        --link-method=copy
        --build-targets=static
    )

    if(MSVC)
        list(APPEND BOTAN_CONFIGURE_ARGS --cc=msvc)
        # Multi-config generators (Visual Studio) don't set CMAKE_BUILD_TYPE
        # at configure time. Check both the variable and the generator type.
        if(CMAKE_BUILD_TYPE MATCHES "Debug" OR
           (NOT CMAKE_BUILD_TYPE AND CMAKE_CONFIGURATION_TYPES))
            # Default to Debug for multi-config generators (matches --config Debug)
            list(APPEND BOTAN_CONFIGURE_ARGS --debug-mode --msvc-runtime=MDd)
        else()
            list(APPEND BOTAN_CONFIGURE_ARGS --msvc-runtime=MD)
        endif()

        # ASan: Botan is built via ExternalProject (separate process), so the
        # global add_compile_options(/fsanitize=address) does not reach it.
        # Pass it via --extra-cxxflags to keep annotate_string metadata consistent.
        if(VMPILOT_ENABLE_SANITIZERS)
            list(APPEND BOTAN_CONFIGURE_ARGS "--extra-cxxflags=/fsanitize=address")
        endif()

        # Use ninja if available, otherwise nmake
        find_program(NINJA_EXECUTABLE ninja)
        if(NINJA_EXECUTABLE)
            list(APPEND BOTAN_CONFIGURE_ARGS --build-tool=ninja)
            set(BOTAN_BUILD_COMMAND ninja)
            set(BOTAN_INSTALL_COMMAND ninja install)
        else()
            set(BOTAN_BUILD_COMMAND nmake)
            set(BOTAN_INSTALL_COMMAND nmake install)
        endif()
    else()
        if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            list(APPEND BOTAN_CONFIGURE_ARGS --cc=clang)
        else()
            list(APPEND BOTAN_CONFIGURE_ARGS --cc=gcc)
        endif()
        if(CMAKE_BUILD_TYPE MATCHES "Debug")
            list(APPEND BOTAN_CONFIGURE_ARGS --debug-mode)
        endif()

        include(ProcessorCount)
        ProcessorCount(NPROC)
        if(NOT NPROC)
            set(NPROC 1)
        endif()
        set(BOTAN_BUILD_COMMAND make -j${NPROC})
        set(BOTAN_INSTALL_COMMAND make install)
    endif()

    ExternalProject_Add(botan_ext
        SOURCE_DIR ${BOTAN_SOURCE_DIR}
        BINARY_DIR ${BOTAN_BUILD_DIR}
        CONFIGURE_COMMAND python3 ${BOTAN_SOURCE_DIR}/configure.py ${BOTAN_CONFIGURE_ARGS}
        BUILD_COMMAND ${BOTAN_BUILD_COMMAND}
        INSTALL_COMMAND ${BOTAN_INSTALL_COMMAND}
        # Redirect to log files: Botan's Ninja build emits MSVC /showIncludes
        # lines that Ninja cannot filter on non-English locales, flooding the
        # console with thousands of "注意: 包含檔案:" lines.
        LOG_CONFIGURE ON
        LOG_BUILD ON
        LOG_INSTALL ON
        BUILD_BYPRODUCTS
            ${BOTAN_INSTALL_DIR}/lib/botan-3.lib
            ${BOTAN_INSTALL_DIR}/lib/libbotan-3.a
    )

    add_library(botan_staticlib STATIC IMPORTED)
    if(MSVC)
        set_target_properties(botan_staticlib PROPERTIES IMPORTED_LOCATION ${BOTAN_INSTALL_DIR}/lib/botan-3.lib)
    else()
        set_target_properties(botan_staticlib PROPERTIES IMPORTED_LOCATION ${BOTAN_INSTALL_DIR}/lib/libbotan-3.a)
    endif()
    add_dependencies(botan_staticlib botan_ext)

    set(BOTAN_INCLUDE_DIR ${BOTAN_INSTALL_DIR}/include/botan-3)

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
    set(SOURCE_FILES sodium.cpp PARENT_SCOPE)

    if(MSVC)
        set(_saved_C_FLAGS "${CMAKE_C_FLAGS}")
        set(_saved_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        set(CMAKE_C_FLAGS "")
        set(CMAKE_CXX_FLAGS "")
    endif()

    find_package(unofficial-sodium CONFIG QUIET)
    if(TARGET unofficial-sodium::sodium)
        set(THIRD_PARTY_LIBS ${THIRD_PARTY_LIBS} unofficial-sodium::sodium PARENT_SCOPE)
    else()
        set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)
        CPMAddPackage(
            NAME sodium
            GITHUB_REPOSITORY robinlinden/libsodium-cmake
            GIT_TAG efe978b574516d7708c0feeb5231cf7ab4906283
        )

        if(sodium_ADDED AND TARGET sodium AND NOT TARGET unofficial-sodium::sodium)
            add_library(unofficial-sodium::sodium ALIAS sodium)
        endif()

        if(TARGET unofficial-sodium::sodium)
            set(THIRD_PARTY_LIBS ${THIRD_PARTY_LIBS} unofficial-sodium::sodium PARENT_SCOPE)
        else()
            message(FATAL_ERROR "libsodium requested but no supported target was found. Tried unofficial-sodium config package and CPM fallback via robinlinden/libsodium-cmake.")
        endif()
    endif()

    if(MSVC)
        set(CMAKE_C_FLAGS "${_saved_C_FLAGS}")
        set(CMAKE_CXX_FLAGS "${_saved_CXX_FLAGS}")
    endif()

    message(WARNING "The libsodium backend only provides SHA256 and Ed25519 parity. AES-256-CBC/PKCS7 remains unsupported because libsodium exposes AES-256-GCM AEAD rather than CBC.")
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
