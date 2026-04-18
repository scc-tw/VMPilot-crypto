set(INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR})

if(CRYPTO_LIB STREQUAL "CryptoPP")
    set(SOURCES cryptopp_main.cpp)
else()
    set(SOURCES main.cpp)
endif()
set(LIBRARIES crypto)

include_directories(${INCLUDE_DIRECTORIES})
add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBRARIES})
