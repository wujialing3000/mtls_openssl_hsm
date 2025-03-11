cmake_minimum_required(VERSION 3.10.2)
project(native-ssl)

add_library(native-ssl SHARED native-ssl.cpp)
include_directories(${CMAKE_SOURCE_DIR}/openssl/include)

add_library(crypto STATIC IMPORTED)
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/openssl/lib/libcrypto.a)

add_library(ssl STATIC IMPORTED)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/openssl/lib/libssl.a)

find_library(log-lib log)
target_link_libraries(native-ssl ssl crypto ${log-lib})


