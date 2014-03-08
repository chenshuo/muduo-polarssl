cmake_minimum_required(VERSION 2.6)

project(muduo-ssl CXX)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "debug")
endif()

if(NOT MUDUO_PATH)
  set(MUDUO_PATH "/home/$ENV{USER}/build/${CMAKE_BUILD_TYPE}-install")
endif()

if(NOT POLARSSL_PATH)
  set(POLARSSL_PATH "${MUDUO_PATH}")
endif()

set(CXX_FLAGS
 -g
 # -DVALGRIND
 # -DMUDUO_STD_STRING
 -Wall
 -Wextra
 # -m32
 -Werror
 # -Wconversion
 -Wno-unused-parameter
 -Wold-style-cast
 -Woverloaded-virtual
 -Wpointer-arith
 -Wshadow
 -Wwrite-strings
 -march=native
 # -MMD
 # -std=c++0x
 -rdynamic
 )
string(REPLACE ";" " " CMAKE_CXX_FLAGS "${CXX_FLAGS}")

set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_CXX_FLAGS_DEBUG "-O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -finline-limit=1000 -DNDEBUG")
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

find_path(Muduo_INCLUDE_DIR muduo "${MUDUO_PATH}/include")
find_path(Muduo_LIBRARY_DIR libmuduo_net.a "${MUDUO_PATH}/lib")
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} ${Muduo_LIBRARY_DIR})
message(STATUS ${Muduo_INCLUDE_DIR})
message(STATUS ${Muduo_LIBRARY_DIR})

include_directories(${Muduo_INCLUDE_DIR})
find_library(muduo_base muduo_base)
find_library(muduo_net muduo_net)
message(STATUS ${muduo_base})
message(STATUS ${muduo_net})

find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

find_path(Polarssl_INCLUDE_DIR polarssl "${POLARSSL_PATH}/include")
find_path(Polarssl_LIBRARY_DIR libpolarssl.a "${POLARSSL_PATH}/lib")
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} ${Polarssl_LIBRARY_DIR})
message(STATUS ${Polarssl_INCLUDE_DIR})
message(STATUS ${Polarssl_LIBRARY_DIR})
find_library(polarssl polarssl)
message(STATUS ${polarssl})

include_directories(${PROJECT_SOURCE_DIR})

add_library(muduo_ssl muduo/net/ssl/SslEnv.cc)
target_link_libraries(muduo_ssl ${muduo_net} ${muduo_base})
target_link_libraries(muduo_ssl ${polarssl} pthread rt z)

add_executable(server muduo/net/ssl/tests/server.cc)
target_link_libraries(server muduo_ssl)

add_executable(client muduo/net/ssl/tests/client.cc)
target_link_libraries(client muduo_ssl)

