cmake_minimum_required(VERSION 3.21)
project(VegaMessengerServer)

set(CMAKE_CXX_STANDARD 14)
find_package(Boost REQUIRED COMPONENTS system thread regex)
find_package(Boost)
find_package(MsgPack)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/modules/")
IF(Boost_FOUND)
    INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})
    LINK_DIRECTORIES(${Boost_LIBRARY_DIRS})
ENDIF(Boost_FOUND)
SET(USED_LIBS ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY} ${Boost_REGEX_LIBRARY})

find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    message(ERROR "Could not find OpenSSL")
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

add_executable(VegaMessengerServer main.cpp Serialization.h Serializer.cpp)

target_link_libraries(VegaMessengerServer ${USED_LIBS} Boost::boost ${OPENSSL_LIBRARIES})