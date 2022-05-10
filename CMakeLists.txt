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

add_executable(VegaMessengerServer main.cpp Serialization.h)

target_link_libraries(VegaMessengerServer ${USED_LIBS} Boost::boost)