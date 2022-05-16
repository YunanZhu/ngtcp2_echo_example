cmake_minimum_required(VERSION 3.5)

project(NGTCP2_ECHO_EXAMPLE LANGUAGES C CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11") # 针对 C++ 采用 C++11 standard 编译
add_definitions(-Wall -O0)

# 控制 ngtcp2 的回调函数 log_printf 是否打印内容
# 使用 cmake 命令选项 -DOPTION_ENABLE_NGTCP2_LOG_PRINTF=ON/OFF 来控制开关
option(OPTION_ENABLE_NGTCP2_LOG_PRINTF "Control #define ENABLE_NGTCP2_LOG_PRINTF." OFF)
message(STATUS "OPTION_ENABLE_NGTCP2_LOG_PRINTF: ${OPTION_ENABLE_NGTCP2_LOG_PRINTF}")
if(OPTION_ENABLE_NGTCP2_LOG_PRINTF)
    add_definitions(-DENABLE_NGTCP2_LOG_PRINTF)
endif()

add_subdirectory(libngtcp2)

set(client_SOURCE
    plaintext.cpp
    utils.cpp
    stream.cpp
    connection.cpp
    client.cpp
)

set(server_SOURCE
    plaintext.cpp
    utils.cpp
    stream.cpp
    connection.cpp
    server.cpp
)

add_executable(client ${client_SOURCE})
target_include_directories(client PRIVATE ${PROJECT_SOURCE_DIR}/libngtcp2/)
target_include_directories(client PRIVATE ${PROJECT_SOURCE_DIR}/libngtcp2/includes)
# target_link_libraries(client ngtcp2_static) # use static library
target_link_libraries(client ngtcp2) # use shared library
target_link_libraries(client ev) # libev

add_executable(server ${server_SOURCE})
target_include_directories(server PRIVATE ${PROJECT_SOURCE_DIR}/libngtcp2/)
target_include_directories(server PRIVATE ${PROJECT_SOURCE_DIR}/libngtcp2/includes)
# target_link_libraries(server ngtcp2_static) # use static library
target_link_libraries(server ngtcp2) # use shared library
target_link_libraries(server ev) # libev