# ngtcp2_echo_example
基于 [lib ngtcp2](https://github.com/ngtcp2/ngtcp2) 的 plaintext echo client/server demo。

参考 lib ngtcp2 中单元测试部分的写法，直接跳过了 QUIC handshake 阶段，消除了对 TLS stack 的依赖。  
直接将创建出来的 `ngtcp2_conn *conn` 设置为『已完成握手』的状态。  

## Requirements
以下依赖的括号中，均为个人采用的版本：
- CMake [cmake version 3.12.1]。
- GCC [gcc 7.5.0]。
- libev [libev-4.33]，用来提供 event loop，必须事先安装好。
- lib ngtcp2 [[v0.5.0](https://github.com/ngtcp2/ngtcp2/releases/tag/v0.5.0), 也即 [commit 094b621cf1fae9e22e2c5883454c5786688c796c](https://github.com/ngtcp2/ngtcp2/commit/094b621cf1fae9e22e2c5883454c5786688c796c)]，已经包含在 project 当中了。

## Build
```bash
mkdir -p build
cd build/
cmake ..
cmake --build .
```

## Params
以下是一些可以调整的参数：

- [client.cpp](./client.cpp)
```cpp
constexpr size_t N_STREAMS_MAX_ONE_CONN = 3; // 一个 QUIC Connection 中可以创建的 Stream 数量的上限
constexpr size_t N_COALESCE_MAX = 2;         // 将 N_COALESCE_MAX 次 stdin 读取的数据合并发送
```

- [plaintext.cpp](./plaintext.cpp)
```cpp
void set_default_ngtcp2_transport_params(bool is_server, ngtcp2_transport_params &params) {
    /* ... */
}
```