# ngtcp2_echo_example
基于 [lib ngtcp2](https://github.com/ngtcp2/ngtcp2) 的 plaintext echo client/server demo。

参考 lib ngtcp2 中单元测试部分的写法，直接跳过了 QUIC handshake 阶段，消除了对 TLS stack 的依赖。  
直接将创建出来的 `ngtcp2_conn *conn` 设置为『已完成握手』的状态。  

## Requirements
以下依赖的括号中，均为个人采用的版本：
- CMake [cmake version 3.12.1]
- GCC [gcc 7.3.0]
- libev [libev-4.33] (用来提供 event loop)
- lib ngtcp2 [[commit 1dd6af547395f6714453eab4d28400c7c5db5692](https://github.com/ngtcp2/ngtcp2/commit/1dd6af547395f6714453eab4d28400c7c5db5692)]

## Build
```bash
mkdir -p build
cd build/
cmake ..
cmake --build .
```