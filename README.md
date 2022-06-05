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

## 实验测试：libngtcp2 内部保存发送数据的模式
首先根据 libngtcp2 的文档给出的描述：
> ### Stream data ownership
> Stream data passed to `ngtcp2_conn` must be held by application until `ngtcp2_callbacks.acked_stream_data_offset` callbacks is invoked, telling that the those data are acknowledged by the remote endpoint and no longer used by the library.

知道 libngtcp2 内部应当是不会拷贝一份要发送的数据的，因此实验目的是证实这一点。

### 实验的做法
1. 在 server 端，创建了 Connection 对象之后，不给其读入任何的 QUIC packet，这样一来就模拟了 client 发往 server 的包全部丢失的情况。
2. 在 client 端，设置一条 connection 中只有一条 stream，同时在外部也就只创建一个 Stream 对象与其作为对应（外部的 Stream 对象主要就是提供一个要发送的数据的 buffer 的作用）。与此同时，每次从 stdin 读入一行数据后，就立刻写成 QUIC packet 发送，即设置 `N_COALESCE_MAX := 1`。  
   在实验时，最好只进行一次 stdin 的输入。
3. 在 libngtcp2 中，每次 expiry 触发时都要调用 `ngtcp2_conn_writev_stream` 来写和发 QUIC packet，因此我们发完包之后，立刻将外部的 Stream 对象里的 buffer 的数据全部重置成「特殊值」。  
   这样一来，在下一次重发时，如果 libngtcp2 内部保存的只是一个指针（即要发送的数据的地址），那么它下一次发送出去的 QUIC packet 里就会有一段「特殊值」。  
   而如果 libngtcp2 内部保存了要发送数据的一份拷贝，那么我们在外面修改 buffer 也不会影响到 libngtcp2 内部的拷贝，那么发送出去的 QUIC packet 自然也就不会受到影响。  
   这样一来，就能判断 libngtcp2 内部保存的到底是数据的地址，还是数据的拷贝。
4. 注意，由于我们是明文传输，所以我们才可以直接观察 QUIC packet 的内容。

### 实验结果
主要是观察 client 端运行的结果：
```
Input remote host & port:
localhost                       // 输入对端的 host。
12345                           // 输入对端的 port。
Remote host: [localhost].
Remote port: [12345].
Debug: open a socket fd = 3.    // 创建了一个 socket fd
Debug: [extend_max_local_streams_bidi_cb] is called.
Debug [extend_max_local_streams_bidi_cb]: max_streams = 5 n_streams_capacity = 1.
Debug [extend_max_local_streams_bidi_cb]: Local open a new bidi stream #0.  // 本端开启了一个 id = 0 的 stream。
Start Event loop.
a1a1a1a1a1a1                                    // 在键盘上输入要发送的数据。
Debug: Read 13 bytes from stdin: a1a1a1a1a1a1   // 6组 "a1" 加上一个换行符，总计 13 个字节。
Debug: Push 13 bytes to stream #0.              // 放到 Stream 对象的 buffer 里缓存。
Debug [write_one_stream]: now is writing stream #0.
Debug [write_one_stream]: stream #0 data gathered, datav.len = 13.      // 从 Stream 对象的 buffer 里获取到了 13 个字节的数据。
Debug [write_one_stream]: to call [send_packet] with socket_fd = 3, n_written = 90.
Debug [debug_print_sockaddr] [getnameinfo] host = localhost, port = 12345.
Debug [debug_print_quic_packet]: [64,238,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,238,0,24,1,0,18,97,53,251,195,132,236,186,13,209,241,218,143,115,20,46,159,204,214,8,58,40,78,31,126,26,110,184,215,168,87,60,9,140,55,10,0,13,97,49,97,49,97,49,97,49,97,49,97,49,10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0].
��ڏs.��:(N~n�רW<�a5�Ä�  �7
a1a1a1a1a1a1
// 可以看到，产生了一个 90 个字节的 QUIC packet，其中有一段 ASCII 码为 [97,49,97,49,97,49,97,49,97,49,97,49,10]，即我们在 stdin 的输入。
Debug [write_one_stream]: stream #-1 data gathered, datav.len = 0.
Debug [write_one_stream]: now is writing stream #0.
Debug [write_one_stream]: stream #-1 data gathered, datav.len = 0.
Debug [write_one_stream]: to call [send_packet] with socket_fd = 3, n_written = 98.
Debug [debug_print_sockaddr] [getnameinfo] host = localhost, port = 12345.
Debug [debug_print_quic_packet]: [64,238,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,238,1,2,0,128,1,243,191,0,0,24,1,0,18,97,53,251,195,132,236,186,13,209,241,218,143,115,20,46,159,204,214,8,58,40,78,31,126,26,110,184,215,168,87,60,9,140,55,10,0,13,97,49,97,49,97,49,97,49,97,49,97,49,10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0].
��ڏs.��:(N~n�רW<���a5�Ä��7
a1a1a1a1a1a1
// 这是第一次触发 expiry 后写的 QUIC packet，此时的数据还是 [97,49,97,49,97,49,97,49,97,49,97,49,10]，没什么变化。
Debug: Fill the whole buf by [$][ASCII = 36].       // 我们将 Stream 对象的 buffer 里的数据全部改成 '$'。
Debug [write_one_stream]: now is writing stream #0.
Debug [write_one_stream]: stream #-1 data gathered, datav.len = 0.
Debug [write_one_stream]: to call [send_packet] with socket_fd = 3, n_written = 98.
Debug [debug_print_sockaddr] [getnameinfo] host = localhost, port = 12345.
Debug [debug_print_quic_packet]: [64,238,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,238,2,2,2,128,3,233,204,0,2,24,1,0,18,97,53,251,195,132,236,186,13,209,241,218,143,115,20,46,159,204,214,8,58,40,78,31,126,26,110,184,215,168,87,60,9,140,55,10,0,13,36,36,36,36,36,36,36,36,36,36,36,36,36,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0].
��ڏs.��:(N~n�רW<����a5�Ä�7
$$$$$$$$$$$$$       // 可以观察到，数据部分变成了 [36,36,36,36,36,36,36,36,36,36,36,36,36]，即 13 个 '$' 字符。
Debug: Fill the whole buf by [$][ASCII = 36].
Debug [write_one_stream]: now is writing stream #0.
Debug [write_one_stream]: stream #-1 data gathered, datav.len = 0.
Debug [write_one_stream]: to call [send_packet] with socket_fd = 3, n_written = 98.
Debug [debug_print_sockaddr] [getnameinfo] host = localhost, port = 12345.
Debug [debug_print_quic_packet]: [64,238,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,238,3,2,4,128,7,210,130,0,4,24,1,0,18,97,53,251,195,132,236,186,13,209,241,218,143,115,20,46,159,204,214,8,58,40,78,31,126,26,110,184,215,168,87,60,9,140,55,10,0,13,36,36,36,36,36,36,36,36,36,36,36,36,36,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0].
��ڏs.��:(N~n�רW<��҂a5�Ä��7
$$$$$$$$$$$$$
Debug: Fill the whole buf by [$][ASCII = 36].
```

因此，可以得出结论，libngtcp2 内部只是保存了要发送的数据的地址，而非保存了要发送的数据的一份拷贝，  
当 libngtcp2 要对某一段已发送的数据进行重传时，libngtcp2 会从其内部保存的该段数据的地址再拷贝一次数据。

因此，对于我们交给 libngtcp2 让其发送的数据，应当确保这些数据始终存在、保持不变，直到 `ngtcp2_callbacks.acked_stream_data_offset` callbacks 通知我们这些数据已经获得了确认。