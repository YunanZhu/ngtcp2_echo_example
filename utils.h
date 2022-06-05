#ifndef __UTILS_H__
#define __UTILS_H__

#include <cstddef>
#include <cstdint>

#include <unistd.h>
#include <sys/socket.h>

#include <ngtcp2/ngtcp2.h>

// 调用 getnameinfo 将 socket addr 转换成 host & port 并打印。
void debug_print_sockaddr(const sockaddr *addr, socklen_t addrlen);

// 调试打印 QUIC packet。
void debug_print_quic_packet(const uint8_t *pkt, size_t pktlen);

// 将指针的所有权从 `ptr` 转移给函数调用者。
template <typename T>
T *steal_pointer(T *&ptr)
{
    if (!ptr)
        return nullptr;

    T &ref = *ptr;
    ptr = nullptr;

    return &ref;
}

// 将 fd 设置为 non-block 模式。
int set_nonblock(int fd);

// 为本端创建 socket fd，并连接到由 host & port 指定的远端地址，返回 fd，并且返回本端以及远端的 socket addr。
int resolve_and_connect(const char *host, const char *port,
                        sockaddr *local_addr, socklen_t *local_addrlen,
                        sockaddr *remote_addr, socklen_t *remote_addrlen);

// 为本端创建 socket fd，并绑定到由 host & port 指定的本端地址，返回 fd，并且返回本端的 socket addr。
int resolve_and_bind(const char *host, const char *port,
                     sockaddr *local_addr, socklen_t *local_addrlen);

// 获取当前的时间戳。
uint64_t timestamp();

// 作为 ngtcp2_settings.log_printf 用以输出 debug logging。
void log_printf(void *user_data, const char *fmt, ...);

// 生成随机的字节数据，长度为 len，存储到 data 中。
void rand_bytes(uint8_t *data, size_t len);

// 从 fd 接收 packet，存储到 data 中。同时返回接收到的这个 packet 的远端 socket addr。
ssize_t recv_packet(int fd, uint8_t *data, size_t data_size,
                    sockaddr *remote_addr, socklen_t *remote_addrlen);

// 将 data 中的 packet 发送到 fd 中。同时传入发送 packet 的目的 socket addr。
ssize_t send_packet(int fd, const uint8_t *data, size_t data_size,
                    sockaddr *remote_addr, socklen_t remote_addrlen);

// 生成长度为 len 的随机 Connection ID，存储到 cid 中。
int get_random_cid(ngtcp2_cid *cid, size_t len = NGTCP2_MAX_CIDLEN);

#endif /* __UTILS_H__ */