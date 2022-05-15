#ifndef __SERVER_H__
#define __SERVER_H__

#include <memory>
#include <algorithm>
#include <list>
#include <vector>

#include <ev.h>

#include "connection.h"

class EchoServer
{
private:
    std::shared_ptr<Connection> connection; // 由于跳过了 QUIC handshake 阶段，因此只能将 CID 预设固定，进而导致 server 只能有一个 QUIC 连接
    int socket_fd;

    sockaddr_storage local_addr;
    socklen_t local_addrlen;

    ngtcp2_callbacks callbacks;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid dcid, scid;

public:
    ev_io socket_fd_watcher;       // libev 中，用来监测 socket_fd 可读的 io watcher
    ev_timer ngtcp2_timer_watcher; // libev 中，用来驱动 ngtcp2 工作的时钟

public:
    EchoServer();
    ~EchoServer();

    // 准备好 ngtcp2_callbacks、ngtcp2_settings 和 ngtcp2_transport_params 等对象，便于后续创建 connection。
    void prepare_for_create_connection();

    // 创建 server 端的 connection 对象。
    std::shared_ptr<Connection> create_connection(const sockaddr *remote_addr, socklen_t remote_addrlen);

    // 设置 server 的 socket fd。
    inline void set_socket_fd(int sock_fd) { this->socket_fd = sock_fd; }

    // 获取 server 用来收发数据的 socket fd。
    inline int get_socket_fd() const { return this->socket_fd; }

    inline void set_local_addr(const sockaddr *local_addr, socklen_t local_addrlen)
    {
        memcpy(&(this->local_addr), local_addr, local_addrlen);
        this->local_addrlen = local_addrlen;
    }

    // 从 socket_fd 取出 packet 并进行处理。
    int handle_incoming();

    inline std::shared_ptr<Connection> get_connection() const { return this->connection; }
    inline void set_connection(std::shared_ptr<Connection> connection) { this->connection = connection; }
};

#endif /* __SERVER_H__ */