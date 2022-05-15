#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <memory>
#include <algorithm>

#include <ev.h>

#include "connection.h"

class EchoClient
{
private:
    std::shared_ptr<Connection> connection; // client 有且仅有一条 connection

public:
    /* 为了方便，把这些变量设置成了 public */
    ev_io stdin_watcher;           // libev 中，用来监测 stdin 可读的 io watcher
    ev_io socket_fd_watcher;       // libev 中，用来监测 socket fd 可读的 io watcher
    ev_timer ngtcp2_timer_watcher; // libev 中，用来驱动 ngtcp2 工作的时钟

    size_t coalesce_limit;
    size_t coalesce_count;

public:
    EchoClient(size_t coalesce_limit = 1)
        : connection(nullptr),
          stdin_watcher(), ngtcp2_timer_watcher(),
          coalesce_limit(coalesce_limit), coalesce_count(0)
    {
    }

    inline std::shared_ptr<Connection> get_connection() const { return this->connection; }
    inline void set_connection(std::shared_ptr<Connection> connection) { this->connection = connection; }
};

#endif /* __CLIENT_H__ */