#include <memory>
#include <assert.h>
#include <iostream>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ev.h>
#include <ngtcp2/ngtcp2.h>

#include "connection.h"
#include "stream.h"
#include "utils.h"
#include "server.h"
#include "plaintext.h"

namespace
{
    constexpr size_t N_STREAMS_MAX_ONE_CONN = 5;
    constexpr size_t NGTCP2_SERVER_SCIDLEN = 18;
    constexpr size_t BUF_SIZE = 1280;
} /* namespace */

namespace
{
    // ngtcp2_callbacks: 当需要随机字节数据时，本函数会被调用。
    static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
    {
        rand_bytes(dest, destlen);
    }

    // ngtcp2_callbacks: 当本端需要新的 SCID 时会调用本函数。
    int get_new_connection_id_cb(ngtcp2_conn *conn,
                                 ngtcp2_cid *cid, uint8_t *token, size_t cidlen,
                                 void *user_data)
    {
        rand_bytes(cid->data, cidlen);
        cid->datalen = cidlen;

        rand_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);

        return 0;
    }

    // ngtcp2_callbacks: 当由远端打开了一个新的 remote stream 时，本函数会被调用。
    int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
    {
        auto connection = static_cast<Connection *>(user_data);
        assert(connection->check_ngtcp2_conn(conn));

        connection->new_stream(stream_id);
        return 0;
    }

    // ngtcp2_callbacks: 当本端发送出去的数据受到累计确认时，本函数会被调用。
    int acked_stream_data_offset_cb(ngtcp2_conn *conn,
                                    int64_t stream_id, uint64_t offset, uint64_t datalen,
                                    void *user_data, void *stream_user_data)
    {
        auto connection = static_cast<Connection *>(user_data);
        assert(connection->check_ngtcp2_conn(conn));

        std::shared_ptr<Stream> stream = connection->get_stream(stream_id);

        if (stream)
        {
            fprintf(stderr, "Debug: Local recv acked (offset = %zu, datalen = %zu) on stream #%zd.\n", offset, datalen, stream_id);
            stream->mark_acked(offset + datalen);
        }

        return 0;
    }

    // ngtcp2_callbacks: 当本端收到远端发送来的 stream data 时，本函数会被调用。
    int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                            int64_t stream_id, uint64_t offset,
                            const uint8_t *data, size_t datalen,
                            void *user_data, void *stream_user_data)
    {
        auto connection = static_cast<Connection *>(user_data);
        assert(connection->check_ngtcp2_conn(conn));

        std::shared_ptr<Stream> stream = connection->get_stream(stream_id);

        if (stream)
        {
            printf("Debug: Local recv data (offset = %zu, datalen = %zu) on stream #%zd.\n", offset, datalen, stream_id);
            write(STDOUT_FILENO, data, datalen);

            /* 将数据中的小写字母都转成大写字母 */
            uint8_t converted_data[datalen];
            for (size_t i = 0; i < datalen; ++i)
                converted_data[i] = (islower(data[i]) ? toupper(data[i]) : data[i]);

            stream->push_data(converted_data, datalen);
        }

        return 0;
    }
} /* namespace */

namespace
{
    // libev event loop - io watcher callback：监测到 socket fd 可读时被调用。
    void socket_fd_cb(struct ev_loop *loop, ev_io *socket_fd_w, int revents)
    {
        printf("Debug: func [%s] is called.\n", __func__);
        EchoServer *srv = static_cast<EchoServer *>(socket_fd_w->data);

        srv->handle_incoming();

        auto connection = srv->get_connection();
        int ret = connection->write();
        if (ret < 0)
        {
            fprintf(stderr, "Error [%s] [connection->write]: ret = %d.\n", __func__, ret);
            connection->close();
            ev_break(loop, EVBREAK_ALL);
            return;
        }

        /* 设置下一次的 timer expire 事件（注意这里，不要忘记了） */
        ngtcp2_tstamp expiry = connection->get_expiry();
        ngtcp2_tstamp now = timestamp();
        ev_tstamp t = ((expiry <= now) ? 1e-9 : (static_cast<ev_tstamp>(expiry - now) / NGTCP2_SECONDS));
        srv->ngtcp2_timer_watcher.repeat = t;
        ev_timer_again(EV_DEFAULT, &(srv->ngtcp2_timer_watcher));
    }

    // libev event loop - timer watcher callback：当驱动 ngtcp2 工作的 timer expire 时被调用。
    void timer_cb(struct ev_loop *loop, ev_timer *ngtcp2_timer_w, int revents)
    {
        EchoServer *srv = static_cast<EchoServer *>(ngtcp2_timer_w->data);
        std::shared_ptr<Connection> connection = srv->get_connection();

        if (connection == nullptr)
        {
            printf("Debug [%s]: Now server's connection is null.\n", __func__);
            return;
        }

        int ret = connection->handle_expiry(timestamp());
        if (ret < 0)
        {
            fprintf(stderr, "Error [%s] [connection->handle_expiry (i.e. ngtcp2_conn_handle_expiry)]: ngtcp2_liberr = %s.\n", __func__, ngtcp2_strerror(ret));

            if (ngtcp2_err_is_fatal(ret))
            {
                connection->close();
                ev_break(loop, EVBREAK_ALL);
                return;
            }
        }

        ret = connection->write();
        if (ret < 0)
        {
            fprintf(stderr, "Error [%s] [connection->write]: ret = %d.\n", __func__, ret);
            connection->close();
            ev_break(loop, EVBREAK_ALL);
            return;
        }

        /* 设置下一次的 timer expire 事件 */
        ngtcp2_tstamp expiry = connection->get_expiry();
        ngtcp2_tstamp now = timestamp();
        ev_tstamp t = ((expiry <= now) ? 1e-9 : (static_cast<ev_tstamp>(expiry - now) / NGTCP2_SECONDS));
        ngtcp2_timer_w->repeat = t;
        ev_timer_again(EV_DEFAULT, ngtcp2_timer_w);
    }
} /* namespace */

EchoServer::EchoServer()
    : connection(nullptr), socket_fd(-1),
      local_addr(), local_addrlen(0),
      callbacks{0}, settings{0}, params{0}, dcid{0}, scid{0},
      socket_fd_watcher(), ngtcp2_timer_watcher()
{
}

EchoServer::~EchoServer()
{
}

void EchoServer::prepare_for_create_connection()
{
    memset(&this->callbacks, 0, sizeof(this->callbacks));
    this->callbacks.recv_stream_data = recv_stream_data_cb;
    this->callbacks.acked_stream_data_offset = acked_stream_data_offset_cb;
    this->callbacks.stream_open = stream_open_cb;
    this->callbacks.rand = rand_cb;
    this->callbacks.get_new_connection_id = get_new_connection_id_cb;
    ngtcp2_plaintext::set_ngtcp2_crypto_callbacks(true, this->callbacks);

    ngtcp2_plaintext::set_default_ngtcp2_settings(true, this->settings, log_printf, timestamp());

    ngtcp2_plaintext::set_default_ngtcp2_transport_params(true, this->params);

    ngtcp2_plaintext::preset_fixed_dcid_scid(true, this->dcid, this->scid);
}

std::shared_ptr<Connection> EchoServer::create_connection(const sockaddr *remote_addr, socklen_t remote_addrlen)
{
    auto connection = std::make_shared<Connection>(this->socket_fd, N_STREAMS_MAX_ONE_CONN);
    connection->set_local_addr((sockaddr *)&(this->local_addr), this->local_addrlen);
    connection->set_remote_addr(remote_addr, remote_addrlen);

    ngtcp2_conn *conn = ngtcp2_plaintext::create_handshaked_ngtcp2_conn(
        true, this->dcid, this->scid,
        (sockaddr *)&this->local_addr, this->local_addrlen,
        remote_addr, remote_addrlen,
        this->callbacks, this->settings, this->params,
        connection.get() /* user_data */
    );

    if (!conn)
        return nullptr;

    connection->steal_ngtcp2_conn(conn);
    return (this->connection = connection);
}

int EchoServer::handle_incoming()
{
    uint8_t buf[BUF_SIZE];

    while (true)
    {
        sockaddr_storage remote_addr;
        socklen_t remote_addrlen = sizeof(remote_addr);

        ssize_t n_read = recv_packet(this->socket_fd, buf, sizeof(buf),
                                     (sockaddr *)&remote_addr, &remote_addrlen);
        if (n_read < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK) // 由于 socket fd 被设定为非阻塞，返回 EAGAIN/EWOULDBLOCK 表示目前暂时读不到数据
                return 0;

            fprintf(stderr, "Error [%s] [recv_packet]: errno = %s.\n", __func__, strerror(errno));
            return -1;
        }

        uint32_t version;
        const uint8_t *dcid, *scid;
        size_t dcid_len, scid_len;

        int ret = ngtcp2_pkt_decode_version_cid(&version,
                                                &dcid, &dcid_len,
                                                &scid, &scid_len,
                                                buf, n_read,
                                                NGTCP2_SERVER_SCIDLEN); // 从存储在 data 里的 packet 中解析得到 QUIC version、DCID 和 SCID
        if (ret < 0)
        {
            fprintf(stderr, "Error [%s] [ngtcp2_pkt_decode_version_cid]: ngtcp2_liberr = %s.\n", __func__, ngtcp2_strerror(ret));
            return -1;
        }

        std::shared_ptr<Connection> connection = this->get_connection();
        if (!connection) // 若 connection 不存在则需要创建
        {
            this->prepare_for_create_connection();
            connection = this->create_connection((sockaddr *)&remote_addr, remote_addrlen);

            if (!connection) // 若 connection 创建失败
            {
                fprintf(stderr, "Error [%s] [this->create_connection]: ret = nullptr.\n", __func__);
                return -1;
            }
        }

        ngtcp2_path path = {0};
        path.local.addr = (sockaddr *)&this->local_addr;
        path.local.addrlen = this->local_addrlen;
        path.remote.addr = (sockaddr *)&remote_addr;
        path.remote.addrlen = remote_addrlen;

        ngtcp2_pkt_info pi = {0}; // packet metadata

        ret = connection->read_packet(path, pi, buf, n_read, timestamp());
        if (ret < 0)
        {
            fprintf(stderr, "Error [%s] [ngtcp2_conn_read_pkt]: ngtcp2_liberr = %s.\n", __func__, ngtcp2_strerror(ret));

            if (ngtcp2_err_is_fatal(ret))
                connection->close();
        }
    }
    return 0;
}

int main()
{
    EchoServer srv;

    /* Get local host & port from stdin */
    char local_host[50] = {0}, local_port[50] = {0};
    printf("Input local host & port:\n");
    std::cin.getline(local_host, sizeof(local_host));
    std::cin.getline(local_port, sizeof(local_port));
    printf("Local host: [%s].\n", local_host);
    printf("Local port: [%s].\n", local_port);

    /* Create a server socket */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen = sizeof(local_addr);

    int sock_fd = resolve_and_bind(
        (local_host[0] ? local_host : nullptr),
        (local_port[0] ? local_port : nullptr),
        (sockaddr *)&local_addr, &local_addrlen);
    if (sock_fd < 0)
    {
        fprintf(stderr, "Error [%s] [resolve_and_connect]: ret = %d.\n", __func__, sock_fd);
        return -1;
    }
    printf("Debug: open a socket fd = %d.\n", sock_fd);
    set_nonblock(sock_fd);
    srv.set_socket_fd(sock_fd);
    srv.set_local_addr((sockaddr *)&local_addr, local_addrlen);

    // 初始化 event loop
    struct ev_loop *loop = EV_DEFAULT;

    // 监测 socket fd 可读的 io watcher
    ev_io_init(&(srv.socket_fd_watcher), socket_fd_cb, srv.get_socket_fd(), EV_READ);
    srv.socket_fd_watcher.data = &srv;
    ev_io_start(loop, &srv.socket_fd_watcher);

    // 驱动 ngtcp2 工作的时钟
    ev_timer_init(&(srv.ngtcp2_timer_watcher), timer_cb, /*after = */ 0, /*repeat = */ 0);
    srv.ngtcp2_timer_watcher.data = &srv;
    ev_timer_again(loop, &(srv.ngtcp2_timer_watcher));

    printf("Start Event loop.\n");
    ev_run(loop, 0); // 启动 event loop

    printf("Destroy event loop.\n");
    ev_loop_destroy(loop);

    close(srv.get_socket_fd()); // 关闭 socket fd

    return 0;
}