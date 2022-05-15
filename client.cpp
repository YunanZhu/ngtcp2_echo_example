#include <memory>
#include <vector>
#include <assert.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ev.h>
#include <ngtcp2/ngtcp2.h>

#include "connection.h"
#include "stream.h"
#include "utils.h"
#include "client.h"
#include "plaintext.h"

namespace
{
    constexpr size_t BUF_SIZE = 1280;
    constexpr size_t N_STREAMS_MAX_ONE_CONN = 3; // 一个 QUIC Connection 中可以创建的 Stream 数量的上限
    constexpr size_t N_COALESCE_MAX = 2;
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

    // ngtcp2_callbacks: 当本端可以打开的双向 stream 的个数上限（max_streams）增大时，本函数会被调用。
    int extend_max_local_streams_bidi_cb(ngtcp2_conn *conn, uint64_t max_streams, void *user_data)
    {
        printf("Debug: [%s] is called.\n", __func__);

        auto connection = static_cast<Connection *>(user_data);

        auto n_streams_capacity = connection->get_streams_capacity();
        printf("Debug [%s]: max_streams = %zu n_streams_capacity = %zu.\n", __func__, max_streams, n_streams_capacity);
        while (connection->get_streams_count() < max_streams &&
               connection->get_streams_count() < n_streams_capacity)
        {
            int64_t stream_id;
            int ret = ngtcp2_conn_open_bidi_stream(conn, &stream_id, nullptr); // open a bidi stream

            if (ret != 0) // 打开 bibi stream 失败
                return 0; // 但不影响整个回调函数正常退出

            printf("Debug [%s]: Local open a new bidi stream #%zd.\n", __func__, stream_id);
            connection->new_stream(stream_id); // 在 connection 中新增一个对应的 stream
        }

        return 0;
    }

    // ngtcp2_callbacks: 当本端发送出去的数据受到累计确认时，本函数会被调用。
    int acked_stream_data_offset_cb(ngtcp2_conn *conn,
                                    int64_t stream_id, uint64_t offset, uint64_t datalen,
                                    void *user_data, void *stream_user_data)
    {
        auto connection = static_cast<Connection *>(user_data);
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
        printf("Debug: Local recv data (offset = %zu, datalen = %zu) on stream #%zd.\n", offset, datalen, stream_id);
        write(STDOUT_FILENO, data, datalen); // TODO: 可以考虑更合理的存储接收到的数据的方式

        return 0;
    }
} /* namespace */

namespace
{
    // libev event loop - io watcher callback：监测到 stdin 可读时被调用。
    void stdin_cb(struct ev_loop *loop, ev_io *stdin_w, int revents)
    {
        assert((revents & EV_READ) == EV_READ);

        EchoClient *cli = static_cast<EchoClient *>(stdin_w->data);
        std::shared_ptr<Connection> connection = cli->get_connection();

        assert(&(cli->stdin_watcher) == stdin_w);

        uint8_t buf[BUF_SIZE + 1];
        size_t n_read = 0;

        int ret;

        while (n_read < BUF_SIZE)
        {
            ret = read(stdin_w->fd, buf + n_read, BUF_SIZE - n_read);

            if (ret == 0)
            {
                connection->close();
                return;
            }
            else if (ret < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK) // 由于 stdin fd 被设定为非阻塞，返回 EAGAIN/EWOULDBLOCK 表示目前暂时读不到数据
                    break;

                fprintf(stderr, "Error [%s] [read]: errno = %s.\n", __func__, strerror(errno));
                return;
            }
            else // ret > 0
            {
                n_read += ret;
            }
        }

        buf[n_read] = '\0';
        printf("Debug: Read %zu bytes from stdin: %s", n_read, buf);

        int64_t cur_stream_id = connection->get_cur_stream_id();
        if (cur_stream_id < 0)
        {
            printf("Debug [%s] [connection->get_cur_stream_id] cur_stream_id = %zd.\n", __func__, cur_stream_id);
            return;
        }
        std::shared_ptr<Stream> cur_stream = connection->get_stream(cur_stream_id);
        if (!cur_stream)
        {
            printf("Debug [%s] [connection->get_stream] cur_stream = nullptr.\n", __func__);
            return;
        }

        /* 能从 connection 中获取到当前用来接收 stdin 数据的 cur_stream */
        size_t n_push = cur_stream->push_data(buf, n_read);
        printf("Debug: Push %zu bytes to stream #%zd.\n", n_push, cur_stream_id); // 剩余没有能够拷贝进 stream 的数据就只能被丢弃了

        if (++(cli->coalesce_count) >= cli->coalesce_limit)
        {
            ret = connection->write();
            if (ret < 0)
            {
                fprintf(stderr, "Error [%s] [connection->write]: ret = %d.\n", __func__, ret);
                connection->close();
                ev_break(loop, EVBREAK_ALL);
                return;
            }

            cli->coalesce_count = 0;       // 将 coalesce_count 重置
            connection->step_cur_stream(); // 切换到下一条 stream

            /* 设置下一次的 timer expire 事件（注意这里，不要忘记了） */
            ngtcp2_tstamp expiry = connection->get_expiry();
            ngtcp2_tstamp now = timestamp();
            ev_tstamp t = ((expiry <= now) ? 1e-9 : (static_cast<ev_tstamp>(expiry - now) / NGTCP2_SECONDS));
            cli->ngtcp2_timer_watcher.repeat = t;
            ev_timer_again(EV_DEFAULT, &(cli->ngtcp2_timer_watcher));
        }
    }

    // libev event loop - socket fd watcher callback：监测到 socket fd 可读时被调用。
    void socket_fd_cb(struct ev_loop *loop, ev_io *sock_fd_w, int revents)
    {
        assert((revents & EV_READ) == EV_READ);

        EchoClient *cli = static_cast<EchoClient *>(sock_fd_w->data);
        std::shared_ptr<Connection> connection = cli->get_connection();

        int ret = connection->read();
        if (ret < 0)
        {
            fprintf(stderr, "Error [%s] [connection->read]: ret = %d.\n", __func__, ret);
            connection->close();
            ev_break(loop, EVBREAK_ALL);
        }
    }

    // libev event loop - timer watcher callback：当驱动 ngtcp2 工作的 timer expire 时被调用。
    void timer_cb(struct ev_loop *loop, ev_timer *ngtcp2_timer_w, int revents)
    {
        EchoClient *cli = static_cast<EchoClient *>(ngtcp2_timer_w->data);
        std::shared_ptr<Connection> connection = cli->get_connection();

        assert(connection);

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

int main()
{
    EchoClient cli(N_COALESCE_MAX);

    /* Create a client socket */
    const char *const remote_host = "127.0.0.1";
    const char *const remote_port = "12047";

    struct sockaddr_storage local_addr, remote_addr;
    socklen_t local_addrlen = sizeof(local_addr), remote_addrlen = sizeof(remote_addr);

    int sock_fd = resolve_and_connect(remote_host, remote_port,
                                      (sockaddr *)&local_addr, &local_addrlen,
                                      (sockaddr *)&remote_addr, &remote_addrlen);
    if (sock_fd < 0)
    {
        fprintf(stderr, "Error [%s] [resolve_and_connect]: ret = %d.\n", __func__, sock_fd);
        return -1;
    }
    printf("Debug: open a socket fd = %d.\n", sock_fd);

    /* Create an client ngtcp2 connection */
    auto connection = std::make_shared<Connection>(sock_fd, N_STREAMS_MAX_ONE_CONN);
    connection->set_local_addr((sockaddr *)&local_addr, local_addrlen);
    connection->set_remote_addr((sockaddr *)&remote_addr, remote_addrlen);

    ngtcp2_callbacks callbacks = {0};
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.recv_stream_data = recv_stream_data_cb;
    callbacks.acked_stream_data_offset = acked_stream_data_offset_cb;
    callbacks.extend_max_local_streams_bidi = extend_max_local_streams_bidi_cb;
    callbacks.rand = rand_cb;
    callbacks.get_new_connection_id = get_new_connection_id_cb;
    ngtcp2_plaintext::set_ngtcp2_crypto_callbacks(false, callbacks);

    ngtcp2_settings settings = {0};
    ngtcp2_plaintext::set_default_ngtcp2_settings(false, settings, log_printf, timestamp());

    ngtcp2_transport_params params = {0};
    ngtcp2_plaintext::set_default_ngtcp2_transport_params(false, params);

    ngtcp2_cid dcid, scid;
    ngtcp2_plaintext::preset_fixed_dcid_scid(false, dcid, scid);

    ngtcp2_conn *conn = ngtcp2_plaintext::create_handshaked_ngtcp2_conn(
        false,
        dcid, scid,
        (const sockaddr *)(&local_addr), local_addrlen,
        (const sockaddr *)(&remote_addr), remote_addrlen,
        callbacks, settings, params,
        connection.get() /* user_data */
    );
    if (!conn)
    {
        fprintf(stderr, "Error [%s] [ngtcp2_plaintext::create_handshaked_ngtcp2_conn]: ret = nullptr.", __func__);
        return -1;
    }
    connection->steal_ngtcp2_conn(conn);

    cli.set_connection(connection);

    /* 基于 libev 库的 event loop */
    struct ev_loop *loop = EV_DEFAULT; // 初始化 event loop

    set_nonblock(STDIN_FILENO);
    ev_io_init(&(cli.stdin_watcher), stdin_cb, STDIN_FILENO, EV_READ); // 监测 stdin 可读的 io watcher
    cli.stdin_watcher.data = &cli;
    ev_io_start(loop, &(cli.stdin_watcher));

    ev_io_init(&(cli.socket_fd_watcher), socket_fd_cb, cli.get_connection()->get_socket_fd(), EV_READ); // 监测 socket_fd 可读的 io watcher
    cli.socket_fd_watcher.data = &cli;
    ev_io_start(loop, &(cli.socket_fd_watcher));

    ev_timer_init(&(cli.ngtcp2_timer_watcher), timer_cb, /*after = */ 0, /*repeat = */ 0); // 驱动 ngtcp2 工作的时钟
    cli.ngtcp2_timer_watcher.data = &cli;

    // connection->write();
    // ngtcp2_tstamp expiry = connection->get_expiry();
    // ngtcp2_tstamp now = timestamp();
    // ev_tstamp t = ((expiry <= now) ? 1e-9 : (static_cast<ev_tstamp>(expiry - now) / NGTCP2_SECONDS));
    // cli.ngtcp2_timer_watcher.repeat = t;
    // ev_timer_again(EV_DEFAULT, &(cli.ngtcp2_timer_watcher));

    printf("Start Event loop.\n");
    ev_run(loop, 0); // 启动 event loop

    printf("Destroy event loop.\n");
    ev_loop_destroy(loop);

    close(cli.get_connection()->get_socket_fd()); // 关闭 socket fd

    return 0;
}