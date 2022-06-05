#include <cstring>
#include <vector>
#include <assert.h>

#include <unistd.h>

#include "client.h"
#include "utils.h"

namespace
{
    constexpr size_t BUF_SIZE = 1280;
} /* namespace */

Connection::Connection(int sock_fd, size_t n_streams_max)
    : conn(nullptr), socket_fd(sock_fd),
      local_addr{0}, local_addrlen(0),
      remote_addr{0}, remote_addrlen(0),
      streams_capacity(n_streams_max), streams(),
      all_streams_id(), cur_stream_idx(0),
      last_error(), is_closed(false)
{
    ngtcp2_connection_close_error_default(&(this->last_error));
}

Connection::~Connection()
{
    assert(this->conn);
    ngtcp2_conn_del(this->conn);
}

int Connection::steal_ngtcp2_conn(ngtcp2_conn *&conn)
{
    if (!conn)
        return -1;

    this->conn = steal_pointer(conn);
    return 0;
}

void Connection::set_local_addr(const sockaddr *local_addr, socklen_t local_addrlen)
{
    memcpy(&(this->local_addr), local_addr, local_addrlen);
    this->local_addrlen = local_addrlen;
}

void Connection::set_remote_addr(const sockaddr *remote_addr, socklen_t remote_addrlen)
{
    memcpy(&(this->remote_addr), remote_addr, remote_addrlen);
    this->remote_addrlen = remote_addrlen;
}

int Connection::new_stream(int64_t stream_id)
{
    if (stream_exist(stream_id)) // 不允许重复添加同一个 stream
        return -1;

    if (get_streams_count() >= get_streams_capacity()) // 如果 streams 的数量已经达到 streams 容量的上限，则不再增加新的 stream
        return 0;

    streams[stream_id] = std::make_shared<Stream>(stream_id);
    all_streams_id.push_back(stream_id);

    return 0;
}

std::shared_ptr<Stream> Connection::get_stream(int64_t stream_id) const
{
    auto iter = streams.find(stream_id);

    if (iter == streams.end())
        return nullptr;

    return iter->second;
}

int Connection::step_cur_stream()
{
    if (all_streams_id.empty())
        return -1;

    cur_stream_idx = (cur_stream_idx + 1) % all_streams_id.size();
    return 0;
}

int64_t Connection::get_cur_stream_id() const
{
    if (cur_stream_idx < 0 || cur_stream_idx >= all_streams_id.size())
        return -1;

    return all_streams_id.at(cur_stream_idx);
}

int Connection::read()
{
    uint8_t buf[BUF_SIZE];

    while (true)
    {
        struct sockaddr_storage remote_addr;
        socklen_t remote_addrlen = sizeof(remote_addr);

        ssize_t ret = recv_packet(this->socket_fd, buf, sizeof(buf), (sockaddr *)&remote_addr, &remote_addrlen);
        if (ret < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK) // EAGAIN 与 EWOULDBLOCK 等价
            {
                // 注意 recv_packet 中对 socket_fd 读取时是采用 non-block 方式，因此 EAGAIN 不能算作是错误，只需要再次调用 recvmsg 即可。
                // 但为了防止阻塞整个 event loop，直接 break 出 while 循环，当 event loop 里下次触发 socket fd 读事件时再来读即可。
                break;
            }

            fprintf(stderr, "Error [%s] [recv_packet], errno = %s.\n", __func__, strerror(errno));
            break; // return -1;
        }

        ngtcp2_path path; // path 用来表明收到的这个 QUIC packet 的网络路径
        memcpy(&path, ngtcp2_conn_get_path(this->conn), sizeof(path));
        path.remote.addrlen = remote_addrlen;
        path.remote.addr = (sockaddr *)&remote_addr;

        ngtcp2_pkt_info pi = {0}; // packet metadata

        ret = this->read_packet(path, pi, buf, ret, timestamp());
        if (ret < 0)
        {
            fprintf(stderr, "Error [%s] [this->read_packet (i.e. ngtcp2_conn_read_pkt)]: ngtcp2_liberr = %s.", __func__, ngtcp2_strerror(ret));
            return -1;
        }
    }

    return 0;
}

int Connection::write()
{
    int ret;

    if (this->streams.empty()) // 如果当前 connection 中还没有建立任何一条 stream
    {
        ret = this->write_one_stream(nullptr);

        if (ret < 0)
            return -1;
    }
    else
    {
        for (const auto &kv : this->streams)
        {
            ret = this->write_one_stream(kv.second);

            if (ret < 0)
                return -1;
        }
    }

    return 0;
}

int Connection::write_one_stream(std::shared_ptr<Stream> stream)
{
    printf("Debug [%s]: now is writing stream #%zd.\n", __func__, (stream ? stream->get_id() : -1));

    uint8_t buf[BUF_SIZE];

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);

    ngtcp2_pkt_info pi;

    uint64_t ts = timestamp();

    uint32_t flags = NGTCP2_WRITE_DATAGRAM_FLAG_NONE;

    // 使用 NGTCP2_WRITE_STREAM_FLAG_MORE 来指明：可能还会从 stream 中取到更多的待发送的数据，应该尽可能将它们合并到同一个 packet 中。
    // 关闭 NGTCP2_WRITE_STREAM_FLAG_MORE 位，便于调试。
    // flags |= NGTCP2_WRITE_STREAM_FLAG_MORE;

    while (true)
    {
        ngtcp2_vec datav;
        int64_t stream_id;

        if (stream)
        {
            datav.base = const_cast<uint8_t *>(stream->peek_tosd_data(datav.len)); // 从 stream 中获取待发送的数据

            if (datav.len == 0) // 若当前 stream 中没有要发送的数据了
            {
                stream_id = -1;                          // 将 stream_id 置为 -1 来表明没有新的 stream data 要发送了
                flags &= ~NGTCP2_WRITE_STREAM_FLAG_MORE; // 事实上，这时即使开启 NGTCP2_WRITE_STREAM_FLAG_MORE 标记也不会有效果
            }
            else
            {
                stream_id = stream->get_id();
            }
        }
        else
        {
            datav.base = nullptr;
            datav.len = 0;
            stream_id = -1;
        }

        printf("Debug [%s]: stream #%zd data gathered, datav.len = %zu.\n", __func__, stream_id, datav.len);

        ngtcp2_ssize n_read;    // 用来记录：当前传入的 datav 中有多少数据被读取到 packet 里了，不会超过 datav.len
        ngtcp2_ssize n_written; // 用来记录：当前写入到 buf 里的 packet，占用了 buf 多少个字节

        n_written = ngtcp2_conn_writev_stream(this->conn, &ps.path, &pi,
                                              buf, sizeof(buf),
                                              &n_read,
                                              flags,
                                              stream_id,
                                              &datav, /*datavcnt = */ 1,
                                              ts);
        if (n_written < 0)
        {
            if (n_written == NGTCP2_ERR_WRITE_MORE)
            {
                // 由于使用了 NGTCP2_WRITE_DATAGRAM_FLAG_NONE，因此可能会返回 NGTCP2_ERR_WRITE_MORE。
                // 这表示数据已经成功写入了，但是需要继续再次调用 ngtcp2_conn_writev_stream 来往同一个 QUIC packet 中合并写入更多的 STREAM frame。
                // 如果确实没有更多的 stream data 要合并到该 packet 里了，可以在下次调用时传入 stream_id = -1 来停止合并，并得到一个 packet。

                stream->mark_sent(n_read); // 注意更新 stream 中已发送的标记

                continue; // 不需要做别的事情，再次调用 ngtcp2_conn_writev_stream 写更多的数据即可
            }

            fprintf(stderr, "Error [%s] [ngtcp2_conn_writev_stream] ngtcp2_liberr = %s.\n", __func__, ngtcp2_strerror((int)n_written));
            ngtcp2_connection_close_error_set_transport_error_liberr(&(this->last_error), (int)n_written, nullptr, 0);

            return -1;
        }

        if (n_written == 0)
        {
            // 该函数返回 0，表明没有成功写任何 STREAM frame 到 packet 中，原因是缓冲区太小或受拥塞限制。（首先确认我们设置了足够大的 buf）
            // 此时 application 不应该再调用 ngtcp2_conn_writev_stream 尝试写新的 STREAM frame 到 packet，应当等待拥塞窗口的增长。
            return 0;
        }

        if (stream && n_read > 0) // 注意 stream->mark_sent 是增量式的标记，若 n_read == 0 则没必要调用 stream->mark_sent
            stream->mark_sent(n_read);

        /* 调用 send_packet 来往 socket fd 中送入 packet */
        printf("Debug [%s]: to call [send_packet] with socket_fd = %d, n_written = %zd.\n", __func__, this->socket_fd, n_written);
        debug_print_sockaddr((sockaddr *)&(this->remote_addr), this->remote_addrlen);
        debug_print_quic_packet(buf, n_written); // 由于是明文传输模式，因此我们可以直接观察产生的 QUIC packet 的情况
        int ret = send_packet(this->socket_fd, buf, n_written,
                              (sockaddr *)&(this->remote_addr), this->remote_addrlen);
        if (ret < 0)
        {
            printf("Error [%s] [send_packet]: ret = %d, errno = %s.\n", __func__, ret, strerror(errno));

            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break; // 为了不阻塞整个 event loop，直接 break 出 while 循环

                // 我们既然已经对 stream 中的这部分数据标记了 sent，但实际最终却没有发送成功，按理来说不应该直接 break，应该反复尝试发送才对。
                // 我推测：将这部分数据最终正确发送给对端，这个责任应该是交给 ngtcp2 内部的重传机制了。
            }

            break; // 替换原先的 `return -1;`
        }

        if (datav.len == 0) // 已经没有 stream data 可发送了，跳出循环
            break;
    }

    return 0;
}

void Connection::close()
{
    printf("Debug: func [%s] is called. State: is_closed = %s.\n",
           __func__, (this->is_closed ? "True" : "False"));

    if (this->is_closed)
        return;

    this->is_closed = true;

    if (ngtcp2_conn_is_in_closing_period(this->conn) || !(this->last_error.error_code))
        return;

    uint8_t buf[BUF_SIZE];

    ngtcp2_pkt_info pi;

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);

    ngtcp2_ssize n_written = ngtcp2_conn_write_connection_close(this->conn, &ps.path, &pi,
                                                                buf, sizeof(buf),
                                                                &(this->last_error),
                                                                timestamp());
    if (n_written < 0)
    {
        fprintf(stderr, "Error [%s] [ngtcp2_conn_write_connection_close] ngtcp2_liberr = %s.\n", __func__, ngtcp2_strerror((int)n_written));
        return;
    }

    ssize_t ret = send_packet(this->socket_fd, buf, (size_t)n_written,
                              (sockaddr *)&(this->remote_addr), this->remote_addrlen);
    if (ret < 0)
        fprintf(stderr, "Error [%s] [send_packet] errno = %s.\n", __func__, strerror(errno));
}