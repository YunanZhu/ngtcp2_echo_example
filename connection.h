#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <memory>
#include <list>
#include <unordered_map>
#include <vector>

#include <ngtcp2/ngtcp2.h>

#include "stream.h"

class Connection
{
private:
    ngtcp2_conn *conn; // ngtcp2 QUIC connection object

    int socket_fd;

    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;

    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;

    size_t streams_capacity;                                      // 开启 stream 数量的上限
    std::unordered_map<int64_t, std::shared_ptr<Stream>> streams; // map: stream_id -> stream object

    std::vector<int64_t> all_streams_id; // 维护所有 streams 的 ID
    size_t cur_stream_idx;               // 是 all_streams_id 的某个元素的下标，表示当前从 stdin 接收的数据存放到哪一个 stream 中

    ngtcp2_connection_close_error last_error; // 记录调用 ngtcp2 库函数时最后一个发生的 error

    bool is_closed;

public:
    Connection(int sock_fd, size_t n_streams_max);
    ~Connection();

    // 将 conn 的所有权转移给 Connection 类对象
    int steal_ngtcp2_conn(ngtcp2_conn *&conn);

    // 检查 `conn_to_check` 是否和当前 connection 中所持有的 ngtcp2_conn 对象相同。
    inline bool check_ngtcp2_conn(const ngtcp2_conn *conn_to_check) const { return this->conn == conn_to_check; }

    inline void set_socket_fd(int sock_fd) { this->socket_fd = sock_fd; }

    inline int get_socket_fd() const { return this->socket_fd; }

    void set_local_addr(const sockaddr *local_addr, socklen_t local_addrlen);

    void set_remote_addr(const sockaddr *remote_addr, socklen_t remote_addrlen);

    // 查询当前 connection 中开启的 streams 的数量。
    inline size_t get_streams_count() const { return streams.size(); }

    // 查询当前 connection 中可以开启的 streams 的数量上限。
    inline size_t get_streams_capacity() const { return streams_capacity; }

    // 在当前的 connection 中新增一个 stream，如果已经到达了数量上限则不会新增，如果 stream_id 已有则返回 -1 且不会新增。
    int new_stream(int64_t stream_id);

    // 根据 stream_id 查询对应的 stream 是否存在。
    inline bool stream_exist(int64_t stream_id) { return streams.find(stream_id) != streams.end(); }

    // 根据 stream_id 返回对应的 stream，若对应的 stream 不存在则返回 nullptr。
    std::shared_ptr<Stream> get_stream(int64_t stream_id) const;

    // 用 cur_stream 表示当前用来接收数据的 stream，将 cur_stream 切换到下一个。
    int step_cur_stream();

    // 用 cur_stream 表示当前用来接收数据的 stream，获取当前 cur_stream 的 ID。
    int64_t get_cur_stream_id() const;

    // 获取 connection 的 last_error 的引用。
    inline ngtcp2_connection_close_error &get_last_error() { return this->last_error; }

    // 查询 connection 是否已经关闭。
    inline bool get_is_closed() const { return this->is_closed; }

    // 从 socket_fd 中读取 QUIC packet 并交付给 lib ngtcp2 处理。
    // 由于调用了 ngtcp2_conn_read_pkt，因此该函数有可能触发关闭连接。
    int read();

    // 调用 lib ngtcp2 写 QUIC packet 并送入 socket_fd 中。
    // 由于调用了 ngtcp2_conn_writev_stream，该函数有可能触发关闭连接。
    int write();

    // 关闭连接。
    void close();

    // A wrapper around `ngtcp2_conn_handle_expiry`.
    // 由于调用了 ngtcp2_conn_handle_expiry，该函数有可能触发关闭连接。
    // 该函数会直接返回 `ngtcp2_conn_handle_expiry` 的返回值。
    inline int handle_expiry(ngtcp2_tstamp ts)
    {
        int ret = ngtcp2_conn_handle_expiry(this->conn, ts);
        if (ret < 0)
            ngtcp2_connection_close_error_set_transport_error_liberr(&(this->last_error), ret, nullptr, 0); // 根据 ngtcp2 liberr 设置 ccerr

        return ret;
    }

    // A wrapper around `ngtcp2_conn_get_expiry`.
    inline ngtcp2_tstamp get_expiry() const { return ngtcp2_conn_get_expiry(this->conn); }

    // A wrapper around `ngtcp2_conn_read_pkt`. 将 QUIC packet 交给 ngtcp2 库进行解析。
    // 该函数会直接返回 `ngtcp2_conn_read_pkt` 的返回值。
    inline int read_packet(const ngtcp2_path &path, const ngtcp2_pkt_info &pi, const uint8_t *pkt, size_t pktlen, ngtcp2_tstamp ts)
    {
        int ret = ngtcp2_conn_read_pkt(this->conn, &path, &pi, pkt, pktlen, ts);
        if (ret < 0)
            ngtcp2_connection_close_error_set_transport_error_liberr(&(this->last_error), ret, nullptr, 0); // 根据 ngtcp2 liberr 设置 ccerr

        return ret;
    }

private:
    // 将某一条 stream 中的待发送数据写成 QUIC packet 并送入 socket_fd 发送出去。
    int write_one_stream(std::shared_ptr<Stream> stream);

private:
    Connection(const Connection &rhs) = delete;            // no copy
    Connection &operator=(const Connection &rhs) = delete; // no assignment
};

#endif /* __CONNECTION_H__ */