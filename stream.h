#ifndef __STREAM_H__
#define __STREAM_H__

#include <cstddef>
#include <cstdint>

class Stream
{
public:
    static constexpr size_t STREAM_BUF_CAPACITY = 1024;

private:
    int64_t id; // Stream ID

    uint8_t buf[STREAM_BUF_CAPACITY]; // 循环向量

    size_t buf_head; // buf 中数据的首地址，是 buf 的某个下标，范围 [0, STREAM_BUF_CAPACITY)。
    size_t buf_size; // buf 中数据的长度，范围 [0, STREAM_BUF_CAPACITY]。

    size_t nsent_offset; // 指示在该 stream 中全部已发送的数据的长度，开区间，单调递增。
    size_t acked_offset; // 指示在该 stream 中全部已确认的数据的长度，开区间，单调递增。
    // 必须保证 nsent_offset - acked_offset 在范围 [0, buf_size] 之内。

    // 根据 buf_head 和 buf_size 可以计算出 buf_tail 的位置
    inline size_t get_buf_tail() const { return (buf_head + buf_size) % STREAM_BUF_CAPACITY; }

public:
    Stream(int64_t stream_id);

    inline int64_t get_id() const { return id; }

    inline size_t get_buf_size() const { return buf_size; }

    // 获取 stream 的 buf 的剩余容量。
    inline size_t get_buf_rmcp() const { return STREAM_BUF_CAPACITY - buf_size; }

    // 往 stream 的 buf 中拷贝进长度为 data_len 的数据，返回实际拷贝到 buf 中的数据长度。
    size_t push_data(const uint8_t *data, size_t data_len);

    // 查询 stream 的 buf 中已发送数据的长度，范围 [0, buf_size]。
    inline size_t get_sent_size() const { return nsent_offset - acked_offset; }

    // 查询 stream 的 buf 中待发送数据的长度，范围 [0, buf_size]。
    inline size_t get_tosd_size() const { return buf_size - get_sent_size(); }

    // 获取 buf 中待发送的数据，返回数据首地址，获取到的待发送数据的长度保存到 data_size 中。
    // 注意：由于循环向量的限制，获取到的待发送数据可能是全部待发送数据的一部分。
    const uint8_t *peek_tosd_data(size_t &data_size) const;

    // 更新已发送的数据的位置。
    int mark_sent(size_t increment);

    // 更新已确认的数据的位置。
    int mark_acked(size_t new_acked_offset);
};

#endif /* __STREAM_H__ */