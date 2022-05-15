#include <algorithm>

#include "stream.h"

Stream::Stream(int64_t stream_id)
    : id(stream_id), buf{0}, buf_head(0), buf_size(0), nsent_offset(0), acked_offset(0)
{
}

size_t Stream::push_data(const uint8_t *data, size_t data_len)
{
    if (data_len == 0)
        return 0;

    size_t actual_len = std::min(data_len, get_buf_rmcp());

    size_t buf_tail = get_buf_tail();
    for (size_t i = 0; i < actual_len; ++i)
        buf[(buf_tail + i) % STREAM_BUF_CAPACITY] = data[i];

    buf_size += actual_len;
    return actual_len;
}

const uint8_t *Stream::peek_tosd_data(size_t &data_size) const
{
    size_t tosd_size = get_tosd_size(); // 当前所有待发送数据的量

    if (tosd_size <= 0)
    {
        data_size = 0;
        return nullptr;
    }

    size_t tosd_begin = (buf_head + get_sent_size()) % STREAM_BUF_CAPACITY; // 待发送数据的起始位置

    data_size = std::min(STREAM_BUF_CAPACITY - tosd_begin, tosd_size); // 由于循环向量的限制，不一定可以取到全部的待发送数据
    return buf + tosd_begin;
}

int Stream::mark_sent(size_t increment)
{
    if (increment <= get_tosd_size())
    {
        nsent_offset += increment;
        return 0;
    }
    else
        return -1;
}

int Stream::mark_acked(size_t new_acked_offset)
{
    if (new_acked_offset > nsent_offset) // 不可能对未发送的数据获得确认
        return -1;

    if (new_acked_offset > acked_offset) // acked_offset 采用的是累计确认，只增不减
    {
        size_t increment = new_acked_offset - acked_offset; // 相比上一次确认的增量

        if (increment > buf_size || increment > get_sent_size()) // 不可能对未发送的数据获得确认
            return -1;

        acked_offset = new_acked_offset;

        buf_head += increment, buf_head %= STREAM_BUF_CAPACITY;
        buf_size -= increment;
    }

    return 0;
}