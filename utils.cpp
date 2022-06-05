#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>

#include "utils.h"

void debug_print_sockaddr(const sockaddr *addr, socklen_t addrlen)
{
    char host[50], port[50];
    int ret = getnameinfo(addr, addrlen, host, sizeof(host), port, sizeof(port), 0);
    if (ret < 0)
    {
        printf("Debug [%s] [getnameinfo] ret = %s.\n", __func__, gai_strerror(ret));
        return;
    }

    printf("Debug [%s] [getnameinfo] host = %s, port = %s.\n", __func__, host, port);
}

void debug_print_quic_packet(const uint8_t *pkt, size_t pktlen)
{
    printf("Debug [%s]: [", __func__);
    for (size_t i = 0; i < pktlen; ++i)
        printf("%d%c", pkt[i], (i + 1 < pktlen ? ',' : '\0'));
    printf("].\n");

    write(STDOUT_FILENO, pkt, pktlen); // 直接查看 ngtcp2_conn_writev_stream 产生的 QUIC packet。
    printf("\n");
}

int set_nonblock(int fd)
{
    int flags = 0;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
    {
        fprintf(stderr, "Error [%s] [fcntl]: errno = %s.\n", __func__, strerror(errno));
        return -1;
    }

    flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (flags < 0)
    {
        fprintf(stderr, "Error [%s] [fcntl]: errno = %s.\n", __func__, strerror(errno));
        return -1;
    }

    return 0;
}

int resolve_and_connect(const char *host, const char *port,
                        sockaddr *local_addr, socklen_t *local_addrlen,
                        sockaddr *remote_addr, socklen_t *remote_addrlen)
{
    struct addrinfo hints = {0};
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM; // 基于 UDP

    struct addrinfo *result = nullptr;
    int ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *rp = result; rp; rp = rp->ai_next)
    {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) // 若创建 socket fd 失败则直接尝试下一个
            continue;

        // 返回：远端的 socket addr
        memcpy(remote_addr, rp->ai_addr, rp->ai_addrlen);
        *remote_addrlen = rp->ai_addrlen;

        // 返回：本端的 socket addr
        socklen_t temp_len = *local_addrlen;
        if (getsockname(fd, local_addr, &temp_len) < 0)
            return -1;
        *local_addrlen = temp_len;

        break;
    }

    freeaddrinfo(result);

    return (fd < 0) ? -1 : fd;
}

int resolve_and_bind(const char *host, const char *port,
                     sockaddr *local_addr, socklen_t *local_addrlen)
{
    struct addrinfo hints = {0};
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *result = nullptr;
    int ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *rp = result; rp; rp = rp->ai_next)
    {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) // 若创建 socket fd 失败则直接尝试下一个
            continue;

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            // 返回：本端的 socket addr
            memcpy(local_addr, rp->ai_addr, rp->ai_addrlen);
            *local_addrlen = rp->ai_addrlen;

            break; // bind 成功，直接结束循环
        }

        close(fd); // bind 失败，尝试下一个
    }

    freeaddrinfo(result);

    return fd;
}

uint64_t timestamp()
{
    struct timespec tp;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
        return 0;

    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

void log_printf(void *user_data, const char *fmt, ...)
{
#ifdef ENABLE_NGTCP2_LOG_PRINTF
    (void)user_data;

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
#endif
}

void rand_bytes(uint8_t *data, size_t len)
{
    static int for_srand = (srand(timestamp()), 0);
    (void)for_srand;

    for (size_t i = 0; i < len; ++i)
        data[i] = static_cast<uint8_t>(rand());
}

ssize_t recv_packet(int fd, uint8_t *data, size_t data_size,
                    sockaddr *remote_addr, socklen_t *remote_addrlen)
{
    struct iovec iov;
    iov.iov_base = data;
    iov.iov_len = data_size;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    msg.msg_name = remote_addr;
    msg.msg_namelen = *remote_addrlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ssize_t ret;
    do
    {
        ret = recvmsg(fd, &msg, MSG_DONTWAIT);
    } while (ret < 0 && errno == EINTR); // 如果在读的过程中遇到了中断，则返回 -1，同时置 errno 为 EINTR，遇到这种错误号表示还没有读完，需要重新再读

    *remote_addrlen = msg.msg_namelen;

    return ret;
}

ssize_t send_packet(int fd, const uint8_t *data, size_t data_size,
                    sockaddr *remote_addr, socklen_t remote_addrlen)
{
    struct iovec iov;
    iov.iov_base = (void *)data;
    iov.iov_len = data_size;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    /* On MacOS，get errno = "Socket is already connected" of a connected UDP socket. */
    msg.msg_name = remote_addr;
    msg.msg_namelen = remote_addrlen;
    // msg.msg_name = nullptr;
    // msg.msg_namelen = 0;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ssize_t ret;
    do
    {
        ret = sendmsg(fd, &msg, MSG_DONTWAIT);
    } while (ret < 0 && errno == EINTR);

    return ret;
}

int get_random_cid(ngtcp2_cid *cid, size_t len)
{
    if (len > NGTCP2_MAX_CIDLEN)
        return -1;

    cid->datalen = len;
    rand_bytes(cid->data, cid->datalen);

    return 0;
}