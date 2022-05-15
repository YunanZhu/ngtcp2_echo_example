#ifndef __PLAINTEXT_CPP__
#define __PLAINTEXT_CPP__

#include <cstdio>
#include <cstring>
#include <assert.h>

#include "ngtcp2/ngtcp2.h"
#include "ngtcp2_conn.h"

#include "utils.h"
#include "plaintext.h"

namespace ngtcp2_plaintext
{
/**
 * 拷贝自 ngtcp2 库的 “lib/ngtcp2_crypto.h”。
 *
 * NGTCP2_INITIAL_AEAD_OVERHEAD is an overhead of AEAD used by Initial packets.
 * Because QUIC uses AEAD_AES_128_GCM, the overhead is 16 bytes.
 */
#define NGTCP2_INITIAL_AEAD_OVERHEAD 16

/**
 * 拷贝自 ngtcp2 库的 “tests/ngtcp2_test_helper.h”。
 *
 * NGTCP2_FAKE_AEAD_OVERHEAD is AEAD overhead used in unit tests.
 * Because we use the same encryption/decryption function for both
 * handshake and post handshake packets, we have to use AEAD overhead
 * used in handshake packets.
 */
#define NGTCP2_FAKE_AEAD_OVERHEAD NGTCP2_INITIAL_AEAD_OVERHEAD

/**
 * NGTCP2_FAKE_HP_MASK is a header protection mask used in unit tests.
 */
#define NGTCP2_FAKE_HP_MASK "\x00\x00\x00\x00\x00"

    static const uint8_t null_secret[32] = {0};
    static const uint8_t null_iv[16] = {0};
    static const uint8_t null_data[4096] = {0};

    /**
     * 将目前 |conn| 中唯一一个 SCID 设置为“已使用”状态。
     */
    void conn_set_scid_used(ngtcp2_conn *conn)
    {
        assert(1 == ngtcp2_ksl_len(&conn->scid.set)); // NOTE: Add extern "C" to its declaration.

        ngtcp2_ksl_it it = ngtcp2_ksl_begin(&conn->scid.set); // NOTE: Add extern "C" to its declaration.
        ngtcp2_scid *scid = static_cast<ngtcp2_scid *>(ngtcp2_ksl_it_get(&it));
        scid->flags |= NGTCP2_SCID_FLAG_USED;
        assert(NGTCP2_PQ_BAD_INDEX == scid->pe.index);

        int rv = ngtcp2_pq_push(&conn->scid.used, &scid->pe); // NOTE: Add extern "C" to its declaration.
        assert(0 == rv);
    }

    /**
     * 摘录总结 lib ngtcp2 doc 中关于 ngtcp2_crypto_ctx 的描述如下：
     * ngtcp2_crypto_ctx is a convenient structure to bind all crypto related objects in one place.
     * Use ngtcp2_crypto_ctx_initial() to initialize this struct for Initial packet encryption.
     * Use ngtcp2_crypto_ctx_tls() to initialize this struct for Handshake and 1RTT packets.
     *
     * 本函数应该和 ngtcp2_crypto_ctx_initial() 在使用上是一致的。
     *
     * 参考
     * 1. "tests/ngtcp2_conn_test.c" 中的函数 init_initial_crypto_ctx()
     */
    void pt_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx)
    {
        memset(ctx, 0, sizeof(*ctx));

        ctx->aead.max_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;

        ctx->max_encryption = 9999;
        ctx->max_decryption_failure = 8888;
    }

    /**
     * 本函数应该和 ngtcp2_crypto_ctx_tls() 在使用上是一致的。
     *
     * 参考
     * 1. "tests/ngtcp2_conn_test.c" 中的函数 init_crypto_ctx
     */
    void pt_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx)
    {
        memset(ctx, 0, sizeof(*ctx));

        ctx->aead.max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;

        ctx->max_encryption = 9999;
        ctx->max_decryption_failure = 8888;
    }

    /**
     * ngtcp2_callbacks: is invoked when client application asks TLS stack to produce first TLS cryptographic handshake data.
     *
     * 参考：
     * 1. ngtcp2_crypto_client_initial_cb
     *      ngtcp2_crypto_derive_and_install_initial_key
     *      ngtcp2_crypto_read_write_crypto_data
     * 2. "tests/ngtcp2_conn_test.c" client_initial
     * 3. "tests/ngtcp2_conn_test.c" setup_handshake_client
     */
    int client_initial_cb(ngtcp2_conn *conn, void *user_data)
    {
        printf("Debug: [%s] is called.\n", __func__);

        /* Set crypto_ctx for Initial packet encryption. */
        ngtcp2_crypto_ctx crypto_ctx = {0};
        pt_crypto_ctx_initial(&crypto_ctx);
        ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);

        /* Install packet protection keying materials for Initial packets. */
        ngtcp2_crypto_aead_ctx aead_ctx = {0};
        ngtcp2_crypto_cipher_ctx hp_ctx = {0};
        ngtcp2_conn_install_initial_key(conn,
                                        &aead_ctx, null_iv, &hp_ctx, // rx
                                        &aead_ctx, null_iv, &hp_ctx, // tx
                                        sizeof(null_iv));

        /* Set AEAD for Retry integrity tag verification. */
        ngtcp2_crypto_aead retry_aead = {0, NGTCP2_FAKE_AEAD_OVERHEAD};
        ngtcp2_conn_set_retry_aead(conn, &retry_aead, &aead_ctx);

        /* Send some meaningless data. */
        ngtcp2_conn_submit_crypto_data(conn, NGTCP2_CRYPTO_LEVEL_INITIAL, null_data, 217);
        return 0;
    }

    /**
     * ngtcp2_callbacks: is invoked when a server receives the first packet from client.
     *
     * 参考：
     * 1. "tests/ngtcp2_conn_test.c" recv_client_initial
     */
    int recv_client_initial_cb(ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *user_data)
    {
        printf("Debug: [%s] is called.\n", __func__);

        /* Set crypto_ctx for Initial packet encryption. */
        ngtcp2_crypto_ctx crypto_ctx = {0};
        pt_crypto_ctx_initial(&crypto_ctx);
        ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);

        /* Install packet protection keying materials for Initial packets. */
        ngtcp2_crypto_aead_ctx aead_ctx = {0};
        ngtcp2_crypto_cipher_ctx hp_ctx = {0};
        ngtcp2_conn_install_initial_key(conn,
                                        &aead_ctx, null_iv, &hp_ctx, // rx
                                        &aead_ctx, null_iv, &hp_ctx, // tx
                                        sizeof(null_iv));

        /* Set crypto_ctx for Handshake/1RTT packet encryption. */
        pt_crypto_ctx_tls(&crypto_ctx);
        ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);

        conn->negotiated_version = conn->original_version;

        /* Install packet protection keying materials for encrypting/decrypting Handshake packets. */
        ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);
        ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

        return 0;
    }

    // ngtcp2_callbacks: is invoked when cryptographic data (CRYPTO frame, in other words, TLS message) is received.
    int recv_crypto_data_cb(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                            uint64_t offset, const uint8_t *data, size_t datalen, void *user_data)
    {
        printf("Debug: [%s] is called.\n", __func__);
        return 0;
    }

    // ngtcp2_callbacks: 当本端需要加密一个 QUIC packet 时会调用本函数。
    int encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                   const ngtcp2_crypto_aead_ctx *aead_ctx,
                   const uint8_t *plaintext, size_t plaintextlen,
                   const uint8_t *nonce, size_t noncelen,
                   const uint8_t *aad, size_t aadlen)
    {
        if (plaintextlen && plaintext != dest)
            memmove(dest, plaintext, plaintextlen); // 直接将明文拷贝到 dest 中

        memset(dest + plaintextlen, 0, aead->max_overhead); // AEAD encryption overhead 部分全部置零

        return 0;
    }

    // ngtcp2_callbacks: 当本端需要解密一个 QUIC packet 时会调用本函数。
    int decrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                   const ngtcp2_crypto_aead_ctx *aead_ctx,
                   const uint8_t *ciphertext, size_t ciphertextlen,
                   const uint8_t *nonce, size_t noncelen,
                   const uint8_t *aad, size_t aadlen)
    {
        assert(ciphertextlen > aead->max_overhead);

        memmove(dest, ciphertext, ciphertextlen - aead->max_overhead);
        return 0;
    }

    // ngtcp2_callbacks: is invoked when lib ngtcp2 asks the application to produce mask to encrypt or decrypt packet header.
    int hp_mask_cb(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                   const ngtcp2_crypto_cipher_ctx *hp_ctx,
                   const uint8_t *sample)
    {
        memcpy(dest, NGTCP2_FAKE_HP_MASK, sizeof(NGTCP2_FAKE_HP_MASK) - 1);
        return 0;
    }

    // ngtcp2_callbacks: is invoked when a client receives Retry packet. This callback is client only.
    int recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data)
    {
        return 0;
    }

    // ngtcp2_callbacks: is invoked when the lib tells the application it must generate new packet protection keying materials and AEAD cipher context objects with new keys.
    int update_key_cb(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                      ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                      ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                      const uint8_t *current_rx_secret, const uint8_t *current_tx_secret, size_t secretlen,
                      void *user_data)
    {
        assert(sizeof(null_secret) == secretlen);

        // 这些内容都置为 0xff 时必须的吗？猜测全部置为 0x00 应该也可以才对。#TODO 待探究
        memset(rx_secret, 0xff, sizeof(null_secret));
        memset(tx_secret, 0xff, sizeof(null_secret));

        rx_aead_ctx->native_handle = nullptr;
        memset(rx_iv, 0xff, sizeof(null_iv));

        tx_aead_ctx->native_handle = nullptr;
        memset(tx_iv, 0xff, sizeof(null_iv));

        return 0;
    }

    // ngtcp2_callbacks: deletes a given AEAD cipher context object.
    void delete_crypto_aead_ctx_cb(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx, void *user_data)
    {
        // 由于 aead_ctx->native_handle 应当是一个空指针，因此并不需要 delete，可以考虑使用 assert 测试一下。#TODO
        return;
    }

    // ngtcp2_callbacks: deletes a given cipher context object.
    void delete_crypto_cipher_ctx_cb(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *cipher_ctx, void *user_data)
    {
        // 由于 cipher_ctx->native_handle 应当是一个空指针，因此并不需要 delete，可以考虑使用 assert 测试一下。#TODO
        return;
    }

    /**
     * ngtcp2_callbacks: ask the application for new data that is sent in PATH_CHALLENGE frame.
     * Application must generate new unpredictable exactly NGTCP2_PATH_CHALLENGE_DATALEN bytes
     * of random data and store them into the buffer pointed by data.
     *
     * PATH_CHALLENGE frame 主要是用于 Path Validation，根据文档要求直接生成一串 random bytes 数据即可。
     */
    int get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data, void *user_data)
    {
        rand_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN);

        return 0;
    }

    // ngtcp2_callbacks: is invoked when the compatible version negotiation takes place.
    // For client, it is called when it sees a change in version field of a long header packet.
    // This callback function might be called multiple times for client.
    // For server, it is called once when the version is negotiated.
    int version_negotiation_cb(ngtcp2_conn *conn, uint32_t version,
                               const ngtcp2_cid *client_dcid, void *user_data)
    {
        ngtcp2_crypto_aead_ctx aead_ctx = {0};
        ngtcp2_crypto_cipher_ctx hp_ctx = {0};

        ngtcp2_conn_install_vneg_initial_key(conn, version,
                                             &aead_ctx, null_iv, &hp_ctx,
                                             &aead_ctx, null_iv, &hp_ctx,
                                             sizeof(null_iv));

        return 0;
    }
} /* ngtcp2_plaintext */

namespace ngtcp2_plaintext
{
    void preset_fixed_dcid_scid(bool is_server, ngtcp2_cid &dcid, ngtcp2_cid &scid)
    {
        static const uint8_t client_cid[19] = "\xff\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                                              "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xff"; // 用来代表 client 端的 CID，长度 18 个字节

        static const uint8_t server_cid[19] = "\xee\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                                              "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xee"; // 用来代表 server 端的 CID，长度 18 个字节

        if (is_server)
        {
            ngtcp2_cid_init(&dcid, client_cid, sizeof(client_cid) - 1);
            ngtcp2_cid_init(&scid, server_cid, sizeof(server_cid) - 1);
        }
        else
        {
            ngtcp2_cid_init(&dcid, server_cid, sizeof(server_cid) - 1);
            ngtcp2_cid_init(&scid, client_cid, sizeof(client_cid) - 1);
        }
    }

    void set_ngtcp2_crypto_callbacks(bool isServer, ngtcp2_callbacks &callbacks)
    {
        if (isServer)
            callbacks.recv_client_initial = ngtcp2_plaintext::recv_client_initial_cb;
        else
            callbacks.client_initial = ngtcp2_plaintext::client_initial_cb;

        callbacks.recv_crypto_data = ngtcp2_plaintext::recv_crypto_data_cb;

        callbacks.encrypt = ngtcp2_plaintext::encrypt_cb;
        callbacks.decrypt = ngtcp2_plaintext::decrypt_cb;
        callbacks.hp_mask = ngtcp2_plaintext::hp_mask_cb;
        callbacks.recv_retry = ngtcp2_plaintext::recv_retry_cb;
        callbacks.update_key = ngtcp2_plaintext::update_key_cb;

        callbacks.delete_crypto_aead_ctx = ngtcp2_plaintext::delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_plaintext::delete_crypto_cipher_ctx_cb;

        callbacks.get_path_challenge_data = ngtcp2_plaintext::get_path_challenge_data_cb;
        callbacks.version_negotiation = ngtcp2_plaintext::version_negotiation_cb;
    }

    void set_default_ngtcp2_settings(bool isServer, ngtcp2_settings &settings, ngtcp2_printf log_printf, ngtcp2_tstamp initial_timestamp)
    {
        ngtcp2_settings_default(&settings);
        settings.log_printf = log_printf;
        settings.initial_ts = initial_timestamp;
    }

    void set_default_ngtcp2_transport_params(bool is_server, ngtcp2_transport_params &params)
    {
        ngtcp2_transport_params_default(&params);

        switch (is_server)
        {
        case true: // server 端

            params.initial_max_streams_uni = 0;  // 远端可以创建的并发的单向 stream 的数目。
            params.initial_max_streams_bidi = 5; // 远端可以创建的并发的双向 stream 的数目。

            // 对由本端初始化的双向  stream，设定 stream level 的 flow control window 大小，
            // 本端必须确保有足够大的 buffer 来接收这么多的 bytes。
            params.initial_max_stream_data_bidi_local = 128 * 1024;

            // 对由远端初始化的双向 stream，设定 stream level 的 flow control window 大小，
            // 本端必须确保有足够大的 buffer 来接收这么多的 bytes。
            params.initial_max_stream_data_bidi_remote = 128 * 1024;

            // 对由远端初始化的单向 stream，设定 stream level 的 flow control window 大小，
            // 本端必须确保有足够大的 buffer 来接收这么多的 bytes。
            params.initial_max_stream_data_uni = 128 * 1024;

            // 设定 connection level 的 flow control window。
            params.initial_max_data = 1024 * 1024;

            break;

        case false: // client 端

            params.initial_max_streams_uni = 0;
            params.initial_max_streams_bidi = 0;

            params.initial_max_stream_data_bidi_local = 128 * 1024;
            params.initial_max_stream_data_bidi_remote = 128 * 1024;
            params.initial_max_stream_data_uni = 128 * 1024;

            params.initial_max_data = 1024 * 1024;

            break;
        }
    }

    ngtcp2_conn *create_handshaked_ngtcp2_conn(
        bool is_server,
        const ngtcp2_cid &dcid, const ngtcp2_cid &scid,
        const sockaddr *local_addr, socklen_t local_addrlen,
        const sockaddr *remote_addr, socklen_t remote_addrlen,
        const ngtcp2_callbacks &callbacks, const ngtcp2_settings &settings, const ngtcp2_transport_params &params,
        void *user_data)
    {
        ngtcp2_conn *conn = nullptr;

        ngtcp2_path_storage ps;
        ngtcp2_path_storage_init(&ps, local_addr, local_addrlen, remote_addr, remote_addrlen, nullptr);

        if (!is_server)
        {
            int ret = ngtcp2_conn_client_new(&conn, &dcid, &scid, &ps.path,
                                             NGTCP2_PROTO_VER_V1,
                                             &callbacks, &settings, &params, /* mem = */ nullptr,
                                             /* user_data = */ user_data);
            if (ret < 0)
                return nullptr;
        }
        else
        {
            int ret = ngtcp2_conn_server_new(&conn, &dcid, &scid, &ps.path,
                                             NGTCP2_PROTO_VER_V1,
                                             &callbacks, &settings, &params, /* mem = */ nullptr,
                                             /* user_data = */ user_data);
            if (ret < 0)
                return nullptr;
        }

        /* Set crypto_ctx for Handshake/1RTT packet encryption. */
        ngtcp2_crypto_ctx crypto_ctx = {0};
        pt_crypto_ctx_tls(&crypto_ctx);
        ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);

        /* Install packet protection keying materials for decrypting incoming Handshake packets. */
        ngtcp2_crypto_aead_ctx aead_ctx = {0};
        ngtcp2_crypto_cipher_ctx hp_ctx = {0};
        ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

        /* Install packet protection keying materials for encrypting outgoing Handshake packets. */
        ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

        /* Install packet protection keying materials for decrypting Short packets. */
        ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret), &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

        /* Install packet protection keying materials for encrypting Short packets. */
        ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &aead_ctx, null_iv, sizeof(null_iv), &hp_ctx);

        /* 直接将连接的状态设置为已经 QUIC handshake 完毕 */
        conn->state = NGTCP2_CS_POST_HANDSHAKE;
        conn->flags |= NGTCP2_CONN_FLAG_CONN_ID_NEGOTIATED |
                       NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED |
                       NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED_HANDLED |
                       NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
        conn->dcid.current.flags |= NGTCP2_DCID_FLAG_PATH_VALIDATED;

        conn_set_scid_used(conn);

        /* 由于没有握手阶段了，因此本端所存储的远端 transport params 需要手动设置 */
        ngtcp2_transport_params &remote_params = conn->remote.transport_params;
        set_default_ngtcp2_transport_params(!is_server, remote_params);

        conn->local.bidi.max_streams = remote_params.initial_max_streams_bidi; // 根据远端的设置，设定本端可以开启的双向 stream 的最大数量
        conn->local.uni.max_streams = remote_params.initial_max_streams_uni;   // 根据远端的设置，设定本端可以开启的单向 stream 的最大数量
        conn->tx.max_offset = remote_params.initial_max_data;

        conn->negotiated_version = conn->original_version;

        /* stateless reset token */
        if (!is_server)
        {
            conn->dcid.current.flags |= NGTCP2_DCID_FLAG_TOKEN_PRESENT;
            memset(conn->dcid.current.token, 0xf1, NGTCP2_STATELESS_RESET_TOKENLEN);
        }

        /* 调用 conn_handshake_completed */
        // 由于我们跳过了 QUIC 握手阶段，因此该函数不会被 ngtcp2 库调用，我们必须手动调用该函数，
        // 该函数作用就是调用 callbacks.{handshake_completed, extend_max_local_streams_bidi, extend_max_local_streams_uni} 这三个回调函数。
        conn_handshake_completed(conn);

        return conn;
    }

} /* ngtcp2_plaintext */

#endif // __PLAINTEXT_CPP__