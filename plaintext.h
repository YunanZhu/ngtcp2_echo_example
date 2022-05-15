#ifndef __PLAINTEXT_H__
#define __PLAINTEXT_H__

#include <ngtcp2/ngtcp2.h>

namespace ngtcp2_plaintext
{
    void pt_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx);

    void pt_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx);

    int client_initial_cb(ngtcp2_conn *conn, void *user_data);

    int recv_client_initial_cb(ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *user_data);

    int recv_crypto_data_cb(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                            uint64_t offset, const uint8_t *data, size_t datalen, void *user_data);

    int recv_crypto_data_server_cb(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                                   uint64_t offset, const uint8_t *data, size_t datalen, void *user_data);

    int handshake_completed_cb(ngtcp2_conn *conn, void *user_data);

    int encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                   const ngtcp2_crypto_aead_ctx *aead_ctx,
                   const uint8_t *plaintext, size_t plaintextlen,
                   const uint8_t *nonce, size_t noncelen,
                   const uint8_t *aad, size_t aadlen);

    int decrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                   const ngtcp2_crypto_aead_ctx *aead_ctx,
                   const uint8_t *ciphertext, size_t ciphertextlen,
                   const uint8_t *nonce, size_t noncelen,
                   const uint8_t *aad, size_t aadlen);

    int hp_mask_cb(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                   const ngtcp2_crypto_cipher_ctx *hp_ctx,
                   const uint8_t *sample);

    int recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data);

    int update_key_cb(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                      ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                      ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                      const uint8_t *current_rx_secret, const uint8_t *current_tx_secret, size_t secretlen,
                      void *user_data);

    void delete_crypto_aead_ctx_cb(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx, void *user_data);

    void delete_crypto_cipher_ctx_cb(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *cipher_ctx, void *user_data);

    int get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data, void *user_data);

    int version_negotiation_cb(ngtcp2_conn *conn, uint32_t version,
                               const ngtcp2_cid *client_dcid, void *user_data);

} /* ngtcp2_plaintext */

namespace ngtcp2_plaintext
{
    /**
     * 由于直接跳过了 QUIC handshake 阶段，因此必须为 client 和 server 端预设 Connection ID。
     */
    void preset_fixed_dcid_scid(bool is_server, ngtcp2_cid &dcid, ngtcp2_cid &scid);

    /**
     * 为 |callbacks| 设置其中 crypto 相关的那些回调函数（注意是明文传输模式下的）。
     * |isServer| 指明 |callbacks| 将会被用于创建 server 端还是 client 端的 ngtcp2_conn 对象。
     */
    void set_ngtcp2_crypto_callbacks(bool is_server, ngtcp2_callbacks &callbacks);

    /**
     * 默认设置 |settings| ，完成后应当可以被直接用于创建 ngtcp2_conn 对象。
     */
    void set_default_ngtcp2_settings(bool is_server, ngtcp2_settings &settings, ngtcp2_printf log_printf, ngtcp2_tstamp initial_timestamp);

    /**
     * 默认设置 |params|，完成后应当可以被直接用于创建 ngtcp2_conn 对象。
     */
    void set_default_ngtcp2_transport_params(bool is_server, ngtcp2_transport_params &params);

    /**
     * 创建一个 QUIC handshake 已完成的 ngtcp2_conn 对象。
     */
    ngtcp2_conn *create_handshaked_ngtcp2_conn(
        bool is_server,
        const ngtcp2_cid &dcid, const ngtcp2_cid &scid,
        const sockaddr *local_addr, socklen_t local_addrlen,
        const sockaddr *remote_addr, socklen_t remote_addrlen,
        const ngtcp2_callbacks &callbacks, const ngtcp2_settings &settings, const ngtcp2_transport_params &params,
        void *user_data);

} /* ngtcp2_plaintext */

#endif /* __PLAINTEXT_H__ */