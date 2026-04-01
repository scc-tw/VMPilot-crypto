#include <VMPilot_crypto.hpp>

#include <blake3.h>

#include <cstring>

std::vector<uint8_t> VMPilot::Crypto::BLAKE3(const std::vector<uint8_t> &data,
                                             const std::vector<uint8_t> &salt) noexcept
{
    // Doc 16 rev.8: all BLAKE3 calls must use keyed mode.
    // salt is treated as the key (padded/truncated to 32 bytes).
    // data is the message.
    uint8_t key[BLAKE3_KEY_LEN] = {};
    const size_t key_len = salt.size() < BLAKE3_KEY_LEN
                         ? salt.size() : BLAKE3_KEY_LEN;
    if (key_len > 0)
        std::memcpy(key, salt.data(), key_len);

    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, key);

    blake3_hasher_update(&hasher, data.data(), data.size());

    std::vector<uint8_t> result(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, result.data(), result.size());

    // Zero the key copy from stack.
    std::memset(key, 0, sizeof(key));

    return result;
}