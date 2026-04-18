#include <VMPilot_crypto.hpp>

#include <sodium.h>

#include <cstdint>
#include <mutex>
#include <vector>

namespace
{
    bool EnsureSodiumInitialized() noexcept
    {
        static std::once_flag init_once;
        static bool init_ok = false;

        std::call_once(init_once, []() {
            init_ok = sodium_init() >= 0;
        });

        return init_ok;
    }
}

std::vector<uint8_t> VMPilot::Crypto::Encrypt_AES_256_CBC_PKCS7(const std::vector<uint8_t> &data,
                                                                const std::string &key) noexcept
{
    (void)data;
    (void)key;

    // libsodium does not provide AES-256-CBC/PKCS7. The only AES surface it
    // exposes is AES-256-GCM AEAD, which would not match this API's contract.
    return {};
}

std::vector<uint8_t> VMPilot::Crypto::Decrypt_AES_256_CBC_PKCS7(const std::vector<uint8_t> &data,
                                                                const std::string &key) noexcept
{
    (void)data;
    (void)key;

    // libsodium does not provide AES-256-CBC/PKCS7. The only AES surface it
    // exposes is AES-256-GCM AEAD, which would not match this API's contract.
    return {};
}

std::vector<uint8_t> VMPilot::Crypto::SHA256(const std::vector<uint8_t> &data,
                                             const std::vector<uint8_t> &salt) noexcept
{
    std::vector<uint8_t> result;
    if (!EnsureSodiumInitialized())
        return result;

    crypto_hash_sha256_state state;
    if (crypto_hash_sha256_init(&state) != 0)
        return result;

    const auto *data_ptr = data.empty() ? nullptr : data.data();
    if (crypto_hash_sha256_update(&state, data_ptr, data.size()) != 0)
        return result;

    const auto *salt_ptr = salt.empty() ? nullptr : salt.data();
    if (crypto_hash_sha256_update(&state, salt_ptr, salt.size()) != 0)
        return result;

    result.resize(crypto_hash_sha256_BYTES);
    if (crypto_hash_sha256_final(&state, result.data()) != 0)
        return {};

    return result;
}

bool VMPilot::Crypto::Verify_Ed25519(const std::vector<uint8_t> &public_key_32,
                                     const std::vector<uint8_t> &signature_64,
                                     const std::string &covered_domain,
                                     const std::vector<uint8_t> &message) noexcept
{
    if (public_key_32.size() != crypto_sign_ed25519_PUBLICKEYBYTES) return false;
    if (signature_64.size() != crypto_sign_ed25519_BYTES) return false;
    if (covered_domain.empty() || covered_domain.size() > 0xff) return false;
    if (!EnsureSodiumInitialized()) return false;

    std::vector<uint8_t> signed_message;
    signed_message.reserve(1 + covered_domain.size() + message.size());
    signed_message.push_back(static_cast<uint8_t>(covered_domain.size()));
    signed_message.insert(signed_message.end(), covered_domain.begin(), covered_domain.end());
    signed_message.insert(signed_message.end(), message.begin(), message.end());

    return crypto_sign_ed25519_verify_detached(signature_64.data(),
                                               signed_message.data(),
                                               signed_message.size(),
                                               public_key_32.data()) == 0;
}
