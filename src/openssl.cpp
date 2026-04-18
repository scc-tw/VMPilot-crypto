#include <VMPilot_crypto.hpp>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

std::vector<uint8_t> VMPilot::Crypto::Encrypt_AES_256_CBC_PKCS7(const std::vector<uint8_t> &data,
                                                                const std::string &key) noexcept
{
    std::vector<uint8_t> result;

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (ctx == nullptr)
        return result;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const uint8_t *>(key.c_str()), nullptr) != 1)
        return result;

    result.resize(data.size() + EVP_CIPHER_CTX_block_size(ctx.get()));

    int len = 0;
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx.get(), result.data(), &len, data.data(), data.size()) != 1)
        return result;

    out_len = len;

    if (EVP_EncryptFinal_ex(ctx.get(), result.data() + len, &len) != 1)
        return result;

    out_len += len;
    result.resize(out_len);
    return result;
}

std::vector<uint8_t> VMPilot::Crypto::Decrypt_AES_256_CBC_PKCS7(const std::vector<uint8_t> &data,
                                                                const std::string &key) noexcept
{
    std::vector<uint8_t> result;

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (ctx == nullptr)
        return result;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const uint8_t *>(key.c_str()), nullptr) != 1)
        return result;

    result.resize(data.size());

    int len = 0;
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx.get(), result.data(), &len, data.data(), data.size()) != 1)
        return result;

    out_len = len;

    if (EVP_DecryptFinal_ex(ctx.get(), result.data() + len, &len) != 1)
        return result;

    out_len += len;
    result.resize(out_len);
    return result;
}

std::vector<uint8_t> VMPilot::Crypto::SHA256(const std::vector<uint8_t> &data,
                                             const std::vector<uint8_t> &salt) noexcept
{
    std::vector<uint8_t> result;

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (ctx == nullptr)
        return result;

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        return result;

    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1)
        return result;

    if (EVP_DigestUpdate(ctx.get(), salt.data(), salt.size()) != 1)
        return result;

    result.resize(EVP_MD_size(EVP_sha256()));

    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), result.data(), &len) != 1)
        return result;

    result.resize(len);
    return result;
}

bool VMPilot::Crypto::Verify_Ed25519(const std::vector<uint8_t> &public_key_32,
                                     const std::vector<uint8_t> &signature_64,
                                     const std::string &covered_domain,
                                     const std::vector<uint8_t> &message) noexcept
{
    if (public_key_32.size() != 32) return false;
    if (signature_64.size() != 64) return false;
    if (covered_domain.empty() || covered_domain.size() > 0xff) return false;

    // Build the signed message: length_prefix(covered_domain) || message
    std::vector<uint8_t> buf;
    buf.reserve(1 + covered_domain.size() + message.size());
    buf.push_back(static_cast<uint8_t>(covered_domain.size()));
    buf.insert(buf.end(),
               reinterpret_cast<const uint8_t *>(covered_domain.data()),
               reinterpret_cast<const uint8_t *>(covered_domain.data()) +
                   covered_domain.size());
    if (!message.empty()) {
        buf.insert(buf.end(), message.begin(), message.end());
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                    public_key_32.data(),
                                    public_key_32.size()),
        &EVP_PKEY_free);
    if (pkey == nullptr) return false;

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (ctx == nullptr) return false;

    // Ed25519 uses a PureEdDSA "one-shot" interface: no hash in
    // EVP_DigestVerifyInit, and the whole message goes to
    // EVP_DigestVerify in a single call.
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr,
                             pkey.get()) != 1) {
        return false;
    }
    const int rc = EVP_DigestVerify(ctx.get(),
                                    signature_64.data(), signature_64.size(),
                                    buf.data(), buf.size());
    return rc == 1;
}