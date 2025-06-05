#include <VMPilot_crypto.hpp>

#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/hex.h>

std::vector<uint8_t> VMPilot::Crypto::Encrypt_AES_256_CBC_PKCS7(
    const std::vector<uint8_t> &data, const std::string &key) noexcept
{
    auto cipher = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7",
                                             Botan::Cipher_Dir::Encryption);

    cipher->set_key(reinterpret_cast<const uint8_t *>(key.data()), key.size());

    const std::vector<uint8_t> iv(cipher->default_nonce_length(), 0);
    cipher->start(iv.data(), iv.size());

    Botan::secure_vector<uint8_t> buffer(data.begin(), data.end());
    cipher->finish(buffer);

    std::vector<uint8_t> result;
    result.reserve(buffer.size());
    std::copy(buffer.begin(), buffer.end(),
              std::back_inserter(result));

    return result;
}

std::vector<uint8_t> VMPilot::Crypto::Decrypt_AES_256_CBC_PKCS7(
    const std::vector<uint8_t> &data, const std::string &key) noexcept
{

    // TODO: Use thread pool to speed up the decryption
    auto cipher = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7",
                                             Botan::Cipher_Dir::Decryption);
    cipher->set_key(reinterpret_cast<const uint8_t *>(key.data()), key.size());

    const std::vector<uint8_t> iv(cipher->default_nonce_length(), 0);
    cipher->start(iv.data(), iv.size());

    Botan::secure_vector<uint8_t> buffer(data.begin(), data.end());
    cipher->finish(buffer);

    std::vector<uint8_t> result;
    result.reserve(buffer.size());
    std::copy(buffer.begin(), buffer.end(),
              std::back_inserter(result));

    return result;
}

std::vector<uint8_t> VMPilot::Crypto::SHA256(
    const std::vector<uint8_t> &data,
    const std::vector<uint8_t> &salt) noexcept
{
    auto hash_fn = Botan::HashFunction::create("SHA-256");
    hash_fn->update(data);
    hash_fn->update(salt);
    auto hash_vec = hash_fn->final();

    std::vector<uint8_t> result;
    result.reserve(hash_vec.size());
    std::copy(hash_vec.begin(), hash_vec.end(), std::back_inserter(result));

    return result;
}
