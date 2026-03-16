#include <VMPilot_crypto.hpp>

#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/hex.h>

#include <algorithm>
#include <iterator>

std::vector<uint8_t> VMPilot::Crypto::Encrypt_AES_256_CBC_PKCS7(
    const std::vector<uint8_t> &data, const std::string &key) noexcept
{
    auto cipher = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7",
                                             Botan::Cipher_Dir::Encryption);

    cipher->set_key(reinterpret_cast<const uint8_t *>(key.data()), key.size());
    cipher->start(reinterpret_cast<const uint8_t *>(data.data()), data.size());

    Botan::secure_vector<uint8_t> encrypted_data(data.size());
    cipher->finish(encrypted_data, encrypted_data.size());

    std::vector<uint8_t> result;
    result.reserve(encrypted_data.size());
    std::copy(encrypted_data.begin(), encrypted_data.end(),
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
    cipher->start(reinterpret_cast<const uint8_t *>(data.data()), data.size());
    Botan::secure_vector<uint8_t> decrypted_data(data.size());
    cipher->finish(decrypted_data, decrypted_data.size());

    std::vector<uint8_t> result;
    result.reserve(decrypted_data.size());
    std::copy(decrypted_data.begin(), decrypted_data.end(),
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