#include <VMPilot_crypto.hpp>

#include <aes.h>
#include <cryptlib.h>
#include <filters.h>
#include <modes.h>
#include <sha.h>
#include <xed25519.h>

#include <array>
#include <string>
#include <vector>

namespace
{
    constexpr size_t kAes256KeyBytes = 32;

    const CryptoPP::byte *ToCryptoPPBytes(const std::vector<uint8_t> &bytes) noexcept
    {
        static constexpr uint8_t kEmptyByte = 0;
        return bytes.empty()
                   ? reinterpret_cast<const CryptoPP::byte *>(&kEmptyByte)
                   : reinterpret_cast<const CryptoPP::byte *>(bytes.data());
    }

    const CryptoPP::byte *ToCryptoPPBytes(const std::string &bytes) noexcept
    {
        static constexpr uint8_t kEmptyByte = 0;
        return bytes.empty()
                   ? reinterpret_cast<const CryptoPP::byte *>(&kEmptyByte)
                   : reinterpret_cast<const CryptoPP::byte *>(bytes.data());
    }
}

std::vector<uint8_t> VMPilot::Crypto::Encrypt_AES_256_CBC_PKCS7(const std::vector<uint8_t> &data,
                                                                const std::string &key) noexcept
{
    std::vector<uint8_t> result;

    try {
        std::array<CryptoPP::byte, CryptoPP::AES::BLOCKSIZE> iv{};
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
        encryption.SetKeyWithIV(ToCryptoPPBytes(key), key.size(), iv.data(), iv.size());

        std::string encrypted;
        CryptoPP::StringSource source(ToCryptoPPBytes(data), data.size(), true,
                                      new CryptoPP::StreamTransformationFilter(
                                          encryption,
                                          new CryptoPP::StringSink(encrypted),
                                          CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING));

        result.assign(encrypted.begin(), encrypted.end());
        return result;
    }
    catch (const CryptoPP::Exception &) {
        return {};
    }
    catch (...) {
        return {};
    }
}

std::vector<uint8_t> VMPilot::Crypto::Decrypt_AES_256_CBC_PKCS7(const std::vector<uint8_t> &data,
                                                                const std::string &key) noexcept
{
    std::vector<uint8_t> result;

    try {
        std::array<CryptoPP::byte, CryptoPP::AES::BLOCKSIZE> iv{};
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
        decryption.SetKeyWithIV(ToCryptoPPBytes(key), key.size(), iv.data(), iv.size());

        std::string decrypted;
        CryptoPP::StringSource source(ToCryptoPPBytes(data), data.size(), true,
                                      new CryptoPP::StreamTransformationFilter(
                                          decryption,
                                          new CryptoPP::StringSink(decrypted),
                                          CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING));

        result.assign(decrypted.begin(), decrypted.end());
        return result;
    }
    catch (const CryptoPP::Exception &) {
        return {};
    }
    catch (...) {
        return {};
    }
}

std::vector<uint8_t> VMPilot::Crypto::SHA256(const std::vector<uint8_t> &data,
                                             const std::vector<uint8_t> &salt) noexcept
{
    std::vector<uint8_t> result(CryptoPP::SHA256::DIGESTSIZE);

    try {
        CryptoPP::SHA256 hash;
        hash.Update(ToCryptoPPBytes(data), data.size());
        hash.Update(ToCryptoPPBytes(salt), salt.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(result.data()));
        return result;
    }
    catch (const CryptoPP::Exception &) {
        return {};
    }
    catch (...) {
        return {};
    }
}

bool VMPilot::Crypto::Verify_Ed25519(const std::vector<uint8_t> &public_key_32,
                                     const std::vector<uint8_t> &signature_64,
                                     const std::string &covered_domain,
                                     const std::vector<uint8_t> &message) noexcept
{
    if (public_key_32.size() != CryptoPP::ed25519Verifier::PUBLIC_KEYLENGTH) return false;
    if (signature_64.size() != CryptoPP::ed25519Verifier::SIGNATURE_LENGTH) return false;
    if (covered_domain.empty() || covered_domain.size() > 0xff) return false;

    try {
        std::vector<uint8_t> signed_message;
        signed_message.reserve(1 + covered_domain.size() + message.size());
        signed_message.push_back(static_cast<uint8_t>(covered_domain.size()));
        signed_message.insert(signed_message.end(), covered_domain.begin(), covered_domain.end());
        signed_message.insert(signed_message.end(), message.begin(), message.end());

        CryptoPP::ed25519Verifier verifier(ToCryptoPPBytes(public_key_32));
        return verifier.VerifyMessage(ToCryptoPPBytes(signed_message),
                                      signed_message.size(),
                                      ToCryptoPPBytes(signature_64),
                                      signature_64.size());
    }
    catch (const CryptoPP::Exception &) {
        return false;
    }
    catch (...) {
        return false;
    }
}
