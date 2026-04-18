#ifndef __VMPILOT_CRYPTO_HPP__
#define __VMPILOT_CRYPTO_HPP__

#include <cstdint>
#include <string>
#include <vector>

namespace VMPilot::Crypto
{
    std::vector<uint8_t> Encrypt_AES_256_CBC_PKCS7(const std::vector<uint8_t> &data,
                                                   const std::string &key) noexcept;

    std::vector<uint8_t> Decrypt_AES_256_CBC_PKCS7(const std::vector<uint8_t> &data,
                                                   const std::string &key) noexcept;

    std::vector<uint8_t> SHA256(const std::vector<uint8_t> &data,
                                const std::vector<uint8_t> &salt) noexcept;

    std::vector<uint8_t> BLAKE3(const std::vector<uint8_t> &data,
                                const std::vector<uint8_t> &salt) noexcept;

    // Verify an Ed25519 signature over a domain-separated message.
    //
    // The verifier reconstructs the signed message as:
    //     length_prefix(covered_domain) || message
    //
    // where length_prefix is a single byte carrying the domain label length
    // (must be in [1, 255]) followed by the UTF-8 label bytes. The same
    // prefix rule is used by the test-only signer and by the domain-hash
    // helper, so the label behaves identically across signature and hash
    // layers.
    //
    // Returns true iff the signature matches; never throws. Any backend
    // error, invalid key size (public_key_32.size() != 32), invalid
    // signature size (signature_64.size() != 64), empty covered_domain, or
    // covered_domain longer than 255 bytes yields false.
    //
    // Deliberately verify-only: Sign_Ed25519 is not part of this interface.
    // Production binaries must never gain a signing capability through the
    // crypto adaptor.
    bool Verify_Ed25519(const std::vector<uint8_t> &public_key_32,
                        const std::vector<uint8_t> &signature_64,
                        const std::string &covered_domain,
                        const std::vector<uint8_t> &message) noexcept;
}

#endif