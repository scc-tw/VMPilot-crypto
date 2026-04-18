VMPilot-crypto
===

The crypto submodule of VMPilot.
We provide two 3-rd party crypto library as the backend of VMPilot-crypto.

- [Botan](https://github.com/randombit/botan)
- [libsodium](https://github.com/jedisct1/libsodium)
- [OpenSSL](https://github.com/openssl/openssl)

# Release
Please refer to the [release page](https://github.com/25077667/VMPilot-crypto/releases)

# Build
## Prerequisites
- CMake support C++20
- C++ compiler support C++20

### Optional dependencies
- Ninja build system
- mold linker

## Compile Options
- `CRYPTO_LIB`: 
    - Description: The backend crypto library. Default is `Botan`. Other options are `OpenSSL` and `libsodium`.
    - Options:
        - `Botan` (default)
        - `OpenSSL`
        - `libsodium` (partial: SHA256 + Ed25519; AES-256-CBC/PKCS7 unsupported)

- `CMAKE_LINKER`: 
    - Description: The linker. Default is `ld`. Other options are `mold`, `lld` and `gold`.
    - Options:
        - `ld`  (default)
        - `mold`
        - `lld`
        - `gold`

### Example
```bash
mkdir build && cd build
cmake .. -DCRYPTO_LIB=Botan -G Ninja -DCMAKE_LINKER=mold
ninja
```

And the output library file will be in `build/`.

# License
Apache License 2.0

# Notes

## OpenSSL
If you are using the OpenSSL in your Apple device, but stuck with the find package error,
you could refer to https://stackoverflow.com/a/69268455 for possible solutions.

## libsodium
The libsodium backend currently supports the SHA256 and Ed25519 parts of the public API.
`BLAKE3` remains provided by the shared `src/blake3.cpp` implementation for every backend.
The AES wrapper API in this repo is `AES-256-CBC/PKCS7`, which libsodium does not provide;
its AES support is limited to AES-256-GCM AEAD. As a result, the libsodium backend does not
provide AES parity with the Botan/OpenSSL backends.

## Botan with AppleClang
If it says something like this:
```
XcodeDefault.xctoolchain/usr/bin/../include/c++/v1/stdlib.h:93:15: fatal error: 'stdlib.h' file not found
```
You could add a cmake option to specify the C++ compiler: 
```cmake
-DCXX=clang++
```
so that it will use the clang++ instead of the AppleClang.
