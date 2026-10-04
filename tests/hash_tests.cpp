#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <vector>

#include "HashAlgorithms.h"
#include "hash_utils.h"

namespace fs = std::filesystem;

static bool check_equal(const std::string &left, const std::string &right, const std::string &label)
{
    if (left != right)
    {
        std::cerr << label << " failure: expected " << right << ", got " << left << "\n";
        return false;
    }
    return true;
}

static bool check_equal(std::size_t left, std::size_t right, const std::string &label)
{
    if (left != right)
    {
        std::cerr << label << " failure: expected " << right << ", got " << left << "\n";
        return false;
    }
    return true;
}

static std::string openssl_digest(const char *algorithm, const std::vector<unsigned char> &data)
{
    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    if (!md)
    {
        throw std::runtime_error("Unsupported OpenSSL digest: " + std::string(algorithm));
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to allocate OpenSSL digest context");
    }

    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_length = 0u;
    const bool ok = EVP_DigestInit_ex(ctx, md, nullptr) &&
                    EVP_DigestUpdate(ctx, data.data(), data.size()) &&
                    EVP_DigestFinal_ex(ctx, digest.data(), &digest_length);
    EVP_MD_CTX_free(ctx);
    if (!ok)
    {
        throw std::runtime_error("Failed to compute OpenSSL digest for: " + std::string(algorithm));
    }

    digest.resize(digest_length);
    return hashmon::hex_encode(digest);
}

int main()
{
    const fs::path root = fs::current_path();
    const fs::path temp_dir = root / "tmp_hash_tests";
    fs::create_directories(temp_dir);

    const fs::path zero_file = temp_dir / "empty.bin";
    std::ofstream(zero_file, std::ios::binary).close();

    const fs::path sample_file = temp_dir / "sample.txt";
    std::ofstream(sample_file, std::ios::binary) << "abc";

    const std::string known_zero_md5 = "d41d8cd98f00b204e9800998ecf8427e";
    const std::string known_zero_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const std::string known_zero_sha224 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
    const std::string known_zero_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const std::string known_zero_sha384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
    const std::string known_zero_sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    const std::string known_zero_crc32 = "00000000";
    const std::string known_zero_crc64 = "0000000000000000";

    bool ok = true;
    ok &= check_equal(hashmon::md5_file(zero_file.string()), known_zero_md5, "md5(empty)");
    ok &= check_equal(hashmon::sha1_file(zero_file.string()), known_zero_sha1, "sha1(empty)");
    ok &= check_equal(hashmon::sha224_file(zero_file.string()), known_zero_sha224, "sha224(empty)");
    ok &= check_equal(hashmon::sha256_file(zero_file.string()), known_zero_sha256, "sha256(empty)");
    ok &= check_equal(hashmon::sha384_file(zero_file.string()), known_zero_sha384, "sha384(empty)");
    ok &= check_equal(hashmon::sha512_file(zero_file.string()), known_zero_sha512, "sha512(empty)");
    ok &= check_equal(hashmon::crc32_file(zero_file.string()), known_zero_crc32, "crc32(empty)");
    ok &= check_equal(hashmon::crc64_file(zero_file.string()), known_zero_crc64, "crc64(empty)");

    const std::string sample_md5 = hashmon::md5_file(sample_file.string());
    const std::string sample_sha1 = hashmon::sha1_file(sample_file.string());
    const std::string sample_sha224 = hashmon::sha224_file(sample_file.string());
    const std::string sample_sha256 = hashmon::sha256_file(sample_file.string());
    const std::string sample_sha384 = hashmon::sha384_file(sample_file.string());
    const std::string sample_sha512 = hashmon::sha512_file(sample_file.string());
    const std::string sample_crc32 = hashmon::crc32_file(sample_file.string());
    const std::string sample_crc64 = hashmon::crc64_file(sample_file.string());

    ok &= check_equal(sample_md5.size(), 32u, "md5(size)");
    ok &= check_equal(sample_sha1.size(), 40u, "sha1(size)");
    ok &= check_equal(sample_sha224.size(), 56u, "sha224(size)");
    ok &= check_equal(sample_sha256.size(), 64u, "sha256(size)");
    ok &= check_equal(sample_sha384.size(), 96u, "sha384(size)");
    ok &= check_equal(sample_sha512.size(), 128u, "sha512(size)");
    ok &= check_equal(sample_crc32.size(), 8u, "crc32(size)");
    ok &= check_equal(sample_crc64.size(), 16u, "crc64(size)");

    const std::vector<unsigned char> data = {'a', 'b', 'c'};
    ok &= check_equal(hashmon::md5_bytes(data), hashmon::md5_file(sample_file.string()), "md5 bytes/file match");
    ok &= check_equal(hashmon::sha1_bytes(data), hashmon::sha1_file(sample_file.string()), "sha1 bytes/file match");
    ok &= check_equal(hashmon::sha224_bytes(data), hashmon::sha224_file(sample_file.string()), "sha224 bytes/file match");
    ok &= check_equal(hashmon::sha256_bytes(data), hashmon::sha256_file(sample_file.string()), "sha256 bytes/file match");
    ok &= check_equal(hashmon::sha384_bytes(data), hashmon::sha384_file(sample_file.string()), "sha384 bytes/file match");
    ok &= check_equal(hashmon::sha512_bytes(data), hashmon::sha512_file(sample_file.string()), "sha512 bytes/file match");
    ok &= check_equal(hashmon::crc32_bytes(data), hashmon::crc32_file(sample_file.string()), "crc32 bytes/file match");
    ok &= check_equal(hashmon::crc64_bytes(data), hashmon::crc64_file(sample_file.string()), "crc64 bytes/file match");

    const auto matches = hashmon::expand_file_pattern((temp_dir / "*.txt").string());
    ok &= !matches.empty();

    const std::vector<unsigned char> openssl_data = {'a', 'b', 'c'};
    ok &= check_equal(hashmon::md5_bytes(openssl_data), openssl_digest("MD5", openssl_data), "md5 matches OpenSSL");
    ok &= check_equal(hashmon::sha1_bytes(openssl_data), openssl_digest("SHA1", openssl_data), "sha1 matches OpenSSL");
    ok &= check_equal(hashmon::sha224_bytes(openssl_data), openssl_digest("SHA224", openssl_data), "sha224 matches OpenSSL");
    ok &= check_equal(hashmon::sha256_bytes(openssl_data), openssl_digest("SHA256", openssl_data), "sha256 matches OpenSSL");
    ok &= check_equal(hashmon::sha384_bytes(openssl_data), openssl_digest("SHA384", openssl_data), "sha384 matches OpenSSL");
    ok &= check_equal(hashmon::sha512_bytes(openssl_data), openssl_digest("SHA512", openssl_data), "sha512 matches OpenSSL");

    if (!ok)
    {
        return 1;
    }

    std::cout << "hash tests passed\n";
    return 0;
}
