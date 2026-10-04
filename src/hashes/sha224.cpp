#include "HashAlgorithms.h"

#include <array>
#include <cstdint>
#include <vector>

#include "hash_utils.h"

namespace hashmon
{
    namespace
    {

        constexpr std::uint32_t rotate_right(std::uint32_t value, std::uint32_t bits)
        {
            return (value >> bits) | (value << (32u - bits));
        }

        constexpr std::uint32_t choice(std::uint32_t x, std::uint32_t y, std::uint32_t z)
        {
            return (x & y) ^ (~x & z);
        }

        constexpr std::uint32_t majority(std::uint32_t x, std::uint32_t y, std::uint32_t z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        constexpr std::uint32_t sigma0(std::uint32_t x)
        {
            return rotate_right(x, 2u) ^ rotate_right(x, 13u) ^ rotate_right(x, 22u);
        }

        constexpr std::uint32_t sigma1(std::uint32_t x)
        {
            return rotate_right(x, 6u) ^ rotate_right(x, 11u) ^ rotate_right(x, 25u);
        }

        constexpr std::uint32_t gamma0(std::uint32_t x)
        {
            return rotate_right(x, 7u) ^ rotate_right(x, 18u) ^ (x >> 3u);
        }

        constexpr std::uint32_t gamma1(std::uint32_t x)
        {
            return rotate_right(x, 17u) ^ rotate_right(x, 19u) ^ (x >> 10u);
        }

        std::vector<unsigned char> sha224_digest_bytes(const std::vector<unsigned char> &data)
        {
            std::vector<unsigned char> message = data;
            const std::size_t bit_length = message.size() * 8u;

            message.push_back(static_cast<unsigned char>(0x80));
            while ((message.size() % 64u) != 56u)
            {
                message.push_back(0u);
            }

            for (int i = 7; i >= 0; --i)
            {
                message.push_back(static_cast<unsigned char>((bit_length >> (i * 8u)) & 0xFFu));
            }

            static constexpr std::array<std::uint32_t, 8> initial_hash = {
                0xC1059ED8u, 0x367CD507u, 0x3070DD17u, 0xF70E5939u,
                0xFFC00B31u, 0x68581511u, 0x64F98FA7u, 0xBEFA4FA4u};

            std::array<std::uint32_t, 8> hash = initial_hash;
            static constexpr std::array<std::uint32_t, 64> k = {
                0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u,
                0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
                0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u,
                0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
                0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu,
                0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
                0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u,
                0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
                0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u,
                0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
                0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u,
                0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
                0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u,
                0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
                0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u,
                0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u};

            for (std::size_t offset = 0; offset < message.size(); offset += 64u)
            {
                std::array<std::uint32_t, 64> w{};
                for (std::size_t i = 0; i < 16; ++i)
                {
                    const std::size_t base = offset + i * 4u;
                    w[i] = ((static_cast<std::uint32_t>(message[base]) << 24u) |
                            (static_cast<std::uint32_t>(message[base + 1]) << 16u) |
                            (static_cast<std::uint32_t>(message[base + 2]) << 8u) |
                            static_cast<std::uint32_t>(message[base + 3]));
                }
                for (std::size_t i = 16; i < 64; ++i)
                {
                    w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
                }

                std::uint32_t a = hash[0];
                std::uint32_t b = hash[1];
                std::uint32_t c = hash[2];
                std::uint32_t d = hash[3];
                std::uint32_t e = hash[4];
                std::uint32_t f = hash[5];
                std::uint32_t g = hash[6];
                std::uint32_t h = hash[7];

                for (std::size_t i = 0; i < 64; ++i)
                {
                    const std::uint32_t t1 = h + sigma1(e) + choice(e, f, g) + k[i] + w[i];
                    const std::uint32_t t2 = sigma0(a) + majority(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }

                hash[0] += a;
                hash[1] += b;
                hash[2] += c;
                hash[3] += d;
                hash[4] += e;
                hash[5] += f;
                hash[6] += g;
                hash[7] += h;
            }

            std::vector<unsigned char> digest(28u);
            for (std::size_t i = 0; i < 7; ++i)
            {
                const std::uint32_t word = hash[i];
                digest[i * 4u + 0u] = static_cast<unsigned char>((word >> 24u) & 0xFFu);
                digest[i * 4u + 1u] = static_cast<unsigned char>((word >> 16u) & 0xFFu);
                digest[i * 4u + 2u] = static_cast<unsigned char>((word >> 8u) & 0xFFu);
                digest[i * 4u + 3u] = static_cast<unsigned char>(word & 0xFFu);
            }
            return digest;
        }

    } // namespace

    std::string sha224_file(const std::string &path)
    {
        return hex_encode(sha224_digest_bytes(read_file_bytes(path)));
    }

    std::string sha224_bytes(const std::vector<unsigned char> &data)
    {
        return hex_encode(sha224_digest_bytes(data));
    }

} // namespace hashmon
