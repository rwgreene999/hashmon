#include "HashAlgorithms.h"

#include <array>
#include <cstdint>
#include <vector>

#include "hash_utils.h"

namespace hashmon
{
    namespace
    {

        constexpr std::uint32_t rotate_left(std::uint32_t value, std::uint32_t bits)
        {
            return (value << bits) | (value >> (32u - bits));
        }

        constexpr std::uint32_t F(std::uint32_t x, std::uint32_t y, std::uint32_t z)
        {
            return (x & y) | (~x & z);
        }

        constexpr std::uint32_t G(std::uint32_t x, std::uint32_t y, std::uint32_t z)
        {
            return (x & z) | (y & ~z);
        }

        constexpr std::uint32_t H(std::uint32_t x, std::uint32_t y, std::uint32_t z)
        {
            return x ^ y ^ z;
        }

        constexpr std::uint32_t I(std::uint32_t x, std::uint32_t y, std::uint32_t z)
        {
            return y ^ (x | ~z);
        }

        std::vector<unsigned char> md5_digest_bytes(const std::vector<unsigned char> &data)
        {
            std::vector<unsigned char> message = data;
            const std::size_t bit_length = message.size() * 8u;

            message.push_back(static_cast<unsigned char>(0x80));
            while ((message.size() % 64u) != 56u)
            {
                message.push_back(0u);
            }

            for (std::size_t i = 0; i < 8; ++i)
            {
                const std::uint64_t shift = (bit_length >> (i * 8u)) & 0xFFu;
                message.push_back(static_cast<unsigned char>(shift));
            }

            std::uint32_t a = 0x67452301u;
            std::uint32_t b = 0xEFCDAB89u;
            std::uint32_t c = 0x98BADCFEu;
            std::uint32_t d = 0x10325476u;

            static constexpr std::array<std::uint32_t, 64> k = {
                0xD76AA478u, 0xE8C7B756u, 0x242070DBu, 0xC1BDCEEEu,
                0xF57C0FAFu, 0x4787C62Au, 0xA8304613u, 0xFD469501u,
                0x698098D8u, 0x8B44F7AFu, 0xFFFF5BB1u, 0x895CD7BEu,
                0x6B901122u, 0xFD987193u, 0xA679438Eu, 0x49B40821u,
                0xF61E2562u, 0xC040B340u, 0x265E5A51u, 0xE9B6C7AAu,
                0xD62F105Du, 0x02441453u, 0xD8A1E681u, 0xE7D3FBC8u,
                0x21E1CDE6u, 0xC33707D6u, 0xF4D50D87u, 0x455A14EDu,
                0xA9E3E905u, 0xFCEFA3F8u, 0x676F02D9u, 0x8D2A4C8Au,
                0xFFFA3942u, 0x8771F681u, 0x6D9D6122u, 0xFDE5380Cu,
                0xA4BEEA44u, 0x4BDECFA9u, 0xF6BB4B60u, 0xBEBFBC70u,
                0x289B7EC6u, 0xEAA127FAu, 0xD4EF3085u, 0x04881D05u,
                0xD9D4D039u, 0xE6DB99E5u, 0x1FA27CF8u, 0xC4AC5665u,
                0xF4292244u, 0x432AFF97u, 0xAB9423A7u, 0xFC93A039u,
                0x655B59C3u, 0x8F0CCC92u, 0xFFEFF47Du, 0x85845DD1u,
                0x6FA87E4Fu, 0xFE2CE6E0u, 0xA3014314u, 0x4E0811A1u,
                0xF7537E82u, 0xBD3AF235u, 0x2AD7D2BBu, 0xEB86D391u};

            static constexpr std::array<std::uint32_t, 64> s = {
                7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u,
                5u, 9u, 14u, 20u, 5u, 9u, 14u, 20u, 5u, 9u, 14u, 20u, 5u, 9u, 14u, 20u,
                4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u,
                6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u};

            static constexpr std::array<std::uint32_t, 64> index = {
                0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u,
                1u, 6u, 11u, 0u, 5u, 10u, 15u, 4u, 9u, 14u, 3u, 8u, 13u, 2u, 7u, 12u,
                5u, 8u, 11u, 14u, 1u, 4u, 7u, 10u, 13u, 0u, 3u, 6u, 9u, 12u, 15u, 2u,
                0u, 7u, 14u, 5u, 12u, 3u, 10u, 1u, 8u, 15u, 6u, 13u, 4u, 11u, 2u, 9u};

            for (std::size_t offset = 0; offset < message.size(); offset += 64u)
            {
                std::array<std::uint32_t, 16> words{};
                for (std::size_t i = 0; i < 16; ++i)
                {
                    const std::size_t base = offset + i * 4u;
                    words[i] = static_cast<std::uint32_t>(message[base]) |
                               (static_cast<std::uint32_t>(message[base + 1]) << 8u) |
                               (static_cast<std::uint32_t>(message[base + 2]) << 16u) |
                               (static_cast<std::uint32_t>(message[base + 3]) << 24u);
                }

                const std::uint32_t aa = a;
                const std::uint32_t bb = b;
                const std::uint32_t cc = c;
                const std::uint32_t dd = d;

                for (std::size_t t = 0; t < 64; ++t)
                {
                    std::uint32_t f = 0u;
                    std::uint32_t g = 0u;
                    if (t < 16u)
                    {
                        f = F(b, c, d);
                        g = t;
                    }
                    else if (t < 32u)
                    {
                        f = G(b, c, d);
                        g = (5u * t + 1u) % 16u;
                    }
                    else if (t < 48u)
                    {
                        f = H(b, c, d);
                        g = (3u * t + 5u) % 16u;
                    }
                    else
                    {
                        f = I(b, c, d);
                        g = (7u * t) % 16u;
                    }

                    const std::uint32_t temp = d;
                    d = c;
                    c = b;
                    b = b + rotate_left((a + f + k[t] + words[g]), s[t]);
                    a = temp;
                }

                a += aa;
                b += bb;
                c += cc;
                d += dd;
            }

            std::vector<unsigned char> digest(16u);
            auto write_word = [&](std::uint32_t word, std::size_t offset)
            {
                digest[offset + 0u] = static_cast<unsigned char>(word & 0xFFu);
                digest[offset + 1u] = static_cast<unsigned char>((word >> 8u) & 0xFFu);
                digest[offset + 2u] = static_cast<unsigned char>((word >> 16u) & 0xFFu);
                digest[offset + 3u] = static_cast<unsigned char>((word >> 24u) & 0xFFu);
            };

            write_word(a, 0u);
            write_word(b, 4u);
            write_word(c, 8u);
            write_word(d, 12u);
            return digest;
        }

    } // namespace

    std::string md5_file(const std::string &path)
    {
        return hex_encode(md5_digest_bytes(read_file_bytes(path)));
    }

    std::string md5_bytes(const std::vector<unsigned char> &data)
    {
        return hex_encode(md5_digest_bytes(data));
    }

} // namespace hashmon
