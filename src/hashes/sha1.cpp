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

        std::vector<unsigned char> sha1_digest_bytes(const std::vector<unsigned char> &data)
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

            std::uint32_t h0 = 0x67452301u;
            std::uint32_t h1 = 0xEFCDAB89u;
            std::uint32_t h2 = 0x98BADCFEu;
            std::uint32_t h3 = 0x10325476u;
            std::uint32_t h4 = 0xC3D2E1F0u;

            for (std::size_t offset = 0; offset < message.size(); offset += 64u)
            {
                std::array<std::uint32_t, 80> words{};
                for (std::size_t i = 0; i < 16; ++i)
                {
                    const std::size_t base = offset + i * 4u;
                    words[i] = (static_cast<std::uint32_t>(message[base]) << 24u) |
                               (static_cast<std::uint32_t>(message[base + 1]) << 16u) |
                               (static_cast<std::uint32_t>(message[base + 2]) << 8u) |
                               static_cast<std::uint32_t>(message[base + 3]);
                }
                for (std::size_t i = 16; i < 80; ++i)
                {
                    words[i] = rotate_left(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1u);
                }

                std::uint32_t a = h0;
                std::uint32_t b = h1;
                std::uint32_t c = h2;
                std::uint32_t d = h3;
                std::uint32_t e = h4;

                for (std::size_t i = 0; i < 80; ++i)
                {
                    std::uint32_t f = 0u;
                    std::uint32_t k = 0u;
                    if (i < 20u)
                    {
                        f = (b & c) | ((~b) & d);
                        k = 0x5A827999u;
                    }
                    else if (i < 40u)
                    {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1u;
                    }
                    else if (i < 60u)
                    {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDCu;
                    }
                    else
                    {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6u;
                    }

                    const std::uint32_t temp = rotate_left(a, 5u) + f + e + k + words[i];
                    e = d;
                    d = c;
                    c = rotate_left(b, 30u);
                    b = a;
                    a = temp;
                }

                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
            }

            std::vector<unsigned char> digest(20u);
            auto write_word = [&](std::uint32_t word, std::size_t offset)
            {
                digest[offset + 0u] = static_cast<unsigned char>((word >> 24u) & 0xFFu);
                digest[offset + 1u] = static_cast<unsigned char>((word >> 16u) & 0xFFu);
                digest[offset + 2u] = static_cast<unsigned char>((word >> 8u) & 0xFFu);
                digest[offset + 3u] = static_cast<unsigned char>(word & 0xFFu);
            };

            write_word(h0, 0u);
            write_word(h1, 4u);
            write_word(h2, 8u);
            write_word(h3, 12u);
            write_word(h4, 16u);
            return digest;
        }

    } // namespace

    std::string sha1_file(const std::string &path)
    {
        return hex_encode(sha1_digest_bytes(read_file_bytes(path)));
    }

    std::string sha1_bytes(const std::vector<unsigned char> &data)
    {
        return hex_encode(sha1_digest_bytes(data));
    }

} // namespace hashmon
