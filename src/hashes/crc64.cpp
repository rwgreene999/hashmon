#include "HashAlgorithms.h"

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <vector>

#include "hash_utils.h"

namespace hashmon
{
    namespace
    {

        std::string crc64_digest(const std::vector<unsigned char> &data)
        {
            std::uint64_t crc = 0xFFFFFFFFFFFFFFFFULL;
            for (unsigned char byte : data)
            {
                crc ^= static_cast<std::uint64_t>(byte) << 56;
                for (int bit = 0; bit < 8; ++bit)
                {
                    if (crc & 0x8000000000000000ULL)
                    {
                        crc = (crc << 1) ^ 0x42F0E1EBA9EA3693ULL;
                    }
                    else
                    {
                        crc <<= 1;
                    }
                }
            }
            crc ^= 0xFFFFFFFFFFFFFFFFULL;

            std::ostringstream oss;
            oss << std::hex << std::nouppercase << std::setw(16) << std::setfill('0') << crc;
            return oss.str();
        }

    } // namespace

    std::string crc64_file(const std::string &path)
    {
        return crc64_digest(read_file_bytes(path));
    }

    std::string crc64_bytes(const std::vector<unsigned char> &data)
    {
        return crc64_digest(data);
    }

} // namespace hashmon
