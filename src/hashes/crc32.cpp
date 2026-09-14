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

        std::string crc32_digest(const std::vector<unsigned char> &data)
        {
            std::uint32_t crc = 0xFFFFFFFFu;
            for (unsigned char byte : data)
            {
                crc ^= byte;
                for (int bit = 0; bit < 8; ++bit)
                {
                    if (crc & 1u)
                    {
                        crc = (crc >> 1) ^ 0xEDB88320u;
                    }
                    else
                    {
                        crc >>= 1;
                    }
                }
            }
            crc ^= 0xFFFFFFFFu;

            std::ostringstream oss;
            oss << std::hex << std::nouppercase << std::setw(8) << std::setfill('0') << crc;
            return oss.str();
        }

    } // namespace

    std::string crc32_file(const std::string &path)
    {
        return crc32_digest(read_file_bytes(path));
    }

    std::string crc32_bytes(const std::vector<unsigned char> &data)
    {
        return crc32_digest(data);
    }

} // namespace hashmon
