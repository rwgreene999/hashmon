#pragma once

#include <string>
#include <vector>

namespace hashmon
{

    std::string md5_file(const std::string &path);
    std::string sha1_file(const std::string &path);
    std::string sha224_file(const std::string &path);
    std::string sha256_file(const std::string &path);
    std::string sha384_file(const std::string &path);
    std::string sha512_file(const std::string &path);
    std::string crc32_file(const std::string &path);
    std::string crc64_file(const std::string &path);

    std::string md5_bytes(const std::vector<unsigned char> &data);
    std::string sha1_bytes(const std::vector<unsigned char> &data);
    std::string sha224_bytes(const std::vector<unsigned char> &data);
    std::string sha256_bytes(const std::vector<unsigned char> &data);
    std::string sha384_bytes(const std::vector<unsigned char> &data);
    std::string sha512_bytes(const std::vector<unsigned char> &data);
    std::string crc32_bytes(const std::vector<unsigned char> &data);
    std::string crc64_bytes(const std::vector<unsigned char> &data);

} // namespace hashmon
