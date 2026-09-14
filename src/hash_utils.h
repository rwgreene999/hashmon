#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hashmon
{

    std::vector<unsigned char> read_file_bytes(const std::string &path);
    std::string hex_encode(const std::vector<unsigned char> &bytes);
    std::string hex_encode(const unsigned char *data, std::size_t len);
    std::string trim(const std::string &value);
    std::vector<std::string> split_csv(const std::string &value);
    std::vector<std::string> expand_file_pattern(const std::string &pattern);
    std::vector<std::string> read_hashfile_lines(const std::string &path);
    std::string lowercase(std::string value);
    bool has_wildcard(const std::string &value);

} // namespace hashmon
