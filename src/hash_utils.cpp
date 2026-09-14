#include "hash_utils.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <fnmatch.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;

namespace hashmon
{

    std::vector<unsigned char> read_file_bytes(const std::string &path)
    {
        std::ifstream input(path, std::ios::binary);
        if (!input)
        {
            throw std::runtime_error("Unable to open file: " + path);
        }

        return std::vector<unsigned char>(
            std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>());
    }

    std::string hex_encode(const std::vector<unsigned char> &bytes)
    {
        return hex_encode(bytes.data(), bytes.size());
    }

    std::string hex_encode(const unsigned char *data, std::size_t len)
    {
        static const char hex[] = "0123456789abcdef";
        std::string out;
        out.reserve(len * 2);
        for (std::size_t i = 0; i < len; ++i)
        {
            out.push_back(hex[(data[i] >> 4) & 0x0F]);
            out.push_back(hex[data[i] & 0x0F]);
        }
        return out;
    }

    std::string trim(const std::string &value)
    {
        std::size_t start = 0;
        while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])))
        {
            ++start;
        }

        std::size_t end = value.size();
        while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])))
        {
            --end;
        }

        return value.substr(start, end - start);
    }

    std::vector<std::string> split_csv(const std::string &value)
    {
        std::vector<std::string> items;
        std::stringstream ss(value);
        std::string item;
        while (std::getline(ss, item, ','))
        {
            std::string cleaned = trim(item);
            if (!cleaned.empty())
            {
                items.push_back(cleaned);
            }
        }
        return items;
    }

    std::vector<std::string> read_hashfile_lines(const std::string &path)
    {
        std::ifstream input(path);
        if (!input)
        {
            throw std::runtime_error("Unable to open hashfile: " + path);
        }

        std::vector<std::string> lines;
        std::string line;
        while (std::getline(input, line))
        {
            const std::string trimmed = trim(line);
            if (!trimmed.empty())
            {
                lines.push_back(trimmed);
            }
        }
        return lines;
    }

    bool has_wildcard(const std::string &value)
    {
        return value.find('*') != std::string::npos ||
               value.find('?') != std::string::npos ||
               value.find('[') != std::string::npos;
    }

    std::string lowercase(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch)
                       { return static_cast<char>(std::tolower(ch)); });
        return value;
    }

    std::vector<std::string> expand_file_pattern(const std::string &pattern)
    {
        if (!has_wildcard(pattern))
        {
            return {pattern};
        }

        fs::path p(pattern);
        fs::path parent = p.parent_path().empty() ? fs::current_path() : p.parent_path();
        std::string filename_pattern = p.filename().string();

        std::vector<std::string> matches;
        std::error_code ec;
        if (!fs::exists(parent, ec) || !fs::is_directory(parent, ec))
        {
            return matches;
        }

        for (const auto &entry : fs::directory_iterator(parent, ec))
        {
            if (ec)
            {
                break;
            }

            const auto &path = entry.path();
            if (!fs::is_regular_file(path, ec))
            {
                continue;
            }

            const std::string candidate = path.filename().string();
            if (fnmatch(filename_pattern.c_str(), candidate.c_str(), 0) == 0)
            {
                matches.push_back(path.string());
            }
        }

        std::sort(matches.begin(), matches.end());
        return matches;
    }

} // namespace hashmon
