#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "HashAlgorithms.h"
#include "cli.h"
#include "hash_utils.h"

namespace fs = std::filesystem;

namespace
{

    constexpr std::uintmax_t kLargeFileWarningBytes = 10 * 1024 * 1024; // 10 MiB

    std::string calculate_hash_for(const std::string &hash_name, const std::string &file_path)
    {
        if (hash_name == "md5")
            return hashmon::md5_file(file_path);
        if (hash_name == "sha1")
            return hashmon::sha1_file(file_path);
        if (hash_name == "sha224")
            return hashmon::sha224_file(file_path);
        if (hash_name == "sha256")
            return hashmon::sha256_file(file_path);
        if (hash_name == "sha384")
            return hashmon::sha384_file(file_path);
        if (hash_name == "sha512")
            return hashmon::sha512_file(file_path);
        if (hash_name == "crc32")
            return hashmon::crc32_file(file_path);
        if (hash_name == "crc64")
            return hashmon::crc64_file(file_path);
        throw std::runtime_error("Unsupported hash: " + hash_name);
    }

    std::vector<std::string> resolve_hashes(const std::vector<std::string> &requested)
    {
        std::vector<std::string> result;
        if (requested.empty() || std::find(requested.begin(), requested.end(), "all") != requested.end())
        {
            return {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "crc32", "crc64"};
        }
        for (const auto &hash : requested)
        {
            result.push_back(hash);
        }
        return result;
    }

    std::vector<std::string> match_hashfile_for_file(const std::string &path, const std::vector<std::string> &hash_lines)
    {
        std::vector<std::string> matches;
        for (const auto &line : hash_lines)
        {
            if (line.find(fs::path(path).filename().string()) != std::string::npos)
            {
                matches.push_back(line);
            }
        }
        return matches;
    }

    bool looks_like_hex_digest(const std::string &value)
    {
        if (value.empty())
            return false;
        for (char ch : value)
        {
            if (!std::isxdigit(static_cast<unsigned char>(ch)))
                return false;
        }
        return true;
    }

    std::string extract_expected_hash_for_file(const std::string &path, const std::string &hash_name, const std::vector<std::string> &hash_lines)
    {
        const std::string target_name = fs::path(path).filename().string();
        const std::string normalized_hash_name = hashmon::lowercase(hash_name);

        for (const auto &line : hash_lines)
        {
            const std::string trimmed = hashmon::trim(line);
            if (trimmed.empty())
                continue;

            const auto equals_pos = trimmed.find('=');
            if (equals_pos != std::string::npos)
            {
                const std::string left = hashmon::trim(trimmed.substr(0, equals_pos));
                const std::string right = hashmon::trim(trimmed.substr(equals_pos + 1));
                const std::string lower_left = hashmon::lowercase(left);
                const bool has_hash_name = lower_left.find(normalized_hash_name) != std::string::npos;
                const bool has_file_name = lower_left.find(target_name) != std::string::npos || trimmed.find(target_name) != std::string::npos;
                if ((has_hash_name && has_file_name) || (has_hash_name && right.size() >= 8) || (lower_left == normalized_hash_name))
                {
                    if (!right.empty())
                        return right;
                }
                continue;
            }

            std::istringstream iss(trimmed);
            std::vector<std::string> tokens;
            std::string token;
            while (iss >> token)
            {
                tokens.push_back(token);
            }

            if (tokens.size() >= 2)
            {
                const std::string digest = tokens[0];
                std::string remainder;
                for (std::size_t i = 1; i < tokens.size(); ++i)
                {
                    remainder += tokens[i];
                    if (i + 1 < tokens.size())
                        remainder += " ";
                }

                std::string canonical_remainder = hashmon::trim(remainder);
                if (canonical_remainder.front() == '*' && !canonical_remainder.empty())
                    canonical_remainder.erase(0, 1);
                if (!canonical_remainder.empty() && canonical_remainder.back() == '*')
                    canonical_remainder.pop_back();

                if (looks_like_hex_digest(digest) && (canonical_remainder.find(target_name) != std::string::npos || canonical_remainder.find(hashmon::lowercase(target_name)) != std::string::npos))
                {
                    return digest;
                }
            }

            if (tokens.size() == 1 && looks_like_hex_digest(tokens[0]))
            {
                return tokens[0];
            }
        }

        return "";
    }

    void print_text_results(const std::string &path, const std::vector<std::string> &hashes, const std::vector<std::pair<std::string, std::string>> &results,
                            const std::string &compare_target, const std::vector<std::string> &hash_lines,
                            const std::string &direct_expected_hash = "", const std::string &direct_expected_algorithm = "")
    {
        std::cout << "File: " << path << "\n";
        for (const auto &[hash_name, hash_value] : results)
        {
            std::string expected = "";
            bool has_expected = false;
            if (!compare_target.empty())
            {
                if (fs::exists(compare_target))
                {
                    expected = extract_expected_hash_for_file(path, hash_name, hash_lines);
                    has_expected = true;
                }
                else if (!direct_expected_hash.empty() && (direct_expected_algorithm.empty() || hash_name == direct_expected_algorithm))
                {
                    expected = direct_expected_hash;
                    has_expected = true;
                }
            }
            std::cout << hash_name << ": " << hash_value;
            if (has_expected)
            {
                std::cout << "  [" << (hashmon::lowercase(hash_value) == hashmon::lowercase(hashmon::trim(expected)) ? "MATCH" : "NO MATCH") << "]";
            }
            std::cout << "\n";
        }
    }

    void print_json_results(const std::string &path, const std::vector<std::pair<std::string, std::string>> &results)
    {
        std::cout << "{\n  \"file\": \"" << path << "\",\n  \"hashes\": {\n";
        for (std::size_t i = 0; i < results.size(); ++i)
        {
            const auto &[hash_name, hash_value] = results[i];
            std::cout << "    \"" << hash_name << "\": \"" << hash_value << "\"" << (i + 1 < results.size() ? "," : "") << "\n";
        }
        std::cout << "  }\n}\n";
    }

    void print_csv_results(const std::string &path, const std::vector<std::pair<std::string, std::string>> &results)
    {
        std::cout << "file,hash,value\n";
        for (const auto &[hash_name, hash_value] : results)
        {
            std::cout << path << "," << hash_name << "," << hash_value << "\n";
        }
    }

} // namespace

std::string format_localized_integer(std::uintmax_t value)
{
    try
    {
        std::ostringstream oss;
        oss.imbue(std::locale("")); // user/system locale (from LANG/LC_* on Linux)
        oss << value;
        return oss.str();
    }
    catch (...)
    {
        return std::to_string(value); // fallback if locale setup fails
    }
}

int main(int argc, char **argv)
{
    try
    {
        const auto options = hashmon::parse_command_line(argc, argv);
        if (options.help)
        {
            if (options.error)
            {
                std::cerr << "Error: " << options.error_message << "\n\n";
            }
            hashmon::print_help(argv[0]);
            return options.error ? 1 : 0;
        }

        const std::vector<std::string> hashes_to_run = resolve_hashes(options.hashes);
        const std::vector<std::string> file_names = hashmon::expand_file_pattern(options.filename);
        if (file_names.empty())
        {
            std::cerr << "No files matched pattern: " << options.filename << "\n";
            return 1;
        }

        std::vector<std::string> hash_lines;
        std::string direct_expected_hash;
        std::string direct_expected_algorithm;
        if (!options.compare_target.empty())
        {
            const std::string compare_target = hashmon::trim(options.compare_target);
            if (fs::exists(compare_target))
            {
                if (hashmon::has_wildcard(options.filename))
                {
                    std::cerr << "Wildcard filename is not compatible with --compare\n";
                    return 1;
                }
                hash_lines = hashmon::read_hashfile_lines(compare_target);
            }
            else
            {
                const std::string lower_target = hashmon::lowercase(compare_target);
                const std::size_t colon_pos = lower_target.find(':');

                if (colon_pos != std::string::npos)
                {
                    direct_expected_algorithm = hashmon::lowercase(hashmon::trim(compare_target.substr(0, colon_pos)));
                    direct_expected_hash = hashmon::trim(compare_target.substr(colon_pos + 1));
                }
                else if (looks_like_hex_digest(compare_target))
                {
                    if (hashes_to_run.size() != 1)
                    {
                        std::cerr << "Bare compare hash requires exactly one hash algorithm; use --hash sha256 or sha256:<digest>\n";
                        return 1;
                    }
                    direct_expected_algorithm = hashmon::lowercase(hashes_to_run[0]);
                    direct_expected_hash = compare_target;
                }
                else
                {
                    std::cerr << "Compare target must be an existing hashfile or a valid hash value\n";
                    return 1;
                }
            }
        }

        for (const auto &file_name : file_names)
        {
            std::error_code ec;
            const auto file_size = fs::file_size(file_name, ec);
            if (!ec && file_size > kLargeFileWarningBytes)
            {
                const std::uintmax_t file_size_kb = file_size / 1024;
                std::cout << "[Working large-file] " << file_name << " (" << format_localized_integer(file_size_kb) << " KB)\n";
            }

            std::vector<std::pair<std::string, std::string>> results;
            for (const auto &hash_name : hashes_to_run)
            {
                const std::string value = calculate_hash_for(hash_name, file_name);
                results.emplace_back(hash_name, value);
            }

            if (options.format == "text")
            {
                print_text_results(file_name, hashes_to_run, results, options.compare_target, hash_lines, direct_expected_hash, direct_expected_algorithm);
            }
            else if (options.format == "json")
            {
                print_json_results(file_name, results);
            }
            else if (options.format == "csv")
            {
                print_csv_results(file_name, results);
            }
        }

        return 0;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
