#include "cli.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "HashAlgorithms.h"
#include "hash_utils.h"

namespace fs = std::filesystem;

namespace hashmon
{

    namespace
    {

        std::set<std::string> known_hashes = {
            "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "crc32", "crc64"};

        std::vector<std::string> hash_names()
        {
            return {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "crc32", "crc64"};
        }

        std::string normalize_hash(const std::string &input)
        {
            std::string normalized = lowercase(trim(input));
            if (normalized == "sha-1")
                normalized = "sha1";
            if (normalized == "sha-224")
                normalized = "sha224";
            if (normalized == "sha-256")
                normalized = "sha256";
            if (normalized == "sha-384")
                normalized = "sha384";
            if (normalized == "sha-512")
                normalized = "sha512";
            if (normalized == "crc-32")
                normalized = "crc32";
            if (normalized == "crc-64")
                normalized = "crc64";
            return normalized;
        }

        std::string get_hash_value(const std::string &hash_name, const std::string &path)
        {
            if (hash_name == "md5")
                return md5_file(path);
            if (hash_name == "sha1")
                return sha1_file(path);
            if (hash_name == "sha224")
                return sha224_file(path);
            if (hash_name == "sha256")
                return sha256_file(path);
            if (hash_name == "sha384")
                return sha384_file(path);
            if (hash_name == "sha512")
                return sha512_file(path);
            if (hash_name == "crc32")
                return crc32_file(path);
            if (hash_name == "crc64")
                return crc64_file(path);
            throw std::runtime_error("Unsupported hash algorithm: " + hash_name);
        }

        bool compare_hash_value(const std::string &calculated, const std::string &expected)
        {
            return lowercase(trim(calculated)) == lowercase(trim(expected));
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
                if (!trim(line).empty())
                {
                    lines.push_back(trim(line));
                }
            }
            return lines;
        }

        std::string hashfile_match_for_file(const std::string &current_path, const std::string &hash_type, const std::vector<std::string> &hash_lines)
        {
            for (const auto &line : hash_lines)
            {
                const auto pos = line.find('=');
                if (pos == std::string::npos)
                {
                    if (line.find(hash_type) != std::string::npos)
                    {
                        const auto value = trim(line.substr(line.find_last_of(" ") + 1));
                        if (!value.empty())
                        {
                            return value;
                        }
                    }
                    continue;
                }

                const std::string left = trim(line.substr(0, pos));
                const std::string right = trim(line.substr(pos + 1));
                const std::string lower_left = lowercase(left);
                if (lower_left.find(normalize_hash(hash_type)) != std::string::npos && lower_left.find(fs::path(current_path).filename().string()) != std::string::npos)
                {
                    return right;
                }
                if (lower_left == normalize_hash(hash_type) || lower_left == hash_type)
                {
                    return right;
                }
            }
            return "";
        }

        std::string describe_match(const std::string &expected, const std::string &actual)
        {
            if (expected.empty())
            {
                return "no expected value found";
            }
            return compare_hash_value(actual, expected) ? "MATCH" : "NO MATCH";
        }

    } // namespace

    void print_help(const std::string &program_name)
    {
        std::cout << R"(Usage: )" << program_name << R"( [options] <filename>
  --format <text|json|csv>   Output format (default: text)
  --hash <name>              Hash algorithm(s), comma-separated or 'all' (default: all)
  --compare <hashfile>       Compare calculated hashes against a text hash list
  --help                     Show this help and exit

Examples:
  )" << program_name
                  << R"( file.txt
  )" << program_name
                  << R"( --format json --hash sha256 file.txt
  )" << program_name
                  << R"( --hash md5,sha256 *.bin
  )" << program_name
                  << R"( --compare hashes.txt --hash sha256 file.txt
)";
    }

    CliOptions parse_command_line(int argc, char **argv)
    {
        CliOptions options;
        if (argc < 2)
        {
            options.help = true;
            options.error = true;
            options.error_message = "Missing filename";
            return options;
        }

        std::vector<std::string> args(argv + 1, argv + argc);
        for (std::size_t i = 0; i < args.size(); ++i)
        {
            const std::string &arg = args[i];
            if (arg == "--help" || arg == "-h")
            {
                options.help = true;
                continue;
            }
            if (arg == "--format" || arg == "-f")
            {
                if (i + 1 >= args.size())
                {
                    options.help = true;
                    options.error = true;
                    options.error_message = "Missing value for --format";
                    return options;
                }
                options.format = lowercase(trim(args[++i]));
                continue;
            }
            if (arg == "--hash" || arg == "-H")
            {
                if (i + 1 >= args.size())
                {
                    options.help = true;
                    options.error = true;
                    options.error_message = "Missing value for --hash";
                    return options;
                }
                const std::string value = trim(args[++i]);
                options.hashes = split_csv(value);
                continue;
            }
            if (arg == "--compare" || arg == "-c")
            {
                if (i + 1 >= args.size())
                {
                    options.help = true;
                    options.error = true;
                    options.error_message = "Missing value for --compare";
                    return options;
                }
                options.hashfile = args[++i];
                continue;
            }
            if (arg.rfind("-", 0) == 0)
            {
                options.help = true;
                options.error = true;
                options.error_message = "Unknown option: " + arg;
                return options;
            }
            if (options.filename.empty())
            {
                options.filename = arg;
            }
            else
            {
                options.help = true;
                options.error = true;
                options.error_message = "Too many positional arguments";
                return options;
            }
        }

        if (options.help)
        {
            return options;
        }

        if (options.filename.empty())
        {
            options.help = true;
            options.error = true;
            options.error_message = "Missing filename";
            return options;
        }

        if (options.format != "text" && options.format != "json" && options.format != "csv")
        {
            options.help = true;
            options.error = true;
            options.error_message = "Output format must be text, json, or csv";
            return options;
        }

        if (options.hashes.empty())
        {
            options.hashes = {"all"};
        }

        for (std::string &hash : options.hashes)
        {
            hash = normalize_hash(hash);
        }

        return options;
    }

} // namespace hashmon
