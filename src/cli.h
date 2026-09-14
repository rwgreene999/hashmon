#pragma once

#include <string>
#include <vector>

namespace hashmon
{

    struct CliOptions
    {
        std::string filename;
        std::string format = "text";
        std::vector<std::string> hashes = {"all"};
        std::string hashfile;
        bool help = false;
        bool error = false;
        std::string error_message;
    };

    CliOptions parse_command_line(int argc, char **argv);
    void print_help(const std::string &program_name);

} // namespace hashmon
