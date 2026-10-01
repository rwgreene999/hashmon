#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main()
{
    namespace fs = std::filesystem;

    const fs::path root = fs::current_path();
    const fs::path temp_dir = root / "tmp_cli_test";
    fs::create_directories(temp_dir);

    const fs::path sample = temp_dir / "sample.txt";
    std::ofstream(sample) << "hello world\n";

    const std::string binary = (root / "hashmon").string();

    const std::vector<std::string> commands = {
        "--help",
        "--format json --hash SHA256 sample.txt",
        "--hash CRC32 missing.txt",
        "--compare hashfile.txt sample.txt",
        "--format csv --hash SHA256 " + sample.string()};

    for (const auto &command : commands)
    {
        std::string full_command = binary + " " + command;
        int result = std::system(full_command.c_str());
        if (command == "--help" && result != 0)
        {
            std::cerr << "Help command failed\n";
            return 1;
        }
        if (command == "--compare hashfile.txt sample.txt" && result == 0)
        {
            std::cerr << "Compare on missing hash file should fail\n";
            return 1;
        }
    }

    const fs::path hashfile = temp_dir / "hashfile.txt";
    std::ofstream hashfile_stream(hashfile);
    hashfile_stream << "SHA256 sample.txt = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n";

    const std::string compare_command = binary + " --format text --hash SHA256 --compare " + hashfile.string() + " " + sample.string();
    int compare_result = std::system(compare_command.c_str());
    if (compare_result != 0)
    {
        std::cerr << "Hash comparison unexpectedly failed for a valid file\n";
        return 1;
    }

    const fs::path sha256sum_style_hashfile = temp_dir / "sha256sum-style.txt";
    std::ofstream sha256sum_style_stream(sha256sum_style_hashfile);
    sha256sum_style_stream << "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  sample.txt\n";

    const std::string sha256sum_style_command = binary + " --format text --hash SHA256 --compare " + sha256sum_style_hashfile.string() + " " + sample.string();
    int sha256sum_style_result = std::system(sha256sum_style_command.c_str());
    if (sha256sum_style_result != 0)
    {
        std::cerr << "sha256sum-style hash comparison unexpectedly failed\n";
        return 1;
    }

    const std::string direct_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const std::string direct_hash_command = binary + " --format text --hash SHA256 --compare " + direct_hash + " " + sample.string();
    int direct_hash_result = std::system(direct_hash_command.c_str());
    if (direct_hash_result != 0)
    {
        std::cerr << "Direct digest comparison unexpectedly failed\n";
        return 1;
    }

    std::cout << "cli tests passed\n";
    return 0;
}
