#include "HashAlgorithms.h"

#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

#include "hash_utils.h"

namespace hashmon
{
    namespace
    {

        std::string compute_digest(const EVP_MD *md, const std::vector<unsigned char> &data)
        {
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            if (!ctx)
            {
                throw std::runtime_error("Failed to allocate EVP digest context");
            }

            std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
            unsigned int digest_len = 0;
            bool ok = EVP_DigestInit_ex(ctx, md, nullptr) &&
                      EVP_DigestUpdate(ctx, data.data(), data.size()) &&
                      EVP_DigestFinal_ex(ctx, digest.data(), &digest_len);
            EVP_MD_CTX_free(ctx);
            if (!ok)
            {
                throw std::runtime_error("Failed to compute digest");
            }

            digest.resize(digest_len);
            return hex_encode(digest);
        }

    } // namespace

    std::string sha256_file(const std::string &path)
    {
        return compute_digest(EVP_sha256(), read_file_bytes(path));
    }

    std::string sha256_bytes(const std::vector<unsigned char> &data)
    {
        return compute_digest(EVP_sha256(), data);
    }

} // namespace hashmon
