// Copyright 2026 moon-naive contributors. Licensed under Apache-2.0.
#include "net/base/moon_naive.h"

#include <algorithm>
#include <cstring>

#include "third_party/boringssl/src/include/openssl/crypto.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/hmac.h"
#include "third_party/boringssl/src/include/openssl/sha.h"

namespace moon_naive {
namespace {
constexpr char kKeyDomain[] = "moon-naive/v4/key";
constexpr char kRequestDomain[] = "moon-naive/v4/request";
constexpr char kResponseDomain[] = "moon-naive/v4/response/200";

void Integer(SHA256_CTX& hash, uint64_t value) {
  uint8_t bytes[8];
  for (int i = 7; i >= 0; --i) {
    bytes[i] = static_cast<uint8_t>(value);
    value >>= 8;
  }
  SHA256_Update(&hash, bytes, sizeof(bytes));
}

std::string Proof(const Key& key, const Binding& binding, const Request& request,
                  bool response) {
  SHA256_CTX hash;
  SHA256_Init(&hash);
  // sizeof includes the required NUL domain separator.
  if (response) {
    SHA256_Update(&hash, kResponseDomain, sizeof(kResponseDomain));
  } else {
    SHA256_Update(&hash, kRequestDomain, sizeof(kRequestDomain));
  }
  SHA256_Update(&hash, binding.exporter.data(), binding.exporter.size());
  Integer(hash, binding.stream_id);
  const uint8_t modes[] = {kOffer, response ? kOffer : uint8_t{0}};
  SHA256_Update(&hash, modes, sizeof(modes));
  const std::optional<std::string_view> fields[] = {
      request.method, request.authority, request.scheme, request.path,
      request.protocol};
  for (const auto& field : fields) {
    Integer(hash, field ? field->size() : UINT64_MAX);
    if (field) {
      SHA256_Update(&hash, field->data(), field->size());
    }
  }
  Key transcript;
  SHA256_Final(transcript.data(), &hash);
  Key mac;
  unsigned length = 0;
  if (!HMAC(EVP_sha256(), key.data(), key.size(), transcript.data(),
            transcript.size(), mac.data(), &length) || length != mac.size()) {
    return {};
  }
  // EVP_EncodeBlock writes a trailing NUL; retain the standard padded Base64.
  char encoded[45];
  if (EVP_EncodeBlock(reinterpret_cast<uint8_t*>(encoded), mac.data(),
                      mac.size()) != 44) {
    return {};
  }
  return std::string("moon-naive 02.") + std::string(encoded, 44);
}
}  // namespace

std::optional<Key> DeriveKey(std::string_view user, std::string_view password) {
  auto control = [](std::string_view value) {
    return std::any_of(value.begin(), value.end(), [](unsigned char c) {
      return c < 0x20 || c == 0x7f;
    });
  };
  if (user.empty() || user.find(':') != std::string_view::npos ||
      password.size() < 16 || user.size() > 2048 ||
      password.size() > 2048 - user.size() || control(user) || control(password)) {
    return std::nullopt;
  }
  SHA256_CTX hash;
  SHA256_Init(&hash);
  SHA256_Update(&hash, kKeyDomain, sizeof(kKeyDomain));
  SHA256_Update(&hash, user.data(), user.size());
  SHA256_Update(&hash, ":", 1);
  SHA256_Update(&hash, password.data(), password.size());
  Key result;
  SHA256_Final(result.data(), &hash);
  return result;
}

std::string Authorization(const Key& key, const Binding& binding,
                          const Request& request) {
  if (binding.stream_id == 0 || request.method != "CONNECT" ||
      request.authority.empty() || request.scheme || request.path ||
      request.protocol) {
    return {};
  }
  return Proof(key, binding, request, false);
}

bool VerifyConfirmation(const Key& key, const Binding& binding,
                        const Request& request, std::string_view response) {
  if (binding.stream_id == 0 || request.method != "CONNECT" ||
      request.authority.empty() || request.scheme || request.path ||
      request.protocol) return false;
  const std::string expected = Proof(key, binding, request, true);
  return !expected.empty() && response.size() == expected.size() &&
         CRYPTO_memcmp(response.data(), expected.data(), expected.size()) == 0;
}

int Decoder::Read(const char* input, int size, char* output, int capacity) {
  if (failed_ || size < 0 || capacity < size) {
    failed_ = true;
    return -1;
  }
  int written = 0;
  while (size > 0) {
    if (records_ == 16) {
      std::memcpy(output + written, input, size);
      return written + size;
    }
    if (header_size_ < 3) {
      header_[header_size_++] = static_cast<uint8_t>(*input++);
      --size;
      if (header_size_ != 3) {
        continue;
      }
      payload_ = (size_t{header_[0]} << 8) | header_[1];
      padding_ = header_[2];
      if (payload_ == 0 || payload_ > kMaxPayload ||
          padding_ > std::min(payload_ / 8, size_t{63 - 4 * records_})) {
        failed_ = true;
        return -1;
      }
    }
    const size_t data = std::min(payload_, static_cast<size_t>(size));
    std::memcpy(output + written, input, data);
    input += data;
    size -= data;
    written += data;
    payload_ -= data;
    if (payload_ == 0) {
      const size_t padding = std::min(padding_, static_cast<size_t>(size));
      for (size_t i = 0; i < padding; ++i) {
        if (input[i] != 0) {
          failed_ = true;
          return -1;
        }
      }
      input += padding;
      size -= padding;
      padding_ -= padding;
      if (padding_ == 0) {
        ++records_;
        header_size_ = 0;
      }
    }
  }
  return written;
}

bool Decoder::AtBoundary() const {
  return !failed_ && header_size_ == 0;
}
}  // namespace moon_naive
