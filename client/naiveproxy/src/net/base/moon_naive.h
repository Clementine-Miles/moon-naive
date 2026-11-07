// Copyright 2026 moon-naive contributors. Licensed under Apache-2.0.
#ifndef NET_BASE_MOON_NAIVE_H_
#define NET_BASE_MOON_NAIVE_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace moon_naive {

inline constexpr char kExporterLabel[] = "EXPORTER-moon-naive-v4";
inline constexpr uint8_t kOffer = 0x02;  // finite sixteen, no wire extension
inline constexpr size_t kMaxPayload = 16309;
using Key = std::array<uint8_t, 32>;
struct Binding {
  std::array<uint8_t, 32> exporter;
  uint64_t stream_id;
};

// The caller supplies the actual assigned HTTP stream ID and the completed
// TLS 1.3 connection's exporter with an explicitly present empty context.
struct Request {
  std::string_view method;
  std::string_view authority;
  std::optional<std::string_view> scheme;
  std::optional<std::string_view> path;
  std::optional<std::string_view> protocol;
};
std::optional<Key> DeriveKey(std::string_view user, std::string_view password);
std::string Authorization(const Key&, const Binding&, const Request&);
bool VerifyConfirmation(const Key&, const Binding&, const Request&,
                        std::string_view response);

// A bounded, allocation-free decoder. Input may split anywhere, including
// across the sixteenth record's padding and the subsequent raw bytes.
class Decoder {
 public:
  int Read(const char* input, int size, char* output, int capacity);
  bool AtBoundary() const;

 private:
  std::array<uint8_t, 3> header_{};
  size_t header_size_ = 0;
  size_t payload_ = 0;
  size_t padding_ = 0;
  unsigned records_ = 0;
  bool failed_ = false;
};

}  // namespace moon_naive
#endif
