// Copyright 2026 Moon-naive contributors. SPDX-License-Identifier: Apache-2.0
//
// Channel-bound CONNECT authentication hook used by the Moon-naive Chromium
// Native Engine. It is protocol-agnostic: Chromium code only supplies the
// actual transport binding (TLS exporter of the proxy connection and the
// stream ID allocated for the CONNECT request) at the moment the request
// HEADERS are about to be serialized. The authenticator, provided through
// ProxyDelegate::GetMoonTunnelAuthenticator(), decides what to add.
#ifndef NET_BASE_MOON_TUNNEL_AUTHENTICATOR_H_
#define NET_BASE_MOON_TUNNEL_AUTHENTICATOR_H_

#include <array>
#include <cstdint>
#include <string_view>

#include "net/base/net_export.h"

namespace quiche {
class HttpHeaderBlock;
}

namespace net {

struct MoonTunnelBinding {
  // TLS exporter (RFC 8446 section 7.5) of the completed TLS 1.3 handshake
  // with the proxy, using ExporterLabel() and an empty, present context.
  std::array<uint8_t, 32> exporter{};
  // The stream ID the transport actually allocated for this CONNECT request
  // (HTTP/2: odd, from 1; HTTP/3: 0, 4, 8, ...).
  uint64_t stream_id = 0;
  // Whether the proxy connection negotiated Encrypted Client Hello.
  bool ech_accepted = false;
  // 2 for HTTP/2, 3 for HTTP/3.
  int http_version = 0;
};

class NET_EXPORT MoonTunnelAuthenticator {
 public:
  virtual ~MoonTunnelAuthenticator() = default;

  // Exporter label used to derive MoonTunnelBinding::exporter.
  virtual std::string_view ExporterLabel() const = 0;

  // Called exactly once per CONNECT stream, after the stream ID is allocated
  // and before the request HEADERS are encoded. `headers` already contains
  // the exact pseudo-header values that will be sent. Returns OK after adding
  // credentials, or a net error, in which case no HEADERS are sent and the
  // stream is closed with that error.
  virtual int AuthorizeTunnel(const MoonTunnelBinding& binding,
                              quiche::HttpHeaderBlock& headers) = 0;
};

}  // namespace net

#endif  // NET_BASE_MOON_TUNNEL_AUTHENTICATOR_H_
