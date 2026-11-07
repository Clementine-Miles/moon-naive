// Copyright 2020 klzgrad <kizdiv@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_TOOLS_NAIVE_NAIVE_PROXY_DELEGATE_H_
#define NET_TOOLS_NAIVE_NAIVE_PROXY_DELEGATE_H_

#include <cstdint>
#include <optional>
#include <string>

#include "net/base/net_errors.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_delegate.h"
#include "net/http/http_request_headers.h"
#include "net/proxy_resolution/proxy_retry_info.h"
#include "net/tools/naive/naive_protocol.h"
#include "url/gurl.h"

namespace net {

class ProxyInfo;

class NaiveProxyDelegate : public ProxyDelegate {
 public:
  NaiveProxyDelegate();
  ~NaiveProxyDelegate() override;

  void OnResolveProxy(const GURL& url,
                      const NetworkAnonymizationKey& network_anonymization_key,
                      const std::string& method,
                      const ProxyRetryInfoMap& proxy_retry_info,
                      ProxyInfo* result) override {}
  void OnFallback(const ProxyChain& bad_proxy, int net_error) override {}
  void OnSuccessfulRequestAfterFailures(
      const ProxyRetryInfoMap& proxy_retry_info) override {}

  // This only affects h2 proxy client socket.
  base::expected<HttpRequestHeaders, Error> OnBeforeTunnelRequest(
      const ProxyChain& proxy_chain,
      size_t chain_index,
      OnBeforeTunnelRequestCallback callback) override;

  Error OnTunnelHeadersReceived(const ProxyChain& proxy_chain,
                                size_t chain_index,
                                const HttpResponseHeaders& response_headers,
                                CompletionOnceCallback callback) override;

  void SetProxyResolutionService(
      ProxyResolutionService* proxy_resolution_service) override {}

  void OnBeforePreambleRequest(const ProxyChain& proxy_chain,
                               size_t proxy_index,
                               size_t preamble_index,
                               HttpRequestHeaders& header) const override;

  void OnPreambleHeadersReceived(
      const ProxyChain& proxy_chain,
      size_t proxy_index,
      size_t preamble_index,
      scoped_refptr<HttpResponseHeaders> response_headers) override;

  // Returns empty if the padding type has not been negotiated.
  std::optional<PaddingType> GetProxyChainPaddingType(
      const ProxyChain& proxy_chain);

};

}  // namespace net
#endif  // NET_TOOLS_NAIVE_NAIVE_PROXY_DELEGATE_H_
