// Copyright 2020 klzgrad <kizdiv@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/tools/naive/naive_proxy_delegate.h"

namespace net {
NaiveProxyDelegate::NaiveProxyDelegate() = default;
NaiveProxyDelegate::~NaiveProxyDelegate() = default;

base::expected<HttpRequestHeaders, Error>
NaiveProxyDelegate::OnBeforeTunnelRequest(
    const ProxyChain&, size_t, OnBeforeTunnelRequestCallback) {
  return HttpRequestHeaders();
}

Error NaiveProxyDelegate::OnTunnelHeadersReceived(
    const ProxyChain&, size_t, const HttpResponseHeaders&,
    CompletionOnceCallback) {
  // The H2 socket checks its own stream-bound response proof before success.
  return OK;
}

void NaiveProxyDelegate::OnBeforePreambleRequest(
    const ProxyChain&, size_t, size_t, HttpRequestHeaders&) const {}

void NaiveProxyDelegate::OnPreambleHeadersReceived(
    const ProxyChain&, size_t, size_t,
    scoped_refptr<HttpResponseHeaders>) {}

std::optional<PaddingType> NaiveProxyDelegate::GetProxyChainPaddingType(
    const ProxyChain&) {
  // Transport success already authenticated the sole supported mode, 0x02.
  return PaddingType::kVariant1;
}
}  // namespace net
