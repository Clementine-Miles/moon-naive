// Copyright 2026 Moon-naive contributors. SPDX-License-Identifier: Apache-2.0
//
// Moon-naive Chromium Native Engine. See moon_engine.h for the contract.
//
// Each tunnel runs its own HttpProxyConnectJob, created through Chromium's
// ConnectJobFactory with a per-tunnel copy of the session's
// CommonConnectJobParams whose ProxyDelegate is the tunnel itself. The proxy
// TLS/QUIC connection still comes from, and is shared through, the session's
// SpdySessionPool and QuicSessionPool. This gives every tunnel an exact
// association between its CONNECT stream binding, the response status and the
// confirmation, without any global bookkeeping.

#ifdef UNSAFE_BUFFERS_BUILD
// This file is the C ABI boundary: it receives raw pointer/length pairs from
// the embedder and copies them into owned containers at the edge.
#pragma allow_unsafe_buffers
#endif

#include "net/tools/moon_engine/moon_engine.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/logging/logging_settings.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/no_destructor.h"
#include "base/strings/string_util.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/moon_tunnel_authenticator.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_delegate.h"
#include "net/base/proxy_server.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/crl_set.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/multi_threaded_cert_verifier.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_transaction_factory.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/quic/quic_context.h"
#include "net/socket/connect_job.h"
#include "net/socket/connect_job_factory.h"
#include "net/socket/socket_tag.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/ssl_config_service.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"
#include "url/url_util.h"

namespace net {
namespace {

constexpr NetworkTrafficAnnotationTag kTrafficAnnotation =
    DefineNetworkTrafficAnnotation("moon_engine", R"(
      semantics {
        sender: "Moon-naive Chromium Native Engine"
        description: "Authenticated CONNECT tunnels through the configured "
                     "Moon-naive proxy."
        trigger: "A local SOCKS5 or HTTP CONNECT request."
        data: "Tunneled application bytes."
        destination: OTHER
      }
      policy {
        cookies_allowed: NO
        setting: "Configured by the embedder."
        policy_exception_justification: "Not a browser feature."
      })");

constexpr size_t kMaxReadSize = 64 * 1024;
constexpr size_t kMaxAuthorizationSize = 256;

// ---------------------------------------------------------------------------
// Process-wide Chromium initialization (performed once, never torn down).

std::atomic<void*> g_log_ctx{nullptr};
std::atomic<moon_log_fn> g_log_fn{nullptr};

bool LogHandler(int severity,
                const char* file,
                int line,
                size_t message_start,
                const std::string& str) {
  moon_log_fn fn = g_log_fn.load();
  if (fn) {
    int level = severity >= logging::LOGGING_ERROR     ? 2
                : severity >= logging::LOGGING_WARNING ? 1
                                                       : 0;
    std::string_view message(str);
    message.remove_prefix(std::min(message_start, message.size()));
    while (!message.empty() &&
           (message.back() == '\n' || message.back() == '\r')) {
      message.remove_suffix(1);
    }
    fn(g_log_ctx.load(), level, message.data(), message.size());
  }
  // Never write to the embedder's stderr directly.
  return true;
}

void InitializeProcessOnce() {
  static const bool initialized = [] {
    // Chromium base expects these process singletons.
    new base::AtExitManager();  // Intentionally leaked.
    // Diagnostics only: MOON_NAIVE_ENGINE_VMODULE takes a Chromium --vmodule
    // pattern list (for example "quic*=1,spdy*=1") and enables verbose logs
    // for those files. Messages still go only to the embedder's log sink.
    const char* vmodule = getenv("MOON_NAIVE_ENGINE_VMODULE");
    std::string vmodule_flag =
        std::string("--vmodule=") + (vmodule ? vmodule : "");
    const char* argv[] = {"moon-engine", vmodule_flag.c_str(), nullptr};
    base::CommandLine::Init(vmodule ? 2 : 1, argv);
    logging::LoggingSettings settings;
    settings.logging_dest = logging::LOG_NONE;
    logging::InitLogging(settings);
    logging::SetMinLogLevel(vmodule ? -3 : logging::LOGGING_WARNING);
    logging::SetLogMessageHandler(&LogHandler);
    base::FeatureList::InitInstance(
        "PartitionConnectionsByNetworkIsolationKey,QuicUseReadMultiple,"
        "EnableUdpGro",
        std::string());
    base::ThreadPoolInstance::CreateAndStartWithDefaultParams("moon_engine");
    url::AddStandardScheme("quic",
                           url::SCHEME_WITH_HOST_PORT_AND_USER_INFORMATION);
    return true;
  }();
  static_cast<void>(initialized);
}

// ---------------------------------------------------------------------------
// Configuration services.

class MoonSSLConfigService : public SSLConfigService {
 public:
  MoonSSLConfigService(std::string server_name, std::vector<uint8_t> ech)
      : server_name_(std::move(server_name)), ech_(std::move(ech)) {}

  SSLContextConfig GetSSLContextConfig() override { return config_; }

  EchMode GetEchMode(std::string_view hostname) const override {
    // A locally configured ECHConfigList makes ECH mandatory for the proxy:
    // no GREASE-only handshake and no retry without ECH.
    if (!ech_.empty() && hostname == server_name_) {
      return EchMode::kStrict;
    }
    return EchMode::kOpportunistic;
  }

  std::vector<uint8_t> GetEchConfigListOverride(
      std::string_view hostname) const override {
    if (hostname == server_name_) {
      return ech_;
    }
    return {};
  }

  bool CanShareConnectionWithClientCerts(std::string_view) const override {
    return false;
  }

 private:
  SSLContextConfig config_;
  const std::string server_name_;
  const std::vector<uint8_t> ech_;
};

// Chrome Root Store plus optional embedder-supplied anchors.
class MoonCertVerifyProcFactory : public CertVerifyProcFactory {
 public:
  explicit MoonCertVerifyProcFactory(bssl::ParsedCertificateList anchors)
      : anchors_(std::move(anchors)) {}

  scoped_refptr<CertVerifyProc> CreateCertVerifyProc(
      scoped_refptr<CertNetFetcher> cert_net_fetcher,
      const CertVerifyProc::ImplParams& impl_params,
      const CertVerifyProc::InstanceParams& instance_params) override {
    CertVerifyProc::InstanceParams params = instance_params;
    params.additional_trust_anchors.insert(
        params.additional_trust_anchors.end(), anchors_.begin(),
        anchors_.end());
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
    return CertVerifyProc::CreateBuiltinWithChromeRootStore(
        std::move(cert_net_fetcher), impl_params.crl_set,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(),
        base::OptionalToPtr(impl_params.root_store_data),
        base::OptionalToPtr(impl_params.root_store_mtc_metadata), params,
        impl_params.time_tracker);
#else
    return CertVerifyProc::CreateBuiltinVerifyProc(
        std::move(cert_net_fetcher), impl_params.crl_set,
        std::make_unique<DoNothingCTVerifier>(),
        base::MakeRefCounted<DefaultCTPolicyEnforcer>(), params,
        impl_params.time_tracker);
#endif
  }

 private:
  ~MoonCertVerifyProcFactory() override = default;
  const bssl::ParsedCertificateList anchors_;
};

bool LoadAnchors(const std::string& path,
                 bssl::ParsedCertificateList* out,
                 std::string* error) {
  std::string pem;
  if (!base::ReadFileToString(base::FilePath(path), &pem)) {
    *error = "cannot read ca_file";
    return false;
  }
  CertificateList certs = X509Certificate::CreateCertificateListFromBytes(
      base::as_byte_span(pem), X509Certificate::FORMAT_PEM_CERT_SEQUENCE);
  for (const auto& cert : certs) {
    bssl::CertErrors errors;
    std::shared_ptr<const bssl::ParsedCertificate> parsed =
        bssl::ParsedCertificate::Create(
            bssl::UpRef(cert->cert_buffer()),
            x509_util::DefaultParseCertificateOptions(), &errors);
    if (!parsed) {
      *error = "ca_file contains an unparsable certificate";
      return false;
    }
    out->push_back(std::move(parsed));
  }
  if (out->empty()) {
    *error = "ca_file contains no PEM certificates";
    return false;
  }
  return true;
}

struct EngineSettings {
  std::string server_name;
  std::string connect_host;
  uint16_t port = 0;
  std::string ca_file;
  std::vector<uint8_t> ech;
  std::string exporter_label;
  uint32_t quic_idle_timeout_secs = 30;
  void* auth_ctx = nullptr;
  moon_authorize_fn authorize = nullptr;
  moon_verify_fn verify = nullptr;
};

class Engine;

// ---------------------------------------------------------------------------
// One tunnel. Lives on the engine thread.

class Tunnel : public ConnectJob::Delegate,
               public ProxyDelegate,
               public MoonTunnelAuthenticator {
 public:
  Tunnel(Engine* engine,
         HostPortPair endpoint,
         uint8_t transport,
         const moon_tunnel_callbacks& callbacks)
      : engine_(engine),
        endpoint_(std::move(endpoint)),
        transport_(transport),
        callbacks_(callbacks) {}

  ~Tunnel() override {
    weak_factory_.InvalidateWeakPtrs();
    // Destroying the socket resets a stream that is still open.
    job_.reset();
    socket_.reset();
    callbacks_.on_closed(callbacks_.ctx);
  }

  void Start();
  void Read(size_t max_len);
  void Write(std::vector<uint8_t> data);
  void ShutdownWrite();

  // ConnectJob::Delegate:
  void OnConnectJobComplete(int result, ConnectJob* job) override;
  void OnNeedsProxyAuth(const HttpResponseInfo& response,
                        HttpAuthController* auth_controller,
                        base::OnceClosure restart_with_auth_callback,
                        ConnectJob* job) override {
    // Moon tunnels never answer HTTP authentication challenges. The job is
    // still on the stack, so drop it from a fresh task.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(
                       [](base::WeakPtr<Tunnel> self) {
                         if (self) {
                           self->job_.reset();
                           self->Finish(ERR_TUNNEL_CONNECTION_FAILED);
                         }
                       },
                       weak_factory_.GetWeakPtr()));
  }

  // ProxyDelegate:
  void OnResolveProxy(const GURL& url,
                      const NetworkAnonymizationKey& network_anonymization_key,
                      const std::string& method,
                      const ProxyRetryInfoMap& proxy_retry_info,
                      ProxyInfo* result) override {}
  void OnFallback(const ProxyChain& bad_chain, int net_error) override {}
  void OnSuccessfulRequestAfterFailures(
      const ProxyRetryInfoMap& proxy_retry_info) override {}
  base::expected<HttpRequestHeaders, Error> OnBeforeTunnelRequest(
      const ProxyChain& proxy_chain,
      size_t proxy_index,
      OnBeforeTunnelRequestCallback callback) override {
    return HttpRequestHeaders();
  }
  Error OnTunnelHeadersReceived(const ProxyChain& proxy_chain,
                                size_t proxy_index,
                                const HttpResponseHeaders& response_headers,
                                CompletionOnceCallback callback) override;
  void SetProxyResolutionService(
      ProxyResolutionService* proxy_resolution_service) override {}
  MoonTunnelAuthenticator* GetMoonTunnelAuthenticator() override {
    return this;
  }

  // MoonTunnelAuthenticator:
  std::string_view ExporterLabel() const override;
  int AuthorizeTunnel(const MoonTunnelBinding& binding,
                      quiche::HttpHeaderBlock& headers) override;

 private:
  void Finish(int result);
  void OnRead(int result);
  void DoWrite();
  void OnWrite(int result);
  void DoShutdown();
  void OnShutdown(int result);

  const raw_ptr<Engine> engine_;
  const HostPortPair endpoint_;
  const uint8_t transport_;
  const moon_tunnel_callbacks callbacks_;

  std::unique_ptr<CommonConnectJobParams> common_params_;
  std::unique_ptr<ConnectJob> job_;
  std::unique_ptr<StreamSocket> socket_;

  // Binding of the most recent authorized CONNECT stream.
  bool authorized_ = false;
  bool refused_ = false;
  bool confirmation_failed_ = false;
  moon_binding binding_{};
  std::string authority_;
  int http_status_ = 0;
  uint8_t selection_ = 0;
  bool opened_ = false;

  scoped_refptr<IOBufferWithSize> read_buf_;
  scoped_refptr<DrainableIOBuffer> write_buf_;
  int write_total_ = 0;
  bool shutdown_pending_ = false;
  bool write_shut_ = false;

  base::WeakPtrFactory<Tunnel> weak_factory_{this};
};

// ---------------------------------------------------------------------------

class Engine {
 public:
  explicit Engine(EngineSettings settings)
      : settings_(std::move(settings)), thread_("moon_engine") {}

  bool Start(std::string* error) {
    base::Thread::Options options(base::MessagePumpType::IO, 0);
    if (!thread_.StartWithOptions(std::move(options))) {
      *error = "cannot start the engine thread";
      return false;
    }
    task_runner_ = thread_.task_runner();
    base::WaitableEvent done;
    bool ok = false;
    task_runner_->PostTask(FROM_HERE, base::BindOnce(
                                          [](Engine* self, std::string* error,
                                             bool* ok, base::WaitableEvent* e) {
                                            *ok = self->InitOnThread(error);
                                            e->Signal();
                                          },
                                          this, error, &ok, &done));
    done.Wait();
    if (!ok) {
      Stop();
    }
    return ok;
  }

  void Stop() {
    if (!task_runner_) {
      return;
    }
    base::WaitableEvent done;
    task_runner_->PostTask(FROM_HERE, base::BindOnce(
                                          [](Engine* self,
                                             base::WaitableEvent* e) {
                                            self->ShutdownOnThread();
                                            e->Signal();
                                          },
                                          this, &done));
    done.Wait();
    thread_.Stop();
    task_runner_ = nullptr;
  }

  uint64_t Open(HostPortPair endpoint,
                uint8_t transport,
                const moon_tunnel_callbacks& callbacks) {
    uint64_t id = next_id_.fetch_add(1);
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&Engine::OpenOnThread, base::Unretained(this), id,
                       std::move(endpoint), transport, callbacks));
    return id;
  }

  template <typename F>
  void WithTunnel(uint64_t id, F f) {
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(
                               [](Engine* self, uint64_t id, F f) {
                                 auto it = self->tunnels_.find(id);
                                 if (it != self->tunnels_.end()) {
                                   f(*it->second);
                                 }
                               },
                               base::Unretained(this), id, std::move(f)));
  }

  void Close(uint64_t id) {
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(
                               [](Engine* self, uint64_t id) {
                                 // Destroying the tunnel runs on_closed.
                                 self->tunnels_.erase(id);
                               },
                               base::Unretained(this), id));
  }

  const EngineSettings& settings() const { return settings_; }
  HttpNetworkSession* session() const {
    return context_->http_transaction_factory()->GetSession();
  }
  const ConnectJobFactory& connect_job_factory() const { return *factory_; }

 private:
  bool InitOnThread(std::string* error) {
    bssl::ParsedCertificateList anchors;
    if (!settings_.ca_file.empty() &&
        !LoadAnchors(settings_.ca_file, &anchors, error)) {
      return false;
    }

    URLRequestContextBuilder builder;
    builder.DisableHttpCache();
    builder.set_proxy_resolution_service(
        ConfiguredProxyResolutionService::CreateDirect());

    // Same HTTP/2 receive windows as upstream NaiveProxy, sized for high
    // bandwidth-delay paths.
    constexpr int kTypicalWindow = 64 * 1024 * 1024;
    HttpNetworkSessionParams session_params;
    session_params.spdy_session_max_recv_window_size = kTypicalWindow * 2;
    session_params.http2_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] =
        kTypicalWindow;
    session_params.enable_early_data = false;
    builder.set_http_network_session_params(session_params);

    if (!settings_.connect_host.empty() &&
        settings_.connect_host != settings_.server_name) {
      HostPortPair target(settings_.connect_host, 0);
      builder.set_host_mapping_rules("MAP " + settings_.server_name + " " +
                                     target.HostForURL());
    }

    auto proc_factory =
        base::MakeRefCounted<MoonCertVerifyProcFactory>(std::move(anchors));
    auto proc = proc_factory->CreateCertVerifyProc(nullptr, {}, {});
    builder.SetCertVerifier(std::make_unique<MultiThreadedCertVerifier>(
        std::move(proc), std::move(proc_factory)));

    builder.set_ssl_config_service(std::make_unique<MoonSSLConfigService>(
        settings_.server_name, settings_.ech));

    auto quic_context = std::make_unique<QuicContext>();
    quic_context->params()->idle_connection_timeout =
        base::Seconds(settings_.quic_idle_timeout_secs);
    if (!settings_.ca_file.empty()) {
      // Chromium's QUIC refuses chains that end at a locally added anchor
      // unless the host is listed here (ProofVerifierChromium). The proxy's
      // configured private anchor is trusted for TLS over TCP, so trust it
      // for QUIC to the same proxy name, and only for that name.
      quic_context->params()->origins_to_force_quic_on.insert(
          url::SchemeHostPort(url::kHttpsScheme, settings_.server_name,
                              settings_.port));
    }
    builder.set_quic_context(std::move(quic_context));

    context_ = builder.Build();
    factory_ = std::make_unique<ConnectJobFactory>();
    return true;
  }

  void ShutdownOnThread() {
    tunnels_.clear();
    factory_.reset();
    context_.reset();
  }

  void OpenOnThread(uint64_t id,
                    HostPortPair endpoint,
                    uint8_t transport,
                    moon_tunnel_callbacks callbacks) {
    auto tunnel =
        std::make_unique<Tunnel>(this, std::move(endpoint), transport,
                                 callbacks);
    Tunnel* raw = tunnel.get();
    tunnels_.emplace(id, std::move(tunnel));
    raw->Start();
  }

  const EngineSettings settings_;
  base::Thread thread_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  std::atomic<uint64_t> next_id_{1};

  // Engine thread only.
  std::unique_ptr<URLRequestContext> context_;
  std::unique_ptr<ConnectJobFactory> factory_;
  std::map<uint64_t, std::unique_ptr<Tunnel>> tunnels_;
};

// ---------------------------------------------------------------------------

void Tunnel::Start() {
  const EngineSettings& s = engine_->settings();
  ProxyServer server(transport_ == MOON_TRANSPORT_H3 ? ProxyServer::SCHEME_QUIC
                                                     : ProxyServer::SCHEME_HTTPS,
                     HostPortPair(s.server_name, s.port));
  ProxyChain chain(server);
  if (!chain.IsValid()) {
    Finish(ERR_INVALID_ARGUMENT);
    return;
  }
  common_params_ = std::make_unique<CommonConnectJobParams>(
      engine_->session()->CreateCommonConnectJobParams());
  common_params_->proxy_delegate = this;
  job_ = engine_->connect_job_factory().CreateConnectJob(
      /*using_ssl=*/false, endpoint_, chain, kTrafficAnnotation,
      /*force_tunnel=*/true, PRIVACY_MODE_DISABLED, OnHostResolutionCallback(),
      MAXIMUM_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, common_params_.get(),
      handles::kInvalidNetworkHandle, this);
  int rv = job_->Connect();
  if (rv != ERR_IO_PENDING) {
    OnConnectJobComplete(rv, job_.get());
  }
}

void Tunnel::OnConnectJobComplete(int result, ConnectJob* job) {
  if (result == OK) {
    socket_ = job->PassSocket();
  }
  job_.reset();
  Finish(result);
}

void Tunnel::Finish(int result) {
  if (opened_) {
    return;
  }
  opened_ = true;
  moon_open_result r{};
  r.transport = transport_;
  r.http_status = http_status_;
  r.net_error = result;
  if (refused_) {
    r.kind = MOON_OPEN_REFUSED;
  } else if (confirmation_failed_) {
    r.kind = MOON_OPEN_CONFIRMATION;
  } else if (http_status_ != 0 && http_status_ != 200) {
    r.kind = MOON_OPEN_STATUS;
  } else if (result == OK && socket_ && selection_ != 0) {
    r.kind = MOON_OPEN_OK;
    r.selection = selection_;
  } else if (result == OK || http_status_ == 200) {
    r.kind = MOON_OPEN_CONFIRMATION;
  } else {
    r.kind = MOON_OPEN_CONNECTION;
  }
  if (r.kind != MOON_OPEN_OK) {
    socket_.reset();
    if (r.net_error == OK) {
      r.net_error = ERR_TUNNEL_CONNECTION_FAILED;
    }
  }
  callbacks_.on_open(callbacks_.ctx, &r);
}

std::string_view Tunnel::ExporterLabel() const {
  return engine_->settings().exporter_label;
}

int Tunnel::AuthorizeTunnel(const MoonTunnelBinding& binding,
                            quiche::HttpHeaderBlock& headers) {
  auto authority = headers.find(":authority");
  if (authority == headers.end() || headers.contains("proxy-authorization")) {
    return ERR_TUNNEL_CONNECTION_FAILED;
  }
  moon_binding b{};
  std::copy(binding.exporter.begin(), binding.exporter.end(), b.exporter);
  b.stream_id = binding.stream_id;
  b.ech_accepted = binding.ech_accepted ? 1 : 0;
  b.http_version = static_cast<uint8_t>(binding.http_version);
  std::string value_authority(authority->second);

  const EngineSettings& s = engine_->settings();
  uint8_t out[kMaxAuthorizationSize];
  size_t out_len = 0;
  int rc = s.authorize(s.auth_ctx, &b, value_authority.data(),
                       value_authority.size(), out, sizeof(out), &out_len);
  if (rc != 0 || out_len == 0 || out_len > sizeof(out)) {
    refused_ = true;
    return ERR_TUNNEL_CONNECTION_FAILED;
  }
  headers["proxy-authorization"] =
      std::string(reinterpret_cast<const char*>(out), out_len);
  binding_ = b;
  authority_ = std::move(value_authority);
  authorized_ = true;
  return OK;
}

Error Tunnel::OnTunnelHeadersReceived(
    const ProxyChain& proxy_chain,
    size_t proxy_index,
    const HttpResponseHeaders& response_headers,
    CompletionOnceCallback callback) {
  http_status_ = response_headers.response_code();
  if (!authorized_) {
    return ERR_TUNNEL_CONNECTION_FAILED;
  }
  if (http_status_ != 200) {
    // The proxy socket fails the tunnel for any status other than 200.
    return OK;
  }
  std::vector<std::string> values;
  size_t iter = 0;
  std::string name;
  std::string value;
  while (response_headers.EnumerateHeaderLines(&iter, &name, &value)) {
    if (base::EqualsCaseInsensitiveASCII(name, "proxy-authentication-info")) {
      values.push_back(value);
    }
  }
  std::vector<const char*> ptrs;
  std::vector<size_t> lens;
  for (const auto& v : values) {
    ptrs.push_back(v.data());
    lens.push_back(v.size());
  }
  const EngineSettings& s = engine_->settings();
  uint8_t selection =
      s.verify(s.auth_ctx, &binding_, authority_.data(), authority_.size(),
               ptrs.data(), lens.data(), ptrs.size());
  if (selection == 0) {
    confirmation_failed_ = true;
    return ERR_TUNNEL_CONNECTION_FAILED;
  }
  selection_ = selection;
  return OK;
}

void Tunnel::Read(size_t max_len) {
  if (!socket_ || read_buf_) {
    callbacks_.on_read(callbacks_.ctx, ERR_UNEXPECTED, nullptr);
    return;
  }
  read_buf_ = base::MakeRefCounted<IOBufferWithSize>(
      std::clamp<size_t>(max_len, 1, kMaxReadSize));
  int rv = socket_->Read(
      read_buf_.get(), read_buf_->size(),
      base::BindOnce(&Tunnel::OnRead, weak_factory_.GetWeakPtr()));
  if (rv != ERR_IO_PENDING) {
    OnRead(rv);
  }
}

void Tunnel::OnRead(int result) {
  scoped_refptr<IOBufferWithSize> buf = std::move(read_buf_);
  callbacks_.on_read(callbacks_.ctx, result,
                     result > 0 ? reinterpret_cast<const uint8_t*>(buf->data())
                                : nullptr);
}

void Tunnel::Write(std::vector<uint8_t> data) {
  if (!socket_ || write_buf_ || write_shut_ || shutdown_pending_ ||
      data.empty()) {
    callbacks_.on_write(callbacks_.ctx, ERR_UNEXPECTED);
    return;
  }
  auto buf = base::MakeRefCounted<IOBufferWithSize>(data.size());
  std::memcpy(buf->data(), data.data(), data.size());
  write_total_ = static_cast<int>(data.size());
  write_buf_ = base::MakeRefCounted<DrainableIOBuffer>(std::move(buf),
                                                       data.size());
  DoWrite();
}

void Tunnel::DoWrite() {
  int rv = socket_->Write(
      write_buf_.get(), write_buf_->BytesRemaining(),
      base::BindOnce(&Tunnel::OnWrite, weak_factory_.GetWeakPtr()),
      kTrafficAnnotation);
  if (rv != ERR_IO_PENDING) {
    OnWrite(rv);
  }
}

void Tunnel::OnWrite(int result) {
  if (result < 0) {
    write_buf_ = nullptr;
    shutdown_pending_ = false;
    callbacks_.on_write(callbacks_.ctx, result);
    return;
  }
  write_buf_->DidConsume(result);
  if (write_buf_->BytesRemaining() > 0) {
    DoWrite();
    return;
  }
  write_buf_ = nullptr;
  base::WeakPtr<Tunnel> self = weak_factory_.GetWeakPtr();
  callbacks_.on_write(callbacks_.ctx, write_total_);
  if (self && shutdown_pending_) {
    shutdown_pending_ = false;
    DoShutdown();
  }
}

void Tunnel::ShutdownWrite() {
  if (!socket_ || write_shut_ || shutdown_pending_) {
    callbacks_.on_shutdown(callbacks_.ctx, ERR_UNEXPECTED);
    return;
  }
  if (write_buf_) {
    shutdown_pending_ = true;
    return;
  }
  DoShutdown();
}

void Tunnel::DoShutdown() {
  write_shut_ = true;
  int rv = socket_->CloseWrite(
      base::BindOnce(&Tunnel::OnShutdown, weak_factory_.GetWeakPtr()));
  if (rv != ERR_IO_PENDING) {
    OnShutdown(rv);
  }
}

void Tunnel::OnShutdown(int result) {
  callbacks_.on_shutdown(callbacks_.ctx, result);
}

bool ParseAuthority(std::string_view authority, HostPortPair* out) {
  if (authority.empty() || authority.size() > 512) {
    return false;
  }
  for (char c : authority) {
    if (static_cast<unsigned char>(c) <= 0x20 || c == 0x7f || c == '/' ||
        c == '@' || c == '?' || c == '#') {
      return false;
    }
  }
  HostPortPair parsed = HostPortPair::FromString(authority);
  if (parsed.host().empty() || parsed.port() == 0) {
    return false;
  }
  *out = std::move(parsed);
  return true;
}

void CopyError(const char* message, char* err, size_t err_cap) {
  if (!err || err_cap == 0) {
    return;
  }
  size_t n = std::min(std::strlen(message), err_cap - 1);
  std::memcpy(err, message, n);
  err[n] = '\0';
}

}  // namespace
}  // namespace net

struct moon_engine {
  std::unique_ptr<net::Engine> engine;
};

extern "C" {

uint32_t moon_engine_abi_version(void) {
  return MOON_ENGINE_ABI_VERSION;
}

moon_engine* moon_engine_create(const moon_engine_config* config,
                                char* err,
                                size_t err_cap) {
  if (!config || config->abi_version != MOON_ENGINE_ABI_VERSION) {
    net::CopyError("engine ABI version mismatch", err, err_cap);
    return nullptr;
  }
  if (!config->server_name || !*config->server_name || config->port == 0 ||
      !config->exporter_label || !*config->exporter_label ||
      !config->authorize || !config->verify) {
    net::CopyError("incomplete engine configuration", err, err_cap);
    return nullptr;
  }
  net::InitializeProcessOnce();
  net::g_log_ctx.store(config->log_ctx);
  net::g_log_fn.store(config->log);

  net::EngineSettings settings;
  settings.server_name = base::ToLowerASCII(config->server_name);
  if (config->connect_host) {
    settings.connect_host = config->connect_host;
  }
  settings.port = config->port;
  if (config->ca_file) {
    settings.ca_file = config->ca_file;
  }
  if (config->ech_config_list && config->ech_config_list_len) {
    settings.ech.assign(config->ech_config_list,
                        config->ech_config_list + config->ech_config_list_len);
  }
  settings.exporter_label = config->exporter_label;
  if (config->quic_idle_timeout_secs) {
    settings.quic_idle_timeout_secs = config->quic_idle_timeout_secs;
  }
  settings.auth_ctx = config->auth_ctx;
  settings.authorize = config->authorize;
  settings.verify = config->verify;

  auto engine = std::make_unique<net::Engine>(std::move(settings));
  std::string error;
  if (!engine->Start(&error)) {
    net::CopyError(error.c_str(), err, err_cap);
    return nullptr;
  }
  return new moon_engine{std::move(engine)};
}

void moon_engine_destroy(moon_engine* engine) {
  if (!engine) {
    return;
  }
  engine->engine->Stop();
  delete engine;
}

uint64_t moon_tunnel_open(moon_engine* engine,
                          const char* authority,
                          size_t authority_len,
                          uint32_t transport,
                          const moon_tunnel_callbacks* callbacks) {
  if (!engine || !authority || !callbacks || !callbacks->on_open ||
      !callbacks->on_read || !callbacks->on_write || !callbacks->on_shutdown ||
      !callbacks->on_closed ||
      (transport != MOON_TRANSPORT_H2 && transport != MOON_TRANSPORT_H3)) {
    return 0;
  }
  net::HostPortPair endpoint;
  if (!net::ParseAuthority(std::string_view(authority, authority_len),
                           &endpoint)) {
    return 0;
  }
  return engine->engine->Open(std::move(endpoint),
                              static_cast<uint8_t>(transport), *callbacks);
}

void moon_tunnel_read(moon_engine* engine, uint64_t tunnel, size_t max_len) {
  engine->engine->WithTunnel(
      tunnel, [max_len](net::Tunnel& t) { t.Read(max_len); });
}

void moon_tunnel_write(moon_engine* engine,
                       uint64_t tunnel,
                       const uint8_t* data,
                       size_t len) {
  std::vector<uint8_t> copy(data, data + len);
  engine->engine->WithTunnel(tunnel,
                             [copy = std::move(copy)](net::Tunnel& t) mutable {
                               t.Write(std::move(copy));
                             });
}

void moon_tunnel_shutdown_write(moon_engine* engine, uint64_t tunnel) {
  engine->engine->WithTunnel(tunnel,
                             [](net::Tunnel& t) { t.ShutdownWrite(); });
}

void moon_tunnel_close(moon_engine* engine, uint64_t tunnel) {
  engine->engine->Close(tunnel);
}

}  // extern "C"
