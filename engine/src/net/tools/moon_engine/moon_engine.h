// Copyright 2026 Moon-naive contributors. SPDX-License-Identifier: Apache-2.0
//
// C ABI of the Moon-naive Chromium Native Engine (libmoon_engine).
//
// The engine owns one Chromium network stack (HttpNetworkSession: host
// resolver, socket factory, TLS, HTTP/2 and QUIC session pools, certificate
// verifier) on a dedicated IO thread, and opens authenticated CONNECT tunnels
// through one proxy. It contains no protocol constants and no cryptography of
// its own: the exporter label, request proofs and confirmation checks are
// supplied by the embedder through callbacks.
//
// Threading: every function may be called from any thread. All callbacks run
// on the engine thread, must not block, and must not call
// moon_engine_destroy(). Calling the tunnel functions from a callback is
// allowed (they only post tasks).
//
// Lifetime: a tunnel's callback context stays referenced until its
// on_closed callback, which is always the last callback for that tunnel.
#ifndef NET_TOOLS_MOON_ENGINE_MOON_ENGINE_H_
#define NET_TOOLS_MOON_ENGINE_MOON_ENGINE_H_

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(MOON_ENGINE_IMPLEMENTATION)
#define MOON_ENGINE_EXPORT __attribute__((visibility("default")))
#else
#define MOON_ENGINE_EXPORT
#endif

// Bumped on every incompatible change of this header.
#define MOON_ENGINE_ABI_VERSION 1u

#define MOON_TRANSPORT_H2 2u
#define MOON_TRANSPORT_H3 3u

// Outcome kinds reported by on_open.
#define MOON_OPEN_OK 0u
// The proxy connection (TCP/TLS or QUIC) or the stream could not be
// established. Nothing was received from the proxy for this tunnel.
#define MOON_OPEN_CONNECTION 1u
// The proxy answered with a status other than 200 (see http_status).
#define MOON_OPEN_STATUS 2u
// Status 200 without exactly one valid confirmation.
#define MOON_OPEN_CONFIRMATION 3u
// The embedder's authorize callback refused to sign (for example, ECH was
// required but not accepted). No request was sent.
#define MOON_OPEN_REFUSED 4u

typedef struct moon_engine moon_engine;

// Channel binding of one CONNECT stream.
typedef struct moon_binding {
  uint8_t exporter[32];
  uint64_t stream_id;
  uint8_t ech_accepted;
  uint8_t http_version;  // 2 or 3
} moon_binding;

// Produce the proxy-authorization value for a CONNECT with this binding and
// exact :authority. Write at most out_cap bytes to out, store the length in
// *out_len and return 0; any other return value refuses the tunnel.
typedef int (*moon_authorize_fn)(void* auth_ctx,
                                 const moon_binding* binding,
                                 const char* authority,
                                 size_t authority_len,
                                 uint8_t* out,
                                 size_t out_cap,
                                 size_t* out_len);

// Verify a 200 response. `values` holds every proxy-authentication-info field
// value of the response (count may be 0 or more than 1). Return the selected
// record mode (1..255) if exactly one value is a valid confirmation for this
// binding and authority, or 0 to reject.
typedef uint8_t (*moon_verify_fn)(void* auth_ctx,
                                  const moon_binding* binding,
                                  const char* authority,
                                  size_t authority_len,
                                  const char* const* values,
                                  const size_t* value_lens,
                                  size_t count);

// Engine diagnostics (no secrets): level 0 info, 1 warning, 2 error.
typedef void (*moon_log_fn)(void* log_ctx,
                            int level,
                            const char* message,
                            size_t message_len);

typedef struct moon_engine_config {
  uint32_t abi_version;  // MOON_ENGINE_ABI_VERSION
  // TLS server name of the proxy (SNI or ECH inner name, certificate name).
  const char* server_name;
  // Host (DNS name or IP literal, IPv6 without brackets) to connect to.
  // NULL or equal to server_name: resolve server_name.
  const char* connect_host;
  uint16_t port;
  // Optional PEM file with additional trust anchors (NULL: none).
  const char* ca_file;
  // Optional ECHConfigList. When present ECH is mandatory (strict mode):
  // a rejection is retried only with server-provided retry configs.
  const uint8_t* ech_config_list;
  size_t ech_config_list_len;
  // TLS exporter label for the channel binding.
  const char* exporter_label;
  uint32_t quic_idle_timeout_secs;
  void* auth_ctx;
  moon_authorize_fn authorize;
  moon_verify_fn verify;
  void* log_ctx;
  moon_log_fn log;  // optional
} moon_engine_config;

typedef struct moon_open_result {
  uint8_t kind;           // MOON_OPEN_*
  uint8_t transport;      // MOON_TRANSPORT_*
  uint8_t selection;      // record mode, valid when kind == MOON_OPEN_OK
  int32_t net_error;      // Chromium net error (0 on success)
  int32_t http_status;    // 0 if no response was received
} moon_open_result;

typedef struct moon_tunnel_callbacks {
  void* ctx;
  void (*on_open)(void* ctx, const moon_open_result* result);
  // result > 0: `data` holds result bytes (valid during the call only);
  // result == 0: clean end of the peer's stream (half-close);
  // result < 0: reset or connection error.
  void (*on_read)(void* ctx, int32_t result, const uint8_t* data);
  // All bytes of the write were accepted (result == length) or an error.
  void (*on_write)(void* ctx, int32_t result);
  // Result of moon_tunnel_shutdown_write (0 or an error).
  void (*on_shutdown)(void* ctx, int32_t result);
  // Final callback; the context may be released.
  void (*on_closed)(void* ctx);
} moon_tunnel_callbacks;

MOON_ENGINE_EXPORT uint32_t moon_engine_abi_version(void);

// Returns NULL on failure, with a message in err (NUL-terminated).
MOON_ENGINE_EXPORT moon_engine* moon_engine_create(
    const moon_engine_config* config,
    char* err,
    size_t err_cap);

// Closes every tunnel (each receives on_closed), tears the stack down and
// joins the engine thread.
MOON_ENGINE_EXPORT void moon_engine_destroy(moon_engine* engine);

// Starts a tunnel to `authority` ("host:port" or "[v6]:port"). Returns a
// nonzero tunnel id; the outcome arrives through on_open. Returns 0 if the
// arguments are invalid, in which case no callback runs.
MOON_ENGINE_EXPORT uint64_t moon_tunnel_open(
    moon_engine* engine,
    const char* authority,
    size_t authority_len,
    uint32_t transport,
    const moon_tunnel_callbacks* callbacks);

// Requests one read of at most max_len bytes (one outstanding read).
MOON_ENGINE_EXPORT void moon_tunnel_read(moon_engine* engine,
                                         uint64_t tunnel,
                                         size_t max_len);

// Copies and writes `len` bytes (one outstanding write; len > 0).
MOON_ENGINE_EXPORT void moon_tunnel_write(moon_engine* engine,
                                          uint64_t tunnel,
                                          const uint8_t* data,
                                          size_t len);

// Half-closes the write direction once the outstanding write, if any, has
// completed. The read direction stays open.
MOON_ENGINE_EXPORT void moon_tunnel_shutdown_write(moon_engine* engine,
                                                   uint64_t tunnel);

// Aborts the tunnel (resets the stream if still open) and releases it.
MOON_ENGINE_EXPORT void moon_tunnel_close(moon_engine* engine,
                                          uint64_t tunnel);

#if defined(__cplusplus)
}  // extern "C"
#endif

#endif  // NET_TOOLS_MOON_ENGINE_MOON_ENGINE_H_
