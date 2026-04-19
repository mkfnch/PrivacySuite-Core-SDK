//! High-level privacy HTTP client (G1) composing the three network-privacy
//! tiers behind one API.
//!
//! Before this module, every BoomLeft consumer (Music, Podcasts, Weather,
//! RSS, DarkGIFs, Blackout, Screenshots, Telephoto) reinvented the same
//! tier router on top of [`PrivacyDns`], [`OhttpClient`], and [`TorClient`].
//! That duplication produced two audit findings (Blackout H-lvl filter-list
//! leak, RSS H10 redirect-SSRF) because the policy was not uniform.
//!
//! [`PrivacyClient`] is the single compose-layer:
//!
//! | [`PrivacyTier`] | Transport stack |
//! |---------------|-----------------|
//! | `Standard` | `reqwest` + [`PrivacyDns`]-backed resolver, rustls, no proxy |
//! | `Enhanced` | [`OhttpClient`] over a `reqwest`-backed [`OhttpTransport`] |
//! | `Maximum`  | `reqwest` with `socks5h://` proxy (per-fetch SOCKS username) |
//!
//! # Security posture
//!
//! - **No SDK-added headers.** Callers pass a full header set, including
//!   `User-Agent`. The SDK never injects anything identifying (no
//!   `privacysuite/x.y` marker). Header names/values containing `\r`,
//!   `\n`, or `\0` are rejected with [`NetworkError::InvalidConfiguration`]
//!   at send time.
//! - **No in-SDK redirect following.** The reqwest client is constructed
//!   with `redirect::Policy::none()`; 3xx status codes surface to the
//!   caller with a `Location` header. Callers re-run their URL validator
//!   (G2) before dialing the next hop. This is the direct fix for the
//!   OPML-redirect-SSRF bug in the RSS audit (H10).
//! - **Response-size cap.** Every response body is bounded by
//!   [`PrivacyClientConfig::response_size_cap`]. An advertised
//!   `Content-Length` exceeding the cap is rejected before any body
//!   byte is read; for chunked/streaming bodies the cap is enforced
//!   during read and produces [`NetworkError::ResponseTooLarge`] on
//!   overflow.
//! - **Tor circuit isolation.** The Tor tier builds a fresh `reqwest`
//!   `Client` per fetch with a unique random SOCKS5 username. That
//!   username triggers Tor's stream-isolation path — different usernames
//!   land on different circuits and are therefore uncorrelatable by the
//!   exit node. This is the fix pattern from RSS audit H8.
//!
//! # Deferred
//!
//! - Dynamic OHTTP key-configuration fetching (the underlying
//!   [`OhttpClient`] already documents this deferral — see
//!   `networking::ohttp`).
//! - UniFFI async export. UniFFI 0.31's async support is awkward for
//!   complex return types; see the `privacysuite-ffi` crate for the
//!   stub and the Phase-2 tracking note.
//! - reqwest-level SPKI pinning. [`PrivacyClientConfig::pinner`] is
//!   accepted but not yet wired into reqwest's rustls backend — hooking
//!   a custom `ServerCertVerifier` into reqwest 0.12 requires the
//!   `rustls-tls-manual-roots` feature path, tracked for a follow-up
//!   PR. Callers that need hard pinning today should continue to use
//!   [`crate::sync::RelayTransport::connect_with_pinner`].

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;
use futures_util::stream::StreamExt;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect;

use crate::crypto::pinning::CertificatePinner;
use crate::crypto::util::secure_random;

use super::{
    NetworkError, OhttpClient, OhttpConfig, OhttpRequest, OhttpTransport, PrivacyDns,
    PrivacyTier,
};

/// Minimum ceiling for the response-size cap (1 byte).
///
/// A cap of `0` would reject every response, including empty-body
/// replies; we treat that as a caller error.
const MIN_RESPONSE_CAP: u64 = 1;

/// Default Tor SOCKS5 proxy address used when the caller leaves
/// [`PrivacyClientConfig::tor_socks_addr`] unset.
const DEFAULT_TOR_SOCKS_ADDR: &str = "127.0.0.1:9050";

/// A single network request honoured through the configured privacy tier.
#[derive(Debug, Clone)]
pub struct FetchSpec {
    /// HTTP method: `"GET"`, `"HEAD"`, or `"POST"`.
    pub method: String,
    /// Target URL. Must begin with `https://`.
    pub url: String,
    /// Request headers, including `User-Agent` (the SDK never injects
    /// one).
    pub headers: Vec<(String, String)>,
    /// Request body. Empty for bodyless methods.
    pub body: Vec<u8>,
}

/// A single response returned from [`PrivacyClient::fetch`] or
/// [`PrivacyClient::fetch_with_decoys`].
#[derive(Debug, Clone)]
pub struct PrivacyResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers as received, in wire order. Duplicates preserved.
    pub headers: Vec<(String, String)>,
    /// Decoded response body. Length is guaranteed to be
    /// `<= config.response_size_cap`.
    pub body: Vec<u8>,
}

/// Configuration for a [`PrivacyClient`].
///
/// The SDK adds no identifying markers of its own — every field the caller
/// sets is reflected on the wire as-is. This is deliberate: privacy-tier
/// fetches must not be distinguishable from mainstream-client fetches by
/// the operator of the relay, exit node, or upstream server.
#[derive(Debug, Clone)]
pub struct PrivacyClientConfig {
    /// Which privacy tier to route through.
    pub tier: PrivacyTier,
    /// `User-Agent` value the caller wants on every fetch (typical
    /// choice: a current Firefox ESR UA). The SDK never overrides or
    /// supplements this — it is the caller's sole responsibility to
    /// avoid fingerprinting leaks.
    pub user_agent: String,
    /// Per-request timeout. Applied to the full request/response cycle.
    pub request_timeout: Duration,
    /// Maximum response body size. Enforced pre-body via `Content-Length`
    /// when advertised, and during read otherwise.
    pub response_size_cap: u64,
    /// OHTTP configuration. **Required** when `tier == Enhanced`.
    pub ohttp: Option<OhttpConfig>,
    /// Optional override for the Tor daemon's SOCKS5 listener. Defaults
    /// to `127.0.0.1:9050`. Only consulted when `tier == Maximum`.
    pub tor_socks_addr: Option<String>,
    /// Optional SPKI certificate pinner for the relay/upstream TLS.
    /// Accepted today; full reqwest-side wiring is deferred (see the
    /// module-level "Deferred" note).
    pub pinner: Option<CertificatePinner>,
}

/// Compose-layer privacy HTTP client.
///
/// Constructed once, then used for many fetches. Internally maintains
/// tier-appropriate state (persistent `reqwest::Client` for Standard /
/// Enhanced, single-shot `reqwest::Client`s for Maximum to preserve
/// circuit isolation).
pub struct PrivacyClient {
    tier: PrivacyTier,
    user_agent: String,
    request_timeout: Duration,
    response_size_cap: u64,
    standard: Option<reqwest::Client>,
    ohttp: Option<Arc<OhttpClient>>,
    tor_socks_addr: Option<String>,
    #[allow(dead_code)]
    pinner: Option<CertificatePinner>,
}

impl std::fmt::Debug for PrivacyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivacyClient")
            .field("tier", &self.tier)
            .field("request_timeout", &self.request_timeout)
            .field("response_size_cap", &self.response_size_cap)
            .field("has_standard_client", &self.standard.is_some())
            .field("has_ohttp_client", &self.ohttp.is_some())
            .field("has_tor_override", &self.tor_socks_addr.is_some())
            .finish()
    }
}

impl PrivacyClient {
    /// Build a configured privacy client.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::InvalidConfiguration`] when:
    ///
    /// - `tier == Enhanced` but no [`OhttpConfig`] is provided.
    /// - `response_size_cap == 0` (would reject every response).
    /// - The OHTTP config's public key fails to decode (propagated from
    ///   [`OhttpConfig::gateway_public_key`]).
    /// - The `User-Agent` contains any of `\r`, `\n`, `\0` (would
    ///   split/smuggle headers).
    ///
    /// Does **not** probe the Tor daemon at construction time; that is
    /// too brittle (the daemon may come up moments after the SDK is
    /// initialised). Callers get a clean [`NetworkError::TorProxy`] on
    /// the first [`Self::fetch`] when the daemon is unavailable.
    pub fn new(config: PrivacyClientConfig) -> Result<Self, NetworkError> {
        if config.response_size_cap < MIN_RESPONSE_CAP {
            return Err(NetworkError::InvalidConfiguration(
                "response_size_cap must be >= 1".to_owned(),
            ));
        }
        validate_header_value("user-agent", &config.user_agent)?;

        let PrivacyClientConfig {
            tier,
            user_agent,
            request_timeout,
            response_size_cap,
            ohttp,
            tor_socks_addr,
            pinner,
        } = config;

        let (standard, ohttp_client) = match tier {
            PrivacyTier::Standard => {
                let client = build_standard_client(&user_agent, request_timeout)?;
                (Some(client), None)
            }
            PrivacyTier::Enhanced => {
                let Some(cfg) = ohttp else {
                    return Err(NetworkError::InvalidConfiguration(
                        "tier=Enhanced requires OhttpConfig".to_owned(),
                    ));
                };
                // The reqwest client in this branch is used only as the
                // OhttpTransport back-end — it never talks directly to
                // the upstream target.
                let relay_client =
                    build_standard_client(&user_agent, request_timeout)?;
                let transport: Arc<dyn OhttpTransport> = Arc::new(
                    ReqwestOhttpTransport {
                        client: relay_client,
                        response_cap: response_size_cap,
                    },
                );
                let ohttp = OhttpClient::new(cfg, transport)?
                    .with_response_cap(
                        usize::try_from(response_size_cap).unwrap_or(usize::MAX),
                    );
                (None, Some(Arc::new(ohttp)))
            }
            PrivacyTier::Maximum => {
                // Tor tier: no persistent client. Each fetch builds its
                // own with a unique SOCKS5 username. See
                // `fetch_maximum` for the full lifecycle.
                (None, None)
            }
        };

        Ok(Self {
            tier,
            user_agent,
            request_timeout,
            response_size_cap,
            standard,
            ohttp: ohttp_client,
            tor_socks_addr,
            pinner,
        })
    }

    /// Returns the configured tier.
    #[must_use]
    pub fn tier(&self) -> PrivacyTier {
        self.tier
    }

    /// Returns the configured response cap in bytes.
    #[must_use]
    pub fn response_size_cap(&self) -> u64 {
        self.response_size_cap
    }

    /// Execute a single fetch honouring the configured tier.
    ///
    /// Does **not** follow redirects — 3xx status codes are returned
    /// verbatim with their `Location` header for the caller to re-run
    /// the URL validator and re-invoke `fetch`.
    ///
    /// # Errors
    ///
    /// Propagates the tier-specific failure mode ([`NetworkError::Connection`]
    /// for Standard/Enhanced transport issues, [`NetworkError::TorProxy`]
    /// for Tor failures, [`NetworkError::ResponseTooLarge`] if the body
    /// exceeds the cap, and [`NetworkError::InvalidConfiguration`] for
    /// malformed method/URL/headers).
    pub async fn fetch(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<PrivacyResponse, NetworkError> {
        let method = normalize_method(method)?;
        if !url.starts_with("https://") {
            return Err(NetworkError::InvalidConfiguration(
                "PrivacyClient only accepts https:// URLs".to_owned(),
            ));
        }
        for (n, v) in headers {
            validate_header_name(n)?;
            validate_header_value(n, v)?;
        }

        match self.tier {
            PrivacyTier::Standard => {
                self.fetch_standard(method, url, headers, body).await
            }
            PrivacyTier::Enhanced => {
                self.fetch_enhanced(method, url, headers, body).await
            }
            PrivacyTier::Maximum => {
                self.fetch_maximum(method, url, headers, body).await
            }
        }
    }

    /// k-anonymity fetch — runs one real fetch alongside `k - 1`
    /// decoys, discards the decoy responses, and returns only the real
    /// one.
    ///
    /// # Behaviour per tier
    ///
    /// - **Standard / Enhanced**: all `k` requests share the client's
    ///   connection pool. Observers on the wire see `k` simultaneous
    ///   fetches and cannot tell which one was real.
    /// - **Maximum (Tor)**: each of the `k` requests is issued through
    ///   a fresh per-fetch SOCKS5 username, landing on an independent
    ///   circuit. An exit-node observer that correlates traffic across
    ///   circuits still only sees `k` uncorrelated connections.
    ///
    /// # Errors
    ///
    /// - [`NetworkError::InvalidConfiguration`] if `k == 0`, if
    ///   `decoys.len() < k - 1`, or if the real request itself is
    ///   malformed.
    /// - Decoy failures are discarded silently — the real response has
    ///   the only privileged place in the return value.
    pub async fn fetch_with_decoys(
        &self,
        real: &FetchSpec,
        decoys: &[FetchSpec],
        k: usize,
    ) -> Result<PrivacyResponse, NetworkError> {
        if k == 0 {
            return Err(NetworkError::InvalidConfiguration(
                "k must be >= 1".to_owned(),
            ));
        }
        let decoy_count = k - 1;
        if decoys.len() < decoy_count {
            return Err(NetworkError::InvalidConfiguration(format!(
                "k={k} requires {decoy_count} decoys, got {actual}",
                actual = decoys.len()
            )));
        }

        // Fire all k in parallel. Only the real result is returned;
        // decoys are driven to completion (and their results dropped)
        // so that timing on the wire matches a genuine k-anonymous
        // set. If we short-circuited on the real result, a network
        // observer could distinguish the real connection by noting
        // that it was the one the client kept open after cancelling
        // the others.
        let real_fut = self.fetch(&real.method, &real.url, &real.headers, &real.body);
        let decoy_futs = decoys
            .iter()
            .take(decoy_count)
            .map(|d| self.fetch(&d.method, &d.url, &d.headers, &d.body));

        let (real_result, _decoys) =
            tokio::join!(real_fut, join_all(decoy_futs));
        real_result
    }

    // -----------------------------------------------------------------
    // Tier-specific back ends
    // -----------------------------------------------------------------

    async fn fetch_standard(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<PrivacyResponse, NetworkError> {
        let Some(client) = &self.standard else {
            return Err(NetworkError::InvalidConfiguration(
                "standard client not initialised".to_owned(),
            ));
        };
        self.execute_reqwest(client, method, url, headers, body).await
    }

    async fn fetch_enhanced(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<PrivacyResponse, NetworkError> {
        let Some(ohttp) = &self.ohttp else {
            return Err(NetworkError::InvalidConfiguration(
                "OHTTP client not initialised for tier=Enhanced".to_owned(),
            ));
        };
        let request = OhttpRequest {
            method: method.as_str().to_owned(),
            url: url.to_owned(),
            headers: headers.to_vec(),
            body: body.to_vec(),
        };
        let resp = ohttp.send(request).await?;
        let body_len = u64::try_from(resp.body.len()).unwrap_or(u64::MAX);
        if body_len > self.response_size_cap {
            return Err(NetworkError::ResponseTooLarge {
                observed: body_len,
                cap: self.response_size_cap,
            });
        }
        Ok(PrivacyResponse {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        })
    }

    async fn fetch_maximum(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<PrivacyResponse, NetworkError> {
        let socks_addr = self
            .tor_socks_addr
            .clone()
            .unwrap_or_else(|| DEFAULT_TOR_SOCKS_ADDR.to_owned());

        // Unique SOCKS5 username per fetch triggers Tor's stream
        // isolation — different usernames map to different circuits.
        let user_part = socks5_isolation_username()?;
        let proxy_url = format!("socks5h://{user_part}:x@{socks_addr}");
        let proxy = reqwest::Proxy::all(&proxy_url).map_err(|_e| {
            NetworkError::InvalidConfiguration(
                "invalid SOCKS5 proxy URL".to_owned(),
            )
        })?;

        let client = reqwest::Client::builder()
            .user_agent(self.user_agent.clone())
            .timeout(self.request_timeout)
            .redirect(redirect::Policy::none())
            .https_only(true)
            .proxy(proxy)
            .build()
            .map_err(|_e| {
                NetworkError::Connection(
                    "failed to build Tor reqwest client".to_owned(),
                )
            })?;

        // Map Tor-specific connection failures to `TorProxy` so the
        // caller can distinguish "daemon down" from "upstream 4xx".
        match self
            .execute_reqwest(&client, method, url, headers, body)
            .await
        {
            Ok(resp) => Ok(resp),
            Err(NetworkError::Connection(msg)) => Err(NetworkError::TorProxy(msg)),
            Err(other) => Err(other),
        }
    }

    async fn execute_reqwest(
        &self,
        client: &reqwest::Client,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<PrivacyResponse, NetworkError> {
        let mut builder = client.request(method, url);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if !body.is_empty() {
            builder = builder.body(body.to_vec());
        }

        let response = builder.send().await.map_err(reqwest_err_to_network)?;
        let status = response.status().as_u16();

        let response_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(n, v)| {
                (n.as_str().to_owned(), header_value_to_string(v))
            })
            .collect();

        // Content-Length pre-check. If an advertised length already
        // exceeds the cap, reject before streaming a single byte.
        if let Some(advertised) = response.content_length() {
            if advertised > self.response_size_cap {
                return Err(NetworkError::ResponseTooLarge {
                    observed: advertised,
                    cap: self.response_size_cap,
                });
            }
        }

        // Stream the body, enforcing the cap as bytes arrive. This
        // bounds memory even for servers that lie about
        // Content-Length (or omit it entirely with
        // Transfer-Encoding: chunked).
        let cap_usize =
            usize::try_from(self.response_size_cap).unwrap_or(usize::MAX);
        let initial = usize::try_from(response.content_length().unwrap_or(0))
            .unwrap_or(0)
            .min(cap_usize);
        let mut body_buf = Vec::with_capacity(initial);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(reqwest_err_to_network)?;
            let next_len = u64::try_from(body_buf.len())
                .unwrap_or(u64::MAX)
                .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            if next_len > self.response_size_cap {
                return Err(NetworkError::ResponseTooLarge {
                    observed: next_len,
                    cap: self.response_size_cap,
                });
            }
            body_buf.extend_from_slice(&chunk);
        }

        Ok(PrivacyResponse {
            status,
            headers: response_headers,
            body: body_buf,
        })
    }
}

// =========================================================================
// OhttpTransport impl: reqwest-backed relay POST
// =========================================================================

/// OHTTP relay transport implemented on top of a `reqwest::Client`.
///
/// Enforces the response-size cap against the advertised
/// `Content-Length` and during streaming, and verifies the
/// `Content-Type: message/ohttp-res` invariant (RFC 9458 §4.4).
#[derive(Debug)]
struct ReqwestOhttpTransport {
    client: reqwest::Client,
    response_cap: u64,
}

#[async_trait::async_trait]
impl OhttpTransport for ReqwestOhttpTransport {
    async fn post_capsule(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, NetworkError> {
        self.post_capsule_capped(
            url,
            body,
            usize::try_from(self.response_cap).unwrap_or(usize::MAX),
        )
        .await
    }

    async fn post_capsule_capped(
        &self,
        url: &str,
        body: Vec<u8>,
        max_bytes: usize,
    ) -> Result<Vec<u8>, NetworkError> {
        let cap_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);

        let response = self
            .client
            .post(url)
            .header("content-type", "message/ohttp-req")
            .body(body)
            .send()
            .await
            .map_err(reqwest_err_to_network)?;

        let status = response.status();
        if !status.is_success() {
            return Err(NetworkError::Connection(format!(
                "OHTTP relay returned HTTP {}",
                status.as_u16()
            )));
        }

        let ct = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_ascii_lowercase);
        match ct {
            Some(ref s) if s.starts_with("message/ohttp-res") => {}
            _ => {
                return Err(NetworkError::Connection(
                    "OHTTP relay missing message/ohttp-res content-type"
                        .to_owned(),
                ));
            }
        }

        if let Some(advertised) = response.content_length() {
            if advertised > cap_u64 {
                return Err(NetworkError::ResponseTooLarge {
                    observed: advertised,
                    cap: cap_u64,
                });
            }
        }

        let initial = usize::try_from(response.content_length().unwrap_or(0))
            .unwrap_or(0)
            .min(max_bytes);
        let mut buf = Vec::with_capacity(initial);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(reqwest_err_to_network)?;
            let next_len = u64::try_from(buf.len())
                .unwrap_or(u64::MAX)
                .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            if next_len > cap_u64 {
                return Err(NetworkError::ResponseTooLarge {
                    observed: next_len,
                    cap: cap_u64,
                });
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    }
}

// =========================================================================
// DoH-backed reqwest DNS resolver
// =========================================================================

/// A reqwest DNS resolver that delegates to the SDK's [`PrivacyDns`].
///
/// Every dial thereby flows through DoH (Cloudflare / Quad9) with the
/// SDK's SSRF / private-IP filter applied — there is no way for a
/// compromised system resolver to steer a Standard-tier fetch onto the
/// LAN or a metadata endpoint.
#[derive(Debug, Clone)]
struct DohResolver {
    inner: Arc<PrivacyDns>,
}

impl DohResolver {
    fn new() -> Result<Self, NetworkError> {
        Ok(Self {
            inner: Arc::new(PrivacyDns::new()?),
        })
    }
}

impl Resolve for DohResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let inner = self.inner.clone();
        Box::pin(async move {
            let addrs = inner.resolve(name.as_str()).await.map_err(|e| {
                Box::new(e) as Box<dyn std::error::Error + Send + Sync>
            })?;
            if addrs.is_empty() {
                return Err(Box::new(NetworkError::DnsResolution(format!(
                    "no public address for {}",
                    name.as_str()
                ))) as Box<dyn std::error::Error + Send + Sync>);
            }
            // Port 0 is filled in by reqwest based on the URL's
            // scheme/port.
            let iter = addrs
                .into_iter()
                .map(|ip| std::net::SocketAddr::new(ip, 0));
            let boxed: Addrs = Box::new(iter);
            Ok(boxed)
        })
    }
}

// =========================================================================
// Helpers
// =========================================================================

fn build_standard_client(
    user_agent: &str,
    timeout: Duration,
) -> Result<reqwest::Client, NetworkError> {
    let resolver = Arc::new(DohResolver::new()?);
    reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(timeout)
        .redirect(redirect::Policy::none())
        .dns_resolver(resolver)
        .https_only(true)
        .build()
        .map_err(|_e| {
            NetworkError::Connection("failed to build reqwest client".to_owned())
        })
}

fn normalize_method(method: &str) -> Result<reqwest::Method, NetworkError> {
    match method.to_ascii_uppercase().as_str() {
        "GET" => Ok(reqwest::Method::GET),
        "HEAD" => Ok(reqwest::Method::HEAD),
        "POST" => Ok(reqwest::Method::POST),
        other => Err(NetworkError::InvalidConfiguration(format!(
            "unsupported method {other}; PrivacyClient only accepts GET/HEAD/POST"
        ))),
    }
}

fn validate_header_name(name: &str) -> Result<(), NetworkError> {
    if name.is_empty() {
        return Err(NetworkError::InvalidConfiguration(
            "empty header name".to_owned(),
        ));
    }
    if name
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || b == b':')
    {
        return Err(NetworkError::InvalidConfiguration(
            "header name contains CR/LF/NUL/colon".to_owned(),
        ));
    }
    Ok(())
}

fn validate_header_value(name: &str, value: &str) -> Result<(), NetworkError> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(NetworkError::InvalidConfiguration(format!(
            "header value for {name} contains CR/LF/NUL"
        )));
    }
    Ok(())
}

fn header_value_to_string(value: &reqwest::header::HeaderValue) -> String {
    // Non-ASCII header values are lossy-stringified; the raw bytes are
    // preserved via `to_str()` when possible. This matches what
    // mainstream clients expose to application code.
    value
        .to_str()
        .map(str::to_owned)
        .unwrap_or_else(|_| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn reqwest_err_to_network(err: reqwest::Error) -> NetworkError {
    // SECURITY: the `Display` on reqwest::Error can leak DNS names and
    // socket-level detail. Collapse to a single scrubbed string.
    let _ = err;
    NetworkError::Connection("reqwest transport failure".to_owned())
}

/// Build a cryptographically-unique SOCKS5 username for Tor stream
/// isolation.
///
/// Tor's stream-isolation path keys on the (username, password) pair:
/// two streams with different usernames land on independent circuits.
/// We generate 16 random bytes, hex-encode them, and use that as the
/// username. The password is an unused static value — the isolation
/// effect comes from the username alone per Tor's SocksPort
/// `IsolateSOCKSAuth` behaviour.
fn socks5_isolation_username() -> Result<String, NetworkError> {
    let bytes = secure_random(16).map_err(|_| {
        NetworkError::Connection("secure_random failed".to_owned())
    })?;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::networking::OhttpResponse;

    // ----- config-validation tests ----------------------------------

    fn base_config(tier: PrivacyTier) -> PrivacyClientConfig {
        PrivacyClientConfig {
            tier,
            user_agent:
                "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
                    .to_owned(),
            request_timeout: Duration::from_secs(30),
            response_size_cap: 1024 * 1024,
            ohttp: None,
            tor_socks_addr: None,
            pinner: None,
        }
    }

    #[test]
    fn rejects_zero_response_cap() {
        let mut cfg = base_config(PrivacyTier::Standard);
        cfg.response_size_cap = 0;
        let err = PrivacyClient::new(cfg).unwrap_err();
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[test]
    fn rejects_crlf_in_user_agent() {
        let mut cfg = base_config(PrivacyTier::Standard);
        cfg.user_agent = "bad\r\nInjected: header".to_owned();
        let err = PrivacyClient::new(cfg).unwrap_err();
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[test]
    fn enhanced_tier_requires_ohttp_config() {
        let cfg = base_config(PrivacyTier::Enhanced);
        let err = PrivacyClient::new(cfg).unwrap_err();
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[test]
    fn enhanced_tier_accepts_valid_ohttp_config() {
        let (_, pk) = crate::networking::ohttp::test_support::gateway_keypair();
        let mut cfg = base_config(PrivacyTier::Enhanced);
        cfg.ohttp = Some(OhttpConfig {
            relay_url: "https://relay.test/ohttp".into(),
            gateway_url: "https://gw.test/ohttp".into(),
            gateway_public_key_b64: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(pk.as_bytes())
            },
        });
        let client = PrivacyClient::new(cfg).expect("should build");
        assert_eq!(client.tier(), PrivacyTier::Enhanced);
    }

    #[test]
    fn maximum_tier_does_not_probe_tor_on_new() {
        let mut cfg = base_config(PrivacyTier::Maximum);
        // Port 1 will almost certainly be closed — but the constructor
        // should NOT probe it. Deferred-probe semantics are explicit
        // in the docs.
        cfg.tor_socks_addr = Some("127.0.0.1:1".to_owned());
        let client = PrivacyClient::new(cfg).expect("should not probe Tor");
        assert_eq!(client.tier(), PrivacyTier::Maximum);
    }

    #[test]
    fn standard_tier_builds_client() {
        let cfg = base_config(PrivacyTier::Standard);
        let client = PrivacyClient::new(cfg).expect("should build");
        assert_eq!(client.tier(), PrivacyTier::Standard);
    }

    // ----- header / method unit tests -------------------------------

    #[test]
    fn header_name_rejects_crlf() {
        assert!(validate_header_name("accept").is_ok());
        assert!(validate_header_name("bad\rname").is_err());
        assert!(validate_header_name("bad\nname").is_err());
        assert!(validate_header_name("bad\0name").is_err());
        assert!(validate_header_name("bad:name").is_err());
        assert!(validate_header_name("").is_err());
    }

    #[test]
    fn header_value_rejects_crlf() {
        assert!(validate_header_value("n", "safe value").is_ok());
        assert!(validate_header_value("n", "bad\rvalue").is_err());
        assert!(validate_header_value("n", "bad\nvalue").is_err());
        assert!(validate_header_value("n", "bad\0value").is_err());
    }

    #[test]
    fn normalize_method_accepts_narrow_set() {
        assert_eq!(normalize_method("GET").unwrap(), reqwest::Method::GET);
        assert_eq!(normalize_method("get").unwrap(), reqwest::Method::GET);
        assert_eq!(normalize_method("HEAD").unwrap(), reqwest::Method::HEAD);
        assert_eq!(normalize_method("POST").unwrap(), reqwest::Method::POST);
        assert!(normalize_method("PUT").is_err());
        assert!(normalize_method("DELETE").is_err());
        assert!(normalize_method("").is_err());
    }

    #[test]
    fn socks_username_is_unique_and_hex() {
        let a = socks5_isolation_username().unwrap();
        let b = socks5_isolation_username().unwrap();
        assert_ne!(a, b, "isolation usernames must be unique");
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ----- Enhanced-tier end-to-end via in-memory OHTTP -------------

    /// Test-only PrivacyClient builder that swaps the reqwest-backed
    /// OhttpTransport for an in-memory mock, so the Enhanced-tier flow
    /// is exercised without touching the network.
    fn build_enhanced_client_with_transport(
        transport: Arc<dyn OhttpTransport>,
        ohttp_cfg: OhttpConfig,
        cap: u64,
    ) -> PrivacyClient {
        let ohttp = OhttpClient::new(ohttp_cfg, transport)
            .expect("OHTTP client")
            .with_response_cap(usize::try_from(cap).unwrap_or(usize::MAX));
        PrivacyClient {
            tier: PrivacyTier::Enhanced,
            user_agent: "test".to_owned(),
            request_timeout: Duration::from_secs(30),
            response_size_cap: cap,
            standard: None,
            ohttp: Some(Arc::new(ohttp)),
            tor_socks_addr: None,
            pinner: None,
        }
    }

    #[tokio::test]
    async fn enhanced_tier_round_trip_through_mock_gateway() {
        let (sk, pk) = crate::networking::ohttp::test_support::gateway_keypair();
        let responder = |req: OhttpRequest| {
            assert_eq!(req.method, "GET");
            assert_eq!(req.url, "https://upstream.test/echo");
            OhttpResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: b"hello via ohttp".to_vec(),
            }
        };
        let transport = MockTransport::new(sk, responder);
        let cfg = config_for_pk(&pk);
        let client =
            build_enhanced_client_with_transport(transport, cfg, 1024 * 1024);

        let resp = client
            .fetch(
                "GET",
                "https://upstream.test/echo",
                &[("accept".into(), "*/*".into())],
                b"",
            )
            .await
            .expect("fetch should succeed");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello via ohttp");
    }

    #[tokio::test]
    async fn fetch_rejects_http_scheme() {
        let cfg = base_config(PrivacyTier::Standard);
        let client = PrivacyClient::new(cfg).unwrap();
        let err = client
            .fetch("GET", "http://insecure.test/", &[], b"")
            .await
            .unwrap_err();
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[tokio::test]
    async fn fetch_rejects_unsupported_method() {
        let cfg = base_config(PrivacyTier::Standard);
        let client = PrivacyClient::new(cfg).unwrap();
        let err = client
            .fetch("DELETE", "https://upstream.test/", &[], b"")
            .await
            .unwrap_err();
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[tokio::test]
    async fn fetch_rejects_crlf_header_at_send_time() {
        let cfg = base_config(PrivacyTier::Standard);
        let client = PrivacyClient::new(cfg).unwrap();
        let err = client
            .fetch(
                "GET",
                "https://upstream.test/",
                &[("bad".into(), "line\r\ninjection".into())],
                b"",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[tokio::test]
    async fn enhanced_tier_enforces_response_cap() {
        // Responder returns a body larger than the 64-byte cap.
        let (sk, pk) = crate::networking::ohttp::test_support::gateway_keypair();
        let responder = |_req: OhttpRequest| OhttpResponse {
            status: 200,
            headers: vec![],
            body: vec![0u8; 2048],
        };
        let transport = MockTransport::new(sk, responder);
        let cfg = config_for_pk(&pk);
        let client =
            build_enhanced_client_with_transport(transport, cfg, 64);

        let err = client
            .fetch("GET", "https://upstream.test/x", &[], b"")
            .await
            .unwrap_err();
        // The cap is checked both at OHTTP-capsule level and at
        // PrivacyClient level; either error is acceptable here.
        assert!(matches!(err, NetworkError::ResponseTooLarge { .. }));
    }

    #[tokio::test]
    async fn enhanced_tier_returns_3xx_verbatim_without_following_redirect() {
        // Gateway responds with a 302 + Location. PrivacyClient MUST
        // return the 3xx to the caller, not follow it.
        let (sk, pk) = crate::networking::ohttp::test_support::gateway_keypair();
        let responder = |_req: OhttpRequest| OhttpResponse {
            status: 302,
            headers: vec![
                ("location".into(), "https://elsewhere.test/".into()),
            ],
            body: b"".to_vec(),
        };
        let transport = MockTransport::new(sk, responder);
        let cfg = config_for_pk(&pk);
        let client =
            build_enhanced_client_with_transport(transport, cfg, 1_000_000);

        let resp = client
            .fetch("GET", "https://upstream.test/redirect", &[], b"")
            .await
            .expect("302 is a successful HTTP result");
        assert_eq!(resp.status, 302);
        assert!(resp
            .headers
            .iter()
            .any(|(n, v)| n == "location" && v == "https://elsewhere.test/"));
    }

    #[tokio::test]
    async fn fetch_with_decoys_fires_k_requests_and_returns_real() {
        let (sk, pk) = crate::networking::ohttp::test_support::gateway_keypair();
        let call_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = call_log.clone();
        let responder = move |req: OhttpRequest| {
            if let Ok(mut guard) = log_clone.lock() {
                guard.push(req.url.clone());
            }
            let body = if req.url.ends_with("/real") {
                b"real-body".to_vec()
            } else {
                b"decoy-body".to_vec()
            };
            OhttpResponse {
                status: 200,
                headers: vec![],
                body,
            }
        };
        let transport = MockTransport::new(sk, responder);
        let cfg = config_for_pk(&pk);
        let client = build_enhanced_client_with_transport(
            transport,
            cfg,
            1_000_000,
        );

        let real = FetchSpec {
            method: "GET".into(),
            url: "https://upstream.test/real".into(),
            headers: vec![],
            body: vec![],
        };
        let decoys = vec![
            FetchSpec {
                method: "GET".into(),
                url: "https://upstream.test/decoy1".into(),
                headers: vec![],
                body: vec![],
            },
            FetchSpec {
                method: "GET".into(),
                url: "https://upstream.test/decoy2".into(),
                headers: vec![],
                body: vec![],
            },
        ];
        let resp = client
            .fetch_with_decoys(&real, &decoys, 3)
            .await
            .expect("fetch_with_decoys");
        assert_eq!(resp.body, b"real-body");

        let urls = {
            let guard = call_log.lock().expect("log lock");
            guard.clone()
        };
        assert_eq!(urls.len(), 3, "k=3 requests must all fire");
        assert!(urls.iter().any(|u| u.ends_with("/real")));
        assert!(urls.iter().any(|u| u.ends_with("/decoy1")));
        assert!(urls.iter().any(|u| u.ends_with("/decoy2")));
    }

    #[tokio::test]
    async fn fetch_with_decoys_rejects_insufficient_decoys() {
        let cfg = base_config(PrivacyTier::Standard);
        let client = PrivacyClient::new(cfg).unwrap();
        let real = FetchSpec {
            method: "GET".into(),
            url: "https://upstream.test/real".into(),
            headers: vec![],
            body: vec![],
        };
        let err = client.fetch_with_decoys(&real, &[], 3).await.unwrap_err();
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[tokio::test]
    async fn fetch_with_decoys_rejects_k_zero() {
        let cfg = base_config(PrivacyTier::Standard);
        let client = PrivacyClient::new(cfg).unwrap();
        let real = FetchSpec {
            method: "GET".into(),
            url: "https://upstream.test/real".into(),
            headers: vec![],
            body: vec![],
        };
        let err = client.fetch_with_decoys(&real, &[], 0).await.unwrap_err();
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[tokio::test]
    #[ignore = "requires running Tor daemon on 127.0.0.1:9050"]
    async fn maximum_tier_live_fetch() {
        let cfg = base_config(PrivacyTier::Maximum);
        let client = PrivacyClient::new(cfg).unwrap();
        let resp = client
            .fetch("GET", "https://check.torproject.org/api/ip", &[], b"")
            .await
            .expect("Tor fetch");
        assert_eq!(resp.status, 200);
    }

    // ----- OHTTP mock transport -------------------------------------

    struct MockTransport {
        gateway_sk: [u8; 32],
        responder: Mutex<Option<Box<dyn FnMut(OhttpRequest) -> OhttpResponse + Send>>>,
    }

    impl std::fmt::Debug for MockTransport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockTransport").finish()
        }
    }

    impl MockTransport {
        fn new(
            gateway_sk: [u8; 32],
            responder: impl FnMut(OhttpRequest) -> OhttpResponse + Send + 'static,
        ) -> Arc<dyn OhttpTransport> {
            Arc::new(Self {
                gateway_sk,
                responder: Mutex::new(Some(Box::new(responder))),
            })
        }
    }

    #[async_trait]
    impl OhttpTransport for MockTransport {
        async fn post_capsule(
            &self,
            _url: &str,
            body: Vec<u8>,
        ) -> Result<Vec<u8>, NetworkError> {
            let sk = self.gateway_sk;
            let mut lock = self
                .responder
                .lock()
                .map_err(|_| NetworkError::Connection("lock".into()))?;
            let responder = lock.as_mut().ok_or_else(|| {
                NetworkError::Connection("no responder".into())
            })?;
            crate::networking::ohttp::test_support::in_memory_gateway_roundtrip(
                &sk,
                &body,
                &mut **responder,
            )
        }
    }

    fn config_for_pk(pk: &x25519_dalek::PublicKey) -> OhttpConfig {
        use base64::Engine;
        OhttpConfig {
            relay_url: "https://relay.test/ohttp".into(),
            gateway_url: "https://gateway.test/ohttp".into(),
            gateway_public_key_b64: base64::engine::general_purpose::STANDARD
                .encode(pk.as_bytes()),
        }
    }
}
