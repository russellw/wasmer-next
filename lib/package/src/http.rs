//! HTTP request/response contracts for package acquisition and embedder providers.
#[cfg(feature = "http-client")]
pub mod reqwest;

use std::{collections::BTreeSet, ops::Deref, sync::Arc};

use futures::future::BoxFuture;
use http::{HeaderMap, Method, StatusCode};
use url::Url;

/// Defines http client permissions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpClientCapabilityV1 {
    pub allow_all: bool,
    pub allowed_hosts: BTreeSet<String>,
}

impl HttpClientCapabilityV1 {
    pub fn new() -> Self {
        Self {
            allow_all: false,
            allowed_hosts: Default::default(),
        }
    }

    pub fn new_allow_all() -> Self {
        Self {
            allow_all: true,
            allowed_hosts: Default::default(),
        }
    }

    pub fn is_deny_all(&self) -> bool {
        !self.allow_all && self.allowed_hosts.is_empty()
    }

    pub fn can_access_domain(&self, domain: &str) -> bool {
        self.allow_all || self.allowed_hosts.contains(domain)
    }

    pub fn update(&mut self, other: HttpClientCapabilityV1) {
        let HttpClientCapabilityV1 {
            allow_all,
            allowed_hosts,
        } = other;
        self.allow_all |= allow_all;
        self.allowed_hosts.extend(allowed_hosts);
    }
}

impl Default for HttpClientCapabilityV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct HttpRequestOptions {
    pub gzip: bool,
    pub cors_proxy: Option<String>,
}

// TODO: use types from http crate?
pub struct HttpRequest {
    pub url: Url,
    pub method: Method,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
    pub options: HttpRequestOptions,
}

impl HttpRequest {
    fn from_http_parts(parts: http::request::Parts, body: impl Into<Option<Vec<u8>>>) -> Self {
        let http::request::Parts {
            method,
            uri,
            headers,
            ..
        } = parts;

        HttpRequest {
            url: uri.to_string().parse().unwrap(),
            method,
            headers,
            body: body.into(),
            options: HttpRequestOptions::default(),
        }
    }
}

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let HttpRequest {
            url,
            method,
            headers,
            body,
            options,
        } = self;

        f.debug_struct("HttpRequest")
            .field("url", &format_args!("{url}"))
            .field("method", method)
            .field("headers", headers)
            .field("body", &body.as_deref().map(String::from_utf8_lossy))
            .field("options", &options)
            .finish()
    }
}

impl From<http::Request<Option<Vec<u8>>>> for HttpRequest {
    fn from(value: http::Request<Option<Vec<u8>>>) -> Self {
        let (parts, body) = value.into_parts();
        HttpRequest::from_http_parts(parts, body)
    }
}

impl From<http::Request<Vec<u8>>> for HttpRequest {
    fn from(value: http::Request<Vec<u8>>) -> Self {
        let (parts, body) = value.into_parts();
        HttpRequest::from_http_parts(parts, body)
    }
}

impl From<http::Request<&str>> for HttpRequest {
    fn from(value: http::Request<&str>) -> Self {
        value.map(|body| body.to_string()).into()
    }
}

impl From<http::Request<String>> for HttpRequest {
    fn from(value: http::Request<String>) -> Self {
        let (parts, body) = value.into_parts();
        HttpRequest::from_http_parts(parts, body.into_bytes())
    }
}

impl From<http::Request<()>> for HttpRequest {
    fn from(value: http::Request<()>) -> Self {
        let (parts, _) = value.into_parts();
        HttpRequest::from_http_parts(parts, None)
    }
}

// TODO: use types from http crate?
pub struct HttpResponse {
    pub body: Option<Vec<u8>>,
    pub redirected: bool,
    pub status: StatusCode,
    pub headers: HeaderMap,
}

impl HttpResponse {
    pub fn is_ok(&self) -> bool {
        !self.status.is_client_error() && !self.status.is_server_error()
    }
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let HttpResponse {
            body,
            redirected,
            status,
            headers,
        } = self;

        f.debug_struct("HttpResponse")
            .field("ok", &self.is_ok())
            .field("redirected", &redirected)
            .field("status", &status)
            .field("headers", &headers)
            .field("body", &body.as_deref().map(String::from_utf8_lossy))
            .finish()
    }
}

/// Bytes retained in the HTTP response body, before package/container decoding.
/// Buffered clients may report only completion. `cached` is provider-supplied.
pub type HttpDownloadObserver = Arc<dyn Fn(u64, Option<u64>, bool) + Send + Sync>;

/// Borrowed, synchronous observations of a response. The observer must not retain
/// the chunk or header borrow. A successful request emits exactly one `Head` before
/// its ordered `Chunk` events; each returned body byte appears exactly once, and
/// concatenating the chunks gives `HttpResponse::body`. A failed request may end
/// after a partial sequence. Reporting the entire buffered body once at completion
/// is valid; providers must not synthesize chunks from byte-count estimates.
#[derive(Debug)]
pub enum HttpBodyEvent<'a> {
    Head {
        status: StatusCode,
        headers: &'a HeaderMap,
        cached: bool,
    },
    Chunk(&'a [u8]),
}

pub type HttpBodyObserver = Arc<dyn for<'a> Fn(HttpBodyEvent<'a>) + Send + Sync>;

pub(crate) fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Adapt actual body events to the tuple observer without interpreting package bytes.
#[cfg(feature = "http-client")]
pub(crate) fn download_observer(observer: HttpDownloadObserver) -> HttpBodyObserver {
    let state = std::sync::Mutex::new((0u64, None, false));
    Arc::new(move |event| {
        let snapshot = {
            let mut state = state.lock().unwrap();
            match event {
                HttpBodyEvent::Head {
                    headers, cached, ..
                } => {
                    *state = (0, content_length(headers), cached);
                }
                HttpBodyEvent::Chunk(chunk) => {
                    state.0 = state.0.saturating_add(chunk.len() as u64);
                    state.1 = state.1.filter(|total| *total >= state.0);
                }
            }
            *state
        };
        observer(snapshot.0, snapshot.1, snapshot.2);
    })
}

pub trait HttpClient: std::fmt::Debug {
    // TODO: use custom error type!
    fn request(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>>;

    /// Compatibility hook: existing clients report the buffered body at completion.
    fn request_with_progress(
        &self,
        request: HttpRequest,
        progress: HttpDownloadObserver,
    ) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
        let response = self.request(request);
        Box::pin(async move {
            let response = response.await?;
            let received = response.body.as_ref().map_or(0, |body| body.len() as u64);
            progress(
                received,
                content_length(&response.headers).filter(|total| *total >= received),
                false,
            );
            Ok(response)
        })
    }

    /// Observe response metadata and actual body chunks. The default preserves a
    /// client's tuple-hook override, then reports the returned body once, at completion.
    fn request_with_body_progress(
        &self,
        request: HttpRequest,
        progress: HttpBodyObserver,
    ) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
        let cached = Arc::new(std::sync::Mutex::new(false));
        let observed_cached = cached.clone();
        // Tuple byte counts may use different units. Only retain the provider's
        // latest cache flag; body observations come from the returned response.
        let response = self.request_with_progress(
            request,
            Arc::new(move |_, _, cached| *observed_cached.lock().unwrap() = cached),
        );
        Box::pin(async move {
            let response = response.await?;
            let cached = *cached.lock().unwrap();
            progress(HttpBodyEvent::Head {
                status: response.status,
                headers: &response.headers,
                cached,
            });
            if let Some(body) = &response.body {
                progress(HttpBodyEvent::Chunk(body));
            }
            Ok(response)
        })
    }
}

impl<D, C> HttpClient for D
where
    D: Deref<Target = C> + std::fmt::Debug,
    C: HttpClient + ?Sized + 'static,
{
    fn request(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
        let client = &**self;
        client.request(request)
    }

    fn request_with_progress(
        &self,
        request: HttpRequest,
        progress: HttpDownloadObserver,
    ) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
        (**self).request_with_progress(request, progress)
    }

    fn request_with_body_progress(
        &self,
        request: HttpRequest,
        progress: HttpBodyObserver,
    ) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
        (**self).request_with_body_progress(request, progress)
    }
}

pub type DynHttpClient = Arc<dyn HttpClient + Send + Sync + 'static>;

// Keep registry and download request identity stable while acquisition moves crates.
pub(crate) const USER_AGENT: &str = concat!("wasmer-wasix-", env!("CARGO_PKG_VERSION"));

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug, Default)]
    struct TupleClient(AtomicUsize, bool);

    impl HttpClient for TupleClient {
        fn request(&self, _: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
            panic!("the compatibility adapter must preserve the tuple override")
        }

        fn request_with_progress(
            &self,
            _: HttpRequest,
            progress: HttpDownloadObserver,
        ) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                progress(1000, None, !self.1);
                progress(1, None, self.1);
                Ok(HttpResponse {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: Some(b"actual buffered body".to_vec()),
                    redirected: false,
                })
            })
        }
    }

    #[tokio::test]
    async fn body_default_keeps_latest_cache_flag_through_deref_and_only_returned_bytes() {
        for cached in [false, true] {
            let client = Arc::new(TupleClient(AtomicUsize::new(0), cached));
            let wrapped: Arc<Box<dyn HttpClient + Send + Sync>> =
                Arc::new(Box::new(client.clone()));
            let chunks = Arc::new(Mutex::new(Vec::new()));
            let captured = chunks.clone();
            let response = wrapped
                .request_with_body_progress(
                    http::Request::get("https://example.test/package")
                        .body(())
                        .unwrap()
                        .into(),
                    Arc::new(move |event| match event {
                        HttpBodyEvent::Head {
                            status,
                            cached: observed,
                            ..
                        } => {
                            assert_eq!(status, StatusCode::OK);
                            assert_eq!(observed, cached);
                        }
                        HttpBodyEvent::Chunk(chunk) => {
                            captured.lock().unwrap().push(chunk.to_vec())
                        }
                    }),
                )
                .await
                .unwrap();
            assert_eq!(client.0.load(Ordering::SeqCst), 1);
            assert_eq!(chunks.lock().unwrap().as_slice(), [response.body.unwrap()]);
        }
    }
}
