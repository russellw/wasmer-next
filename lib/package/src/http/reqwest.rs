use std::time::Duration;

use anyhow::Context;
use futures::{TryStreamExt, future::BoxFuture};
use std::convert::TryFrom;
use tokio::runtime::Handle;

use super::{HttpBodyEvent, HttpBodyObserver, HttpDownloadObserver, HttpRequest, HttpResponse};

#[derive(Clone, Debug)]
pub struct ReqwestHttpClient {
    handle: Handle,
    connect_timeout: Duration,
    response_body_chunk_timeout: Option<std::time::Duration>,
}

impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self {
            handle: Handle::current(),
            connect_timeout: Self::DEFAULT_CONNECT_TIMEOUT,
            response_body_chunk_timeout: None,
        }
    }
}

impl ReqwestHttpClient {
    const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_response_body_chunk_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.response_body_chunk_timeout = Some(timeout);
        self
    }

    #[tracing::instrument(target = "wasmer_wasix::http::reqwest", skip_all, fields(method=?request.method, url=%request.url))]
    async fn request(
        &self,
        request: HttpRequest,
        progress: Option<HttpBodyObserver>,
    ) -> Result<HttpResponse, anyhow::Error> {
        let method = reqwest::Method::try_from(request.method.as_str())
            .with_context(|| format!("Invalid http method {}", request.method))?;

        // TODO: use persistent client?
        let builder = {
            let _guard = Handle::try_current().map_err(|_| self.handle.enter());
            let mut builder = reqwest::ClientBuilder::new();
            #[cfg(not(feature = "http-client-js"))]
            {
                builder = builder.connect_timeout(self.connect_timeout);
            }
            builder
        };
        let client = builder.build().context("failed to create reqwest client")?;

        tracing::event!(target: "wasmer_wasix::http::reqwest", tracing::Level::DEBUG, "sending http request");
        let mut builder = client.request(method, request.url.as_str());
        for (header, val) in &request.headers {
            builder = builder.header(header, val);
        }

        if let Some(body) = request.body {
            builder = builder.body(reqwest::Body::from(body));
        }

        let request = builder
            .build()
            .context("Failed to construct http request")?;

        let mut response = client.execute(request).await?;
        let headers = std::mem::take(response.headers_mut());

        let status = response.status();

        if let Some(progress) = &progress {
            progress(HttpBodyEvent::Head {
                status,
                headers: &headers,
                cached: false,
            });
        }

        tracing::event!(target: "wasmer_wasix::http::reqwest", tracing::Level::DEBUG, status=?status, "received http response");

        // Download the body.
        #[cfg(not(feature = "http-client-js"))]
        let data = if let Some(timeout_duration) = self.response_body_chunk_timeout {
            // Download the body with a chunk timeout.
            // The timeout prevents long stalls.

            let mut stream = response.bytes_stream();
            let mut buf = Vec::new();

            // Creating tokio timeouts has overhead, so instead of a fresh
            // timeout per chunk a shared timeout is used, and a chunk counter
            // is kept. Only if no chunk was downloaded within the timeout a
            // timeout error is raised.
            'OUTER: loop {
                let timeout = tokio::time::sleep(timeout_duration);
                pin_utils::pin_mut!(timeout);

                let mut chunk_count = 0;

                loop {
                    tokio::select! {
                        // Biased because the timeout is secondary,
                        // and chunks should always have priority.
                        biased;

                        res = stream.try_next() => {
                            match res {
                                Ok(Some(chunk)) => {
                                    buf.extend_from_slice(&chunk);
                                    if let Some(progress) = &progress {
                                        progress(HttpBodyEvent::Chunk(&chunk));
                                    }
                                    chunk_count += 1;
                                }
                                Ok(None) => {
                                    break 'OUTER;
                                }
                                Err(e) => {
                                    return Err(e.into());
                                }
                            }
                        }

                        _ = &mut timeout => {
                            if chunk_count == 0 {
                                tracing::event!(target: "wasmer_wasix::http::reqwest", tracing::Level::WARN, timeout= "timeout while downloading response body");
                                return Err(anyhow::anyhow!("Timeout while downloading response body"));
                            } else {
                                tracing::event!(target: "wasmer_wasix::http::reqwest", tracing::Level::DEBUG, downloaded_body_size_bytes=%buf.len(), "download progress");
                                // Timeout, but chunks were downloaded, so
                                // just continue with a fresh timeout.
                                continue 'OUTER;
                            }
                        }
                    }
                }
            }

            buf
        } else if let Some(progress) = &progress {
            let mut stream = response.bytes_stream();
            let mut buf = Vec::new();
            while let Some(chunk) = stream.try_next().await? {
                buf.extend_from_slice(&chunk);
                progress(HttpBodyEvent::Chunk(&chunk));
            }
            buf
        } else {
            response.bytes().await?.to_vec()
        };
        #[cfg(feature = "http-client-js")]
        let data = {
            let data = response.bytes().await?.to_vec();
            if let Some(progress) = &progress {
                progress(HttpBodyEvent::Chunk(&data));
            }
            data
        };

        tracing::event!(target: "wasmer_wasix::http::reqwest", tracing::Level::DEBUG, body_size_bytes=%data.len(), "downloaded http response body");

        Ok(HttpResponse {
            status,
            redirected: false,
            body: Some(data),
            headers,
        })
    }
}

impl ReqwestHttpClient {
    fn request_observed(
        &self,
        request: HttpRequest,
        progress: HttpBodyObserver,
    ) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
        let client = self.clone();
        #[cfg(not(feature = "http-client-js"))]
        {
            Box::pin(async move { client.request(request, Some(progress)).await })
        }
        #[cfg(feature = "http-client-js")]
        {
            let (sender, receiver) = futures::channel::oneshot::channel();
            wasm_bindgen_futures::spawn_local(async move {
                let result = client.request(request, Some(progress)).await;
                let _ = sender.send(result);
            });
            Box::pin(async move { receiver.await.map_err(anyhow::Error::new)? })
        }
    }
}

impl super::HttpClient for ReqwestHttpClient {
    fn request_with_progress(
        &self,
        request: HttpRequest,
        progress: HttpDownloadObserver,
    ) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
        self.request_observed(request, super::download_observer(progress))
    }

    fn request_with_body_progress(
        &self,
        request: HttpRequest,
        progress: HttpBodyObserver,
    ) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
        self.request_observed(request, progress)
    }

    #[cfg(not(feature = "http-client-js"))]
    fn request(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
        let client = self.clone();
        let f = async move { client.request(request, None).await };
        Box::pin(f)
    }

    #[cfg(feature = "http-client-js")]
    fn request(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, anyhow::Error>> {
        let client = self.clone();
        let (sender, receiver) = futures::channel::oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let result = client.request(request, None).await;
            let _ = sender.send(result);
        });
        Box::pin(async move {
            match receiver.await {
                Ok(result) => result,
                Err(e) => Err(anyhow::Error::new(e)),
            }
        })
    }
}

#[cfg(all(test, not(feature = "http-client-js"), not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::http::HttpClient;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex, mpsc},
    };

    // Like the local socket fixtures in api/tests/vnet_reference_relay.rs, but
    // the server withholds its second body chunk until the observer saw the first.
    fn server() -> (url::Url, mpsc::SyncSender<()>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/package", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let (observed, receiver) = mpsc::sync_channel(1);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 65536);
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nfirst\r\n").unwrap();
            stream.flush().unwrap();
            receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("first chunk is observable before body completion");
            stream.write_all(b"6\r\nsecond\r\n0\r\n\r\n").unwrap();
        });
        (url, observed, server)
    }

    #[tokio::test]
    async fn native_body_and_tuple_observers_receive_real_chunks_with_and_without_timeouts() {
        for timed in [false, true] {
            for tuple in [false, true] {
                let (url, observed, server) = server();
                let mut client = ReqwestHttpClient::default();
                if timed {
                    client = client.with_response_body_chunk_timeout(Duration::from_secs(5));
                }
                let request = HttpRequest {
                    url,
                    method: http::Method::GET,
                    headers: http::HeaderMap::new(),
                    body: None,
                    options: Default::default(),
                };
                let chunks = Arc::new(Mutex::new(Vec::new()));
                let counts = Arc::new(Mutex::new(Vec::new()));
                let response = if tuple {
                    let counts = counts.clone();
                    client
                        .request_with_progress(
                            request,
                            Arc::new(move |received, total, cached| {
                                assert_eq!(total, None);
                                assert!(!cached);
                                counts.lock().unwrap().push(received);
                                if received > 0 {
                                    let _ = observed.try_send(());
                                }
                            }),
                        )
                        .await
                        .unwrap()
                } else {
                    let chunks = chunks.clone();
                    client
                        .request_with_body_progress(
                            request,
                            Arc::new(move |event| match event {
                                HttpBodyEvent::Head { status, cached, .. } => {
                                    assert_eq!(status, http::StatusCode::OK);
                                    assert!(!cached);
                                }
                                HttpBodyEvent::Chunk(chunk) => {
                                    chunks.lock().unwrap().push(chunk.to_vec());
                                    let _ = observed.try_send(());
                                }
                            }),
                        )
                        .await
                        .unwrap()
                };
                server.join().unwrap();
                assert_eq!(response.body.as_deref(), Some(b"firstsecond".as_slice()));
                if tuple {
                    let counts = counts.lock().unwrap();
                    assert_eq!(counts.first(), Some(&0));
                    assert_eq!(counts.last(), Some(&11));
                    assert!(counts.len() >= 3);
                    assert!(counts.windows(2).all(|pair| pair[0] < pair[1]));
                } else {
                    let chunks = chunks.lock().unwrap();
                    assert!(chunks.len() >= 2);
                    assert_eq!(chunks.concat(), b"firstsecond");
                }
            }
        }
    }
}
