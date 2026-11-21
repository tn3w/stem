use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::ClientConfig;

use crate::error::{Error, Result};

pub const USER_AGENT: &str = concat!("Stem/", env!("CARGO_PKG_VERSION"));
pub const MAX_DOWNLOAD_LENGTH: usize = 1 << 29;

pub type ReplyHeaders = HashMap<String, String>;

fn client() -> Result<&'static reqwest::Client> {
    static CLIENT: OnceLock<std::result::Result<reqwest::Client, String>> =
        OnceLock::new();
    let built = CLIENT.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| error.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|error| error.to_string())
    });
    built.as_ref().map_err(|message| {
        Error::Socket(format!("Unable to build an HTTP client: {message}"))
    })
}

async fn fetch_once(
    url: &str,
    request_headers: &[(&str, &str)],
    timeout: Option<Duration>,
) -> Result<(Vec<u8>, ReplyHeaders)> {
    let mut request = client()?.get(url);
    for (name, value) in request_headers {
        request = request.header(*name, *value);
    }
    if let Some(limit) = timeout {
        request = request.timeout(limit);
    }
    let failure = |error: reqwest::Error| match error.is_timeout() {
        true => Error::DownloadTimeout {
            url: url.to_string(),
            seconds: timeout.map_or(0.0, |limit| limit.as_secs_f64()),
        },
        false => Error::DownloadFailed {
            url: url.to_string(),
            message: error.to_string(),
        },
    };
    let mut response = request.send().await.map_err(failure)?;
    if !response.status().is_success() {
        return Err(Error::DownloadFailed {
            url: url.to_string(),
            message: format!("HTTP status {}", response.status()),
        });
    }
    if response.url().path().ends_with("/users/sign_in") {
        return Err(Error::DownloadFailed {
            url: url.to_string(),
            message: "the host redirected to a sign-in page and blocks anonymous \
                downloads"
                .to_string(),
        });
    }
    let headers: ReplyHeaders = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
        })
        .collect();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(failure)? {
        if body.len() + chunk.len() > MAX_DOWNLOAD_LENGTH {
            return Err(Error::DownloadFailed {
                url: url.to_string(),
                message: "response exceeded the size limit".to_string(),
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, headers))
}

pub async fn download(
    url: &str,
    timeout: Option<Duration>,
    retries: u32,
) -> Result<Vec<u8>> {
    download_with_headers(url, &[], timeout, retries)
        .await
        .map(|(body, _)| body)
}

pub async fn download_with_headers(
    url: &str,
    request_headers: &[(&str, &str)],
    timeout: Option<Duration>,
    retries: u32,
) -> Result<(Vec<u8>, ReplyHeaders)> {
    let mut remaining = retries;
    loop {
        match fetch_once(url, request_headers, timeout).await {
            Ok(result) => return Ok(result),
            Err(error) if remaining == 0 => return Err(error),
            Err(error) => {
                log::debug!(
                    "Failed to download from {url} ({remaining} retries remaining): \
                    {error}"
                );
                remaining -= 1;
            }
        }
    }
}
