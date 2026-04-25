use std::io;
use std::sync::mpsc;
use std::sync::Arc;

use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::config::{RequestChecksumCalculation, ResponseChecksumValidation};
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::{config::Builder as S3ConfigBuilder, Client};
use once_cell::sync::Lazy;
use tokio::runtime::Handle;

use crate::config::S3Config;
use crate::storage::{StorageBackend, StorageError, StorageResult};

/// Dedicated tokio runtime for S3 operations.
///
/// The `StorageBackend` trait is synchronous but aws-sdk-s3 is async. Tokio
/// forbids calling `block_on` from inside another runtime, so we cannot
/// simply drive the AWS futures on walletrs's outer `#[tokio::main]`
/// runtime: the first attempt panics with "Cannot start a runtime from
/// within a runtime".
///
/// Instead we spawn a dedicated OS thread that owns a multi-thread runtime,
/// keep it alive for the process lifetime, and submit futures to it via
/// `Handle::spawn`. The sync caller blocks on a `std::sync::mpsc` channel to
/// wait for the result. This works from any context — async worker thread,
/// blocking task, or plain sync — because the S3 runtime's worker threads
/// are entirely separate from whatever runtime the caller lives in.
static S3_HANDLE: Lazy<Handle> = Lazy::new(|| {
    let (tx, rx) = mpsc::channel::<Handle>();
    std::thread::Builder::new()
        .name("walletrs-s3".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("walletrs-s3-worker")
                .build()
                .expect("build S3 runtime");
            tx.send(rt.handle().clone()).expect("send handle");
            // Park this thread on the runtime for the rest of the process
            // lifetime so spawned tasks have something to drive them.
            rt.block_on(std::future::pending::<()>());
        })
        .expect("spawn walletrs-s3 thread");
    rx.recv().expect("receive S3 runtime handle")
});

fn run_on_s3<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel::<T>(1);
    S3_HANDLE.spawn(async move {
        let _ = tx.send(fut.await);
    });
    rx.recv().expect("S3 task was dropped")
}

#[derive(Clone)]
pub struct S3Backend {
    inner: Arc<S3Inner>,
}

struct S3Inner {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3Backend {
    pub fn from_config(cfg: &S3Config) -> StorageResult<Self> {
        let client = run_on_s3(build_client(cfg.clone()));
        Ok(Self {
            inner: Arc::new(S3Inner {
                client,
                bucket: cfg.bucket.clone(),
                prefix: normalize_prefix(&cfg.prefix),
            }),
        })
    }

    fn key(&self, path: &str) -> String {
        // Normalize away leading slashes and any "./" segments. walletrs's
        // path strategy sometimes yields "./global/..." which, combined with
        // path-style S3 URIs, produces "/bucket/./global/...". aws-sdk-s3
        // signs the canonical URI with normalization disabled, but R2
        // canonicalizes server-side ("/./" → "/"), so signatures mismatch
        // and every mutating call returns SignatureDoesNotMatch. Strip the
        // dot segments before we hand the key to the SDK.
        let mut trimmed = path.trim_start_matches('/');
        while let Some(rest) = trimmed.strip_prefix("./") {
            trimmed = rest;
        }
        let trimmed = trimmed.trim_start_matches('/');
        if self.inner.prefix.is_empty() {
            trimmed.to_string()
        } else {
            format!("{}/{}", self.inner.prefix, trimmed)
        }
    }
}

impl StorageBackend for S3Backend {
    fn read_bytes(&self, path: &str) -> StorageResult<Vec<u8>> {
        let client = self.inner.client.clone();
        let bucket = self.inner.bucket.clone();
        let key = self.key(path);
        run_on_s3(async move {
            let resp = client.get_object().bucket(bucket).key(&key).send().await;
            match resp {
                Ok(out) => {
                    let data = out
                        .body
                        .collect()
                        .await
                        .map_err(|e| StorageError::Io(io::Error::new(io::ErrorKind::Other, e)))?;
                    Ok(data.into_bytes().to_vec())
                }
                Err(e) => Err(map_sdk_err(e, "get_object")),
            }
        })
    }

    fn write_bytes(&self, path: &str, data: &[u8]) -> StorageResult<()> {
        let client = self.inner.client.clone();
        let bucket = self.inner.bucket.clone();
        let key = self.key(path);
        let body = data.to_vec();
        run_on_s3(async move {
            client
                .put_object()
                .bucket(bucket)
                .key(&key)
                .body(body.into())
                .send()
                .await
                .map_err(|e| map_sdk_err(e, "put_object"))?;
            Ok(())
        })
    }

    fn delete_file(&self, path: &str) -> StorageResult<bool> {
        let client = self.inner.client.clone();
        let bucket = self.inner.bucket.clone();
        let key = self.key(path);
        run_on_s3(async move {
            let head = client
                .head_object()
                .bucket(&bucket)
                .key(&key)
                .send()
                .await;
            match head {
                Ok(_) => {
                    client
                        .delete_object()
                        .bucket(&bucket)
                        .key(&key)
                        .send()
                        .await
                        .map_err(|e| map_sdk_err(e, "delete_object"))?;
                    Ok(true)
                }
                Err(SdkError::ServiceError(svc))
                    if matches!(svc.err(), HeadObjectError::NotFound(_)) =>
                {
                    Ok(false)
                }
                Err(e) => Err(map_sdk_err(e, "head_object")),
            }
        })
    }

    fn list_files(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let client = self.inner.client.clone();
        let bucket = self.inner.bucket.clone();
        let key_prefix = self.key(prefix);
        let strip_len = if self.inner.prefix.is_empty() {
            0
        } else {
            self.inner.prefix.len() + 1
        };
        run_on_s3(async move {
            let mut keys = Vec::new();
            let mut continuation: Option<String> = None;
            loop {
                let mut req = client
                    .list_objects_v2()
                    .bucket(&bucket)
                    .prefix(&key_prefix);
                if let Some(token) = continuation.clone() {
                    req = req.continuation_token(token);
                }
                let out = req
                    .send()
                    .await
                    .map_err(|e| map_sdk_err(e, "list_objects_v2"))?;
                for obj in out.contents() {
                    if let Some(k) = obj.key() {
                        let logical = if strip_len > 0 && k.len() >= strip_len {
                            &k[strip_len..]
                        } else {
                            k
                        };
                        keys.push(logical.to_string());
                    }
                }
                if out.is_truncated().unwrap_or(false) {
                    continuation = out.next_continuation_token().map(|s| s.to_string());
                    if continuation.is_none() {
                        break;
                    }
                } else {
                    break;
                }
            }
            Ok(keys)
        })
    }

    fn file_exists(&self, path: &str) -> StorageResult<bool> {
        let client = self.inner.client.clone();
        let bucket = self.inner.bucket.clone();
        let key = self.key(path);
        run_on_s3(async move {
            let resp = client.head_object().bucket(bucket).key(&key).send().await;
            match resp {
                Ok(_) => Ok(true),
                Err(SdkError::ServiceError(svc))
                    if matches!(svc.err(), HeadObjectError::NotFound(_)) =>
                {
                    Ok(false)
                }
                Err(e) => Err(map_sdk_err(e, "head_object")),
            }
        })
    }

    fn create_directory(&self, _path: &str) -> StorageResult<()> {
        Ok(())
    }
}

fn normalize_prefix(prefix: &str) -> String {
    prefix.trim_matches('/').to_string()
}

async fn build_client(cfg: S3Config) -> Client {
    let region = Region::new(cfg.region.clone());

    // Pin to a BehaviorVersion from before aws-sdk-s3 started auto-adding
    // CRC32 checksum headers by default. Those headers change the SigV4
    // canonical request in a way Cloudflare R2 rejects, producing
    // SignatureDoesNotMatch on every mutating call. The newer
    // request_checksum_calculation(WhenRequired) knob is supposed to opt
    // out, but as of aws-sdk-s3 1.103 it doesn't fully suppress the
    // header in all code paths — pinning the behavior version is the
    // reliable workaround.
    let loader = aws_config::defaults(BehaviorVersion::v2024_03_28()).region(region);
    let loader = match (&cfg.access_key_id, &cfg.secret_access_key) {
        (Some(id), Some(secret)) => loader.credentials_provider(Credentials::new(
            id.clone(),
            secret.clone(),
            None,
            None,
            "walletrs-static",
        )),
        _ => loader,
    };

    let shared = loader.load().await;

    // aws-sdk-s3 started adding CRC32 checksums by default in 2025, but
    // Cloudflare R2 signs the request differently when those headers are
    // present — the mismatch surfaces as SignatureDoesNotMatch on every
    // PUT. Forcing checksum-when-required drops the extra headers and R2
    // accepts the request. Harmless against real S3.
    let mut builder = S3ConfigBuilder::from(&shared)
        .force_path_style(cfg.force_path_style)
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .response_checksum_validation(ResponseChecksumValidation::WhenRequired);
    if let Some(ep) = &cfg.endpoint {
        builder = builder.endpoint_url(ep);
    }

    Client::from_conf(builder.build())
}

fn map_sdk_err<E, R>(err: SdkError<E, R>, op: &'static str) -> StorageError
where
    E: std::fmt::Debug + std::fmt::Display + std::error::Error + Send + Sync + 'static,
    R: std::fmt::Debug + Send + Sync + 'static,
{
    // SdkError's Display impl is generic ("service error", "dispatch failure"
    // etc.) — useless for diagnostics. Walk the source chain to get the real
    // reason (HTTP status, AWS error code, IO error, …) and stash it.
    let mut detail = format!("{}", err);
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(&err);
    while let Some(s) = src {
        detail.push_str(" -> ");
        detail.push_str(&s.to_string());
        src = s.source();
    }

    if let SdkError::ServiceError(ref svc) = err {
        let svc_msg = format!("{}", svc.err());
        if svc_msg.contains("NoSuchKey") || svc_msg.contains("NotFound") {
            return StorageError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("s3 {}: {} ({})", op, svc_msg, detail),
            ));
        }
    }

    StorageError::Io(io::Error::new(
        io::ErrorKind::Other,
        format!("s3 {}: {}", op, detail),
    ))
}
