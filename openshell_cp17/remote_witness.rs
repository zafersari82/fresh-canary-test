// SPDX-License-Identifier: Apache-2.0
// BLACKBOX ACV CP17: authenticated remote high-water witness client.

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use uuid::Uuid;

pub const REMOTE_WITNESS_ADDR_ENV: &str = "OPENSHELL_BLACKBOX_REMOTE_WITNESS_ADDR";
pub const REMOTE_WITNESS_PUBLIC_KEY_ENV: &str =
    "OPENSHELL_BLACKBOX_REMOTE_WITNESS_PUBLIC_KEY_HEX";
pub const REMOTE_WITNESS_TIMEOUT_MS_ENV: &str =
    "OPENSHELL_BLACKBOX_REMOTE_WITNESS_TIMEOUT_MS";

const RECEIPT_SCHEMA: &str = "blackbox.remote-witness.receipt.v1";
const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RemoteWitnessState {
    pub(crate) sequence: u64,
    pub(crate) head_record_sha256: String,
}

impl RemoteWitnessState {
    pub(crate) fn genesis() -> Self {
        Self {
            sequence: 0,
            head_record_sha256: GENESIS_HASH.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RemoteWitnessClient {
    address: String,
    public_key: Vec<u8>,
    timeout: Duration,
    namespace: String,
}

#[derive(Serialize)]
struct WitnessRequest<'a> {
    op: &'static str,
    namespace: &'a str,
    nonce: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_head_record_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    head_record_sha256: Option<&'a str>,
}

#[derive(Deserialize)]
struct WitnessResponse {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    receipt: Option<SignedWitnessReceipt>,
}

#[derive(Clone, Debug, Deserialize)]
struct SignedWitnessReceipt {
    schema: String,
    namespace: String,
    sequence: u64,
    head_record_sha256: String,
    nonce: String,
    signature_hex: String,
}

impl RemoteWitnessClient {
    pub(crate) fn from_env(namespace: &str) -> io::Result<Option<Self>> {
        let address = std::env::var(REMOTE_WITNESS_ADDR_ENV).ok();
        let public_key_hex = std::env::var(REMOTE_WITNESS_PUBLIC_KEY_ENV).ok();

        match (address, public_key_hex) {
            (None, None) => Ok(None),
            (Some(_), None) | (None, Some(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{REMOTE_WITNESS_ADDR_ENV} and {REMOTE_WITNESS_PUBLIC_KEY_ENV} must be configured together"
                ),
            )),
            (Some(address), Some(public_key_hex)) => {
                if namespace.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "BLACKBOX remote witness namespace must not be empty",
                    ));
                }
                let public_key = hex::decode(public_key_hex.trim()).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("BLACKBOX remote witness public key is not valid hex: {error}"),
                    )
                })?;
                if public_key.len() != 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "BLACKBOX remote witness Ed25519 public key must be 32 bytes, got {}",
                            public_key.len()
                        ),
                    ));
                }

                let timeout_ms = std::env::var(REMOTE_WITNESS_TIMEOUT_MS_ENV)
                    .ok()
                    .map(|value| {
                        value.parse::<u64>().map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "BLACKBOX remote witness timeout is invalid: {error}"
                                ),
                            )
                        })
                    })
                    .transpose()?
                    .unwrap_or(2_000);
                if timeout_ms == 0 || timeout_ms > 30_000 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "BLACKBOX remote witness timeout must be in 1..=30000 ms",
                    ));
                }

                // Resolve once at construction only to reject malformed addresses.
                let mut resolved = address.to_socket_addrs().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("BLACKBOX remote witness address is invalid: {error}"),
                    )
                })?;
                if resolved.next().is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "BLACKBOX remote witness address resolved to no sockets",
                    ));
                }

                Ok(Some(Self {
                    address,
                    public_key,
                    timeout: Duration::from_millis(timeout_ms),
                    namespace: namespace.to_string(),
                }))
            }
        }
    }

    pub(crate) fn current(&self) -> io::Result<RemoteWitnessState> {
        let nonce = Uuid::new_v4().to_string();
        let request = WitnessRequest {
            op: "get",
            namespace: &self.namespace,
            nonce: &nonce,
            previous_sequence: None,
            previous_head_record_sha256: None,
            sequence: None,
            head_record_sha256: None,
        };
        self.exchange(&request, &nonce)
    }

    pub(crate) fn advance(
        &self,
        previous: &RemoteWitnessState,
        next: &RemoteWitnessState,
    ) -> io::Result<RemoteWitnessState> {
        if next.sequence != previous.sequence.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "BLACKBOX remote witness sequence overflow",
            )
        })? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "BLACKBOX remote witness advance must be exactly one sequence",
            ));
        }

        let nonce = Uuid::new_v4().to_string();
        let request = WitnessRequest {
            op: "advance",
            namespace: &self.namespace,
            nonce: &nonce,
            previous_sequence: Some(previous.sequence),
            previous_head_record_sha256: Some(&previous.head_record_sha256),
            sequence: Some(next.sequence),
            head_record_sha256: Some(&next.head_record_sha256),
        };
        let observed = self.exchange(&request, &nonce)?;
        if observed != *next {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX remote witness acknowledged an unexpected head",
            ));
        }
        Ok(observed)
    }

    fn exchange(
        &self,
        request: &WitnessRequest<'_>,
        expected_nonce: &str,
    ) -> io::Result<RemoteWitnessState> {
        let mut addrs = self.address.to_socket_addrs()?;
        let mut last_error = None;
        let mut stream = loop {
            let Some(address) = addrs.next() else {
                return Err(last_error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "BLACKBOX remote witness has no reachable address",
                    )
                }));
            };
            match TcpStream::connect_timeout(&address, self.timeout) {
                Ok(stream) => break stream,
                Err(error) => last_error = Some(error),
            }
        };

        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let mut payload = serde_json::to_vec(request).map_err(io::Error::other)?;
        payload.push(b'\n');
        stream.write_all(&payload)?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "BLACKBOX remote witness closed without a receipt",
            ));
        }
        if line.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX remote witness response exceeded 64 KiB",
            ));
        }

        let response: WitnessResponse =
            serde_json::from_slice(&line).map_err(io::Error::other)?;
        if !response.ok {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "BLACKBOX remote witness rejected request: {}",
                    response.error.as_deref().unwrap_or("unspecified rejection")
                ),
            ));
        }
        let receipt = response.receipt.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX remote witness success response omitted receipt",
            )
        })?;
        self.verify_receipt(receipt, expected_nonce)
    }

    fn verify_receipt(
        &self,
        receipt: SignedWitnessReceipt,
        expected_nonce: &str,
    ) -> io::Result<RemoteWitnessState> {
        if receipt.schema != RECEIPT_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX remote witness receipt schema mismatch",
            ));
        }
        if receipt.namespace != self.namespace {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX remote witness receipt namespace mismatch",
            ));
        }
        if receipt.nonce != expected_nonce {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX remote witness receipt nonce mismatch (replay rejected)",
            ));
        }
        if receipt.head_record_sha256.len() != 64
            || !receipt
                .head_record_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX remote witness receipt head hash is malformed",
            ));
        }

        let signature = hex::decode(receipt.signature_hex.trim()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("BLACKBOX remote witness signature is not valid hex: {error}"),
            )
        })?;
        let signed = receipt_signing_bytes(
            &receipt.namespace,
            receipt.sequence,
            &receipt.head_record_sha256,
            &receipt.nonce,
        );
        UnparsedPublicKey::new(&ED25519, &self.public_key)
            .verify(&signed, &signature)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "BLACKBOX remote witness Ed25519 signature verification failed",
                )
            })?;

        Ok(RemoteWitnessState {
            sequence: receipt.sequence,
            head_record_sha256: receipt.head_record_sha256,
        })
    }
}

fn receipt_signing_bytes(
    namespace: &str,
    sequence: u64,
    head_record_sha256: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(RECEIPT_SCHEMA.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(sequence.to_string().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(head_record_sha256.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(nonce.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_payload_is_domain_separated_and_unambiguous() {
        let payload = receipt_signing_bytes("sandbox-a", 7, "abcd", "nonce");
        assert_eq!(
            payload,
            b"blackbox.remote-witness.receipt.v1\0sandbox-a\07\0abcd\0nonce"
        );
    }

    #[test]
    fn remote_state_genesis_is_stable() {
        assert_eq!(RemoteWitnessState::genesis().sequence, 0);
        assert_eq!(
            RemoteWitnessState::genesis().head_record_sha256,
            GENESIS_HASH
        );
    }
}
