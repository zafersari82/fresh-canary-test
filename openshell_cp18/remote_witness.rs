// SPDX-License-Identifier: Apache-2.0
// BLACKBOX ACV CP18: authenticated multi-witness quorum for execution finality.

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const REMOTE_WITNESS_ADDR_ENV: &str = "OPENSHELL_BLACKBOX_REMOTE_WITNESS_ADDR";
pub const REMOTE_WITNESS_PUBLIC_KEY_ENV: &str =
    "OPENSHELL_BLACKBOX_REMOTE_WITNESS_PUBLIC_KEY_HEX";
pub const REMOTE_WITNESS_TIMEOUT_MS_ENV: &str =
    "OPENSHELL_BLACKBOX_REMOTE_WITNESS_TIMEOUT_MS";

pub const REMOTE_WITNESS_QUORUM_JSON_ENV: &str =
    "OPENSHELL_BLACKBOX_REMOTE_WITNESS_QUORUM_JSON";
pub const REMOTE_WITNESS_QUORUM_THRESHOLD_ENV: &str =
    "OPENSHELL_BLACKBOX_REMOTE_WITNESS_QUORUM_THRESHOLD";
pub const REMOTE_WITNESS_CLIENT_ID_ENV: &str =
    "OPENSHELL_BLACKBOX_REMOTE_WITNESS_CLIENT_ID";
pub const REMOTE_WITNESS_CLIENT_HMAC_KEY_ENV: &str =
    "OPENSHELL_BLACKBOX_REMOTE_WITNESS_CLIENT_HMAC_KEY_HEX";

const RECEIPT_SCHEMA: &str = "blackbox.remote-witness.receipt.v1";
const REQUEST_AUTH_SCHEMA: &str = "blackbox.remote-witness.request-auth.v1";
const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(Clone, Debug, Deserialize)]
struct WitnessMemberConfig {
    id: String,
    address: String,
    public_key_hex: String,
}

#[derive(Clone, Debug)]
struct WitnessMember {
    id: String,
    address: String,
    public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct RemoteWitnessClient {
    members: Vec<WitnessMember>,
    threshold: usize,
    timeout: Duration,
    namespace: String,
    client_id: Option<String>,
    client_hmac_key: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize)]
struct WitnessRequest {
    op: String,
    namespace: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_head_record_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    head_record_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_hex: Option<String>,
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
        if namespace.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "BLACKBOX remote witness namespace must not be empty",
            ));
        }

        let timeout = parse_timeout()?;

        if let Ok(raw) = std::env::var(REMOTE_WITNESS_QUORUM_JSON_ENV) {
            let configs: Vec<WitnessMemberConfig> =
                serde_json::from_str(&raw).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("BLACKBOX witness quorum JSON is invalid: {error}"),
                    )
                })?;
            if configs.len() < 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "BLACKBOX witness quorum requires at least two members",
                ));
            }

            let threshold = std::env::var(REMOTE_WITNESS_QUORUM_THRESHOLD_ENV)
                .ok()
                .map(|value| {
                    value.parse::<usize>().map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("BLACKBOX witness quorum threshold is invalid: {error}"),
                        )
                    })
                })
                .transpose()?
                .unwrap_or(configs.len() / 2 + 1);
            if threshold == 0 || threshold > configs.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "BLACKBOX witness quorum threshold {threshold} is outside 1..={}",
                        configs.len()
                    ),
                ));
            }

            let client_id = std::env::var(REMOTE_WITNESS_CLIENT_ID_ENV).ok();
            let client_hmac_key = std::env::var(REMOTE_WITNESS_CLIENT_HMAC_KEY_ENV)
                .ok()
                .map(|value| parse_hmac_key(&value))
                .transpose()?;
            match (&client_id, &client_hmac_key) {
                (Some(id), Some(_)) if !id.trim().is_empty() => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "{REMOTE_WITNESS_CLIENT_ID_ENV} and {REMOTE_WITNESS_CLIENT_HMAC_KEY_ENV} are both required for quorum mode"
                        ),
                    ));
                }
            }

            let mut ids = HashSet::new();
            let mut members = Vec::with_capacity(configs.len());
            for config in configs {
                if config.id.trim().is_empty() || !ids.insert(config.id.clone()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "BLACKBOX witness quorum member ids must be unique and non-empty",
                    ));
                }
                validate_address(&config.address)?;
                members.push(WitnessMember {
                    id: config.id,
                    address: config.address,
                    public_key: parse_public_key(&config.public_key_hex)?,
                });
            }

            return Ok(Some(Self {
                members,
                threshold,
                timeout,
                namespace: namespace.to_string(),
                client_id,
                client_hmac_key,
            }));
        }

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
                validate_address(&address)?;
                Ok(Some(Self {
                    members: vec![WitnessMember {
                        id: "legacy-single".to_string(),
                        address,
                        public_key: parse_public_key(&public_key_hex)?,
                    }],
                    threshold: 1,
                    timeout,
                    namespace: namespace.to_string(),
                    client_id: None,
                    client_hmac_key: None,
                }))
            }
        }
    }

    pub(crate) fn current(&self) -> io::Result<RemoteWitnessState> {
        let mut groups: HashMap<RemoteWitnessState, usize> = HashMap::new();
        let mut errors = Vec::new();

        for member in &self.members {
            match self.exchange_member(
                member,
                "get",
                None,
                None,
                None,
                None,
            ) {
                Ok(state) => {
                    *groups.entry(state).or_insert(0) += 1;
                }
                Err(error) => errors.push(format!("{}:{error}", member.id)),
            }
        }

        let mut best: Option<(RemoteWitnessState, usize)> = None;
        for (state, count) in groups {
            match &best {
                Some((current, current_count))
                    if *current_count > count
                        || (*current_count == count
                            && current.sequence >= state.sequence) => {}
                _ => best = Some((state, count)),
            }
        }

        let Some((state, count)) = best else {
            return Err(quorum_error(
                self.threshold,
                0,
                &errors,
                "current state",
            ));
        };
        if count < self.threshold {
            return Err(quorum_error(
                self.threshold,
                count,
                &errors,
                "current state",
            ));
        }
        Ok(state)
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

        let mut acknowledgements = 0usize;
        let mut errors = Vec::new();
        for member in &self.members {
            match self.exchange_member(
                member,
                "advance",
                Some(previous.sequence),
                Some(&previous.head_record_sha256),
                Some(next.sequence),
                Some(&next.head_record_sha256),
            ) {
                Ok(observed) if observed == *next => acknowledgements += 1,
                Ok(observed) => errors.push(format!(
                    "{}:unexpected head {}:{}",
                    member.id, observed.sequence, observed.head_record_sha256
                )),
                Err(error) => errors.push(format!("{}:{error}", member.id)),
            }
        }

        if acknowledgements < self.threshold {
            return Err(quorum_error(
                self.threshold,
                acknowledgements,
                &errors,
                "advance",
            ));
        }
        Ok(next.clone())
    }

    fn exchange_member(
        &self,
        member: &WitnessMember,
        op: &str,
        previous_sequence: Option<u64>,
        previous_head_record_sha256: Option<&str>,
        sequence: Option<u64>,
        head_record_sha256: Option<&str>,
    ) -> io::Result<RemoteWitnessState> {
        let nonce = Uuid::new_v4().to_string();
        let client_id = self.client_id.clone();
        let auth_hex = match (&client_id, &self.client_hmac_key) {
            (Some(client_id), Some(key)) => Some(request_auth_hex(
                key,
                op,
                &self.namespace,
                &nonce,
                previous_sequence,
                previous_head_record_sha256,
                sequence,
                head_record_sha256,
                client_id,
            )?),
            _ => None,
        };

        let request = WitnessRequest {
            op: op.to_string(),
            namespace: self.namespace.clone(),
            nonce: nonce.clone(),
            previous_sequence,
            previous_head_record_sha256: previous_head_record_sha256.map(str::to_string),
            sequence,
            head_record_sha256: head_record_sha256.map(str::to_string),
            client_id,
            auth_hex,
        };
        self.exchange(member, &request, &nonce)
    }

    fn exchange(
        &self,
        member: &WitnessMember,
        request: &WitnessRequest,
        expected_nonce: &str,
    ) -> io::Result<RemoteWitnessState> {
        let mut addrs = member.address.to_socket_addrs()?;
        let mut last_error = None;
        let mut stream = loop {
            let Some(address) = addrs.next() else {
                return Err(last_error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        format!("BLACKBOX witness {} has no reachable address", member.id),
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
                format!("BLACKBOX witness {} closed without a receipt", member.id),
            ));
        }
        if line.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("BLACKBOX witness {} response exceeded 64 KiB", member.id),
            ));
        }

        let response: WitnessResponse =
            serde_json::from_slice(&line).map_err(io::Error::other)?;
        if !response.ok {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "BLACKBOX witness {} rejected request: {}",
                    member.id,
                    response.error.as_deref().unwrap_or("unspecified rejection")
                ),
            ));
        }
        let receipt = response.receipt.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("BLACKBOX witness {} success response omitted receipt", member.id),
            )
        })?;
        verify_receipt(
            &self.namespace,
            &member.public_key,
            receipt,
            expected_nonce,
            &member.id,
        )
    }
}

fn parse_timeout() -> io::Result<Duration> {
    let timeout_ms = std::env::var(REMOTE_WITNESS_TIMEOUT_MS_ENV)
        .ok()
        .map(|value| {
            value.parse::<u64>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("BLACKBOX remote witness timeout is invalid: {error}"),
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
    Ok(Duration::from_millis(timeout_ms))
}

fn parse_public_key(value: &str) -> io::Result<Vec<u8>> {
    let public_key = hex::decode(value.trim()).map_err(|error| {
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
    Ok(public_key)
}

fn parse_hmac_key(value: &str) -> io::Result<Vec<u8>> {
    let key = hex::decode(value.trim()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("BLACKBOX witness client HMAC key is not valid hex: {error}"),
        )
    })?;
    if key.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BLACKBOX witness client HMAC key must contain at least 32 bytes",
        ));
    }
    Ok(key)
}

fn validate_address(address: &str) -> io::Result<()> {
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
    Ok(())
}

fn quorum_error(
    threshold: usize,
    valid: usize,
    errors: &[String],
    phase: &str,
) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "BLACKBOX remote witness quorum unavailable during {phase} \
             [required:{threshold} valid:{valid} errors:{}]",
            errors.join(" | ")
        ),
    )
}

fn verify_receipt(
    namespace: &str,
    public_key: &[u8],
    receipt: SignedWitnessReceipt,
    expected_nonce: &str,
    member_id: &str,
) -> io::Result<RemoteWitnessState> {
    if receipt.schema != RECEIPT_SCHEMA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("BLACKBOX witness {member_id} receipt schema mismatch"),
        ));
    }
    if receipt.namespace != namespace {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("BLACKBOX witness {member_id} receipt namespace mismatch"),
        ));
    }
    if receipt.nonce != expected_nonce {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "BLACKBOX witness {member_id} receipt nonce mismatch (replay rejected)"
            ),
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
            format!("BLACKBOX witness {member_id} receipt head hash is malformed"),
        ));
    }

    let signature = hex::decode(receipt.signature_hex.trim()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "BLACKBOX witness {member_id} signature is not valid hex: {error}"
            ),
        )
    })?;
    let signed = receipt_signing_bytes(
        &receipt.namespace,
        receipt.sequence,
        &receipt.head_record_sha256,
        &receipt.nonce,
    );
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, &signature)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "BLACKBOX witness {member_id} Ed25519 signature verification failed"
                ),
            )
        })?;

    Ok(RemoteWitnessState {
        sequence: receipt.sequence,
        head_record_sha256: receipt.head_record_sha256,
    })
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

fn request_auth_hex(
    key: &[u8],
    op: &str,
    namespace: &str,
    nonce: &str,
    previous_sequence: Option<u64>,
    previous_head_record_sha256: Option<&str>,
    sequence: Option<u64>,
    head_record_sha256: Option<&str>,
    client_id: &str,
) -> io::Result<String> {
    let payload = request_auth_bytes(
        op,
        namespace,
        nonce,
        previous_sequence,
        previous_head_record_sha256,
        sequence,
        head_record_sha256,
        client_id,
    );
    let mut mac = HmacSha256::new_from_slice(key).map_err(io::Error::other)?;
    mac.update(&payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn request_auth_bytes(
    op: &str,
    namespace: &str,
    nonce: &str,
    previous_sequence: Option<u64>,
    previous_head_record_sha256: Option<&str>,
    sequence: Option<u64>,
    head_record_sha256: Option<&str>,
    client_id: &str,
) -> Vec<u8> {
    let fields = [
        REQUEST_AUTH_SCHEMA.to_string(),
        client_id.to_string(),
        op.to_string(),
        namespace.to_string(),
        nonce.to_string(),
        previous_sequence.map(|value| value.to_string()).unwrap_or_default(),
        previous_head_record_sha256.unwrap_or_default().to_string(),
        sequence.map(|value| value.to_string()).unwrap_or_default(),
        head_record_sha256.unwrap_or_default().to_string(),
    ];
    fields.join("\0").into_bytes()
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
    fn request_auth_payload_is_domain_separated_and_stable() {
        let payload = request_auth_bytes(
            "advance",
            "sandbox-a",
            "nonce-1",
            Some(4),
            Some("prev"),
            Some(5),
            Some("next"),
            "client-a",
        );
        assert_eq!(
            payload,
            b"blackbox.remote-witness.request-auth.v1\0client-a\0advance\0sandbox-a\0nonce-1\04\0prev\05\0next"
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
