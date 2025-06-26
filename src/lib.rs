extern crate alloc;

use ethereum::{AUTHORIZATION_MAGIC, AuthorizationListItem};
use ethereum_types::{Address, H256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rlp::RlpStream;
use sha3::{Digest, Keccak256};

/// Error type for EIP-7702 authorization signature recovery
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    /// Invalid signature format
    InvalidSignature,
    /// Invalid recovery ID
    InvalidRecoveryId,
    /// Signature recovery failed
    RecoveryFailed,
    /// Invalid public key format
    InvalidPublicKey,
}

pub trait Authorizer {
    fn authorizing_address(&self) -> Result<Address, AuthorizationError>;
    fn authorization_message_hash(&self) -> H256;
    fn verifying_key_to_address(
        verifying_key: &VerifyingKey,
    ) -> Result<Address, AuthorizationError>;
}

impl Authorizer for &AuthorizationListItem {
    /// Recover the authorizing address from the authorization signature according to EIP-7702
    fn authorizing_address(&self) -> Result<Address, AuthorizationError> {
        // Create the authorization message hash according to EIP-7702
        let message_hash = self.authorization_message_hash();

        // Create signature from r and s components
        let mut signature_bytes = [0u8; 64];
        signature_bytes[0..32].copy_from_slice(&self.r[..]);
        signature_bytes[32..64].copy_from_slice(&self.s[..]);

        // Create the signature and recovery ID
        let signature = Signature::from_bytes(&signature_bytes.into())
            .map_err(|_| AuthorizationError::InvalidSignature)?;

        let recovery_id = RecoveryId::try_from(if self.y_parity { 1u8 } else { 0u8 })
            .map_err(|_| AuthorizationError::InvalidRecoveryId)?;

        // Recover the verifying key using VerifyingKey::recover_from_prehash
        // message_hash is already a 32-byte Keccak256 hash, so we use recover_from_prehash
        let verifying_key =
            VerifyingKey::recover_from_prehash(message_hash.as_bytes(), &signature, recovery_id)
                .map_err(|_| AuthorizationError::RecoveryFailed)?;

        // Convert public key to Ethereum address
        Self::verifying_key_to_address(&verifying_key)
    }

    /// Create the authorization message hash according to EIP-7702
    fn authorization_message_hash(&self) -> H256 {
        // EIP-7702 authorization message format:
        // MAGIC || rlp([chain_id, address, nonce])
        let mut message = alloc::vec![AUTHORIZATION_MAGIC];

        // RLP encode the authorization tuple
        let mut rlp_stream = RlpStream::new_list(3);
        rlp_stream.append(&self.chain_id);
        rlp_stream.append(&self.address);
        rlp_stream.append(&self.nonce);
        message.extend_from_slice(&rlp_stream.out());

        // Return keccak256 hash of the complete message
        H256::from_slice(Keccak256::digest(&message).as_slice())
    }

    /// Convert VerifyingKey to Ethereum address
    fn verifying_key_to_address(
        verifying_key: &VerifyingKey,
    ) -> Result<Address, AuthorizationError> {
        // Convert public key to bytes (uncompressed format, skip the 0x04 prefix)
        let pubkey_point = verifying_key.to_encoded_point(false);
        let pubkey_bytes = pubkey_point.as_bytes();

        // pubkey_bytes is 65 bytes: [0x04, x_coord (32 bytes), y_coord (32 bytes)]
        // We want just the x and y coordinates (64 bytes total)
        if pubkey_bytes.len() >= 65 && pubkey_bytes[0] == 0x04 {
            let pubkey_coords = &pubkey_bytes[1..65];
            // Ethereum address is the last 20 bytes of keccak256(pubkey)
            let hash = Keccak256::digest(pubkey_coords);
            Ok(Address::from_slice(&hash[12..]))
        } else {
            Err(AuthorizationError::InvalidPublicKey)
        }
    }
}
