//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod curve25519;

use std::fmt;

use curve25519_dalek::{MontgomeryPoint, scalar};
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;
// === PQC: Dilithium constants (correct values from pqcrypto-dilithium) ===
pub const DILITHIUM_PUBLIC_KEY_LENGTH: usize = 1312; // For Dilithium2
pub const DILITHIUM_PRIVATE_KEY_LENGTH: usize = 2560; // For Dilithium2 (corrected)
pub const DILITHIUM_SIGNATURE_LENGTH: usize = 2420; // For Dilithium2

// For storing both public and private keys together
pub const DILITHIUM_KEYPAIR_LENGTH: usize = DILITHIUM_PUBLIC_KEY_LENGTH + DILITHIUM_PRIVATE_KEY_LENGTH;

// --- Add imports for Dilithium2 ---
use pqcrypto_dilithium::dilithium2::{
    keypair as dilithium2_keypair,
    detached_sign as dilithium2_detached_sign,
    verify_detached_signature as dilithium2_verify,
    PublicKey as Dilithium2PublicKey,
    SecretKey as Dilithium2SecretKey,
    DetachedSignature as Dilithium2Signature,
};
use pqcrypto_traits::sign::{
    PublicKey as PqPublicKey,
    SecretKey as PqSecretKey,
    DetachedSignature as PqDetachedSignature,
};

// Define Dilithium2 keypair structure
#[derive(Clone)]
pub struct Dilithium2Keypair {
    pub public: Dilithium2PublicKey,
    pub secret: Dilithium2SecretKey,
}

impl Dilithium2Keypair {
    pub fn generate(_rng: Option<&mut dyn rand::RngCore>) -> Self {
        let (public, secret) = dilithium2_keypair();
        Dilithium2Keypair { public, secret }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyType {
    Djb,
    Dilithium2, // PQC
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl KeyType {
    fn value(&self) -> u8 {
        match &self {
            KeyType::Djb => 0x05u8,
            KeyType::Dilithium2 => 0x20u8, // Arbitrary, must be unique
        }
    }
}

#[derive(Debug, displaydoc::Display)]
pub enum CurveError {
    /// no key type identifier
    NoKeyTypeIdentifier,
    /// bad key type <{0:#04x}>
    BadKeyType(u8),
    /// bad key length <{1}> for key with type <{0}>
    BadKeyLength(KeyType, usize),
    /// invalid key agreement output (all-zero shared secret)
    InvalidKeyAgreement,
}

impl std::error::Error for CurveError {}

impl TryFrom<u8> for KeyType {
    type Error = CurveError;

    fn try_from(x: u8) -> Result<Self, CurveError> {
        match x {
            0x05u8 => Ok(KeyType::Djb),
            0x20u8 => Ok(KeyType::Dilithium2),
            t => Err(CurveError::BadKeyType(t)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PublicKeyData {
    DjbPublicKey([u8; curve25519::PUBLIC_KEY_LENGTH]),
    DilithiumPublicKey([u8; DILITHIUM_PUBLIC_KEY_LENGTH]), // PQC
}

#[derive(Clone, Copy, Eq, derive_more::From)]
pub struct PublicKey {
    key: PublicKeyData,
}

// This implementation allows functions with the following signature
// ```
// fn foo(impl AsRef<PublicKey>) { ... }
// ```
// to accept both referenced `&PublicKey` and owned `PublicKey`.
impl AsRef<PublicKey> for PublicKey {
    fn as_ref(&self) -> &PublicKey {
        self
    }
}

impl PublicKey {
    fn new(key: PublicKeyData) -> Self {
        Self { key }
    }

    pub fn deserialize(value: &[u8]) -> Result<Self, CurveError> {
        let (key_type, value) = value.split_first().ok_or(CurveError::NoKeyTypeIdentifier)?;
        let key_type = KeyType::try_from(*key_type)?;
        match key_type {
            KeyType::Djb => {
                let (key, tail): (&[u8; curve25519::PUBLIC_KEY_LENGTH], _) = value
                    .split_first_chunk()
                    .ok_or(CurveError::BadKeyLength(KeyType::Djb, value.len() + 1))?;
                if !tail.is_empty() {
                    log::warn!(
                        "ECPublicKey deserialized with {} trailing bytes",
                        tail.len()
                    );
                }
                Ok(PublicKey {
                    key: PublicKeyData::DjbPublicKey(*key),
                })
            }
            KeyType::Dilithium2 => {
                let (key, tail): (&[u8; DILITHIUM_PUBLIC_KEY_LENGTH], _) = value
                    .split_first_chunk()
                    .ok_or(CurveError::BadKeyLength(KeyType::Dilithium2, value.len() + 1))?;
                if !tail.is_empty() {
                    log::warn!(
                        "DilithiumPublicKey deserialized with {} trailing bytes",
                        tail.len()
                    );
                }
                Ok(PublicKey {
                    key: PublicKeyData::DilithiumPublicKey(*key),
                })
            }
        }
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        match &self.key {
            PublicKeyData::DjbPublicKey(v) => v,
            PublicKeyData::DilithiumPublicKey(v) => v,
        }
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let (type_byte, value) = match &self.key {
            PublicKeyData::DjbPublicKey(v) => (KeyType::Djb.value(), &v[..]),
            PublicKeyData::DilithiumPublicKey(v) => (KeyType::Dilithium2.value(), &v[..]),
        };
        let mut result = Vec::with_capacity(1 + value.len());
        result.push(type_byte);
        result.extend_from_slice(value);
        result.into_boxed_slice()
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify_signature_for_multipart_message(&[message], signature)
    }

    pub fn verify_signature_for_multipart_message(
        &self,
        message: &[&[u8]],
        signature: &[u8],
    ) -> bool {
        match &self.key {
            PublicKeyData::DjbPublicKey(pub_key) => {
                let Ok(signature) = signature.try_into() else {
                    return false;
                };
                curve25519::PrivateKey::verify_signature(pub_key, message, signature)
            }
            PublicKeyData::DilithiumPublicKey(ref pk_bytes) => {
                let pk: Dilithium2PublicKey = match PqPublicKey::from_bytes(pk_bytes) {
                    Ok(pk) => pk,
                    Err(_) => return false,
                };
                let msg = message.concat();
                let sig: Dilithium2Signature = match PqDetachedSignature::from_bytes(signature) {
                    Ok(sig) => sig,
                    Err(_) => return false,
                };
                dilithium2_verify(&sig, &msg, &pk).is_ok()
            }
        }
    }

    fn key_data(&self) -> &[u8] {
        match &self.key {
            PublicKeyData::DjbPublicKey(ref k) => k.as_ref(),
            PublicKeyData::DilithiumPublicKey(ref k) => k.as_ref(),
        }
    }

    pub fn key_type(&self) -> KeyType {
        match &self.key {
            PublicKeyData::DjbPublicKey(_) => KeyType::Djb,
            PublicKeyData::DilithiumPublicKey(_) => KeyType::Dilithium2,
        }
    }

    fn is_torsion_free(&self) -> bool {
        match &self.key {
            PublicKeyData::DjbPublicKey(k) => {
                let mont_point = MontgomeryPoint(*k);
                mont_point
                    .to_edwards(0)
                    .is_some_and(|ed| ed.is_torsion_free())
            }
        }
    }

    fn scalar_is_in_range(&self) -> bool {
        match &self.key {
            PublicKeyData::DjbPublicKey(k) => {
                // it is not true that the scalar is greater than 2^255 - 19
                // specifically, it is not true that either the high bit is set
                // or that the high 247 bits are all 1 and the bottom byte is >(2^8 - 19)
                !(k[31] & 0b1000_0000_u8 != 0
                    || (k[0] >= 0u8.wrapping_sub(19) && k[1..31] == [0xFFu8; 30] && k[31] == 0x7F))
            }
        }
    }

    pub fn is_canonical(&self) -> bool {
        self.is_torsion_free() && self.scalar_is_in_range()
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = CurveError;

    fn try_from(value: &[u8]) -> Result<Self, CurveError> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for PublicKey {
    /// A constant-time comparison as long as the two keys have a matching type.
    ///
    /// If the two keys have different types, the comparison short-circuits,
    /// much like comparing two slices of different lengths.
    fn ct_eq(&self, other: &PublicKey) -> subtle::Choice {
        if self.key_type() != other.key_type() {
            return 0.ct_eq(&1);
        }
        self.key_data().ct_eq(other.key_data())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ key_type={}, serialize={:?} }}",
            self.key_type(),
            self.serialize()
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PrivateKeyData {
    DjbPrivateKey([u8; curve25519::PRIVATE_KEY_LENGTH]),
    DilithiumKeypair {
        public_key: [u8; DILITHIUM_PUBLIC_KEY_LENGTH],
        secret_key: [u8; DILITHIUM_PRIVATE_KEY_LENGTH],
    }, // PQC
}

#[derive(Clone, Copy, Eq, PartialEq, derive_more::From)]
pub struct PrivateKey {
    key: PrivateKeyData,
}

impl PrivateKey {
    pub fn deserialize(value: &[u8]) -> Result<Self, CurveError> {
        // For Djb, no type byte; for Dilithium, expect type byte
        if value.len() == curve25519::PRIVATE_KEY_LENGTH {
            // Legacy Djb
            let mut key: [u8; curve25519::PRIVATE_KEY_LENGTH] = value
                .try_into()
                .map_err(|_| CurveError::BadKeyLength(KeyType::Djb, value.len()))?;
            key = scalar::clamp_integer(key);
            Ok(Self {
                key: PrivateKeyData::DjbPrivateKey(key),
            })
        } else if value.len() == 1 + DILITHIUM_KEYPAIR_LENGTH && value[0] == KeyType::Dilithium2.value() {
            let keypair_bytes = &value[1..];
            let public_key: [u8; DILITHIUM_PUBLIC_KEY_LENGTH] = keypair_bytes[..DILITHIUM_PUBLIC_KEY_LENGTH]
                .try_into()
                .map_err(|_| CurveError::BadKeyLength(KeyType::Dilithium2, value.len()))?;
            let secret_key: [u8; DILITHIUM_PRIVATE_KEY_LENGTH] = keypair_bytes[DILITHIUM_PUBLIC_KEY_LENGTH..]
                .try_into()
                .map_err(|_| CurveError::BadKeyLength(KeyType::Dilithium2, value.len()))?;
            Ok(Self {
                key: PrivateKeyData::DilithiumKeypair { public_key, secret_key },
            })
        } else {
            Err(CurveError::BadKeyLength(KeyType::Djb, value.len()))
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match &self.key {
            PrivateKeyData::DjbPrivateKey(v) => v.to_vec(),
            PrivateKeyData::DilithiumKeypair { public_key, secret_key } => {
                let mut result = Vec::with_capacity(1 + DILITHIUM_KEYPAIR_LENGTH);
                result.push(KeyType::Dilithium2.value());
                result.extend_from_slice(public_key);
                result.extend_from_slice(secret_key);
                result
            }
        }
    }

    pub fn generate_dilithium2() -> Result<Self, CurveError> {
        let keypair = Dilithium2Keypair::generate(None);
        let sk_bytes = keypair.secret.as_bytes();
        let pk_bytes = keypair.public.as_bytes();
        
        let mut secret_key = [0u8; DILITHIUM_PRIVATE_KEY_LENGTH];
        let mut public_key = [0u8; DILITHIUM_PUBLIC_KEY_LENGTH];
        
        secret_key.copy_from_slice(sk_bytes);
        public_key.copy_from_slice(pk_bytes);
        
        Ok(PrivateKey {
            key: PrivateKeyData::DilithiumKeypair { public_key, secret_key },
        })
    }

    pub fn public_key(&self) -> Result<PublicKey, CurveError> {
        match &self.key {
            PrivateKeyData::DjbPrivateKey(private_key) => {
                let public_key =
                    curve25519::PrivateKey::from(*private_key).derive_public_key_bytes();
                Ok(PublicKey::new(PublicKeyData::DjbPublicKey(public_key)))
            }
            PrivateKeyData::DilithiumKeypair { public_key, .. } => {
                Ok(PublicKey::new(PublicKeyData::DilithiumPublicKey(*public_key)))
            }
        }
    }

    pub fn key_type(&self) -> KeyType {
        match &self.key {
            PrivateKeyData::DjbPrivateKey(_) => KeyType::Djb,
            PrivateKeyData::DilithiumKeypair { .. } => KeyType::Dilithium2,
        }
    }

    pub fn calculate_signature<R: CryptoRng + Rng + ?Sized>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>, CurveError> {
        self.calculate_signature_for_multipart_message(&[message], csprng)
    }

    pub fn calculate_signature_for_multipart_message<R: CryptoRng + Rng + ?Sized>(
        &self,
        message: &[&[u8]],
        _csprng: &mut R,
    ) -> Result<Box<[u8]>, CurveError> {
        match self.key {
            PrivateKeyData::DjbPrivateKey(k) => {
                let private_key = curve25519::PrivateKey::from(k);
                Ok(Box::new(private_key.calculate_signature(_csprng, message)))
            }
            PrivateKeyData::DilithiumKeypair { secret_key, .. } => {
                let sk: Dilithium2SecretKey = PqSecretKey::from_bytes(&secret_key)
                    .map_err(|_| CurveError::BadKeyType(KeyType::Dilithium2.value()))?;
                let msg = message.concat();
                let signature = dilithium2_detached_sign(&msg, &sk);
                Ok(signature.as_bytes().to_vec().into_boxed_slice())
            }
        }
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>, CurveError> {
        match (self.key, their_key.key) {
            (PrivateKeyData::DjbPrivateKey(priv_key), PublicKeyData::DjbPublicKey(pub_key)) => {
                let private_key = curve25519::PrivateKey::from(priv_key);
                let shared: [u8; curve25519::AGREEMENT_LENGTH] =
                    private_key.calculate_agreement(&pub_key);
                if bool::from(shared.ct_eq(&[0u8; curve25519::AGREEMENT_LENGTH])) {
                    // Reject the invalid all-zero shared secret in constant time
                    return Err(CurveError::InvalidKeyAgreement);
                }
                Ok(Box::new(shared))
            }
            // No agreement for Dilithium
            _ => Err(CurveError::BadKeyType(KeyType::Dilithium2.value())),
        }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = CurveError;

    fn try_from(value: &[u8]) -> Result<Self, CurveError> {
        Self::deserialize(value)
    }
}

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    pub fn generate<R: Rng + CryptoRng + ?Sized>(csprng: &mut R) -> Self {
        let private_key = curve25519::PrivateKey::new(csprng);

        let public_key = PublicKey::from(PublicKeyData::DjbPublicKey(
            private_key.derive_public_key_bytes(),
        ));
        let private_key = PrivateKey::from(PrivateKeyData::DjbPrivateKey(
            private_key.private_key_bytes(),
        ));

        Self {
            public_key,
            private_key,
        }
    }

    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    pub fn from_public_and_private(
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Self, CurveError> {
        let public_key = PublicKey::try_from(public_key)?;
        let private_key = PrivateKey::try_from(private_key)?;
        Ok(Self {
            public_key,
            private_key,
        })
    }

    pub fn calculate_signature<R: CryptoRng + Rng + ?Sized>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>, CurveError> {
        self.private_key.calculate_signature(message, csprng)
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>, CurveError> {
        self.private_key.calculate_agreement(their_key)
    }
}

impl TryFrom<PrivateKey> for KeyPair {
    type Error = CurveError;

    fn try_from(value: PrivateKey) -> Result<Self, CurveError> {
        let public_key = value.public_key()?;
        Ok(Self::new(public_key, value))
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use const_str::hex;
    use curve25519_dalek::constants::EIGHT_TORSION;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_generate_dilithium_keys() -> Result<(), CurveError> {
        // Test Dilithium key generation and signature
        let private_key = PrivateKey::generate_dilithium2()?;
        let public_key = private_key.public_key()?;
        
        let msg = b"test message";
        let mut csprng = OsRng.unwrap_err();
        let sig = private_key.calculate_signature_for_multipart_message(&[msg.as_ref()], &mut csprng)?;
        assert!(public_key.verify_signature_for_multipart_message(&[msg.as_ref()], &sig));
        
        Ok(())
    }

    #[test]
    fn test_large_signatures() -> Result<(), CurveError> {
        let mut csprng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut csprng);
        let mut message = [0u8; 1024 * 1024];
        let signature = key_pair
            .private_key
            .calculate_signature(&message, &mut csprng)?;

        assert!(key_pair.public_key.verify_signature(&message, &signature));
        message[0] ^= 0x01u8;
        assert!(!key_pair.public_key.verify_signature(&message, &signature));
        message[0] ^= 0x01u8;
        let public_key = key_pair.private_key.public_key()?;
        assert!(public_key.verify_signature(&message, &signature));

        assert!(
            public_key.verify_signature_for_multipart_message(
                &[&message[..7], &message[7..]],
                &signature
            )
        );

        let signature = key_pair
            .private_key
            .calculate_signature_for_multipart_message(
                &[&message[..20], &message[20..]],
                &mut csprng,
            )?;
        assert!(public_key.verify_signature(&message, &signature));

        Ok(())
    }

    #[test]
    fn test_decode_size() -> Result<(), CurveError> {
        let mut csprng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut csprng);
        let serialized_public = key_pair.public_key.serialize();

        assert_eq!(
            serialized_public,
            key_pair.private_key.public_key()?.serialize()
        );
        let empty: [u8; 0] = [];

        let just_right = PublicKey::try_from(&serialized_public[..])?;

        assert!(PublicKey::try_from(&serialized_public[1..]).is_err());
        assert!(PublicKey::try_from(&empty[..]).is_err());

        let mut bad_key_type = [0u8; 33];
        bad_key_type[..].copy_from_slice(&serialized_public[..]);
        bad_key_type[0] = 0x01u8;
        assert!(PublicKey::try_from(&bad_key_type[..]).is_err());

        let mut extra_space = [0u8; 34];
        extra_space[..33].copy_from_slice(&serialized_public[..]);
        let extra_space_decode = PublicKey::try_from(&extra_space[..]);
        assert!(extra_space_decode.is_ok());

        assert_eq!(&serialized_public[..], &just_right.serialize()[..]);
        assert_eq!(&serialized_public[..], &extra_space_decode?.serialize()[..]);
        Ok(())
    }

    #[test]
    fn test_dilithium_key_serialization() -> Result<(), CurveError> {
        // Test Dilithium key serialization and deserialization
        let private_key = PrivateKey::generate_dilithium2()?;
        let public_key = private_key.public_key()?;
        
        // Test private key serialization
        let private_serialized = private_key.serialize();
        let private_deserialized = PrivateKey::try_from(&private_serialized[..])?;
        
        // Test public key serialization
        let public_serialized = public_key.serialize();
        let public_deserialized = PublicKey::try_from(&public_serialized[..])?;
        
        // Verify the keys work the same after deserialization
        let msg = b"test serialization message";
        let mut csprng = OsRng.unwrap_err();
        
        let sig1 = private_key.calculate_signature(&msg[..], &mut csprng)?;
        let sig2 = private_deserialized.calculate_signature(&msg[..], &mut csprng)?;
        
        // Both original and deserialized keys should be able to verify signatures
        assert!(public_key.verify_signature(&msg[..], &sig1));
        assert!(public_key.verify_signature(&msg[..], &sig2));
        assert!(public_deserialized.verify_signature(&msg[..], &sig1));
        assert!(public_deserialized.verify_signature(&msg[..], &sig2));
        
        Ok(())
    }

    #[test]
    fn curve_error_impls_std_error() {
        let error = CurveError::BadKeyType(u8::MAX);
        let error = Box::new(error) as Box<dyn std::error::Error>;
        assert_matches!(error.downcast_ref(), Some(CurveError::BadKeyType(_)));
    }

    #[test]
    fn honest_keys_are_torsion_free() {
        let mut csprng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut csprng);
        assert!(key_pair.public_key.is_torsion_free());
    }

    #[test]
    fn tweaked_keys_are_not_torsion_free() {
        let mut csprng = OsRng.unwrap_err();
        let key_pair = KeyPair::generate(&mut csprng);
        let pk_bytes: [u8; 32] = key_pair.public_key.public_key_bytes().try_into().unwrap();
        let mont_pt = MontgomeryPoint(pk_bytes);
        let ed_pt = mont_pt.to_edwards(0).unwrap();
        for t in EIGHT_TORSION.iter().skip(1) {
            let tweaked = ed_pt + *t; // add a torsion point
            let tweaked_mont = tweaked.to_montgomery();
            let tweaked_pk_bytes: [u8; 32] = tweaked_mont.to_bytes();
            let tweaked_pk = PublicKey::from_djb_public_key_bytes(&tweaked_pk_bytes).unwrap();
            assert!(!tweaked_pk.is_torsion_free());
        }
    }

    #[test]
    fn keys_with_the_high_bit_set_are_out_of_range() {
        assert!(
            PublicKey::from_djb_public_key_bytes(&[0; 32])
                .expect("structurally valid")
                .scalar_is_in_range(),
            "0 should be in range"
        );
        assert!(
            !PublicKey::from_djb_public_key_bytes(&hex!(
                "0000000000000000000000000000000000000000000000000000000000000080"
            ))
            .expect("structurally valid")
            .scalar_is_in_range(),
            "2^255 should be out of range"
        );
        assert!(
            !PublicKey::from_djb_public_key_bytes(&[0xFF; 32])
                .expect("structurally valid")
                .scalar_is_in_range(),
            "2^256 - 1 should be out of range"
        );
        {
            let mut csprng = OsRng.unwrap_err();
            let key_pair = KeyPair::generate(&mut csprng);
            assert!(key_pair.public_key.scalar_is_in_range());
            let mut pk_bytes: [u8; 32] = key_pair.public_key.public_key_bytes().try_into().unwrap();
            assert!(pk_bytes[31] & 0x80 == 0);
            pk_bytes[31] |= 0x80;
            assert!(
                !PublicKey::from_djb_public_key_bytes(&pk_bytes)
                    .expect("structurally valid")
                    .scalar_is_in_range(),
                ">2^255 should be out of range"
            );
        }
    }

    #[test]
    fn keys_above_the_prime_modulus_are_out_of_range() {
        // Curve25519 scalars use a little-endian representation.
        let two_to_the_255_minus_one =
            hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

        for i in 1..=19 {
            let mut pk_bytes = two_to_the_255_minus_one;
            pk_bytes[0] -= i;
            pk_bytes[0] += 1; // because our original literal was 2^255 - 1
            assert!(
                !PublicKey::from_djb_public_key_bytes(&pk_bytes)
                    .expect("structurally valid")
                    .scalar_is_in_range(),
                "2^255 - {i} should be out of range",
            );

            let mut canonical_representative = [0; 32];
            canonical_representative[0] = 19 - i;

            assert_eq!(
                MontgomeryPoint(pk_bytes),
                MontgomeryPoint(canonical_representative)
            );
        }

        let mut pk_bytes = two_to_the_255_minus_one;
        pk_bytes[0] -= 19; // resulting in the value 2^255 - 20
        assert!(
            PublicKey::from_djb_public_key_bytes(&pk_bytes)
                .expect("structurally valid")
                .scalar_is_in_range()
        );
    }
}
