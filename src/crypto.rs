//! Cryptographic primitives of the Schnorr signature.
//!
//! ## Contents
//! - `H(m, r)`                 : SHA-256(m || enc(r)) reduced mod q.
//!                               enc(r) is big-endian with a fixed size.
//! - `keygen(params, rng)`     : draws x in [1, q), computes y = g^x mod p.
//! //! - `sign(m, x, k)`           : nonce k is provided, returns (s, e).
//! - `verify(m, sigma, y)`     : recomputes r_v = g^s * y^(-e), checks H(m, r_v) = e.
//! - `sample_nonce(q, rng)`    : draws a fresh nonce in [1, q).
//! - `encode_secret(s, q)`     : UTF-8 text to integer µ, with 1 <= µ < q.
//!
//! ## Properties
//! The serialization of r in H must be identical for `sign` and `verify`.
use num_bigint::{BigInt, BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{Num, One, Zero};
use sha2::{Digest, Sha256};
use rand::{thread_rng, Rng};
use rand::rngs::ThreadRng;
use crate::types::{GroupParams, KeyPair, Signature};

/// Generated with OpenSSL
///
///     openssl genpkey -genparam -algorithm DSA \
///       -pkeyopt dsa_paramgen_bits:2048 \
///       -pkeyopt dsa_paramgen_q_bits:256 \
///       -out dsa.pem
///     openssl pkeyparam -in dsa.pem -text -noout
///
const P_HEX: &str = "9e0aaf600acb73f6898f42953a526516828debc72516a009422cec67f34f9a0c99694ad169e3e9c04082229dc2bf89266fe8e876253dd7a956d87582bf68d7b6db4d55cd66efef9f47896e5d11cabea5467f208d9770eb79bcaecf84bb02d3cc89159c3b3eae5c8ba45460eb029d1b88a9d908b2143609a96cd18dc724867e888842a3b59c628091e9e7087e7ca32932bf971b02c02271dff96508c28b11918c07268e5a5e8e6024144476908ed23b7e4483fd2fd28bb23000ca0563f9a1bf5c593f0ab4ab836ccdf30d2d76e8fbc7074e7a928390ae17d7c689eb9c62f458b4599134f4ed866dfb42778330a07257b3ea93463cfdc33dc52e14187ccc069993";
const Q_HEX: &str = "991d406da8e7ed10c07ecaedae2f84840022fae60415079accf6ac447458b035";
const G_HEX: &str = "2193ae34e9acabfb1a9c4715f37e385ed37add9774a24f913cbce64456032fc7318255a3b22564972d8d3ac2221a9fd3a2b7c9f89c7e1a90952590b60d989946070516a4979216103c39b6ee12a759b3b46f9d607c42b906e4a8fde1cc1349c923810cc021940c21469c29a4406b7bc530abd51dfcb078616b408c3946e441cbc966b011c2ca50b449645f587b61d08f96c925fccea07dc0ed93f2bca56a344a48a213c7eb960005f6412dcf7bc45ab84cbe1871cf68fc6347c36cc3c0bf86f2b8e784a6e8358cd887fa1526eb0c4741a730da4d6f3ffbf6294e08350efd83a1f00069dd72fd5ceaffec1e1745a76048ac7e747f81ff71b0a3b090b1218ad109";


pub fn params() -> GroupParams {
    GroupParams {
        p: BigUint::parse_bytes(P_HEX.as_bytes(), 16).expect("P_HEX is invalid"),
        q: BigUint::parse_bytes(Q_HEX.as_bytes(), 16).expect("Q_HEX is invalid"),
        g: BigUint::parse_bytes(G_HEX.as_bytes(), 16).expect("G_HEX is invalid"),
    }
}


/// Function H
///
/// # Arguments
/// * `params` - The group parameters (`p`, `q`, `g`).
/// * `m` - The message to sign.
/// * `r` - The nonce.
///
/// # Returns
/// H(r||m) mod q
pub fn h(params: &GroupParams, m:&str, r:&BigUint) -> BigUint {
    let r_bytes = r.to_bytes_be();
    let mut hasher = Sha256::new();
    // Length prefix so that the split between (r, m) is unambiguous
    hasher.update((r_bytes.len() as u32).to_be_bytes());
    hasher.update(&r_bytes);
    hasher.update(m.as_bytes());
    let digest = hasher.finalize();
    BigUint::from_bytes_be(&digest) % &params.q
}


/// Generates a key pair for the given group.
///
/// The private key `x` is drawn uniformly in `[1, q-1]` and the public
/// key is `y = g^x mod p`.
///
/// # Arguments
/// * `params` - The group parameters (`p`, `q`, `g`).
///
/// # Returns
///
/// A [`KeyPair`] containing the private key and the public key.
pub fn keygen(params: &GroupParams) -> KeyPair {
    let mut rng:ThreadRng = thread_rng();
    let x:BigUint =rng.gen_biguint_below(&params.q);
    // y = g^(-x) = g^(q - x) mod p, car g^q = 1
    let y:BigUint = params.g.modpow(&(&params.q - &x), &params.p);
    KeyPair{ x, y }
}


/// Signs a message
///
/// # Arguments
/// * `params` - The group parameters (`p`, `q`, `g`).
/// * `m` - The message to sign.
/// * `x` - The private signing key.
/// * `k` - The nonce.
///
/// # Returns
///
/// The Schnorr signature of m by x.
pub fn sign(params:&GroupParams, m:&str, x:&BigUint, k:&BigUint) -> Signature {
    let r:BigUint = BigUint::modpow(&params.g, k, &params.p);
    let e:BigUint = h(params, m, &r);
    let s:BigUint = k + x * &e;
    Signature{ s, e }
}


/// Verifies a signature.
///
/// Recomputes the commitment `r_v = g^s · y^e mod p`. For a valid signature
/// this equals `g^k`, since `y = g^(-x)` and `s = k + x·e`. The signature is
/// accepted if and only if `H(m, r_v) = e`.
///
/// # Arguments
/// * `params` - The group parameters (`p`, `q`, `g`).
/// * `m` - The signed message.
/// * `y` - The public key of the signer.
/// * `sigma` - The signature `(s, e)` to check.
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
pub fn verify(params:&GroupParams, m:&str, y:&BigUint, sigma: &Signature) -> bool {
    let mut rv:BigUint = BigUint::modpow(&params.g, &sigma.s, &params.p) *  BigUint::modpow(y, &sigma.e, &params.p);
    rv = rv.modpow(&BigUint::ONE, &params.p);
    let ev:BigUint = h(params, m, &rv);
    ev == sigma.e
}


/// Draws a fresh nonce uniformly in `[1, q-1]`.
///
/// # Arguments
/// * `params` - The group parameters (only `q` is used).
/// * `rng` - The random number generator (should be cryptographically secure).
///
/// # Returns
/// A nonce `k` with `1 ≤ k < q`, to be used for a single signature.
pub fn sample_nonce<R:Rng>(params:&GroupParams, rng: &mut R) -> BigUint {
    rng.gen_biguint_range(&BigUint::one(), &params.q)
}


/// Errors returned by [`encode_secret`].
#[derive(Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// Empty secret or made up only of null bytes (μ = 0)
    Zero,
    /// μ >= q, or secret exceeding the maximum allowed size
    TooLong,
}


/// Encodes a text secret into an integer μ.
///
/// The UTF-8 bytes of the secret are read as big-endian to form the integer μ,
/// such that 1 ≤ μ < q. The function fails if the secret is too long.
///
/// The maximum length is ⌊(bits(q) − 1) / 8⌋ bytes (not characters):
/// 31 bytes for a 256-bit q. This bound guarantees
/// μ < 2^(8n) ≤ 2^(bits(q)−1) ≤ q whatever the content of the secret.
///
/// # Arguments
///
/// * `secret`- The secret m̂ to encode (UTF-8 string, never normalized).
/// * `q` - The prime order of the group G (exclusive bound for μ).
///
/// # Returns
/// * The integer μ encoding the secret, with 1 ≤ μ < q.
///
/// * EncodeError::TooLong The secret exceeds the maximum allowed size
///                              (in bytes) or μ ≥ q.
/// * EncodeError::Zero    The secret is empty or contains only
///                              null bytes (μ = 0).
///
pub fn encode_secret(secret: &str, q: &BigUint) -> Result<BigUint, EncodeError> {
    // (q.bits() - 1) / 8 garantit que tout secret de cette taille est < q.
    let max_len:usize = ((q.bits() - 1) / 8) as usize;
    if secret.len() > max_len { return Err(EncodeError::TooLong); }
    // Big-endian integer built from the raw UTF-8 bytes
    let mu:BigUint = BigUint::from_bytes_be(secret.as_bytes());
    // Empty secret or only null bytes
    if mu.is_zero() { return Err(EncodeError::Zero); }
    // Safeguard (always true here thanks to the byte-length limit)
    if &mu >= q { return Err(EncodeError::TooLong); }
    Ok(mu)
}


/// Inverse operation, useful for solving: μ -> secret.
///
/// # Arguments
/// * `mu` - The integer μ to decode.
///
/// # Returns
/// `Some(secret)` if the big-endian bytes of μ are valid UTF-8, `None`
/// otherwise. Leading null bytes of the original secret are not recovered.
pub fn decode_secret(mu: &BigUint) -> Option<String> {
    String::from_utf8(mu.to_bytes_be()).ok()
}


/// Unit tests of the primitives.
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::RandBigInt;
    use num_traits::One;
    use rand::thread_rng;
    use sha2::digest::crypto_common::Key;

    fn random_k(params: &GroupParams) -> BigUint {
        thread_rng().gen_biguint_range(&BigUint::one(), &params.q)
    }

    #[test]
    fn test_keygen(){
        let p:GroupParams = params();
        let kp:KeyPair = keygen(&p);
        assert_eq!(kp.y, p.g.modpow(&(&p.q - &kp.x), &p.p));
    }

    #[test]
    fn test_valid_signature() {
        let p:GroupParams = params();
        let kp:KeyPair = keygen(&p);
        let k:BigUint = random_k(&p);
        let sig:Signature = sign(&p, "Hello", &kp.x, &k,);
        assert!(verify(&p, "Hello", &kp.y, &sig));
    }

    #[test]
    fn encode_decode_secret() {
        let p = params();
        let encoded = encode_secret("mon secret", &p.q).unwrap();
        assert_eq!(decode_secret(&encoded).unwrap(), "mon secret");
    }
}