use alloc::vec::Vec;
use md5::digest::{Digest, FixedOutputReset, HashMarker};

/// The [OpenSSL EVP_BytesToKey key derivation function](https://www.openssl.org/docs/man3.0/man3/EVP_BytesToKey.html).
///
/// Modified from [the `evpkdf` crate](https://github.com/PoiScript/evpkdf/blob/master/src/lib.rs).
pub fn evpkdf<D>(password: &[u8], salt: &[u8], iterations: usize, output: &mut [u8])
where
    D: Default + FixedOutputReset + HashMarker,
{
    let mut hasher = D::default();
    let mut derived_key = Vec::with_capacity(output.len());
    let mut block = Vec::new();

    while derived_key.len() < output.len() {
        if !block.is_empty() {
            hasher.update(&block);
        }
        hasher.update(password);
        hasher.update(salt.as_ref());
        block = hasher.finalize_reset().to_vec();

        // avoid subtract with overflow
        if iterations > 1 {
            for _ in 0..(iterations - 1) {
                hasher.update(&block);
                block = hasher.finalize_reset().to_vec();
            }
        }

        derived_key.extend_from_slice(&block);
    }

    output.copy_from_slice(&derived_key[0..output.len()]);
}
