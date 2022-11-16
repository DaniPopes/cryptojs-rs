use crate::{evpkdf, Error, Result};
use aes::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Aes256,
};
use alloc::{string::String, vec, vec::Vec};
use cbc::{Decryptor, Encryptor};
use core::{fmt, str::FromStr};
use md5::Md5;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

macro_rules! salt_ref {
    ($value:expr) => {{
        #[cfg(feature = "std")]
        {
            Some($value.salt.as_ref())
        }
        #[cfg(not(feature = "std"))]
        {
            $value.salt.as_ref()
        }
    }};
}

/// Encrypts and decrypts data using [AES-256][Aes256], padded in [CBC][cbc] mode using
/// [PKCS7][Pkcs7].
///
/// The key and IV are derived from a password and salt using [evpkdf][evpkdf::evpkdf].
///
/// Fully compatible with [CryptoJS](https://www.npmjs.com/package/crypto-js)'s default AES.encrypt() and AES.decrypt().
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedValue {
    pub salt: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Default for EncryptedValue {
    fn default() -> Self {
        Self { salt: vec![0u8; Self::SALT_LEN], ciphertext: Vec::default() }
    }
}

impl FromStr for EncryptedValue {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl fmt::Display for EncryptedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.format())
    }
}

impl fmt::Debug for EncryptedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedValue")
            .field("salt", &hex::encode(&self.salt))
            .field("ciphertext", &hex::encode(&self.ciphertext))
            .finish()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for EncryptedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl Serialize for EncryptedValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.format())
    }
}

impl EncryptedValue {
    /// The length of the [magic value](https://github.com/brix/crypto-js/blob/4dcaa7afd08f48cd285463b8f9499cdb242605fa/src/cipher-core.js#L589).
    pub const MAGIC_LEN: usize = 8;
    /// The [magic value](https://github.com/brix/crypto-js/blob/4dcaa7afd08f48cd285463b8f9499cdb242605fa/src/cipher-core.js#L589) that prefixes all data.
    pub const MAGIC: &'static [u8; Self::MAGIC_LEN] = b"Salted__";

    /// The [salt byte length](https://github.com/brix/crypto-js/blob/4dcaa7afd08f48cd285463b8f9499cdb242605fa/src/cipher-core.js#L771).
    pub const SALT_LEN: usize = Self::MAGIC_LEN;

    /// Encrypts data.
    ///
    /// # Example
    ///
    /// ```
    /// use cryptojs_rs::EncryptedValue;
    ///
    /// let value = EncryptedValue::encrypt("my secret data", "password123", None).unwrap();
    /// ```
    pub fn encrypt<V: AsRef<[u8]>, P: AsRef<[u8]>>(
        value: V,
        password: P,
        #[cfg(feature = "std")] salt: Option<&[u8]>,
        #[cfg(not(feature = "std"))] salt: &[u8],
    ) -> Result<Self> {
        let (salt, key) = keygen(password, salt)?;
        let aes = Encryptor::<Aes256>::new_from_slices(&key[..32], &key[32..]).unwrap();

        let value = value.as_ref();
        let len = value.len();
        let mut buf = Vec::with_capacity(len * 2);
        buf.extend_from_slice(value);
        buf.extend(core::iter::repeat(0u8).take(len));

        // Pad using CBC and Pkcs7: <https://github.com/brix/crypto-js/blob/4dcaa7afd08f48cd285463b8f9<499cdb242605fa/src/cipher-core.js#L437-L440>
        let ciphertext = aes.encrypt_padded_mut::<Pkcs7>(&mut buf, len).unwrap();
        Ok(Self { salt, ciphertext: ciphertext.to_vec() })
    }

    /// Decrypts data.
    ///
    /// # Example
    ///
    /// ```
    /// use cryptojs_rs::EncryptedValue;
    ///
    /// let data = "my secret data";
    /// let password = "password123";
    ///
    /// let value = EncryptedValue::encrypt(data, password, None).unwrap();
    ///
    /// let bytes = value.decrypt(password).unwrap();
    /// let decrypted = String::from_utf8(bytes).unwrap();
    /// assert_eq!(decrypted, data);
    /// ```
    pub fn decrypt<P: AsRef<[u8]>>(&self, password: P) -> Result<Vec<u8>> {
        let (_, key) = keygen(password, salt_ref!(self))?;
        let aes = Decryptor::<Aes256>::new_from_slices(&key[..32], &key[32..]).unwrap();

        let len = self.ciphertext.len();
        let mut buf = Vec::with_capacity(len);
        buf.extend_from_slice(&self.ciphertext);

        match aes.decrypt_padded_mut::<Pkcs7>(&mut buf) {
            Ok(ciphertext) => Ok(ciphertext.to_vec()),
            Err(_) => Err(Error::InvalidPassword),
        }
    }

    /// Formats the encrypted value using the OpenSSL formatting strategy.
    ///
    /// Ref: <https://github.com/brix/crypto-js/blob/4dcaa7afd08f48cd285463b8f9499cdb242605fa/src/cipher-core.js#L580>
    ///
    /// # Example
    ///
    /// ```
    /// use cryptojs_rs::EncryptedValue;
    ///
    /// let value = EncryptedValue::encrypt("my secret data", "password123", None).unwrap();
    /// let formatted1 = value.format();
    /// // or using the Display impl
    /// let formatted2 = format!("{value}");
    /// // or using the derived ToString impl
    /// let formatted3 = value.to_string();
    ///
    /// assert_eq!(formatted1, formatted2);
    /// assert_eq!(formatted2, formatted3);
    /// ```
    pub fn format(&self) -> String {
        let mut ciphertext =
            Vec::with_capacity(Self::MAGIC.len() + self.salt.len() + self.ciphertext.len());
        ciphertext.extend_from_slice(Self::MAGIC);
        ciphertext.extend_from_slice(&self.salt);
        ciphertext.extend_from_slice(&self.ciphertext);
        base64::encode(ciphertext)
    }

    /// Parses an OpenSSL-compatible string.
    ///
    /// Ref: <https://github.com/brix/crypto-js/blob/4dcaa7afd08f48cd285463b8f9499cdb242605fa/src/cipher-core.js#L610>
    ///
    /// # Example
    ///     
    /// ```
    /// use cryptojs_rs::EncryptedValue;
    ///
    /// let data = "my secret data";
    /// let password = "password123";
    ///
    /// let value = EncryptedValue::encrypt(data, password, None).unwrap();
    /// let formatted = value.format();
    ///
    /// let parsed1 = EncryptedValue::parse(&formatted).unwrap();
    /// // or using the FromStr impl
    /// use std::str::FromStr;
    /// let parsed2 = EncryptedValue::from_str(&formatted).unwrap();
    /// // or using str::parse
    /// let parsed3 = formatted.parse().unwrap();
    ///
    /// assert_eq!(parsed1, parsed2);
    /// assert_eq!(parsed2, parsed3);
    ///
    /// assert_eq!(parsed1, value);
    /// ```
    pub fn parse<T: AsRef<str>>(s: T) -> Result<Self> {
        let s = s.as_ref();
        let data = base64::decode(s)?;
        if data.len() < Self::MAGIC_LEN || &data[..Self::MAGIC_LEN] != Self::MAGIC {
            return Err(Error::InvalidInput)
        }
        let salt = data[Self::MAGIC_LEN..Self::MAGIC_LEN + Self::SALT_LEN].into();
        let ciphertext = data[Self::MAGIC_LEN + Self::SALT_LEN..].to_vec();
        Ok(Self { salt, ciphertext })
    }
}

/// Generates a key and IV from a password string.
///
/// Returns (salt, key); `key[..32] == key`, `key[32..] == iv`
///
/// Ref: <https://github.com/brix/crypto-js/blob/4dcaa7afd08f48cd285463b8f9499cdb242605fa/src/cipher-core.js#L750>
fn keygen<T: AsRef<[u8]>>(
    password: T,
    #[cfg(feature = "std")] salt: Option<&[u8]>,
    #[cfg(not(feature = "std"))] salt: &[u8],
) -> Result<(Vec<u8>, [u8; 48])> {
    let password = password.as_ref();
    #[cfg(feature = "std")]
    let salt: Vec<u8> = salt.map(Into::into).unwrap_or_else(|| {
        use rand::{thread_rng, Rng};
        thread_rng().gen::<[u8; EncryptedValue::SALT_LEN]>().into()
    });
    if salt.len() != EncryptedValue::SALT_LEN {
        return Err(Error::InvalidSalt)
    }
    #[cfg(not(feature = "std"))]
    let salt: Vec<u8> = salt.into();
    let mut derived_key = [0u8; 48];
    evpkdf::<Md5>(password, &salt, 1, &mut derived_key);
    Ok((salt, derived_key))
}

#[cfg(test)]
mod tests {
    pub use super::*;
    use alloc::{format, string::ToString};

    const DATA: &str = r#"
a6dcbaded13d2716d2417e5ac791b32481c5c91e91b53cf3ef700638f2167b76;U2FsdGVkX1/Vk4DBQ4Cb0GymgZDyFN4darXwGEBYh6RC9/G7OYBLDKicvFF/YF7uL3yf2/u/2agxWlttg3MPMUg8rG79VdJIq7H4wGScB8ycSox7lbyYXDTw3xXPznmy;a
243a2d54843b914a66600df81a2e459fd7eadeeb55257ad8f2dd624cc34e24a4;U2FsdGVkX1/BEBUtaxjbbDVVltDi3DJk+7pjS0zKzhMpOcmi0n29rX1LNNfbstJY9x6WruOnUVwLb8uOCHwLybryOjE7UtQaMCQcpKGQ/odNVyRd6L3/OOYxB6HGOK95;b
b73e19cb52dacd18ba41321f0d434643b2c02bb7f7d314835400ff40671f4b37;U2FsdGVkX18off7Sg/inn12ivzwIRUrRAqEjRH4VIvP7+578jdKG8t0CvguVqDloJYKY4AFGm3UiXB3obfHVqM7Ydf5LsEgpXs2uCa5txEBO8IRSOBiq5yyekIFH/fGo;c
d45d7a024c0dc3d584fae4c3be11a9f18c9b577125556824b80b7fb2ab08f171;U2FsdGVkX19+1wWI1KlsMZzpxUvqus3fKn7ZJvSuT3zNR/rsvUmvYNl5GT+8P8c17AlQa/Pnm+ehoA7O4dquxYxrXiAlOZcP3qNee4nxvYkww+p+C1bYs5lQ9VVI+gXN;d
386ab1ea0e8fa75647577467f98e30737fa514b9d6cea4c85ccb9086c14e630f;U2FsdGVkX19G70QoEep584eFQ/JOryLfTI4LazGPTsLJmZIvOFenZjshYaf8BliGBJc85iqRjrzUnDDw/KdSXl5x7pOCRcQ+PBlg4LXLgMD58CtHl/SnVLTT+7+n3J77;e
ecbbe62b4402baf84e562d8fd13cada359c372fbb8a69e480b6d4f4b1ba4ec8a;U2FsdGVkX1+/G2WwRpbdQUKaZxHrh/TXQ9WVjTy1/PSjW2MPITaiEl7BG9A7kCh1YX9QADYy/II2TuwW1+mc/xd2ldNK24UeJCqM37xmwNz1E7p7F7xXMyXx0uUJr+4X;f
1d1d61675277c6452cdc5bba66b6f8b5cff7505914d0311383e695245e1b897a;U2FsdGVkX19pShdNW+tj4peHEfd5K2RvvgR6eF2lhvN1bxRiyaXUX4fPEo6LSN8Mn1WnxFlBHdOChEBlffZ9vcyyeu4klnZWT89S8wtQDvT2io4T5w7O+KMlRK985CHI;g
"#;

    fn data() -> Vec<(String, String, String)> {
        DATA.lines()
            .filter_map(|x| {
                if x.is_empty() || x.trim_start().starts_with('#') {
                    None
                } else {
                    let v: Vec<_> = x.split(';').map(|s| s.trim()).collect();
                    Some((v[0].to_string(), v[1].to_string(), v[2].to_string()))
                }
            })
            .collect()
    }

    fn values() -> Vec<(EncryptedValue, String)> {
        data().into_iter().map(|(_, v, p)| (v.parse::<EncryptedValue>().unwrap(), p)).collect()
    }

    #[test]
    fn test_keygen() {
        for (value, password) in values() {
            let (salt, _key) = keygen(password, salt_ref!(value)).unwrap();
            assert_eq!(salt, value.salt);
        }
    }

    #[test]
    fn test_default() {
        let value1 = EncryptedValue::default();
        let s = value1.to_string();
        assert_eq!(s, "U2FsdGVkX18AAAAAAAAAAA==");
        let value2: EncryptedValue = s.parse().unwrap();
        assert_eq!(value1, value2);
    }

    #[test]
    fn test_encryption() {
        for (data, encrypted, password) in data() {
            let parsed: EncryptedValue = encrypted.parse().unwrap();
            assert_eq!(parsed.to_string(), format!("{parsed}"));
            assert_eq!(parsed.to_string(), parsed.format());
            assert_eq!(parsed.to_string(), encrypted);

            let value = EncryptedValue::encrypt(&data, &password, salt_ref!(parsed)).unwrap();
            assert_eq!(value, parsed);

            let decrypted_data = value.decrypt(password).unwrap();
            assert_eq!(String::from_utf8(decrypted_data).unwrap(), data);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        for (value, _) in values() {
            use serde::{Deserialize, Serialize};
            #[derive(Debug, Serialize, Deserialize, PartialEq)]
            struct Test {
                value: EncryptedValue,
            }
            let test = Test { value: value.clone() };
            let s = serde_json::to_string(&test).unwrap();
            assert_eq!(s, format!("{{\"value\":\"{}\"}}", value));
            let test2 = serde_json::from_str(&s).unwrap();
            assert_eq!(test, test2);
        }
    }
}
