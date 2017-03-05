/*
Copyright (c) 2017 angelsl

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

extern crate openssl;
extern crate rustc_serialize;
extern crate crc;
extern crate encoding;

use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::iter::Iterator;
use std::str::FromStr;
use std::mem::{transmute, drop};
use std::env::args;
use std::cmp::min;

use openssl::hash::{MessageDigest, Hasher};
use openssl::symm::{Cipher, Crypter, Mode};
use rustc_serialize::hex::{ToHex, FromHex};
use crc::crc32::checksum_ieee;
use encoding::{Encoding, EncoderTrap};
use encoding::all::UTF_16LE;

fn main() {
    let mut stderr = std::io::stderr();
    macro_rules! next {
        ($argv:expr) => {
            match $argv.next() {
                Some(v) => v,
                None => {
                    drop(writeln!(&mut stderr, "usage: crack7z <hashes file> <dictionary>"));
                    return;
                }
            }
        }
    }
    let mut argv = args();
    next!(argv);
    let hfn = next!(argv);
    let dfn = next!(argv);

    let hf = match File::open(hfn.clone()) {
        Ok(v) => v,
        Err(e) => {
            drop(writeln!(&mut stderr, "failed to open {}: {}", hfn, e));
            return;
        }
    };
    let h = BufReader::new(hf);
    let mut hashes = h.lines().filter_map(|u| u.ok()).filter_map(|s| s.parse().ok()).map(|h| (false, h)).collect::<Vec<(bool, Hash)>>();

    let df = match File::open(dfn.clone()) {
        Ok(v) => v,
        Err(e) => {
            drop(writeln!(&mut stderr, "failed to open {}: {}", dfn, e));
            return;
        }
    };
    let d = BufReader::new(df);
    let mut hasher = match Hasher::new(MessageDigest::sha256()) {
        Ok(v) => v,
        Err(e) => {
            drop(writeln!(&mut stderr, "failed to init sha256: {}", e));
            return;
        }
    };

    for (cnt, candidate) in d.lines().filter_map(|u| u.ok()).enumerate() {
        if cnt & 0x7F == 0 {
            drop(write!(&mut stderr, "{}..", cnt));
        }
        let mut nosaltkey: Option<Vec<u8>> = None;
        for &mut (ref mut done, ref hash) in hashes.iter_mut() {
            let saltkey;
            let key = if hash.salt.is_some() {
                saltkey = match transform_key(hash, &candidate, &mut hasher) {
                    Ok(v) => v,
                    Err(e) => {
                        drop(writeln!(&mut stderr, "{}", e));
                        continue;
                    }
                };
                &saltkey
            } else {
                if let Some(ref k) = nosaltkey {
                    k
                } else {
                    nosaltkey = match transform_key(hash, &candidate, &mut hasher) {
                        Ok(v) => Some(v),
                        Err(e) => {
                            drop(writeln!(&mut stderr, "{}", e));
                            continue;
                        }
                    };
                    nosaltkey.as_ref().unwrap()
                }
            };
            let r = match try_key(hash, &key) {
                Ok(v) => v,
                Err(e) => {
                    drop(writeln!(&mut stderr, "{}", e));
                    continue;
                }
            };
            if r {
                println!("{} <=> {}", hash.enc_data.to_hex(), candidate);
                drop(write!(&mut stderr, "*"));
                *done = true;
            }
        }

        hashes.retain(|&(d, _)| !d);
    }
}

fn transform_key(hash: &Hash, pass: &str, hasher: &mut Hasher) -> Result<Vec<u8>, String> {
    let pass_bytes = UTF_16LE.encode(pass, EncoderTrap::Strict).map_err(|e| format!("failed to encode password as utf16le: {}", e))?;
    let pass_len = pass_bytes.len();
    let salt_len = hash.salt.as_ref().map_or(0, |s| s.len());
    if hash.cost == 0x3f {
        let mut key_vec = vec![0u8; 32];
        let salt_len = min(salt_len, 32);
        let pass_len = min(32 - salt_len, pass_len);
        if let Some(ref salt) = hash.salt {
            key_vec[0..salt_len].copy_from_slice(&salt[0..salt_len]);
        }
        key_vec[salt_len..32].copy_from_slice(&pass_bytes[0..pass_len]);
        Ok(key_vec)
    } else {
        let rounds: usize = 1 << hash.cost;
        let buflen = salt_len + pass_len + 8;
        let mut buf: Vec<u8> = Vec::with_capacity(buflen);
        unsafe { buf.set_len(buflen); }
        if let Some(ref salt) = hash.salt {
            buf[0..salt_len].copy_from_slice(&salt);
        }
        buf[salt_len..salt_len + pass_len].copy_from_slice(&pass_bytes);
        for ctr in 0..rounds {
            buf[salt_len + pass_len..].copy_from_slice(&unsafe { transmute::<_, [u8; 8]>(ctr.to_le()) });
            hasher.update(&buf).map_err(|e| format!("failed to transform key (1): {}", e))?;
        }
        hasher.finish().map_err(|e| format!("failed to transform key (2): {}", e))
    }
}

fn try_key(hash: &Hash, key: &[u8]) -> Result<bool, String> {
    let mut crypter = Crypter::new(Cipher::aes_256_cbc(), Mode::Decrypt, key, Some(&hash.iv)).map_err(|e| format!("failed to init decrypter: {}", e))?;
    crypter.pad(false);
    let mut dec = vec![0; hash.enc_data.len() + 16];
    crypter.update(&hash.enc_data, &mut dec).map_err(|e| format!("failed to decrypt (1): {}", e))?;;
    crypter.finalize(&mut dec).map_err(|e| format!("failed to init decrypt (2): {}", e))?;
    if hash.data_type != 0 {
        // TODO decompress and check
        for &b in dec[hash.dec_len..].iter() {
            if b == 0 {
                return Ok(true);
            }
        }
    }
    dec.truncate(hash.dec_len);
    Ok(checksum_ieee(&dec) == hash.crc32)
}

#[derive(Debug, PartialEq)]
struct Hash {
    data_type: u32,
    cost: u32,
    salt: Option<Vec<u8>>,
    iv: [u8; 16],
    enc_data: Vec<u8>,
    dec_len: usize,
    crc32: u32
    // TODO: non-raw data
}

impl FromStr for Hash {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Hash, &'static str> {
        /*
        # "$"
        # [1] "7z"
        # "$"
        # [2] [data type indicator]           # see "Explanation of the data type indicator" below
        # "$"
        # [3] [cost factor]                   # means: 2 ^ [cost factor] iterations
        # "$"
        # [4] [length of salt]
        # "$"
        # [5] [salt]
        # "$"
        # [6] [length of iv]                  # the initialization vector length
        # "$"
        # [7] [iv]                            # the initialization vector itself
        # "$"
        # [8] [CRC32]                         # the actual "hash"
        # "$"
        # [9] [length of encrypted data]      # the encrypted data length in bytes
        # "$"
        # [10] [length of decrypted data]      # the decrypted data length in bytes
        # "$"
        # [11] [encrypted data]                # the encrypted (and possibly also compressed data)

        # in case the data was not truncated and a decompression step is needed to verify the CRC32, these fields are appended:
        # "$"
        # [12] [length of data for CRC32]      # the length of the first "file" needed to verify the CRC32 checksum
        # "$"
        # [13] [coder attributes]              # most of the coders/decompressors need some attributes (e.g. encoded lc, pb, lp, dictSize values);
        */
        let mut split = s.split('$');
        split.next().ok_or("no '$' in string")?;
        if split.next().ok_or("magic '7z' missing")? != "7z" {
            return Err("magic wrong");
        }
        let data_type: u32 = split.next().ok_or("data type missing")?.parse().or(Err("data type is invalid u32"))?;
        let cost: u32 = split.next().ok_or("cost missing")?.parse().or(Err("cost is invalid u32"))?;
        let salt_len: usize = split.next().ok_or("salt length missing")?.parse().or(Err("salt length is invalid usize"))?;
        let salt_str = split.next().ok_or("salt missing")?;
        let iv_len: usize = min(16, split.next().ok_or("iv length missing")?.parse().or(Err("iv length is invalid usize"))?);
        let iv_str = split.next().ok_or("iv missing")?;
        let crc32: u32 = split.next().ok_or("crc32 missing")?.parse().or(Err("crc32 is invalid u32"))?;
        let enc_len: usize = split.next().ok_or("encrypted data length missing")?.parse().or(Err("encrypted data length is invalid usize"))?;
        let dec_len: usize = split.next().ok_or("decrypted data length missing")?.parse().or(Err("decrypted data length is invalid usize"))?;
        let enc_str = split.next().ok_or("encrypted data missing")?;

        if salt_str.len() < salt_len * 2 {
            return Err("salt hex data too short for length given");
        }

        if iv_str.len() < iv_len * 2 {
            return Err("iv hex data too short for length given");
        }

        if enc_str.len() < enc_len * 2 {
            return Err("encrypted hex data too short for length given");
        }
        let iv_vec = iv_str[0..iv_len*2].from_hex().or(Err("failed to parse iv hex data"))?;
        let mut iv_arr = [0u8; 16];
        iv_arr[0..iv_len].copy_from_slice(&iv_vec);
        Ok(Hash {
            data_type: data_type,
            cost: cost & 0x3f,
            dec_len: dec_len,
            crc32: crc32,
            salt: if salt_len == 0 { None } else { Some(salt_str[0..salt_len*2].from_hex().or(Err("failed to parse salt hex data"))?) },
            iv: iv_arr,
            enc_data: enc_str[0..enc_len*2].from_hex().or(Err("failed to parse encrypted hex data"))?
        })
    }
}

#[cfg(test)]
mod test {
    use {Hash, transform_key, try_key};
    use openssl::hash::{MessageDigest, Hasher};
    use rustc_serialize::hex::FromHex;

    macro_rules! hash {
        () => {
            Hash {
                data_type: 0,
                cost: 19,
                dec_len: 98,
                crc32: 1455749825,
                salt: None,
                iv: [0x8e, 0x67, 0x8c, 0xd9, 0x4b, 0x7d, 0x2f, 0xcf, 0, 0, 0, 0, 0, 0, 0, 0],
                enc_data: "4909b7c9e899a73b58d5fc8b4b64c60a56bf4f5a0e2c4c708ecee4e105c67cc7a179d7cc6f6715d764c1c0ec2ac31e7cdf0e06a9c7562e6dfe95997f74442a42c4bf5c3198abf729854e492558bd3a8f79099971a24312f55d57136ffa7a0cf2164699e29e0f2fa62df9c142db7f85d3".from_hex().unwrap()
            };
        }
    }

    macro_rules! hash_str {
        () => { "$7z$0$19$0$$8$8e678cd94b7d2fcf0000000000000000$1455749825$112$98$4909b7c9e899a73b58d5fc8b4b64c60a56bf4f5a0e2c4c708ecee4e105c67cc7a179d7cc6f6715d764c1c0ec2ac31e7cdf0e06a9c7562e6dfe95997f74442a42c4bf5c3198abf729854e492558bd3a8f79099971a24312f55d57136ffa7a0cf2164699e29e0f2fa62df9c142db7f85d3" }
    }

    #[test]
    pub fn parse() {
        assert_eq!(hash_str!().parse::<Hash>().unwrap(), hash!());
    }

    #[test]
    pub fn check() {
        let hash = hash!();
        let key = transform_key(&hash, "test", &mut Hasher::new(MessageDigest::sha256()).unwrap()).unwrap();
        assert_eq!(key, "886660203C30B116AC07BC8D24066697F35E476E7F07D6118EA9F27FBFB5D27B".from_hex().unwrap());
        assert!(try_key(&hash, &key).unwrap());
    }
}
