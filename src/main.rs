extern crate crypto;
extern crate num_bigint as bigint;
extern crate num_traits;
use bigint::{BigUint, ToBigUint};
use num_traits::Pow;

use crypto::digest::Digest;
use crypto::hkdf::{hkdf_expand, hkdf_extract};
use crypto::sha2::Sha256;

use std::iter::repeat;

pub fn hkdf(salt: &[u8], ikm: &[u8], okm: &mut [u8]) {
    let digest = Sha256::new();
    let prk: &mut [u8] = &mut [0u8; 32];
    hkdf_extract(digest, salt, ikm, prk);
    hkdf_expand (digest, prk, "".as_bytes(), okm);
}

pub fn flip_bits(num: BigUint) -> BigUint {
    return num
        ^ (Pow::pow(
            &ToBigUint::to_biguint(&2).unwrap(),
            &ToBigUint::to_biguint(&256).unwrap(),
        ) - &ToBigUint::to_biguint(&1).unwrap());
}

fn ikm_to_lamport_sk(ikm: &[u8], salt: &[u8]) -> Vec<Vec<u8>> {
    let mut okm: Vec<u8> = repeat(0).take(8160).collect();
    hkdf(salt, ikm, &mut okm);
    let mut ret_v: Vec<Vec<u8>> = Vec::new();
    for r in 0..255 {
        ret_v.push(Vec::new());
        for c in 0..32 {
            ret_v[r].push(okm[r * 32 + c]);
        }
    }

    return ret_v;
}

pub fn parent_sk_to_lamport_pk(parent_sk: BigUint, index: BigUint) -> Vec<u8> {
    let mut sha256 = Sha256::new();
    let salt = index.to_bytes_be();
    let ikm = parent_sk.to_bytes_be();
    let mut lamport_0 = ikm_to_lamport_sk(ikm.as_slice(), salt.as_slice());

    let not_ikm = flip_bits(parent_sk).to_bytes_be();
    let mut lamport_1 = ikm_to_lamport_sk(not_ikm.as_slice(), salt.as_slice());

    lamport_0.append(&mut lamport_1);
    for sk in &mut lamport_0 {
        sha256.input(sk.as_slice());
        let tmp: &mut [u8] = &mut [0u8; 32];
        sha256.result(tmp);
        *sk = tmp.to_vec();
        sha256.reset();
    }

    let compressed_pk = lamport_0.into_iter().flatten().collect::<Vec<u8>>();
    sha256.input(compressed_pk.as_slice());
    let cmp_pk: &mut [u8] = &mut [0u8; 32];
    sha256.result(cmp_pk);
    return cmp_pk.to_vec();
}

fn main() {}

#[cfg(test)]
mod test {
    use crate::num_traits::{FromPrimitive, Num};
    use crate::*;
    use bigint::BigUint;
    use hex;

    #[test]
    fn test_2333() {
        let master_sk = match BigUint::from_str_radix(
            "12513733877922233913083619867448865075222526338446857121953625441395088009793",
            10,
        ) {
            Ok(v) => v,
            Err(e) => {
                println!("err {}", e);
                return;
            }
        };

        let child_index = match BigUint::from_u64(0) {
            Some(v) => v,
            None => {
                println!("err");
                return;
            }
        };
        let pk = parent_sk_to_lamport_pk(master_sk, child_index);
        let expected_pk = match hex::decode("672ba456d0257fe01910d3a799c068550e84881c8d441f8f5f833cbd6c1a9356") {
            Ok(v) => v,
            Err(_) => return,
        };
        // println!("{:?}", expected_pk);
        // println!("{:?}", pk);
        assert_eq!(expected_pk, pk);
    }
}
