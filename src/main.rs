extern crate crypto;
extern crate num_bigint as bigint;
extern crate num_traits;
use bigint::{BigUint, ToBigUint};
use crypto::digest::Digest;
use crypto::hkdf::{hkdf_expand, hkdf_extract};
use crypto::sha2::Sha256;
use num_traits::{Num, Pow};

use std::iter::repeat;

const DIGEST_SIZE: usize = 32;
const NUM_DIGESTS: usize = 255;
const OUTPUT_SIZE: usize = DIGEST_SIZE * NUM_DIGESTS;

fn hkdf(salt: &[u8], ikm: &[u8], okm: &mut [u8]) {
    let digest = Sha256::new();
    let prk: &mut [u8] = &mut [0u8; DIGEST_SIZE];
    hkdf_extract(digest, salt, ikm, prk);
    hkdf_expand(digest, prk, b"", okm);
}

fn flip_bits(num: BigUint) -> BigUint {
    return num
        ^ (Pow::pow(
            &ToBigUint::to_biguint(&2).unwrap(),
            &ToBigUint::to_biguint(&256).unwrap(),
        ) - &ToBigUint::to_biguint(&1).unwrap());
}

fn ikm_to_lamport_sk(ikm: &[u8], salt: &[u8], split_bytes: &mut[[u8; DIGEST_SIZE]; NUM_DIGESTS]) {
    let mut okm: Vec<u8> = repeat(0).take(OUTPUT_SIZE).collect();
    hkdf(salt, ikm, &mut okm);
    let mut i = 0;
    for r in 0..NUM_DIGESTS {
        for c in 0..DIGEST_SIZE {
            split_bytes[r][c] = okm[i];
            i += 1;
        }
    }
}

pub fn parent_sk_to_lamport_pk(parent_sk: BigUint, index: BigUint) -> Vec<u8> {
    let salt = index.to_bytes_be();
    let ikm = parent_sk.to_bytes_be();
    let mut lamport_0 = [[0u8; DIGEST_SIZE]; NUM_DIGESTS];
    ikm_to_lamport_sk(ikm.as_slice(), salt.as_slice(), &mut lamport_0);

    let not_ikm = flip_bits(parent_sk).to_bytes_be();
    let mut lamport_1 = [[0u8; DIGEST_SIZE]; NUM_DIGESTS];
    ikm_to_lamport_sk(not_ikm.as_slice(), salt.as_slice(), &mut lamport_1);

    // TODO: find better way to combine 2d byte arrays
    let mut combined = [[0u8; DIGEST_SIZE]; NUM_DIGESTS * 2];
    for i in 0..NUM_DIGESTS {
        combined[i] = lamport_0[i];
        combined[i + NUM_DIGESTS] = lamport_1[i];
    }
    let mut sha256 = Sha256::new();
    let mut flattened_key: Vec<u8> = vec![0u8; OUTPUT_SIZE * 2];
    for i in 0..NUM_DIGESTS * 2 {
        let sha_slice = &mut combined[i];
        sha256.input(sha_slice);
        sha256.result(sha_slice);
        sha256.reset();
        flattened_key[i * DIGEST_SIZE..(i + 1) * DIGEST_SIZE].clone_from_slice(sha_slice);
    }

    sha256.input(flattened_key.as_slice());
    let cmp_pk: &mut [u8] = &mut [0u8; DIGEST_SIZE];
    sha256.result(cmp_pk);
    return cmp_pk.to_vec();
}

pub fn hkdf_mod_r(ikm: &[u8]) -> BigUint {
    let mut okm: Vec<u8> = repeat(0).take(48).collect();
    hkdf("BLS-SIG-KEYGEN-SALT-".as_bytes(), ikm, &mut okm);
    let r = BigUint::from_str_radix(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        16,
    )
    .unwrap();
    return BigUint::from_bytes_be(okm.as_ref()) % r;
}

pub fn derive_child(parent_sk: BigUint, index: BigUint) -> BigUint {
    let lamp_pk = parent_sk_to_lamport_pk(parent_sk, index);
    return hkdf_mod_r(lamp_pk.as_ref());
}

pub fn derive_master_sk(seed: &[u8]) -> BigUint {
    assert_eq!(true, seed.len() >= 16);
    return hkdf_mod_r(seed);
}

// EIP 2334
pub fn path_to_node(path: String) -> Vec<BigUint> {
    let mut parsed: Vec<&str> = path.split('/').collect();
    assert_eq!(parsed.remove(0), "m");
    return parsed
        .iter()
        .map(|node| node.parse::<BigUint>().unwrap())
        .collect();
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
        let seed = hex::decode("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04").unwrap();

        let derived_master_sk = derive_master_sk(seed.as_ref());
        let master_sk = BigUint::from_str_radix(
            "12513733877922233913083619867448865075222526338446857121953625441395088009793",
            10,
        )
        .unwrap();

        assert_eq!(derived_master_sk, master_sk);

        let child_index = BigUint::from_u64(0).unwrap();
        let pk = parent_sk_to_lamport_pk(master_sk, child_index);
        let expected_pk =
            hex::decode("672ba456d0257fe01910d3a799c068550e84881c8d441f8f5f833cbd6c1a9356")
                .unwrap();

        assert_eq!(expected_pk, pk);
    }

    #[test]
    fn test_2334() {
        let orig_pk = BigUint::from_str_radix(
            "12513733877922233913083619867448865075222526338446857121953625441395088009793",
            10,
        )
        .unwrap();
        let paths = path_to_node(String::from("m/5/3/1726/0"));
        let mut prev = orig_pk;
        for path in paths {
            // println!(path);
            let next = derive_child(prev.clone(), path);
            assert_ne!(next, prev);
            prev = next;
        }
    }
}
