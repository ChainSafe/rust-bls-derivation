extern crate crypto;
extern crate num_bigint as bigint;
extern crate num_traits;
use bigint::{BigUint, ToBigUint};
use num_traits::Pow;
use num_traits::Num;

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

pub fn hkdf_mod_r(ikm: &[u8]) -> BigUint {
    let mut okm: Vec<u8> = repeat(0).take(48).collect();
    hkdf("BLS-SIG-KEYGEN-SALT-".as_bytes(), ikm, &mut okm);
    let r = BigUint::from_str_radix("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16).unwrap();
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
    return parsed.iter().map(|node| node.parse::<BigUint>().unwrap()).collect();
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
        ).unwrap();

        assert_eq!(derived_master_sk, master_sk);

        let child_index = BigUint::from_u64(0).unwrap();
        let pk = parent_sk_to_lamport_pk(master_sk, child_index);
        let expected_pk = match hex::decode("672ba456d0257fe01910d3a799c068550e84881c8d441f8f5f833cbd6c1a9356") {
            Ok(v) => v,
            Err(_) => return,
        };

        assert_eq!(expected_pk, pk);
    }
}
