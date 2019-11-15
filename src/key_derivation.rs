extern crate crypto;
extern crate num_bigint as bigint;
extern crate num_traits;
use bigint::{BigUint, ToBigUint};
use crypto::digest::Digest;
use crypto::hkdf::{hkdf_expand, hkdf_extract};
use crypto::sha2::Sha256;
use num_traits::{Num, Pow};

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
    num ^ (Pow::pow(
        &ToBigUint::to_biguint(&2).unwrap(),
        &ToBigUint::to_biguint(&256).unwrap(),
    ) - &ToBigUint::to_biguint(&1).unwrap())
}

fn ikm_to_lamport_sk(ikm: &[u8], salt: &[u8], split_bytes: &mut [[u8; DIGEST_SIZE]; NUM_DIGESTS]) {
    let mut okm = [0u8; OUTPUT_SIZE];
    hkdf(salt, ikm, &mut okm);
    let mut i = 0;
    for row in split_bytes.iter_mut().take(NUM_DIGESTS) {
        for c in row.iter_mut().take(DIGEST_SIZE) {
            *c = okm[i];
            i += 1;
        }
    }
}

fn parent_sk_to_lamport_pk(parent_sk: BigUint, index: BigUint) -> Vec<u8> {
    let salt = index.to_bytes_be();
    let ikm = parent_sk.to_bytes_be();
    let mut lamport_0 = [[0u8; DIGEST_SIZE]; NUM_DIGESTS];
    ikm_to_lamport_sk(ikm.as_slice(), salt.as_slice(), &mut lamport_0);

    let not_ikm = flip_bits(parent_sk).to_bytes_be();
    let mut lamport_1 = [[0u8; DIGEST_SIZE]; NUM_DIGESTS];
    ikm_to_lamport_sk(not_ikm.as_slice(), salt.as_slice(), &mut lamport_1);

    let mut combined = [[0u8; DIGEST_SIZE]; NUM_DIGESTS * 2];
    combined[..NUM_DIGESTS].clone_from_slice(&lamport_0[..NUM_DIGESTS]);
    combined[NUM_DIGESTS..NUM_DIGESTS * 2].clone_from_slice(&lamport_1[..NUM_DIGESTS]);

    let mut sha256 = Sha256::new();
    let mut flattened_key = [0u8; OUTPUT_SIZE * 2];
    for i in 0..NUM_DIGESTS * 2 {
        let sha_slice = &mut combined[i];
        sha256.input(sha_slice);
        sha256.result(sha_slice);
        sha256.reset();
        flattened_key[i * DIGEST_SIZE..(i + 1) * DIGEST_SIZE].clone_from_slice(sha_slice);
    }

    sha256.input(&flattened_key);
    let cmp_pk: &mut [u8] = &mut [0u8; DIGEST_SIZE];
    sha256.result(cmp_pk);
    cmp_pk.to_vec()
}

fn hkdf_mod_r(ikm: &[u8]) -> BigUint {
    let mut okm = [0u8; 48];
    hkdf(b"BLS-SIG-KEYGEN-SALT-", ikm, &mut okm);
    let r = BigUint::from_str_radix(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        16,
    )
    .unwrap();
    BigUint::from_bytes_be(okm.as_ref()) % r
}

pub fn derive_child(parent_sk: BigUint, index: BigUint) -> BigUint {
    let lamp_pk = parent_sk_to_lamport_pk(parent_sk, index);
    hkdf_mod_r(lamp_pk.as_ref())
}

pub fn derive_master_sk(seed: &[u8]) -> Result<BigUint, String> {
    if seed.len() < 16 {
        return Err("seed must be greater than or equal to 16 bytes".to_string());
    }

    Ok(hkdf_mod_r(seed))
}

// EIP 2334
pub fn path_to_node(path: String) -> Result<Vec<BigUint>, String> {
    let mut parsed: Vec<&str> = path.split('/').collect();
    let m = parsed.remove(0);
    if m != "m" {
        return Err(format!("First value must be m, got {}", m));
    }

    let mut ret: Vec<BigUint> = vec![];
    for value in parsed {
        match value.parse::<BigUint>() {
            Ok(v) => ret.push(v),
            Err(_) => return Err(format!("could not parse value: {}", value)),
        }
    }

    Ok(ret)
}

#[cfg(test)]
mod test {
    use super::bigint::BigUint;
    use super::*;
    use hex;
    use num_traits::{FromPrimitive, Num};

    struct TestVector {
        seed: &'static str,
        master_sk: &'static str,
        child_index: &'static str,
        child_sk: &'static str,
    }

    #[test]
    fn test_2333() {
        let test_vectors = vec!(
                    TestVector{
                        seed : "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                        master_sk : "12513733877922233913083619867448865075222526338446857121953625441395088009793",
                        child_index : "0",
                        child_sk : "7419543105316279183937430842449358701327973165530407166294956473095303972104",
                    },
                    // TestVector{
                    //     seed: "3141592653589793238462643383279502884197169399375105820974944592",
                    //     master_sk: "46029459550803682895343812821003080589696405386150182061394330539196052371668",
                    //     child_index: "3141592653589793238462643383279502884197169399375105820974944592",
                    //     child_sk: "52355059779601818323170390700812190085791545700943775185630512585202016942671",
                    // },
                    TestVector{
                        seed: "0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
                        master_sk: "45379166311535261329029945990467475187325618028073620882733843918126031931161",
                        child_index: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                        child_sk: "3001977934078166987926353732839098506754809480904566732795462937312900783942",
                    },
                    TestVector{
                        seed: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                        master_sk: "8591296517642752610571443601667923790682754368613740552668934360711284428110",
                        child_index: "96295644508963302359223866841007920022480890644992946816264522587871600414627",
                        child_sk: "18992511018606881439236209510845138630250367286140373438339392563268870207242",
                    }
                );

        for t in test_vectors.iter() {
            let seed = hex::decode(t.seed).expect("invalid seed format");
            let master_sk = t
                .master_sk
                .parse::<BigUint>()
                .expect("invalid master key format");
            let child_index = t
                .child_index
                .parse::<BigUint>()
                .expect("invalid index format");
            let child_sk = t
                .child_sk
                .parse::<BigUint>()
                .expect("invalid child key format");

            let derived_master_sk = derive_master_sk(seed.as_ref()).unwrap();
            assert_eq!(derived_master_sk, master_sk);
            let pk = derive_child(master_sk, child_index);
            assert_eq!(child_sk, pk);
        }
    }

    #[test]
    fn test_2334() {
        let orig_pk = BigUint::from_str_radix(
            "12513733877922233913083619867448865075222526338446857121953625441395088009793",
            10,
        )
        .unwrap();
        let mut invalid_path = path_to_node(String::from("m/a/3s/1726/0"));
        invalid_path.expect_err("This path should be invalid");
        invalid_path = path_to_node(String::from("1/2"));
        invalid_path.expect_err("Path must include a m");
        invalid_path = path_to_node(String::from("m"));
        assert_eq!(invalid_path.unwrap(), vec![]);
        let paths = path_to_node(String::from("m/5/3/1726/0")).unwrap();
        let mut prev = orig_pk.clone();
        for path in paths {
            let next = derive_child(prev.clone(), path);
            assert_ne!(next, prev);
            prev = next;
        }
        let mut other = orig_pk.clone();
        other = derive_child(other.clone(), BigUint::from_u64(5).unwrap());
        other = derive_child(other.clone(), BigUint::from_u64(3).unwrap());
        other = derive_child(other.clone(), BigUint::from_u64(1726).unwrap());
        assert_ne!(prev, other);
        other = derive_child(other.clone(), BigUint::from_u64(0).unwrap());
        assert_eq!(prev, other)
    }
}
