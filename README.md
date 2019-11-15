# Rust BLS key derivation (EIP2333, EIP2334)

## Usage

The following functions are available:

Derive master key from seed
```
pub fn derive_master_sk(seed: &[u8]) -> Result<BigUint, String>
```

Derive child key from parent and index:
```
pub fn derive_child(parent_sk: BigUint, index: BigUint) -> BigUint
```

Get path of indexes from a string path following EIP2334 spec
```
pub fn path_to_node(path: String) -> Result<Vec<BigUint>, String>
```

## Testing

run tests with:

```
cargo test
```

