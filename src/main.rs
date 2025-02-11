use starknet_types_core::hash::StarkHash;

fn main() {
    use starknet_types_core::{felt::Felt, hash::Poseidon};

    let mut null_hashes = Vec::new();

    let base_null = Poseidon::hash(&Felt::from(0), &Felt::from(0)).to_bytes_be();
    null_hashes.push(base_null);

    for i in 1..=12 {
        let parent_hash = Poseidon::hash(
            &Felt::from_bytes_be(&null_hashes[i - 1]),
            &Felt::from_bytes_be(&null_hashes[i - 1]),
        );
        null_hashes.push(parent_hash.to_bytes_be());
    }

    println!("const NULL_HASHES: [[u8; 32]; 13] = {:?};", null_hashes);
}

pub mod merkle;
