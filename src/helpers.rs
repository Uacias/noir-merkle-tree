use starknet_types_core::{
    felt::Felt,
    hash::{Poseidon, StarkHash},
};

/// Generates a vector of precomputed "null" hashes as Felt values for the given tree height.
/// Here we use a custom base value (which can be set to Felt::ZERO if desired).
pub fn precomputed_hashes(height: usize) -> Vec<Felt> {
    let mut hashes = Vec::with_capacity(height);
    let base_bytes: [u8; 32] = [
        2, 147, 211, 232, 168, 15, 64, 13, 170, 175, 253, 213, 147, 46, 43, 204, 136, 20, 186, 184,
        244, 20, 167, 93, 202, 207, 135, 49, 143, 139, 20, 197,
    ];
    let base = Felt::from_bytes_be(&base_bytes);
    hashes.push(base.clone());
    let mut current = base;
    for _ in 1..height {
        current = Poseidon::hash(&current, &current);
        hashes.push(current.clone());
    }
    hashes
}

/// Simulates the Noir circuit function to compute the Merkle root from a leaf and its proof.
pub fn compute_merkle_root_rust(leaf: Felt, mut index: u32, hash_path: &[Felt]) -> Felt {
    let mut current = leaf;
    for sibling in hash_path {
        if index % 2 == 1 {
            current = Poseidon::hash(sibling, &current);
        } else {
            current = Poseidon::hash(&current, sibling);
        }
        index /= 2;
    }
    current
}
