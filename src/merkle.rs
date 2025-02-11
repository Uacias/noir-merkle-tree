use std::collections::HashMap;

use rs_merkle::{Hasher, MerkleTree};
use starknet_types_core::{felt::Felt, hash::StarkHash};

#[derive(Clone)]
pub struct StarknetPoseidonHasher;

impl Hasher for StarknetPoseidonHasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        // Oczekujemy, że data ma długość 64 bajtów (32 bajty na każdy element)
        assert!(data.len() == 64, "Expected 64 bytes of data");

        let left: [u8; 32] = data[..32].try_into().expect("slice with incorrect length");
        let right: [u8; 32] = data[32..64]
            .try_into()
            .expect("slice with incorrect length");

        let left_felt = Felt::from_bytes_be(&left);
        let right_felt = Felt::from_bytes_be(&right);
        let poseidon_hash = starknet_types_core::hash::Poseidon::hash(&left_felt, &right_felt);
        poseidon_hash.to_bytes_be()
    }
}
const TREE_DEPTH: usize = 12;

const NULL_HASHES: [[u8; 32]; 13] = [
    [
        2, 147, 211, 232, 168, 15, 64, 13, 170, 175, 253, 213, 147, 46, 43, 204, 136, 20, 186, 184,
        244, 20, 167, 93, 202, 207, 135, 49, 143, 139, 20, 197,
    ],
    [
        2, 150, 236, 72, 57, 103, 173, 63, 190, 52, 7, 35, 61, 179, 120, 182, 40, 76, 193, 252,
        199, 141, 98, 69, 123, 151, 164, 190, 103, 68, 173, 13,
    ],
    [
        4, 18, 123, 232, 59, 66, 41, 111, 226, 143, 152, 248, 253, 218, 41, 185, 110, 34, 229, 217,
        5, 1, 247, 211, 27, 132, 231, 41, 236, 47, 172, 63,
    ],
    [
        3, 56, 131, 48, 90, 176, 223, 26, 183, 97, 1, 83, 87, 138, 77, 81, 11, 132, 88, 65, 184,
        77, 144, 237, 153, 49, 51, 206, 76, 232, 248, 39,
    ],
    [
        4, 14, 64, 147, 254, 90, 247, 59, 236, 246, 80, 127, 71, 90, 82, 154, 120, 228, 159, 96,
        69, 57, 234, 95, 53, 71, 5, 155, 94, 127, 16, 118,
    ],
    [
        5, 93, 172, 116, 55, 82, 122, 137, 182, 192, 62, 203, 113, 65, 25, 62, 48, 163, 143, 135,
        50, 79, 61, 162, 47, 59, 140, 231, 65, 26, 136, 205,
    ],
    [
        1, 236, 133, 154, 25, 202, 154, 184, 216, 102, 62, 184, 90, 9, 207, 185, 2, 50, 111, 193,
        75, 58, 33, 33, 86, 158, 210, 132, 122, 156, 34, 191,
    ],
    [
        7, 101, 225, 55, 205, 166, 104, 88, 48, 207, 20, 236, 82, 152, 244, 96, 151, 231, 138, 59,
        224, 106, 161, 91, 236, 237, 144, 127, 26, 34, 217, 253,
    ],
    [
        5, 210, 93, 107, 143, 17, 227, 69, 66, 204, 133, 4, 7, 137, 153, 38, 189, 97, 226, 83, 221,
        119, 100, 119, 153, 97, 81, 246, 85, 79, 61, 161,
    ],
    [
        4, 162, 19, 88, 195, 231, 84, 118, 98, 22, 180, 201, 62, 207, 174, 34, 46, 134, 130, 47,
        116, 110, 112, 110, 86, 63, 58, 5, 239, 57, 137, 89,
    ],
    [
        7, 84, 239, 66, 179, 227, 183, 77, 250, 114, 180, 211, 161, 210, 9, 228, 43, 177, 202, 151,
        255, 44, 136, 255, 24, 85, 52, 95, 91, 53, 126, 72,
    ],
    [
        2, 188, 177, 54, 170, 203, 219, 36, 176, 74, 241, 228, 187, 11, 63, 251, 180, 152, 251, 78,
        24, 238, 208, 169, 234, 109, 103, 209, 227, 100, 72, 59,
    ],
    [
        5, 33, 112, 145, 223, 236, 99, 240, 81, 51, 81, 160, 8, 32, 137, 111, 210, 234, 202, 101,
        105, 8, 72, 55, 60, 249, 194, 132, 4, 128, 238, 127,
    ],
];

pub struct Merkle {
    tree: MerkleTree<StarknetPoseidonHasher>,
    leaves: HashMap<usize, [u8; 32]>,
}

impl Merkle {
    pub fn new() -> Self {
        let tree = MerkleTree::<StarknetPoseidonHasher>::new();
        Self {
            tree,
            leaves: HashMap::new(),
        }
    }

    pub fn add_leaf(&mut self, index: usize, leaf: Felt) {
        let leaf_bytes = leaf.to_bytes_be();
        self.leaves.insert(index, leaf_bytes);
    }

    pub fn get_root(&self) -> Felt {
        let mut computed_tree = MerkleTree::<StarknetPoseidonHasher>::new();
        let mut all_leaves = vec![NULL_HASHES[0]; 2usize.pow(TREE_DEPTH as u32)];

        for (&index, &leaf) in &self.leaves {
            all_leaves[index] = leaf;
        }

        computed_tree.append(&mut all_leaves);
        computed_tree.commit();

        let root = computed_tree.root().unwrap_or(NULL_HASHES[TREE_DEPTH]);

        println!("Computed empty root: {:?}", computed_tree.root());
        println!("Expected empty root: {:?}", NULL_HASHES[TREE_DEPTH]);

        Felt::from_bytes_be(&root)
    }

    pub fn get_proof(&self, index: usize) -> Vec<[u8; 32]> {
        let mut computed_tree = MerkleTree::<StarknetPoseidonHasher>::new();
        let mut all_leaves = vec![NULL_HASHES[0]; 2usize.pow(TREE_DEPTH as u32)];

        for (&index, &leaf) in &self.leaves {
            all_leaves[index] = leaf;
        }

        computed_tree.append(&mut all_leaves);
        computed_tree.commit();

        let mut proof = computed_tree.proof(&[index]).proof_hashes().to_vec();

        while proof.len() < TREE_DEPTH {
            let null_level = proof.len();
            proof.push(NULL_HASHES[null_level]);
        }

        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree_root() {
        let merkle = Merkle::new();
        let computed_root = merkle.get_root();
        let expected_root = Felt::from_bytes_be(&NULL_HASHES[TREE_DEPTH]);

        assert_eq!(
            computed_root, expected_root,
            "invalid empty trie root! \ncomputed: {:?}\nexpected: {:?}",
            computed_root, expected_root
        );
    }

    #[test]
    fn test_add_leaf_changes_root() {
        let mut merkle = Merkle::new();
        let old_root = merkle.get_root();

        let leaf = Felt::from(42);
        merkle.add_leaf(0, leaf);
        let new_root = merkle.get_root();

        assert_ne!(old_root, new_root, "Root the same after insert!");
    }

    #[test]
    fn test_proof_length() {
        let mut merkle = Merkle::new();
        merkle.add_leaf(0, Felt::from(42));
        let proof = merkle.get_proof(0);

        assert_eq!(proof.len(), TREE_DEPTH, "bad proof len");
    }
}
