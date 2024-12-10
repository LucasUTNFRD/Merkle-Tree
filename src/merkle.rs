use sha3::{Digest, Sha3_256};

macro_rules! debug {
    ($($arg:tt)*) => {
        #[cfg(test)]
        println!($($arg)*);
    };
}

type Hash = [u8; 32];

#[derive(Debug)]
struct MerkleTree {
    tree: Vec<Hash>,   // This will be a binary tree represented as a vector
    leaves: Vec<Hash>, // This will be uses to add new elements to the tree
}

#[derive(Debug)]
struct MerkleProof {
    proof: Vec<Hash>,
}

fn hash(element: &[u8]) -> Hash {
    Sha3_256::digest(element).into()
}

// Helper function to hash two internal nodes
fn hash_internal_node(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn index_of_parent_in_level(current_index: usize, level_start: usize, level_size: usize) -> usize {
    level_start + (current_index - (level_start - level_size)) / 2
}

impl MerkleTree {
    /// Creates a new Merkle tree from a list of data elements.
    /// TODO: Make this function generic to accept any type that can be hashed.
    /// TODO:  Return an error if the data is empty.
    pub fn new(data: &[Vec<u8>]) -> Self {
        assert!(!data.is_empty(), "Data must have at least 1 elements");
        let leaves: Vec<Hash> = data.iter().map(|element| hash(element)).collect();
        let mut tree = MerkleTree {
            tree: vec![],
            leaves,
        };
        tree.build();
        tree
    }

    /// Builds the Merkle Tree using a recursive bottom-up approach.
    fn build(&mut self) {
        // Initialize tree with leaf-level hashes
        let mut current_level = self.leaves.clone();
        let mut tree = current_level.clone();

        // Build tree bottom-up
        let mut count_leaves = current_level.len();
        while count_leaves > 1 {
            let mut level_hashes: Vec<Hash> = vec![];
            for i in (0..count_leaves).step_by(2) {
                if i + 1 < count_leaves {
                    // Combine adjacent hashes
                    level_hashes.push(hash_internal_node(&current_level[i], &current_level[i + 1]));
                } else {
                    // Clone the last hash to create a pair
                    level_hashes.push(hash_internal_node(&current_level[i], &current_level[i]));
                }
            }

            // Update current level and extend tree
            current_level = level_hashes.clone();
            tree.extend(level_hashes);
            count_leaves = (count_leaves + 1) / 2;
        }

        self.tree = tree;
    }

    /// Returns the root hash of the Merkle tree.
    pub fn root(&self) -> Hash {
        *self.tree.last().unwrap()
    }

    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = leaf_index;
        let mut level_size = self.leaves.len();
        let mut offset = 0;

        // Same logic as build()
        while level_size > 1 {
            // Calculate sibling index
            let sibling_index = if current_index % 2 == 0 {
                // If current_index is even, sibling is to the right
                if current_index + 1 < offset + level_size {
                    current_index + 1
                } else {
                    // If no right sibling exists, use current node
                    current_index
                }
            } else {
                // If current_index is odd, sibling is to the left
                current_index - 1
            };

            // Add sibling to proof
            proof.push(self.tree[sibling_index]);

            // Move to parent level
            offset += level_size;
            // Calculate parent index
            // current_index = offset + (current_index - (offset - level_size)) / 2;
            current_index = offset + (current_index % level_size) / 2;
            level_size = (level_size + 1) / 2;
        }

        Some(MerkleProof { proof })
    }

    /// Validate a Merkle proof
    pub fn generate_verify() {
        todo!()
    }

    /// Should update a leef at the bottom most level of the tree
    pub fn set() {
        todo!()
    }

    pub fn add(&mut self, data: Vec<u8>) {
        // Add to the leaves and rebuild the tree
        self.leaves.push(hash(&data));
        self.build();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tree() {
        // Test data
        let data = vec![
            b"block1".to_vec(),
            b"block2".to_vec(),
            b"block3".to_vec(),
            b"block4".to_vec(),
        ];

        let merkle = MerkleTree::new(&data);

        // Verify tree structure is not empty
        assert!(!merkle.tree.is_empty());

        // Manually calculate expected hashes
        let leaf1 = hash(&data[0]);
        let leaf2 = hash(&data[1]);
        let leaf3 = hash(&data[2]);
        let leaf4 = hash(&data[3]);

        // Calculate internal nodes
        let internal1 = hash_internal_node(&leaf1, &leaf2);
        let internal2 = hash_internal_node(&leaf3, &leaf4);

        // Calculate root
        let root = hash_internal_node(&internal1, &internal2);

        // A merkle tree built from 4 elements should have 7 nodes
        assert_eq!(merkle.tree.len(), 7);

        // First 4 elements should be leaf hashes
        assert_eq!(merkle.tree[0], leaf1);
        assert_eq!(merkle.tree[1], leaf2);
        assert_eq!(merkle.tree[2], leaf3);
        assert_eq!(merkle.tree[3], leaf4);

        // Next 2 elements should be internal nodes
        assert_eq!(merkle.tree[4], internal1);
        assert_eq!(merkle.tree[5], internal2);

        assert_eq!(merkle.tree[6], root);
        assert_eq!(merkle.root(), root);
    }

    #[test]
    fn test_build_tree_non_power_of_2() {
        // Test data
        let data = vec![b"block1".to_vec(), b"block2".to_vec(), b"block3".to_vec()];

        let merkle = MerkleTree::new(&data);

        let leaf1 = hash(&data[0]);
        let leaf2 = hash(&data[1]);
        let leaf3 = hash(&data[2]);

        let internal1 = hash_internal_node(&leaf1, &leaf2);
        let internal2 = hash_internal_node(&leaf3, &leaf3);

        let root = hash_internal_node(&internal1, &internal2);

        assert_eq!(merkle.tree.len(), 6);

        assert_eq!(merkle.tree[0], leaf1);
        assert_eq!(merkle.tree[1], leaf2);
        assert_eq!(merkle.tree[2], leaf3);

        assert_eq!(merkle.tree[3], internal1);
        assert_eq!(merkle.tree[4], internal2);

        assert_eq!(merkle.tree[5], root);
        assert_eq!(merkle.root(), root);
    }

    #[test]
    fn test_build_tree_single() {
        // Test data
        let data = vec![b"block1".to_vec()];

        let merkle = MerkleTree::new(&data);

        let leaf1 = hash(&data[0]);

        assert_eq!(merkle.tree.len(), 1);
        assert_eq!(merkle.tree[0], leaf1);
    }

    #[test]
    #[should_panic]
    fn test_build_tree_empty() {
        let data = vec![];
        let _merkle = MerkleTree::new(&data);
    }

    #[test]
    fn test_get_root() {
        let data = vec![
            b"block1".to_vec(),
            b"block2".to_vec(),
            b"block3".to_vec(),
            b"block4".to_vec(),
        ];

        let merkle = MerkleTree::new(&data);
        let root = merkle.root();

        let leaf1 = hash(&data[0]);
        let leaf2 = hash(&data[1]);
        let leaf3 = hash(&data[2]);
        let leaf4 = hash(&data[3]);

        let internal1 = hash_internal_node(&leaf1, &leaf2);
        let internal2 = hash_internal_node(&leaf3, &leaf4);

        let expected_root = hash_internal_node(&internal1, &internal2);

        assert_eq!(root, expected_root);
    }

    #[test]
    fn test_generate_proof_four_leaves() {
        let data = vec![
            b"block1".to_vec(),
            b"block2".to_vec(),
            b"block3".to_vec(),
            b"block4".to_vec(),
        ];
        let merkle = MerkleTree::new(&data);

        let proof = merkle.generate_proof(1).unwrap();

        //            root
        //              6
        //           /    \
        //         AB       CD
        //          4       5
        //        / \       / \
        //       A    B    C    D
        //       0    1    2    3
        // Proof for B should be [A, CD]
        let elem1 = merkle.tree[0]; // A
        let elem2 = merkle.tree[5]; // CD

        let expected_proof = MerkleProof {
            proof: vec![elem1, elem2],
        };

        assert_eq!(proof.proof, expected_proof.proof);
    }

    #[test]
    fn test_generate_proof_three_leaves() {
        //            root (5)
        //           /        \
        //         AB(3)    CC'(4)
        //        / \         /
        //    A(0)  B(1)   C(2)
        let data = vec![b"block1".to_vec(), b"block2".to_vec(), b"block3".to_vec()];
        let merkle = MerkleTree::new(&data);

        // print the tree size
        println!("Tree size: {:?}", merkle.tree.len());

        // Get proof for leaf B (index 1)
        let proof = merkle.generate_proof(1).unwrap();

        // For debugging
        println!("Tree structure:");
        for (i, hash) in merkle.tree.iter().enumerate() {
            println!("Index {}: {:?}", i, hash);
        }

        // For leaf B (index 1), the proof should contain:
        // 1. Hash of A (sibling at leaf level)
        // 2. Hash of CC' (sibling at internal level)
        let expected_proof = MerkleProof {
            proof: vec![merkle.tree[0], merkle.tree[4]],
        };

        println!("Generated proof: {:?}", proof);
        println!("Expected proof: {:?}", expected_proof);

        assert_eq!(proof.proof, expected_proof.proof);

        // Also test proof for leaf C (index 2)
        let proof_c = merkle.generate_proof(2).unwrap();
        let expected_proof_c = MerkleProof {
            proof: vec![merkle.tree[2], merkle.tree[3]], // [C (duplicate), AB]
        };

        assert_eq!(proof_c.proof, expected_proof_c.proof);
    }
}
