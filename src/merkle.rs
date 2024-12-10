use sha3::{Digest, Sha3_256};

type Hash = [u8; 32];

struct MerkleTree {
    tree: Vec<Hash>,   // This will be a binary tree represented as a vector
    leaves: Vec<Hash>, // This will be uses to add new elements to the tree
}

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

    /// Generate proof for a given leaf index.
    pub fn generate_proof(self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }
        // init proof vector
        let mut proof = vec![];
        let mut current_index = leaf_index;
        let mut level_size = self.leaves.len();
        let mut level_start = 0;

        // Same logic as build to break loop when level_size becomes 1
        while level_size > 1 {
            let if_left = current_index % 2 == 0;
            let sibling_index = if if_left {
                if current_index + 1 < level_size {
                    current_index + 1
                } else {
                    current_index
                }
            } else {
                current_index - 1
            };

            // Add sibling to proof
            proof.push(self.tree[sibling_index]);

            // Move to parent node
            level_start += level_size;
            current_index = index_of_parent_in_level(current_index, level_start, level_size);
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
}
