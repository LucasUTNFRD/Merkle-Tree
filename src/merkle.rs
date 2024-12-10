use sha3::{Digest, Sha3_256};

type Hash = [u8; 32];

struct Merkle {
    tree: Vec<Hash>, // This will be a binary tree represented as a vector
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

impl Merkle {
    /// Creates a new Merkle tree from a list of data elements.
    /// TODO: Make this function generic to accept any type that can be hashed.
    ///
    pub fn new(data: &[Vec<u8>]) -> Self {
        assert!(!data.is_empty(), "Data must have at least 1 elements");
        let mut tree = Merkle { tree: vec![] };
        tree.build(data);
        tree
    }

    /// Builds the Merkle Tree using a recursive bottom-up approach.
    fn build(&mut self, data: &[Vec<u8>]) {
        // Initialize tree with leaf-level hashes
        let mut current_level: Vec<Hash> = data.iter().map(|element| hash(element)).collect();
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

        let merkle = Merkle::new(&data);

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
    }

    #[test]
    fn test_build_tree_non_power_of_2() {
        // Test data
        let data = vec![b"block1".to_vec(), b"block2".to_vec(), b"block3".to_vec()];

        let merkle = Merkle::new(&data);

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
    }

    #[test]
    fn test_build_tree_single() {
        // Test data
        let data = vec![b"block1".to_vec()];

        let merkle = Merkle::new(&data);

        let leaf1 = hash(&data[0]);

        assert_eq!(merkle.tree.len(), 1);
        assert_eq!(merkle.tree[0], leaf1);
    }

    #[test]
    #[should_panic]
    fn test_build_tree_empty() {
        let data = vec![];
        let _merkle = Merkle::new(&data);
    }
}
