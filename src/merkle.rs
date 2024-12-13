use sha3::{Digest, Sha3_256};

type Hash = [u8; 32];

#[derive(Debug)]
pub enum MerkleError {
    LeafNotFound,
    EmptyData,
}

#[derive(Debug)]
/// Represents a Merkle Tree data structure
/// The tree is represented as a list of levels, where each level is a list of hashes
/// The leaves are stored separately from the internal nodes
/// The root hash is the first element of the last level
pub struct MerkleTree {
    tree: Vec<Vec<Hash>>,
    leaves: Vec<Hash>,
}

#[derive(Debug, PartialEq, Eq)]
enum Direction {
    Left,
    Right,
}

/// Type alias for a Merkle proof
/// A proof is a list of hashes that can be used to verify the membership of a leaf in the tree
/// Each hash has associated a Direction Enum that indicates if the hash is a left or right sibling
type MerkleProof = Vec<(Hash, Direction)>;

fn hash<T: AsRef<[u8]>>(element: T) -> Hash {
    Sha3_256::digest(element).into()
}

/// Hashes two hashes together to create a new hash
fn hash_internal_node(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn determine_direction(index: usize) -> Direction {
    if index % 2 == 0 {
        Direction::Left
    } else {
        Direction::Right
    }
}

impl MerkleTree {
    /// Creates a new Merkle Tree from a list of data elements
    /// The data elements are hashed to create the leaves of the tree
    /// The tree is then built using a recursive bottom-up approach
    ///
    /// # Arguments
    /// a list of data elements that implement AsRef<[u8]>
    ///
    /// # Returns
    /// A MerkleTree instance if the data is not empty, otherwise an error
    ///
    /// # Example
    /// ```
    /// let data = vec![b"block1", b"block2", b"block3"];
    /// let merkle = MerkleTree::new(&data).expect("Should create merkle tree");
    /// ```
    pub fn new<T: AsRef<[u8]>>(data: &[T]) -> Result<Self, MerkleError> {
        if data.is_empty() {
            return Err(MerkleError::EmptyData);
        }
        let leaves: Vec<Hash> = data.iter().map(hash).collect();
        let mut tree = MerkleTree {
            tree: vec![],
            leaves,
        };
        tree.build();
        Ok(tree)
    }

    /// Builds the Merkle Tree using a recursive bottom-up approach.
    fn build(&mut self) {
        let mut levels: Vec<Vec<Hash>> = Vec::new();
        // Add the leaves at first level
        levels.push(self.leaves.clone());

        // Build subsequent levels until we reach the root
        let mut current_level = self.leaves.clone();
        while current_level.len() > 1 {
            let mut next_level: Vec<Hash> = Vec::new();

            // process pair of nodes
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    left
                };

                let parent = hash_internal_node(&left, &right);
                next_level.push(parent);
            }
            levels.push(next_level.clone());
            current_level = next_level;
        }
        self.tree = levels;
    }

    /// Returns the root hash of the Merkle tree.
    pub fn root(&self) -> Hash {
        *self.tree.last().unwrap().first().unwrap()
    }

    /// A proof is a list of hashes that can be used to verify the membership of a leaf in the tree
    /// For now the proof is simply that a  list of hashes.
    /// Possible improvements:
    /// 1. Store the direction of the hash (left or right) and the level of the tree
    pub fn generate_proof<T: AsRef<[u8]>>(&self, data: &T) -> Result<MerkleProof, MerkleError> {
        // Find index of the leaf that corresponds to the given data
        let leaf_index = self
            .leaves
            .iter()
            .position(|leaf| hash(data) == *leaf)
            .ok_or(MerkleError::LeafNotFound)?;

        let mut proof: MerkleProof = Vec::new();
        let mut current_index = leaf_index;
        // loop each level of the tree
        for level in 0..self.tree.len() - 1 {
            let current_level = &self.tree[level];
            // let is_left = current_index % 2 == 0;
            let current_direction = determine_direction(current_index);
            let sibling_index = match current_direction {
                Direction::Left => {
                    if current_index + 1 < current_level.len() {
                        current_index + 1
                    } else {
                        current_index
                    }
                }
                Direction::Right => current_index - 1,
            };
            let sibling_direction = match current_direction {
                Direction::Left => Direction::Right,
                Direction::Right => Direction::Left,
            };
            proof.push((current_level[sibling_index], sibling_direction));

            current_index /= 2;
        }

        Ok(proof)
    }

    /// Validates a Merkle proof for a given piece of data
    /// Returns true if the proof is valid, false otherwise
    pub fn verify_proof<T: AsRef<[u8]>>(&self, data: &T, proof: &MerkleProof) -> bool {
        // First hash the data
        let mut current_hash = hash(data);

        // Get the current root
        let root = self.root();

        // Work up from the leaf to the root using the proof
        for (sibling_hash, sibling_direction) in proof {
            current_hash = match sibling_direction {
                Direction::Left => hash_internal_node(sibling_hash, &current_hash),
                Direction::Right => hash_internal_node(&current_hash, sibling_hash),
            };
        }

        // The final hash should match the root
        current_hash == root
    }

    /// Add a new element to the tree
    /// This will add a new leaf to the tree and rebuild it
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

        let merkle = MerkleTree::new(&data).expect("Should create merkle tree");

        let leaf1 = hash(&data[0]);
        let leaf2 = hash(&data[1]);
        let leaf3 = hash(&data[2]);
        let leaf4 = hash(&data[3]);

        // Calculate internal nodes
        let internal1 = hash_internal_node(&leaf1, &leaf2);
        let internal2 = hash_internal_node(&leaf3, &leaf4);

        // Calculate root
        let _root = hash_internal_node(&internal1, &internal2);

        assert_eq!(_root, merkle.root());

        // A merkle tree built from 4 elements should have 7 nodes and 3 levels
        assert_eq!(merkle.tree.len(), 3);
        let total_nodes: usize = merkle.tree.iter().map(|level| level.len()).sum();
        assert_eq!(total_nodes, 7);

        // Create an expected tree and compare it to the actual tree
        let expected_tree = vec![
            vec![leaf1, leaf2, leaf3, leaf4],
            vec![internal1, internal2],
            vec![_root],
        ];

        assert_eq!(expected_tree, merkle.tree);
    }

    #[test]
    fn test_build_tree_odd_number() {
        let data = vec![b"block1".to_vec(), b"block2".to_vec(), b"block3".to_vec()];

        let merkle = MerkleTree::new(&data).expect("Should create merkle tree");

        let leaf1 = hash(&data[0]);
        let leaf2 = hash(&data[1]);
        let leaf3 = hash(&data[2]);

        let internal1 = hash_internal_node(&leaf1, &leaf2);
        let internal2 = hash_internal_node(&leaf3, &leaf3);

        let root = hash_internal_node(&internal1, &internal2);

        assert_eq!(root, merkle.root());

        let expected_tree = vec![
            vec![leaf1, leaf2, leaf3],
            vec![internal1, internal2],
            vec![root],
        ];

        assert_eq!(expected_tree, merkle.tree);
    }

    #[test]
    fn test_generate_proof() {
        let data = vec![
            b"block1".to_vec(),
            b"block2".to_vec(),
            b"block3".to_vec(),
            b"block4".to_vec(),
        ];

        let merkle = MerkleTree::new(&data).expect("Should create merkle tree");

        let proof = merkle
            .generate_proof(&data[1])
            .expect("Should generate proof");

        assert_eq!(proof.len(), 2);

        let leaf1 = hash(&data[0]);
        let leaf2 = hash(&data[1]);
        let leaf3 = hash(&data[2]);
        let leaf4 = hash(&data[3]);

        // Calculate internal nodes
        let _internal1 = hash_internal_node(&leaf1, &leaf2);
        let internal2 = hash_internal_node(&leaf3, &leaf4);

        // Left and the other is right
        let expected_proof = vec![(leaf1, Direction::Left), (internal2, Direction::Right)];

        // Print the tree by levels and print the proof
        for level in merkle.tree.iter() {
            println!("{:?}", level);
        }

        println!("{:?}", proof);

        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_generate_proof_edge_case() {
        let data = vec![b"block1".to_vec(), b"block2".to_vec(), b"block3".to_vec()];

        let merkle = MerkleTree::new(&data).expect("Should create merkle tree");

        let leaf1 = hash(&data[0]);
        let leaf2 = hash(&data[1]);
        let leaf3 = hash(&data[2]);

        let internal1 = hash_internal_node(&leaf1, &leaf2);
        let internal2 = hash_internal_node(&leaf3, &leaf3);

        let _root = hash_internal_node(&internal1, &internal2);

        let proof = merkle
            .generate_proof(&data[1])
            .expect("Should generate proof");

        let expected_proof = vec![(leaf1, Direction::Left), (internal2, Direction::Right)];

        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_verify_proof() {
        let data = vec![
            b"block1".to_vec(),
            b"block2".to_vec(),
            b"block3".to_vec(),
            b"block4".to_vec(),
        ];

        let merkle = MerkleTree::new(&data).expect("Should create merkle tree");

        // Generate and verify proof for "block2"
        let proof = merkle
            .generate_proof(&data[1])
            .expect("Should generate proof");
        assert!(merkle.verify_proof(&data[1], &proof));

        // Verify with wrong data (should fail)
        assert!(!merkle.verify_proof(b"wrong_data", &proof));

        // Verify with wrong proof (should fail)
        let wrong_proof = merkle
            .generate_proof(&data[2])
            .expect("Should generate proof");
        assert!(!merkle.verify_proof(&data[1], &wrong_proof));
    }

    #[test]
    fn test_verify_proof_edge_case() {
        let data = vec![b"block1".to_vec(), b"block2".to_vec(), b"block3".to_vec()];

        let merkle = MerkleTree::new(&data).expect("Should create merkle tree");

        let proof = merkle
            .generate_proof(&data[1])
            .expect("Should generate proof");

        assert!(merkle.verify_proof(&data[1], &proof));

        // Verify with wrong data (should fail)
        assert!(!merkle.verify_proof(b"wrong_data", &proof));
    }

    #[test]
    fn test_generic_data_types() {
        // Test with different types that implement AsRef<[u8]>
        let string_data = vec![
            String::from("test1"),
            String::from("test2"),
            String::from("test3"),
        ];

        let bytes_data = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        let str_data = vec!["hello", "world", "!"];

        // Test creation with different types
        let string_merkle =
            MerkleTree::new(&string_data).expect("Should create merkle tree from strings");
        let bytes_merkle =
            MerkleTree::new(&bytes_data).expect("Should create merkle tree from bytes");
        let str_merkle = MerkleTree::new(&str_data).expect("Should create merkle tree from str");

        // Test proof generation and verification with different types
        let string_proof = string_merkle
            .generate_proof(&string_data[0])
            .expect("Should generate proof");
        assert!(string_merkle.verify_proof(&string_data[0], &string_proof));

        let bytes_proof = bytes_merkle
            .generate_proof(&bytes_data[1])
            .expect("Should generate proof");
        assert!(bytes_merkle.verify_proof(&bytes_data[1], &bytes_proof));

        let str_proof = str_merkle
            .generate_proof(&str_data[2])
            .expect("Should generate proof");
        assert!(str_merkle.verify_proof(&str_data[2], &str_proof));
    }
}
