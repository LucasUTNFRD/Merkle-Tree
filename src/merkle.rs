use sha3::{Digest, Sha3_256};

type Hash = [u8; 32];

#[derive(Debug)]
struct MerkleTree {
    tree: Vec<Vec<Hash>>, // This will be a binary tree represented as a vector, with each level as a sub-vector with the hashes
    leaves: Vec<Hash>,    // This will be uses to add new elements to the tree
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

    // A proof is a list of hashes that can be used to verify the membership of a leaf in the tree
    // For now the proof is simply that a  list of hashes.
    // Possible improvements:
    // 1. Store the direction of the hash (left or right) and the level of the tree
    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        // Implement this for refactored Merkle Tree
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut proof = vec![];
        let mut current_index = leaf_index;
        // loop each level of the tree
        for level in 0..self.tree.len() - 1 {
            let current_level = &self.tree[level];
            let sibling_index = if current_index % 2 == 0 {
                // if current sibling is leaft, check right sibling
                if current_index + 1 < current_level.len() {
                    current_index + 1
                } else {
                    current_index
                }
            } else {
                current_index - 1
            };
            // push the sibling hash to the proof
            proof.push(current_level[sibling_index]);

            current_index /= 2;
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

        let merkle = MerkleTree::new(&data);

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

        let merkle = MerkleTree::new(&data);

        let proof = merkle.generate_proof(1).unwrap();

        assert_eq!(proof.proof.len(), 2);

        let leaf1 = hash(&data[0]);
        let leaf2 = hash(&data[1]);
        let leaf3 = hash(&data[2]);
        let leaf4 = hash(&data[3]);

        // Calculate internal nodes
        let _internal1 = hash_internal_node(&leaf1, &leaf2);
        let internal2 = hash_internal_node(&leaf3, &leaf4);

        let expected_proof = vec![leaf1, internal2];

        assert_eq!(proof.proof, expected_proof);
    }

    #[test]
    fn test_generate_proof_edge_case() {
        let data = vec![b"block1".to_vec(), b"block2".to_vec(), b"block3".to_vec()];

        let merkle = MerkleTree::new(&data);

        let leaf1 = hash(&data[0]);
        let leaf2 = hash(&data[1]);
        let leaf3 = hash(&data[2]);

        let internal1 = hash_internal_node(&leaf1, &leaf2);
        let internal2 = hash_internal_node(&leaf3, &leaf3);

        let _root = hash_internal_node(&internal1, &internal2);

        let proof = merkle.generate_proof(1).unwrap();

        let expected_proof = vec![leaf1, internal2];

        assert_eq!(proof.proof, expected_proof);
    }
}
