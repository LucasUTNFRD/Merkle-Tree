# Rusty Merkle Tree Implementation

Simple Merkle tree implementation in Rust.

## Installation

1.  Clone the repository

```bash
git clone https://github.com/LucasUTNFRD/Merkle-Tree.git && cd Merkle-Tree
```

2. Use `make` to compile the project
```bash 
make run
```
## Features

- Create a Merkle Tree from any data type that implements the trait `AsRef<[u8]>`.
- Generate and verify Merkle proofs
- Add new elements dynamically
- Support for generic data types

## Usage

### Creating a Merkle Tree
```Rust
// Create a Merkle tree from a vector of data
let data = vec![b"block1", b"block2", b"block3"];
let merkle = MerkleTree::new(&data)?;

// Get the root hash
let root_hash = merkle.root();

// Add a new element
merkle.add(b"block4".to_vec());
```

### Generating and Verifying proofs
```Rust
// Generate a proof for a specific element
let proof = merkle.generate_proof(&element)?;

// Verify the proof
let is_valid = merkle.verify_proof(&element, &proof);
```

#### Example
```Rust
fn main() {
    // Create a Merkle tree with some data
    let data = vec![
        b"transaction1".to_vec(), 
        b"transaction2".to_vec(), 
        b"transaction3".to_vec()
    ];
    
    let merkle = MerkleTree::new(&data).expect("Failed to create Merkle tree");
    
    // Generate a proof for the second transaction
    let proof = merkle.generate_proof(&data[1])
        .expect("Failed to generate proof");
    
    // Verify the proof
    assert!(merkle.verify_proof(&data[1], &proof));
}
```

