# Rusty Merkle Tree Implementation

Simple Merkle tree implementation in Rust.

## Installation

- Clone the repository
```bash
git clone https://github.com/LucasUTNFRD/Merkle-Tree.git && cd Merkle-Tree
```

## Features

- Create Merkle trees from any data that implements `AsRef<[u8]>`
- Generate Merkle proofs for leaf verification
- Verify Merkle proofs
- Add new elements to existing trees
- Generic implementation supporting different data types
- Uses SHA3-256 for secure hashing

## API

### Creating a New Merkle Tree

```rust
let merkle = MerkleTree::new(&data)?;
```

### Generating a Proof

```rust
let proof = merkle.generate_proof(&element)?;
```

### Verifying a Proof

```rust
let is_valid = merkle.verify_proof(&element, &proof);
```

### Adding New Elements

```rust
merkle.add(new_element);
```
