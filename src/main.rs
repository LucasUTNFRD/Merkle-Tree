mod merkle;

use merkle::MerkleTree;

fn main() {
    let block = vec![
        "Transaction 1",
        "Transaction 2",
        "Transaction 3",
        "Transaction 4",
        "Transaction 5",
    ];

    let mut tree = MerkleTree::new(&block);
}

