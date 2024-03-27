# SpaceDB

<small>Note: this project is still under active development and should be considered experimental.</small>

SpaceDB is a cryptographically verifiable data store and universal accumulator for the [Spaces protocol](https://spacesprotocol.org). It's a Merkle-ized binary trie described in the [Merklix](https://blog.vermorel.com/pdf/merklix-tree-for-bitcoin-2018-07.pdf) paper and explained in detail [here](https://spacesprotocol.org/#binary-trie).


## Features

- Fast, portable, single-file database.
- MVCC-based concurrency control with multi-reader/single-writer lock-free access.
- Provides compact proofs of membership/non-membership for batches of elements through subtrees.
- Subtrees act as cryptographic accumulators and can be updated independently.
- `no_std` support, particularly for use within RISC0 zkVM and leverages SHA256 acceleration.
- Accumulator keeps a constant size state of a single 32-byte tree root.



## Usage

```rust
use spacedb::db::Database;


let db = Database::open("example.sdb")?;

// Insert some data
let mut tx = db.begin_write()?;
for i in 0..100 {
    let key = format!("key{}", i);
    let value = format!("value{}", i);
    tx.insert(db.hash(key.as_bytes()), value.into_bytes())?;
}
tx.commit()?;

let mut snapshot = db.begin_read()?;
println!("Tree root: {}", hex::encode(snapshot.root()?));

// Prove a subset of the keys
let keys_to_prove: Vec<_> = (0..10)
    .map(|i| format!("key{}", i))
    // prove exclusion of some other keys
    .chain((0..5).map(|i| format!("other{}", i)))
    .map(|key| db.hash(key.as_bytes()))
    .collect();

// Reveal relevant nodes needed to prove the specified set of keys
let mut subtree = snapshot.prove_all(&keys_to_prove)?;

// Will have the exact same root as the snapshot
println!("Subtree root: {}", hex::encode(subtree.root().unwrap()));

// Inclusion and exclusion proofs
assert!(subtree.contains(&db.hash("key0".as_bytes())).unwrap());
assert!(!subtree.contains(&db.hash("other0".as_bytes())).unwrap());

// Proving exclusion of "other100" fails since we didn't reveal 
// relevant branches needed to traverse its path in this subtree
assert!(subtree.contains(&db.hash("other100".as_bytes())).is_err());

```



## Subtrees

Subtrees can function as cryptographic accumulators, allowing clients to verify and update their state without keeping a database.

```rust

// Client maintains a 32-byte tree root
let mut accumulator_root = snapshot.root()?;
assert_eq!(accumulator_root, subtree.root().unwrap(), "Roots must match");

// Update leaves
for (key, value) in subtree.iter_mut() {
    *value = "new value".to_string().into_bytes();
}

// Inserting a non-existent key (must be provably absent)
let key = subtree.hash("other0".as_bytes());
subtree.insert(key, "new value".into_bytes()).unwrap();

// Updating the accumulator root
accumulator_root = subtree.root().unwrap();

```

## Using in RISC0 zkVM

Subtrees work in `no_std` environments utilizing the SHA256 accelerator when running inside the RISC0 zkVM. 

```toml
[dependencies]
spacedb = { version = "0.1", default-features = false }
```




## Key Iteration

Iterate over all keys in a given snapshot:

```rust
let db = Database::open("my.sdb")?;
let snapshot = db.begin_read()?;

for (key, value) in snapshot.iter().filter_map(Result::ok) {
    // do something ...
}

```



## Snapshot iteration

Iterate over all snapshots:

```rust
let db = Database::open("my.sdb")?;

for snapshot in db.iter().filter_map(Result::ok) {
    let root = snapshot.root()?;
    println!("Snapshot Root: {}", hex::encode(root));
}
```

## Prior Art

Merkle-ized tries, including variations like Patricia tries and Merkle prefix trees, are foundational structures that have been used in numerous projects and cryptocurrencies. Some other libraries that implement some form of Merkle-ized binary tries include
[liburkel](https://github.com/chjj/liburkel) which this library initially drew some inspiration from — although SpaceDB is generally around ~20% faster,  and [multiproof,](https://github.com/gballet/multiproof-rs/tree/master) but they either lack memory safety, core features such as subtrees/accumulators needed for Spaces protocol or are unmaintained. Other popular cryptographically verifiable data stores include [Trillian](https://github.com/google/trillian) used for [Certificate Transparency](https://www.certificate-transparency.org/)


## License

This project is licensed under the [Apache 2.0](LICENSE).
