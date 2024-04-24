use std::collections::HashSet;
use spacedb::{db::Database, subtree::{SubTree, ValueOrHash}, NodeHasher, Sha256Hasher, Hash};
use spacedb::tx::ProofType;
use rand::{Rng, SeedableRng, rngs::StdRng};


#[test]
fn it_works_with_empty_trees() {
    let db = Database::memory().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let root = snapshot.root().unwrap();
    assert_eq!(root, db.hash(&[]), "empty tree must return zero hash");

    let foo = db.hash("foo".as_bytes());
    let subtree = snapshot.prove(&[foo], ProofType::Standard).unwrap();

    assert_eq!(
        subtree.root().unwrap(),
        root,
        "empty subtree must return zero hash"
    );

    assert_eq!(subtree.contains(&foo).unwrap(), false)
}

#[test]
fn it_inserts_into_tree() {
    let db = Database::memory().unwrap();
    let mut tx = db.begin_write().unwrap();
    let key = db.hash(&[]);
    let value = "some data".as_bytes().to_vec();

    tx.insert(key.clone(), value.clone()).unwrap();
    tx.commit().unwrap();

    let mut tree = db.begin_read().unwrap();

    let mut subtree = SubTree::<Sha256Hasher>::empty();
    subtree.insert(key, ValueOrHash::Value(value)).unwrap();

    assert_eq!(
        subtree.root().unwrap(),
        tree.root().unwrap(),
        "subtree root != tree root"
    )
}

#[test]
fn it_inserts_many_items_into_tree() {
    let db = Database::memory().unwrap();
    let mut tx = db.begin_write().unwrap();

    // Initialize the subtree
    let mut subtree = SubTree::<Sha256Hasher>::empty();

    // Insert 100 key-value pairs into the transaction and the subtree
    let mut keys = Vec::new();
    for i in 0..100 {
        let key = Sha256Hasher::hash(format!("key{}", i).as_bytes());
        keys.push(key.clone());
        let value = format!("data{}", i).as_bytes().to_vec();

        tx.insert(key.clone(), value.clone()).unwrap();
        subtree.insert(key, ValueOrHash::Value(value)).unwrap();
    }

    // Commit the transaction
    tx.commit().unwrap();

    let mut tree = db.begin_read().unwrap();
    let subtree2 = tree.prove(&keys, ProofType::Standard).unwrap();

    assert_eq!(
        subtree2.root().unwrap(),
        tree.root().unwrap(),
        "subtree2 != tree"
    );

    // Compare the root hash of the subtree and the main tree
    assert_eq!(
        subtree.root().unwrap(),
        tree.root().unwrap(),
        "subtree root != tree root after inserting many items"
    );
}

#[test]
fn it_should_iterate_over_tree() {
    use std::collections::HashSet;
    let db = Database::memory().unwrap();
    let mut tx = db.begin_write().unwrap();
    let mut inserted_values = HashSet::new();

    let n = 1000;
    for i in 0..n {
        let key = Sha256Hasher::hash(format!("key{}", i).as_bytes());
        let value = format!("data{}", i).as_bytes().to_vec();
        tx.insert(key.clone(), value.clone()).unwrap();
        inserted_values.insert(String::from_utf8(value).unwrap());
    }

    tx.commit().unwrap();

    let snapshot = db.begin_read().unwrap();
    for (_, value) in snapshot.iter().filter_map(Result::ok) {
        let value_str = String::from_utf8(value).unwrap();
        assert!(
            inserted_values.contains(&value_str),
            "Value not found in set: {}",
            value_str
        );
    }

    assert_eq!(
        inserted_values.len(),
        n,
        "The number of iterated items does not match the number of inserted items."
    );
}

#[test]
fn it_returns_none_when_key_not_exists() {
    let db = Database::memory().unwrap();
    let mut tx = db.begin_write().unwrap();
    let key = db.hash(&[]);
    let value = "some data".as_bytes().to_vec();

    tx.insert(key.clone(), value.clone()).unwrap();
    tx.commit().unwrap();

    let mut tree = db.begin_read().unwrap();
    assert_eq!(tree.get(&key.clone()).unwrap(), Some(value));
    let non_existing_key = db.hash(&[1]);
    assert!(tree.get(&non_existing_key.clone()).unwrap().is_none());
}

fn u32_to_key(k : u32) -> Hash {
    let mut h = [0u8;32];
    h[0..4].copy_from_slice(&k.to_be_bytes());
    h
}

#[test]
fn it_should_delete_elements_from_snapshot() {
    let mut rng = StdRng::seed_from_u64(12345);
    let mut keys_to_delete = HashSet::new();
    let mut initial_set = Vec::new();
    let sample_size = 100u32;
    let items_to_delete = 22usize;

    while keys_to_delete.len() < items_to_delete {
        keys_to_delete.insert(rng.gen_range(0u32..sample_size));
    }

    for key in 0u32..sample_size {
        if !keys_to_delete.contains(&key) {
            initial_set.push(key);
        }
    }

    let db = Database::memory().unwrap();
    let mut tx = db.begin_write().unwrap();
    for key in initial_set {
        tx.insert(u32_to_key(key), vec![0]).unwrap();
    }
    tx.commit().unwrap();

    let expected_root_after_deletion = db.begin_read().unwrap().root().unwrap();

    // add all elements that we wish to delete
    let mut tx = db.begin_write().unwrap();
    for key in &keys_to_delete {
        tx.insert(u32_to_key(*key), vec![0]).unwrap();
    }
    tx.commit().unwrap();

    let root_with_entire_sample_size = db.begin_read().unwrap().root().unwrap();
    assert_ne!(expected_root_after_deletion, root_with_entire_sample_size);

    let mut tx = db.begin_write().unwrap();
    for key in &keys_to_delete {
        tx.delete(u32_to_key(*key)).unwrap();
    }
    tx.commit().unwrap();

    let actual_root_after_deletion = db.begin_read().unwrap().root().unwrap();
    assert_eq!(expected_root_after_deletion, actual_root_after_deletion);
}
