use std::collections::HashSet;
use spacedb::{db::Database, subtree::{SubTree, ValueOrHash}, NodeHasher, Sha256Hasher, Hash};
use spacedb::tx::{ProofType, ReadTransaction};
use rand::{Rng, SeedableRng, rngs::StdRng};

#[test]
fn it_proves_non_existence_single_key_opposite_path() {
    let db = Database::memory().unwrap();

    // Insert a key starting with bit 1 (0b1xxx_xxxx)
    let key_with_1 = {
        let mut k = [0u8; 32];
        k[0] = 0b1000_0000;
        k
    };

    db.begin_write().unwrap()
        .insert(key_with_1, vec![1, 2, 3]).unwrap()
        .commit().unwrap();

    // Try to prove a key starting with bit 0 (0b0xxx_xxxx)
    let key_with_0 = {
        let mut k = [0u8; 32];
        k[0] = 0b0000_0000;
        k
    };

    let mut snapshot = db.begin_read().unwrap();
    let tree_root = snapshot.compute_root().unwrap();

    // Generate proof for the non-existent key
    let subtree = snapshot.prove(&[key_with_0], ProofType::Standard).unwrap();

    // The proof should have the same root as the tree
    assert_eq!(subtree.compute_root().unwrap(), tree_root);

    // contains should return false for the non-existent key (not error)
    assert_eq!(subtree.contains(&key_with_0).unwrap(), false);

    // The existing key is still visible in the proof (the leaf node contains its key)
    // but the value is hashed since we didn't ask for it
    assert_eq!(subtree.contains(&key_with_1).unwrap(), true);
}

#[test]
fn it_proves_non_existence_when_key_diverges_at_prefix() {
    let db = Database::memory().unwrap();

    // Insert 10 keys all starting with bit 1
    let mut write = db.begin_write().unwrap();
    for i in 0u8..10 {
        let mut k = [0u8; 32];
        k[0] = 0b1000_0000 | (i >> 1);
        k[1] = i;
        write = write.insert(k, vec![i]).unwrap();
    }
    write.commit().unwrap();

    // Prove a key starting with bit 0 (completely different subtree)
    let non_existent = [0u8; 32];  // all zeros

    let mut snapshot = db.begin_read().unwrap();
    let proof = snapshot.prove(&[non_existent], ProofType::Standard).unwrap();

    let result = proof.contains(&non_existent);
    println!("contains result: {:?}", result);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn subtree_borsh_serialization_roundtrip() {

    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    // Insert several keys
    for i in 0u8..10 {
        let mut k = [0u8; 32];
        k[0] = i;
        write = write.insert(k, vec![i, i + 1, i + 2]).unwrap();
    }
    write.commit().unwrap();

    // Create a proof for some keys
    let keys_to_prove: Vec<Hash> = (0u8..5).map(|i| {
        let mut k = [0u8; 32];
        k[0] = i;
        k
    }).collect();

    let mut snapshot = db.begin_read().unwrap();
    let subtree: SubTree<Sha256Hasher> = snapshot.prove(&keys_to_prove, ProofType::Standard).unwrap();
    let original_root = subtree.compute_root().unwrap();

    // Serialize and deserialize
    let serialized = borsh::to_vec(&subtree).unwrap();
    let deserialized: SubTree<Sha256Hasher> = borsh::from_slice(&serialized).unwrap();

    // Verify the root is the same
    assert_eq!(deserialized.compute_root().unwrap(), original_root);

    // Verify contains works on deserialized subtree
    for key in &keys_to_prove {
        assert!(deserialized.contains(key).unwrap());
    }

    // Non-existent key should return false
    let mut non_existent = [0u8; 32];
    non_existent[0] = 100;
    assert!(!deserialized.contains(&non_existent).unwrap());
}

#[test]
fn mixed_existence_proof() {
    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    // Insert keys 0, 2, 4, 6, 8 (even numbers)
    for i in (0u8..10).step_by(2) {
        let mut k = [0u8; 32];
        k[0] = i;
        write = write.insert(k, vec![i]).unwrap();
    }
    write.commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let tree_root = snapshot.compute_root().unwrap();

    // Prove a mix of existing (0, 2, 4) and non-existing (1, 3, 5) keys
    let keys_to_prove: Vec<Hash> = (0u8..6).map(|i| {
        let mut k = [0u8; 32];
        k[0] = i;
        k
    }).collect();

    let subtree = snapshot.prove(&keys_to_prove, ProofType::Standard).unwrap();

    // Root should match
    assert_eq!(subtree.compute_root().unwrap(), tree_root);

    // Check existing keys return true
    for i in (0u8..6).step_by(2) {
        let mut k = [0u8; 32];
        k[0] = i;
        assert!(subtree.contains(&k).unwrap(), "key {} should exist", i);
    }

    // Check non-existing keys return false (not error)
    for i in (1u8..6).step_by(2) {
        let mut k = [0u8; 32];
        k[0] = i;
        assert!(!subtree.contains(&k).unwrap(), "key {} should not exist", i);
    }
}

#[test]
fn adjacent_keys_differ_by_one_bit() {
    let db = Database::memory().unwrap();

    // Two keys that differ only in the last bit
    let key_a = {
        let mut k = [0xFFu8; 32];
        k[31] = 0b1111_1110; // ends in 0
        k
    };
    let key_b = {
        let mut k = [0xFFu8; 32];
        k[31] = 0b1111_1111; // ends in 1
        k
    };

    db.begin_write().unwrap()
        .insert(key_a, vec![0xAA]).unwrap()
        .insert(key_b, vec![0xBB]).unwrap()
        .commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let tree_root = snapshot.compute_root().unwrap();

    // Prove only key_a
    let subtree = snapshot.prove(&[key_a], ProofType::Standard).unwrap();
    assert_eq!(subtree.compute_root().unwrap(), tree_root);
    assert!(subtree.contains(&key_a).unwrap());
    // key_b is a sibling hash node - we can't prove it exists without its own proof
    assert!(subtree.contains(&key_b).is_err(), "key_b should be incomplete proof");

    // Prove only key_b
    let mut snapshot = db.begin_read().unwrap();
    let subtree = snapshot.prove(&[key_b], ProofType::Standard).unwrap();
    assert_eq!(subtree.compute_root().unwrap(), tree_root);
    assert!(subtree.contains(&key_b).unwrap());
    // key_a is a sibling hash node
    assert!(subtree.contains(&key_a).is_err(), "key_a should be incomplete proof");

    // Prove both keys together
    let mut snapshot = db.begin_read().unwrap();
    let subtree = snapshot.prove(&[key_a, key_b], ProofType::Standard).unwrap();
    assert_eq!(subtree.compute_root().unwrap(), tree_root);
    assert!(subtree.contains(&key_a).unwrap());
    assert!(subtree.contains(&key_b).unwrap());

    // A key that differs more significantly should not exist
    let key_c = [0x00u8; 32];
    assert!(!subtree.contains(&key_c).unwrap());
}

#[test]
fn it_works_with_empty_trees() {
    let db = Database::memory().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let root = snapshot.compute_root().unwrap();
    assert_eq!(root, db.hash(&[]), "empty tree must return zero hash");
    let foo = db.hash("foo".as_bytes());
    let subtree = snapshot.prove(&[foo], ProofType::Standard).unwrap();

    assert_eq!(
        subtree.compute_root().unwrap(),
        root,
        "empty subtree must return zero hash"
    );

    assert_eq!(subtree.contains(&foo).unwrap(), false)
}

#[test]
fn it_inserts_into_tree() {
    let db = Database::memory().unwrap();
    let tx = db.begin_write().unwrap();
    let key = db.hash(&[]);
    let value = "some data".as_bytes().to_vec();

    tx.insert(key.clone(), value.clone()).unwrap().commit().unwrap();

    let mut tree = db.begin_read().unwrap();

    let mut subtree = SubTree::<Sha256Hasher>::empty();
    subtree.insert(key, ValueOrHash::Value(value)).unwrap();

    assert_eq!(
        subtree.compute_root().unwrap(),
        tree.compute_root().unwrap(),
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

        tx = tx.insert(key.clone(), value.clone()).unwrap();
        subtree.insert(key, ValueOrHash::Value(value)).unwrap();
    }

    // Commit the transaction
    tx.commit().unwrap();

    let mut tree = db.begin_read().unwrap();
    let subtree2 = tree.prove(&keys, ProofType::Standard).unwrap();

    assert_eq!(
        subtree2.compute_root().unwrap(),
        tree.compute_root().unwrap(),
        "subtree2 != tree"
    );

    // Compare the root hash of the subtree and the main tree
    assert_eq!(
        subtree.compute_root().unwrap(),
        tree.compute_root().unwrap(),
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
        tx = tx.insert(key, value.clone()).unwrap();
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
    let mut snapshot = db.begin_read().unwrap();
    assert_eq!(snapshot.get(&[0u8; 32]).unwrap(), None, "empty tree should return none");

    let mut tx = db.begin_write().unwrap();
    let key = db.hash(&[]);
    let value = "some data".as_bytes().to_vec();

    tx = tx.insert(key.clone(), value.clone()).unwrap();
    tx.commit().unwrap();

    let mut tree = db.begin_read().unwrap();
    assert_eq!(tree.get(&key.clone()).unwrap(), Some(value));
    let non_existing_key = db.hash(&[1]);
    assert!(tree.get(&non_existing_key.clone()).unwrap().is_none());
}

fn u32_to_key(k: u32) -> Hash {
    let mut h = [0u8; 32];
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
        tx = tx.insert(u32_to_key(key), vec![0]).unwrap();
    }
    tx.commit().unwrap();

    let expected_root_after_deletion = db.begin_read().unwrap().compute_root().unwrap();

    // add all elements that we wish to delete
    let mut tx = db.begin_write().unwrap();
    for key in &keys_to_delete {
        tx = tx.insert(u32_to_key(*key), vec![0]).unwrap();
    }
    tx.commit().unwrap();

    let root_with_entire_sample_size = db.begin_read().unwrap().compute_root().unwrap();
    assert_ne!(expected_root_after_deletion, root_with_entire_sample_size);

    let mut tx = db.begin_write().unwrap();
    for key in &keys_to_delete {
        tx = tx.delete(u32_to_key(*key)).unwrap();
    }
    tx.commit().unwrap();

    let actual_root_after_deletion = db.begin_read().unwrap().compute_root().unwrap();
    assert_eq!(expected_root_after_deletion, actual_root_after_deletion);
}

#[test]
fn it_should_delete_elements_from_subtree() {
    let mut rng = StdRng::seed_from_u64(12345);
    let mut keys_to_delete = HashSet::new();
    let mut initial_set = Vec::new();
    let sample_size = 1000u32;
    let items_to_delete = 28usize;

    while keys_to_delete.len() < items_to_delete {
        let k = rng.gen_range(0u32..sample_size);
        keys_to_delete.insert(k);
    }

    for key in 0u32..sample_size {
        if !keys_to_delete.contains(&key) {
            initial_set.push(key);
        }
    }

    // Add only the initial set
    let db = Database::memory().unwrap();
    let mut tx = db.begin_write().unwrap();
    for key in initial_set {
        tx = tx.insert(u32_to_key(key), vec![0]).unwrap();
    }
    tx.commit().unwrap();

    let expected_root_after_deletion = db.begin_read().unwrap().compute_root().unwrap();

    // Add all elements that we wish to delete as well
    let mut tx = db.begin_write().unwrap();
    for key in &keys_to_delete {
        tx = tx.insert(u32_to_key(*key), vec![0]).unwrap();
    }
    tx.commit().unwrap();

    let root_with_entire_sample_size = db.begin_read().unwrap().compute_root().unwrap();
    assert_ne!(expected_root_after_deletion, root_with_entire_sample_size);

    let key_hashes: Vec<Hash> = keys_to_delete.iter().map(|k: &u32| u32_to_key(*k)).collect();
    let mut snapshot = db.begin_read().unwrap();
    let mut subtree = snapshot.prove(&key_hashes, ProofType::Extended).unwrap();

    for kh in key_hashes {
        subtree = subtree.delete(&kh).unwrap()
    }

    let subtree_root = subtree.compute_root().unwrap();
    assert_eq!(expected_root_after_deletion, subtree_root);
}

#[test]
fn it_should_store_metadata() {
    let db = Database::memory().unwrap();
    let mut tx = db.begin_write().unwrap();
    tx.metadata("snapshot 0".as_bytes().to_vec()).unwrap();
    tx.commit().unwrap();

    let snapshot = db.begin_read().unwrap();
    assert_eq!(snapshot.metadata(), "snapshot 0".as_bytes());

    let mut tx = db.begin_write().unwrap();
    for i in 0..100 {
        let key = Sha256Hasher::hash(format!("key{}", i).as_bytes());
        let value = format!("data{}", i).as_bytes().to_vec();
        tx = tx.insert(key, value.clone()).unwrap();
    }
    tx.metadata("snapshot 1".as_bytes().to_vec()).unwrap();
    tx.commit().unwrap();

    let snapshot = db.begin_read().unwrap();
    assert_eq!(snapshot.metadata(), "snapshot 1".as_bytes());

    let snapshots: Vec<ReadTransaction<Sha256Hasher>> = db.iter()
        .map(|s| s.unwrap()).collect();

    assert_eq!(snapshots.len(), 2);

    for (index, snapshot) in snapshots.iter().rev().enumerate() {
        assert_eq!(String::from_utf8_lossy(snapshot.metadata()), format!("snapshot {}", index));
    }
}

#[test]
fn it_should_rollback() -> spacedb::Result<()> {
    let db = Database::memory()?;
    let snapshots_len: usize = 20;
    let items_per_snapshot: usize = 10;

    for snapshot_index in 0..snapshots_len {
        let mut tx = db.begin_write()?;
        for entry in 0..items_per_snapshot {
            tx = tx.insert(u32_to_key((snapshot_index * entry) as u32), entry.to_be_bytes().to_vec())?;
        }
        tx.commit()?;
    }

    let mut roots = Vec::with_capacity(snapshots_len);
    for snapshot in db.iter() {
        roots.push(snapshot?.compute_root()?)
    }
    assert_eq!(roots.len(), snapshots_len, "expected roots == snapshots len");

    // try rolling back latest snapshot
    let snapshot = db.begin_read()?;
    assert!(snapshot.rollback().is_ok(), "expected rollback to work");

    // confirm we still have the same snapshot
    let mut snapshot = db.begin_read()?;

    assert_eq!(&snapshot.compute_root()?, roots.first().unwrap(), "bad roots");

    // rollback the 6th snapshot
    db.iter().skip(5).next().unwrap()?.rollback()?;
    let snapshots_len = snapshots_len - 5;
    assert_eq!(db.iter().count(), snapshots_len, "snapshot count mismatch");

    // db should now point to the snapshot we just rolled back
    let mut snapshot = db.begin_read()?;
    assert_eq!(&snapshot.compute_root()?, roots.iter().skip(5).next().unwrap(), "bad roots");
    Ok(())
}
