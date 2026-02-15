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
fn subtree_prove_creates_smaller_proof() {
    use spacedb::subtree::ProofType;

    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    // Insert 10 keys
    for i in 0u8..100 {
        let mut k = [0u8; 32];
        k[0] = i;
        write = write.insert(k, vec![i; 100]).unwrap(); // 100 byte values
    }
    write.commit().unwrap();

    // Get a proof for all 10 keys from the main tree
    let mut snapshot = db.begin_read().unwrap();
    let all_keys: Vec<Hash> = (0u8..10).map(|i| {
        let mut k = [0u8; 32];
        k[0] = i;
        k
    }).collect();
    let full_subtree: SubTree<Sha256Hasher> = snapshot.prove(&all_keys, spacedb::tx::ProofType::Standard).unwrap();
    let full_root = full_subtree.compute_root().unwrap();

    // Now create a smaller proof from the subtree for just 2 keys
    let subset_keys: Vec<Hash> = (0u8..2).map(|i| {
        let mut k = [0u8; 32];
        k[0] = i;
        k
    }).collect();
    let smaller_subtree = full_subtree.prove(&subset_keys, ProofType::Standard).unwrap();

    // Root should still match
    assert_eq!(smaller_subtree.compute_root().unwrap(), full_root);

    // Should be able to verify the subset keys
    for key in &subset_keys {
        assert!(smaller_subtree.contains(key).unwrap());
    }

    // Keys not in the subset should either return false or IncompleteProof
    let mut other_key = [0u8; 32];
    other_key[0] = 5;
    // This key exists in full_subtree but we didn't include it in smaller proof
    // It should be a hash node now
    assert!(smaller_subtree.contains(&other_key).is_err());

    // Serialized size should be smaller (fewer values included)
    let full_serialized = borsh::to_vec(&full_subtree).unwrap();
    let smaller_serialized = borsh::to_vec(&smaller_subtree).unwrap();
    assert!(smaller_serialized.len() < full_serialized.len(),
        "smaller proof should serialize to fewer bytes: {} vs {}",
        smaller_serialized.len(), full_serialized.len());
}

#[test]
fn subtree_prove_empty_subtree() {
    use spacedb::subtree::ProofType;

    let empty: SubTree<Sha256Hasher> = SubTree::empty();
    let key = [0u8; 32];

    let result = empty.prove(&[key], ProofType::Standard).unwrap();
    assert!(result.is_empty());
    assert_eq!(result.compute_root().unwrap(), empty.compute_root().unwrap());
}

#[test]
fn subtree_prove_nonexistent_keys() {
    use spacedb::subtree::ProofType;

    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();
    for i in 0u8..5 {
        let mut k = [0u8; 32];
        k[0] = i * 2; // 0, 2, 4, 6, 8
        write = write.insert(k, vec![i]).unwrap();
    }
    write.commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let all_keys: Vec<Hash> = (0u8..5).map(|i| {
        let mut k = [0u8; 32];
        k[0] = i * 2;
        k
    }).collect();
    let subtree: SubTree<Sha256Hasher> = snapshot.prove(&all_keys, spacedb::tx::ProofType::Standard).unwrap();
    let original_root = subtree.compute_root().unwrap();

    // Prove keys that don't exist (odd numbers)
    let nonexistent: Vec<Hash> = (0u8..3).map(|i| {
        let mut k = [0u8; 32];
        k[0] = i * 2 + 1; // 1, 3, 5
        k
    }).collect();
    let proof = subtree.prove(&nonexistent, ProofType::Standard).unwrap();

    // Root should still match
    assert_eq!(proof.compute_root().unwrap(), original_root);

    // Non-existent keys should return false (not error)
    for key in &nonexistent {
        assert!(!proof.contains(key).unwrap(), "nonexistent key should return false");
    }
}

#[test]
fn subtree_prove_through_hash_node_fails() {
    use spacedb::subtree::ProofType;

    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    // Insert keys on both sides of the tree
    let key_left = [0u8; 32]; // starts with 0
    let mut key_right = [0u8; 32];
    key_right[0] = 0x80; // starts with 1

    write = write.insert(key_left, vec![1]).unwrap();
    write = write.insert(key_right, vec![2]).unwrap();
    write.commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    // Only prove key_left - key_right becomes a hash node
    let partial_subtree: SubTree<Sha256Hasher> = snapshot.prove(&[key_left], spacedb::tx::ProofType::Standard).unwrap();

    // Now try to prove key_right from the partial subtree - should fail
    let result = partial_subtree.prove(&[key_right], ProofType::Standard);
    assert!(result.is_err(), "proving through hash node should fail");
}

#[test]
fn subtree_prove_duplicate_keys() {
    use spacedb::subtree::ProofType;

    let db = Database::memory().unwrap();
    let key = [42u8; 32];
    db.begin_write().unwrap()
        .insert(key, vec![1, 2, 3]).unwrap()
        .commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let subtree: SubTree<Sha256Hasher> = snapshot.prove(&[key], spacedb::tx::ProofType::Standard).unwrap();
    let original_root = subtree.compute_root().unwrap();

    // Prove with duplicate keys
    let proof = subtree.prove(&[key, key, key], ProofType::Standard).unwrap();
    assert_eq!(proof.compute_root().unwrap(), original_root);
    assert!(proof.contains(&key).unwrap());
}

#[test]
fn subtree_prove_order_independence() {
    use spacedb::subtree::ProofType;

    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    let keys: Vec<Hash> = (0u8..5).map(|i| {
        let mut k = [0u8; 32];
        k[0] = i;
        k
    }).collect();

    for (i, key) in keys.iter().enumerate() {
        write = write.insert(*key, vec![i as u8]).unwrap();
    }
    write.commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let subtree: SubTree<Sha256Hasher> = snapshot.prove(&keys, spacedb::tx::ProofType::Standard).unwrap();

    // Prove in forward order
    let proof_forward = subtree.prove(&[keys[0], keys[1], keys[2]], ProofType::Standard).unwrap();

    // Prove in reverse order
    let proof_reverse = subtree.prove(&[keys[2], keys[1], keys[0]], ProofType::Standard).unwrap();

    // Both should produce same root
    assert_eq!(
        proof_forward.compute_root().unwrap(),
        proof_reverse.compute_root().unwrap()
    );

    // Both should have same serialized form
    let ser_forward = borsh::to_vec(&proof_forward).unwrap();
    let ser_reverse = borsh::to_vec(&proof_reverse).unwrap();
    assert_eq!(ser_forward, ser_reverse, "order should not affect proof structure");
}

#[test]
fn subtree_prove_chained() {
    use spacedb::subtree::ProofType;

    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    let keys: Vec<Hash> = (0u8..10).map(|i| {
        let mut k = [0u8; 32];
        k[0] = i;
        k
    }).collect();

    for (i, key) in keys.iter().enumerate() {
        write = write.insert(*key, vec![i as u8; 50]).unwrap();
    }
    write.commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let original_root = snapshot.compute_root().unwrap();
    let full_subtree: SubTree<Sha256Hasher> = snapshot.prove(&keys, spacedb::tx::ProofType::Standard).unwrap();

    // First prove: 10 keys -> 5 keys
    let proof1 = full_subtree.prove(&keys[0..5], ProofType::Standard).unwrap();
    assert_eq!(proof1.compute_root().unwrap(), original_root);

    // Second prove: 5 keys -> 2 keys
    let proof2 = proof1.prove(&keys[0..2], ProofType::Standard).unwrap();
    assert_eq!(proof2.compute_root().unwrap(), original_root);

    // Third prove: 2 keys -> 1 key
    let proof3 = proof2.prove(&keys[0..1], ProofType::Standard).unwrap();
    assert_eq!(proof3.compute_root().unwrap(), original_root);

    // The one remaining key should still be verifiable
    assert!(proof3.contains(&keys[0]).unwrap());

    // Size should decrease at each step
    let size_full = borsh::to_vec(&full_subtree).unwrap().len();
    let size1 = borsh::to_vec(&proof1).unwrap().len();
    let size2 = borsh::to_vec(&proof2).unwrap().len();
    let size3 = borsh::to_vec(&proof3).unwrap().len();

    assert!(size1 < size_full, "proof1 should be smaller than full");
    assert!(size2 < size1, "proof2 should be smaller than proof1");
    assert!(size3 < size2, "proof3 should be smaller than proof2");
}

#[test]
fn subtree_prove_extended_includes_sibling_leaves() {
    use spacedb::subtree::ProofType;

    let db = Database::memory().unwrap();

    // Create two adjacent keys that will be siblings
    let mut key_a = [0xFFu8; 32];
    key_a[31] = 0b1111_1110; // ends in 0
    let mut key_b = [0xFFu8; 32];
    key_b[31] = 0b1111_1111; // ends in 1

    db.begin_write().unwrap()
        .insert(key_a, vec![0xAA]).unwrap()
        .insert(key_b, vec![0xBB]).unwrap()
        .commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let full_subtree: SubTree<Sha256Hasher> = snapshot.prove(&[key_a, key_b], spacedb::tx::ProofType::Standard).unwrap();
    let original_root = full_subtree.compute_root().unwrap();

    // Standard proof of key_a - key_b becomes Hash node
    let standard_proof = full_subtree.prove(&[key_a], ProofType::Standard).unwrap();
    assert_eq!(standard_proof.compute_root().unwrap(), original_root);
    assert!(standard_proof.contains(&key_b).is_err(), "standard proof should have hash node for sibling");

    // Extended proof of key_a - key_b should be a leaf with hashed value
    let extended_proof = full_subtree.prove(&[key_a], ProofType::Extended).unwrap();
    assert_eq!(extended_proof.compute_root().unwrap(), original_root);
    // In extended proof, sibling leaf structure is preserved (key visible, value hashed)
    // So contains should return true (key is there) but value is hashed
    assert!(extended_proof.contains(&key_b).unwrap(), "extended proof should preserve sibling leaf key");
}

#[test]
fn subtree_prove_single_key_tree() {
    use spacedb::subtree::ProofType;

    let db = Database::memory().unwrap();
    let key = [0x42u8; 32];
    let value = vec![1, 2, 3, 4, 5];

    db.begin_write().unwrap()
        .insert(key, value.clone()).unwrap()
        .commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let subtree: SubTree<Sha256Hasher> = snapshot.prove(&[key], spacedb::tx::ProofType::Standard).unwrap();
    let original_root = subtree.compute_root().unwrap();

    // Prove the same key
    let proof = subtree.prove(&[key], ProofType::Standard).unwrap();
    assert_eq!(proof.compute_root().unwrap(), original_root);
    assert!(proof.contains(&key).unwrap());

    // Prove a different key (non-existent)
    let other_key = [0x00u8; 32];
    let proof_other = subtree.prove(&[other_key], ProofType::Standard).unwrap();
    assert_eq!(proof_other.compute_root().unwrap(), original_root);
    assert!(!proof_other.contains(&other_key).unwrap());
    // The original key should still be visible (it's the only leaf)
    assert!(proof_other.contains(&key).unwrap());
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

#[test]
fn subtree_merge_disjoint_proofs() {
    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    // Insert keys with different first bits to ensure they go to different branches
    let key1 = [0x00u8; 32]; // starts with 0
    let key2 = [0x80u8; 32]; // starts with 1
    write = write.insert(key1, vec![1, 2, 3]).unwrap();
    write = write.insert(key2, vec![4, 5, 6]).unwrap();
    write.commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let original_root = snapshot.compute_root().unwrap();

    // Create two separate proofs for each key
    let proof1: SubTree<Sha256Hasher> = snapshot.prove(&[key1], spacedb::tx::ProofType::Standard).unwrap();
    let proof2: SubTree<Sha256Hasher> = snapshot.prove(&[key2], spacedb::tx::ProofType::Standard).unwrap();

    // Verify each proof individually
    assert_eq!(proof1.compute_root().unwrap(), original_root);
    assert_eq!(proof2.compute_root().unwrap(), original_root);
    assert!(proof1.contains(&key1).unwrap());
    assert!(proof2.contains(&key2).unwrap());

    // proof1 has key2 as hash, proof2 has key1 as hash
    assert!(proof1.contains(&key2).is_err()); // key2 is hashed in proof1
    assert!(proof2.contains(&key1).is_err()); // key1 is hashed in proof2

    // Merge the two proofs
    let merged = proof1.merge(proof2).unwrap();

    // Merged proof should have same root
    assert_eq!(merged.compute_root().unwrap(), original_root);

    // Both keys should now be accessible
    assert!(merged.contains(&key1).unwrap());
    assert!(merged.contains(&key2).unwrap());
}

#[test]
fn subtree_merge_overlapping_proofs() {
    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    let key1 = [0x00u8; 32];
    let key2 = [0x40u8; 32];
    let key3 = [0x80u8; 32];

    write = write.insert(key1, vec![1]).unwrap();
    write = write.insert(key2, vec![2]).unwrap();
    write = write.insert(key3, vec![3]).unwrap();
    write.commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let original_root = snapshot.compute_root().unwrap();

    // Create overlapping proofs
    let proof12: SubTree<Sha256Hasher> = snapshot.prove(&[key1, key2], spacedb::tx::ProofType::Standard).unwrap();
    let proof23: SubTree<Sha256Hasher> = snapshot.prove(&[key2, key3], spacedb::tx::ProofType::Standard).unwrap();

    // Merge them
    let merged = proof12.merge(proof23).unwrap();
    assert_eq!(merged.compute_root().unwrap(), original_root);

    // All keys should be accessible
    assert!(merged.contains(&key1).unwrap());
    assert!(merged.contains(&key2).unwrap());
    assert!(merged.contains(&key3).unwrap());
}

#[test]
fn subtree_merge_with_empty() {
    let db = Database::memory().unwrap();
    db.begin_write().unwrap()
        .insert([1u8; 32], vec![1, 2, 3]).unwrap()
        .commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let subtree: SubTree<Sha256Hasher> = snapshot.prove(&[[1u8; 32]], spacedb::tx::ProofType::Standard).unwrap();
    let original_root = subtree.compute_root().unwrap();

    let empty: SubTree<Sha256Hasher> = SubTree::empty();

    // Merge with empty should return the non-empty one
    let merged1 = subtree.clone().merge(empty.clone()).unwrap();
    assert_eq!(merged1.compute_root().unwrap(), original_root);

    let merged2 = empty.merge(subtree).unwrap();
    assert_eq!(merged2.compute_root().unwrap(), original_root);
}

#[test]
fn subtree_merge_identical_proofs() {
    let db = Database::memory().unwrap();
    db.begin_write().unwrap()
        .insert([1u8; 32], vec![1, 2, 3]).unwrap()
        .commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let proof1: SubTree<Sha256Hasher> = snapshot.prove(&[[1u8; 32]], spacedb::tx::ProofType::Standard).unwrap();
    let proof2: SubTree<Sha256Hasher> = snapshot.prove(&[[1u8; 32]], spacedb::tx::ProofType::Standard).unwrap();
    let original_root = proof1.compute_root().unwrap();

    // Merging identical proofs should work
    let merged = proof1.merge(proof2).unwrap();
    assert_eq!(merged.compute_root().unwrap(), original_root);
    assert!(merged.contains(&[1u8; 32]).unwrap());
}

#[test]
fn subtree_merge_mismatched_roots_fails() {
    // Create two different databases with different data
    let db1 = Database::memory().unwrap();
    db1.begin_write().unwrap()
        .insert([1u8; 32], vec![1, 2, 3]).unwrap()
        .commit().unwrap();

    let db2 = Database::memory().unwrap();
    db2.begin_write().unwrap()
        .insert([2u8; 32], vec![4, 5, 6]).unwrap()
        .commit().unwrap();

    let mut snapshot1 = db1.begin_read().unwrap();
    let mut snapshot2 = db2.begin_read().unwrap();

    let proof1: SubTree<Sha256Hasher> = snapshot1.prove(&[[1u8; 32]], spacedb::tx::ProofType::Standard).unwrap();
    let proof2: SubTree<Sha256Hasher> = snapshot2.prove(&[[2u8; 32]], spacedb::tx::ProofType::Standard).unwrap();

    // These have different roots, merge should fail
    assert!(proof1.merge(proof2).is_err());
}

#[test]
fn subtree_bucket_hashes_basic() {
    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    // Insert keys with known prefixes:
    // 0x00 = 0b00000000 -> bucket 00
    // 0x40 = 0b01000000 -> bucket 01
    // 0x80 = 0b10000000 -> bucket 10
    let key00 = [0x00u8; 32];
    let key01 = [0x40u8; 32];
    let key10 = [0x80u8; 32];

    write = write.insert(key00, vec![0]).unwrap();
    write = write.insert(key01, vec![1]).unwrap();
    write = write.insert(key10, vec![2]).unwrap();
    write.commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let subtree: SubTree<Sha256Hasher> = snapshot.prove(
        &[key00, key01, key10],
        spacedb::tx::ProofType::Standard
    ).unwrap();

    // Get bucket hashes with 2 bits (4 buckets)
    let hashes = subtree.bucket_hashes(2);
    assert_eq!(hashes.len(), 4);

    // Buckets 00, 01, 10 should have hashes, bucket 11 should be None
    assert!(hashes[0b00].is_some(), "bucket 00 should have a hash");
    assert!(hashes[0b01].is_some(), "bucket 01 should have a hash");
    assert!(hashes[0b10].is_some(), "bucket 10 should have a hash");
    assert!(hashes[0b11].is_none(), "bucket 11 should be empty");
}

#[test]
fn subtree_bucket_hashes_single_bit() {
    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    // Keys starting with 0
    let key0a = [0x00u8; 32];
    let key0b = [0x40u8; 32];
    // Key starting with 1
    let key1 = [0x80u8; 32];

    write = write.insert(key0a, vec![1]).unwrap();
    write = write.insert(key0b, vec![2]).unwrap();
    write = write.insert(key1, vec![3]).unwrap();
    write.commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let subtree: SubTree<Sha256Hasher> = snapshot.prove(
        &[key0a, key0b, key1],
        spacedb::tx::ProofType::Standard
    ).unwrap();

    // Get bucket hashes with 1 bit (2 buckets)
    let hashes = subtree.bucket_hashes(1);
    assert_eq!(hashes.len(), 2);
    assert!(hashes[0].is_some(), "bucket 0 should have a hash");
    assert!(hashes[1].is_some(), "bucket 1 should have a hash");
}

#[test]
fn subtree_bucket_hashes_empty() {
    let empty: SubTree<Sha256Hasher> = SubTree::empty();
    let hashes = empty.bucket_hashes(2);
    assert_eq!(hashes.len(), 4);
    assert!(hashes.iter().all(|h| h.is_none()));
}

#[test]
fn subtree_get_prefix_basic() {
    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    let key00 = [0x00u8; 32]; // 0b00...
    let key01 = [0x40u8; 32]; // 0b01...
    let key10 = [0x80u8; 32]; // 0b10...

    write = write.insert(key00, vec![0]).unwrap();
    write = write.insert(key01, vec![1]).unwrap();
    write = write.insert(key10, vec![2]).unwrap();
    write.commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let subtree: SubTree<Sha256Hasher> = snapshot.prove(
        &[key00, key01, key10],
        spacedb::tx::ProofType::Standard
    ).unwrap();

    // Get subtree for prefix "0" (should contain key00 and key01)
    let prefix_0 = subtree.get_prefix(&[false]).unwrap();
    assert!(prefix_0.contains(&key00).unwrap());
    assert!(prefix_0.contains(&key01).unwrap());
    assert!(!prefix_0.contains(&key10).is_ok() || !prefix_0.contains(&key10).unwrap());

    // Get subtree for prefix "1" (should contain key10)
    let prefix_1 = subtree.get_prefix(&[true]).unwrap();
    assert!(prefix_1.contains(&key10).unwrap());

    // Get subtree for prefix "00" (should contain only key00)
    let prefix_00 = subtree.get_prefix(&[false, false]).unwrap();
    assert!(prefix_00.contains(&key00).unwrap());
}

#[test]
fn subtree_get_prefix_no_match() {
    let db = Database::memory().unwrap();
    db.begin_write().unwrap()
        .insert([0x00u8; 32], vec![1]).unwrap()  // starts with 0
        .commit().unwrap();

    let mut snapshot = db.begin_read().unwrap();
    let subtree: SubTree<Sha256Hasher> = snapshot.prove(
        &[[0x00u8; 32]],
        spacedb::tx::ProofType::Standard
    ).unwrap();
    let original_root = subtree.compute_root().unwrap();

    // Get prefix "1" - no keys start with 1
    // Returns a subtree with hashed nodes (preserving root hash)
    let prefix_1 = subtree.get_prefix(&[true]).unwrap();

    // Root hash should be preserved
    assert_eq!(prefix_1.compute_root().unwrap(), original_root);

    // No keys are accessible (they're all hashed)
    assert!(prefix_1.contains(&[0x00u8; 32]).is_err());
}

#[test]
fn subtree_bucket_hashes_sync_scenario() {
    // Simulate a sync scenario where Alice and Bob have different keys
    let alice_db = Database::memory().unwrap();
    let bob_db = Database::memory().unwrap();

    // Shared keys
    let shared1 = [0x00u8; 32];
    let shared2 = [0x40u8; 32];
    // Bob has an extra key
    let bob_only = [0x80u8; 32];

    alice_db.begin_write().unwrap()
        .insert(shared1, vec![1]).unwrap()
        .insert(shared2, vec![2]).unwrap()
        .commit().unwrap();

    bob_db.begin_write().unwrap()
        .insert(shared1, vec![1]).unwrap()
        .insert(shared2, vec![2]).unwrap()
        .insert(bob_only, vec![3]).unwrap()
        .commit().unwrap();

    let mut alice_snapshot = alice_db.begin_read().unwrap();
    let mut bob_snapshot = bob_db.begin_read().unwrap();

    let alice_tree: SubTree<Sha256Hasher> = alice_snapshot.prove(
        &[shared1, shared2],
        spacedb::tx::ProofType::Standard
    ).unwrap();

    let bob_tree: SubTree<Sha256Hasher> = bob_snapshot.prove(
        &[shared1, shared2, bob_only],
        spacedb::tx::ProofType::Standard
    ).unwrap();

    // Compare bucket hashes at 2 bits
    let alice_hashes = alice_tree.bucket_hashes(2);
    let bob_hashes = bob_tree.bucket_hashes(2);

    // Buckets 00 and 01 should match (shared keys)
    assert_eq!(alice_hashes[0b00], bob_hashes[0b00], "bucket 00 should match");
    assert_eq!(alice_hashes[0b01], bob_hashes[0b01], "bucket 01 should match");

    // Bucket 10 should differ (Bob has extra key)
    assert_ne!(alice_hashes[0b10], bob_hashes[0b10], "bucket 10 should differ");

    // Alice can now request bucket 10 from Bob
    let bob_prefix_10 = bob_tree.get_prefix(&[true, false]).unwrap();
    assert!(bob_prefix_10.contains(&bob_only).unwrap());
}

#[test]
fn subtree_sync_100k_keys_80_differ() {
    use spacedb::subtree::{ValueOrHash, DiffSession, DiffRequest, DiffResponse};

    fn make_key(n: u32) -> Hash {
        Sha256Hasher::hash(&n.to_le_bytes())
    }

    // Alice: 100k keys, Bob: 100k + 80 extra + 1 modified
    let mut alice: SubTree<Sha256Hasher> = SubTree::empty();
    for i in 0..100_000u32 {
        alice.insert(make_key(i), ValueOrHash::Value(vec![(i % 256) as u8])).unwrap();
    }

    let mut bob = alice.clone();
    for i in 100_000..100_080u32 {
        bob.insert(make_key(i), ValueOrHash::Value(vec![0xBB])).unwrap();
    }
    bob.update(make_key(100), ValueOrHash::Value(vec![0xCC])).unwrap(); // modify one

    let bob_root = bob.compute_root().unwrap();
    assert_ne!(alice.compute_root().unwrap(), bob_root);

    // Use DiffSession state machine
    let mut session = DiffSession::new(&alice);
    while let Some(request) = session.next_request() {
        let response = match request {
            DiffRequest::BucketHashes { ref prefix, bits } => {
                DiffResponse::BucketHashes(bob.bucket_hashes_at_prefix(prefix, bits))
            }
            DiffRequest::Entries { ref prefix } => {
                DiffResponse::Entries(bob.entries_at_prefix(prefix))
            }
        };
        session.process_response(response);
    }

    let differing = session.result();
    assert_eq!(differing.len(), 81); // 80 new + 1 modified

    // Apply differing entries
    for (key, value_hash) in differing {
        alice.update(key, ValueOrHash::Hash(value_hash)).unwrap();
    }

    assert_eq!(alice.compute_root().unwrap(), bob_root);
}

#[test]
fn compare_encoding_sizes() {
    let db = Database::memory().unwrap();
    let mut write = db.begin_write().unwrap();

    // Insert keys with varied prefixes and value sizes
    for i in 0u8..50 {
        let mut k = [0u8; 32];
        k[0] = i;
        k[1] = i.wrapping_mul(37);
        write = write.insert(k, vec![i; (i as usize % 20) + 1]).unwrap();
    }
    write.commit().unwrap();

    let all_keys: Vec<Hash> = (0u8..50).map(|i| {
        let mut k = [0u8; 32];
        k[0] = i;
        k[1] = i.wrapping_mul(37);
        k
    }).collect();

    let mut snapshot = db.begin_read().unwrap();

    // Full proof with all keys (has values)
    let full_proof: SubTree<Sha256Hasher> = snapshot.prove(&all_keys, ProofType::Standard).unwrap();

    // Partial proof (mix of values and hash nodes)
    let partial_keys: Vec<Hash> = all_keys[..10].to_vec();
    let partial_proof = full_proof.prove(&partial_keys, spacedb::subtree::ProofType::Standard).unwrap();

    // Single leaf
    let single_proof = full_proof.prove(&all_keys[..1], spacedb::subtree::ProofType::Standard).unwrap();

    for (label, subtree) in [
        ("full (50 keys)", &full_proof),
        ("partial (10 keys)", &partial_proof),
        ("single (1 key)", &single_proof),
    ] {
        let bytes = borsh::to_vec(subtree).unwrap();

        eprintln!("{label}: {} bytes", bytes.len());

        // Verify round-trip
        let deserialized: SubTree<Sha256Hasher> = borsh::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.compute_root().unwrap(), subtree.compute_root().unwrap());
    }
}

#[test]
fn export_produces_identical_file() {
    use std::fs;
    let tmp_dir = std::env::temp_dir();
    let original_path = tmp_dir.join("test_original.sdb");
    let exported_path = tmp_dir.join("test_exported.sdb");
    let fresh_path = tmp_dir.join("test_fresh.sdb");

    // Clean up any existing files
    let _ = fs::remove_file(&original_path);
    let _ = fs::remove_file(&exported_path);
    let _ = fs::remove_file(&fresh_path);

    // Create original DB with multiple commits (to create savepoint history)
    {
        let db = Database::open(original_path.to_str().unwrap()).unwrap();
        let mut tx = db.begin_write().unwrap();
        for i in 0..500u32 {
            let key = Sha256Hasher::hash(&i.to_le_bytes());
            tx = tx.insert(key, i.to_le_bytes().to_vec()).unwrap();
        }
        tx.commit().unwrap();

        // Second commit
        let mut tx = db.begin_write().unwrap();
        for i in 500..1000u32 {
            let key = Sha256Hasher::hash(&i.to_le_bytes());
            tx = tx.insert(key, i.to_le_bytes().to_vec()).unwrap();
        }
        tx.commit().unwrap();

        // Export
        let read_tx = db.begin_read().unwrap();
        read_tx.export(exported_path.to_str().unwrap()).unwrap();
    }

    // Create fresh DB with single commit containing all the same data
    {
        let db = Database::open(fresh_path.to_str().unwrap()).unwrap();
        let mut tx = db.begin_write().unwrap();
        for i in 0..1000u32 {
            let key = Sha256Hasher::hash(&i.to_le_bytes());
            tx = tx.insert(key, i.to_le_bytes().to_vec()).unwrap();
        }
        tx.commit().unwrap();
    }

    // Read and compare file contents
    let exported_bytes = fs::read(&exported_path).unwrap();
    let fresh_bytes = fs::read(&fresh_path).unwrap();

    assert_eq!(exported_bytes.len(), fresh_bytes.len(), "File sizes differ");
    assert_eq!(exported_bytes, fresh_bytes, "File contents differ");

    // Verify the exported DB is fully functional
    {
        let db = Database::open(exported_path.to_str().unwrap()).unwrap();
        let mut read_tx = db.begin_read().unwrap();

        // Check we can read all keys
        for i in 0..1000u32 {
            let key = Sha256Hasher::hash(&i.to_le_bytes());
            let value = read_tx.get(&key).unwrap().unwrap();
            assert_eq!(value, i.to_le_bytes().to_vec());
        }

        // Verify root hash matches
        let exported_root = read_tx.compute_root().unwrap();

        let fresh_db = Database::open(fresh_path.to_str().unwrap()).unwrap();
        let mut fresh_tx = fresh_db.begin_read().unwrap();
        let fresh_root = fresh_tx.compute_root().unwrap();

        assert_eq!(exported_root, fresh_root);
    }

    // Clean up
    let _ = fs::remove_file(&original_path);
    let _ = fs::remove_file(&exported_path);
    let _ = fs::remove_file(&fresh_path);
}

#[test]
fn read_only_while_writer_holds_db() {
    use std::fs;

    let tmp_dir = std::env::temp_dir();
    let db_path = tmp_dir.join("test_read_only_lock.sdb");
    let _ = fs::remove_file(&db_path);
    let path = db_path.to_str().unwrap();

    // Open for writing and insert some data
    let db = Database::open(path).unwrap();
    let mut write = db.begin_write().unwrap();
    for i in 0u8..10 {
        let mut k = [0u8; 32];
        k[0] = i;
        write = write.insert(k, vec![i; 4]).unwrap();
    }
    write.commit().unwrap();

    // While writer is still open, open read-only and verify data
    let reader = Database::open_read_only(path).unwrap();
    let mut snapshot = reader.begin_read().unwrap();
    let reader_root = snapshot.compute_root().unwrap();

    let mut writer_snapshot = db.begin_read().unwrap();
    let writer_root = writer_snapshot.compute_root().unwrap();

    assert_eq!(reader_root, writer_root, "reader should see the same root as writer");

    for i in 0u8..10 {
        let mut k = [0u8; 32];
        k[0] = i;
        assert_eq!(snapshot.get(&k).unwrap(), Some(vec![i; 4]));
    }

    // A second writer should fail
    let second_writer = Database::open(path);
    assert!(second_writer.is_err(), "second writer should be denied");

    // A second reader should succeed
    let reader2 = Database::open_read_only(path).unwrap();
    let mut snapshot2 = reader2.begin_read().unwrap();
    assert_eq!(snapshot2.compute_root().unwrap(), writer_root);

    drop(reader);
    drop(reader2);
    drop(db);
    let _ = fs::remove_file(&db_path);
}
