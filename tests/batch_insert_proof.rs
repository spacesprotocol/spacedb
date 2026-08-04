//! `prove(keys, Standard)` should return a subtree carrying enough of the tree
//! to insert those same keys.
use spacedb::db::Database;
use spacedb::subtree::ValueOrHash;
use spacedb::tx::ProofType;
use spacedb::{Hash, NodeHasher, Sha256Hasher};

fn key(tag: &str, i: usize) -> Hash {
    Sha256Hasher::hash(format!("{}{}", tag, i).as_bytes())
}

/// In-memory tree pre-populated with `existing` keys.
fn tree_with(existing: usize) -> Database<Sha256Hasher> {
    let db = Database::memory().expect("memory db");
    let mut tx = db.begin_write().expect("write tx");
    for i in 0..existing {
        tx = tx
            .insert(key("existing", i), b"v".to_vec())
            .expect("insert");
    }
    tx.commit().expect("commit");
    db
}

/// Prove `n` absent keys, then insert exactly those keys into the returned
/// subtree. Returns the index of the first insert that failed.
fn replay(db: &Database<Sha256Hasher>, n: usize) -> Option<usize> {
    let keys: Vec<Hash> = (0..n).map(|i| key("new", i)).collect();

    let mut snapshot = db.begin_read().expect("read tx");
    let mut proof = snapshot
        .prove(&keys, ProofType::Standard)
        .expect("prove should succeed");

    for (i, k) in keys.iter().enumerate() {
        if proof.insert(*k, ValueOrHash::Hash(key("val", i))).is_err() {
            return Some(i);
        }
    }
    None
}

/// A proof over N keys should support inserting those N keys.
#[test]
fn standard_proof_supports_inserting_its_own_keys() {
    for existing in [2usize, 102, 1000] {
        let db = tree_with(existing);
        assert_eq!(
            replay(&db, 900),
            None,
            "tree with {} existing keys: proving 900 absent keys returned a \
             subtree that cannot insert all 900",
            existing
        );
    }
}

/// Proving a superset of keys must not support fewer insertions than proving
/// a subset — the larger proof strictly contains more of the tree.
#[test]
fn proving_more_keys_does_not_reduce_capability() {
    let db = tree_with(102);

    // Largest batch that replays cleanly.
    let mut largest = 0;
    for n in 1..=512 {
        if replay(&db, n).is_none() {
            largest = n;
        } else {
            break;
        }
    }
    assert!(largest > 0, "no batch size replayed at all");

    // A proof over more keys must still handle at least that many inserts.
    let failed_at = replay(&db, largest * 2);
    assert!(
        failed_at.is_none() || failed_at.unwrap() >= largest,
        "proving {} keys supports {} inserts, but proving {} keys fails at \
         entry {} — a larger proof supports fewer insertions",
        largest,
        largest,
        largest * 2,
        failed_at.unwrap()
    );
}

/// `SubTree::prove` mirrors the tree's prove and had the same one-sided key
/// trimming: chaining a proof from a full subtree must also support inserting
/// the proven keys.
#[test]
fn chained_subtree_proof_supports_inserting_its_own_keys() {
    for existing in [2usize, 102, 1000] {
        let db = tree_with(existing);

        // Prove every existing key so the subtree carries the full tree.
        let all: Vec<Hash> = (0..existing).map(|i| key("existing", i)).collect();
        let mut snapshot = db.begin_read().expect("read tx");
        let full = snapshot
            .prove(&all, ProofType::Standard)
            .expect("prove existing keys");

        let keys: Vec<Hash> = (0..900).map(|i| key("new", i)).collect();
        let mut proof = full
            .prove(&keys, spacedb::subtree::ProofType::Standard)
            .expect("subtree prove should succeed");

        for (i, k) in keys.iter().enumerate() {
            assert!(
                proof.insert(*k, ValueOrHash::Hash(key("val", i))).is_ok(),
                "tree with {} existing keys: chained proof over 900 absent \
                 keys cannot insert entry {}",
                existing,
                i
            );
        }
    }
}
