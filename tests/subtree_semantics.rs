//! Error-semantics regressions for `SubTree`:
//! - deleting a key that provably isn't in the proof must report
//!   `KeyNotFound`, not `IncompleteProof`
//! - merging must reject proofs containing interior `None` nodes instead of
//!   silently absorbing them

use spacedb::db::Database;
use spacedb::subtree::SubTreeNode;
use spacedb::tx::ProofType;
use spacedb::{Error, Hash, NodeHasher, Sha256Hasher, VerifyError};

fn key(tag: &str, i: usize) -> Hash {
    Sha256Hasher::hash(format!("{}{}", tag, i).as_bytes())
}

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

/// `base` with every bit from `from_bit` onward inverted: diverges from
/// `base` at exactly `from_bit` and takes the opposite branch at every
/// decision afterwards.
fn probe(base: &Hash, from_bit: usize) -> Hash {
    let mut k = *base;
    for i in from_bit..256 {
        k[i / 8] ^= 0x80 >> (i % 8);
    }
    k
}

/// A key the proof shows to be absent (`contains` == false) must delete with
/// `KeyNotFound`. Keys diverging inside an internal node's prefix used to
/// descend anyway and surface `IncompleteProof` when they hit a hash node.
#[test]
fn deleting_provably_absent_key_reports_key_not_found() {
    // Crafted keys giving the proven path a 254-bit prefix: proving `proven`
    // yields root(prefix ∅) → internal(prefix bits 1..254) → leaf, with hash
    // siblings. Probes diverging inside that prefix and routed toward the
    // hash sibling exercise the missing prefix check.
    let proven = [0u8; 32];
    let mut deep_sibling = [0u8; 32];
    deep_sibling[31] = 0x01; // diverges from `proven` at bit 255
    let mut top_sibling = [0u8; 32];
    top_sibling[0] = 0x80; // diverges from `proven` at bit 0

    let db = Database::memory().expect("memory db");
    let mut tx = db.begin_write().expect("write tx");
    for k in [proven, deep_sibling, top_sibling] {
        tx = tx.insert(k, b"v".to_vec()).expect("insert");
    }
    tx.commit().expect("commit");

    let mut absent_probes = 0;
    for from_bit in 1..256 {
        let candidate = probe(&proven, from_bit);

        let mut snapshot = db.begin_read().expect("read tx");
        let proof = snapshot
            .prove(&[proven], ProofType::Standard)
            .expect("prove");

        // Only probes the proof can decide about: provably absent keys.
        if !matches!(proof.contains(&candidate), Ok(false)) {
            continue;
        }
        absent_probes += 1;

        match proof.delete(&candidate) {
            Err(Error::Verify(VerifyError::KeyNotFound)) => {}
            other => panic!(
                "probe diverging at bit {}: proof shows the key is absent, \
                 expected KeyNotFound, got {:?}",
                from_bit,
                other.map(|_| "Ok(subtree)")
            ),
        }
    }
    assert!(absent_probes > 0, "no probe was provably absent");
}

/// Replaces the first `Hash` node found under `node` with `None`,
/// returning whether one was replaced.
fn null_out_first_hash(node: &mut SubTreeNode) -> bool {
    match node {
        SubTreeNode::Hash(_) => {
            *node = SubTreeNode::None;
            true
        }
        SubTreeNode::Internal { left, right, .. } => {
            null_out_first_hash(left) || null_out_first_hash(right)
        }
        _ => false,
    }
}

/// A proof with an interior `None` node cannot compute a root, so merging it
/// must fail — not silently absorb the `None` and return a valid-looking
/// proof built from the other side.
#[test]
fn merging_proof_with_interior_none_fails() {
    let db = tree_with(100);
    let proven = key("existing", 0);

    let mut snapshot = db.begin_read().expect("read tx");
    let mut broken = snapshot
        .prove(&[proven], ProofType::Standard)
        .expect("prove");
    let honest = snapshot
        .prove(&[proven], ProofType::Standard)
        .expect("prove");

    assert!(
        null_out_first_hash(&mut broken.root),
        "expected the proof to contain at least one hash node"
    );
    // Sanity: the broken proof is unverifiable on its own.
    assert!(broken.compute_root().is_err());

    assert!(
        broken.merge(honest).is_err(),
        "merging an unverifiable proof (interior None) must fail instead of \
         laundering it into a valid-looking one"
    );
}
