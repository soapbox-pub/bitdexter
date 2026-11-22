//! Double SHA-256, the hash Bitcoin uses for blocks, transactions and merkle
//! trees, on `sha2`, which uses the CPU's SHA extensions where it has them.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub fn sha256(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

pub fn sha256d(data: &[u8]) -> Hash {
    sha256(&sha256(data))
}

/// Double SHA-256 of several slices, as if they were one.
pub fn sha256d_parts(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let first: Hash = hasher.finalize().into();
    sha256(&first)
}

/// The parent of two nodes in a merkle tree.
pub fn merkle_parent(left: &Hash, right: &Hash) -> Hash {
    let mut both = [0u8; 64];
    both[..32].copy_from_slice(left);
    both[32..].copy_from_slice(right);
    sha256d(&both)
}

/// The merkle root of `leaves`, and whether the tree is mutated: whether two
/// identical nodes were paired at any level, which lets a different list of
/// transactions have the same root (CVE-2012-2459). Consumes `leaves`.
pub fn merkle_root(mut leaves: Vec<Hash>) -> (Hash, bool) {
    if leaves.is_empty() {
        return ([0; 32], false);
    }
    let mut mutated = false;
    while leaves.len() > 1 {
        for pair in leaves.as_chunks::<2>().0 {
            if pair[0] == pair[1] {
                mutated = true;
            }
        }
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().unwrap());
        }
        let next: Vec<Hash> = leaves.chunks_exact(2).map(|pair| merkle_parent(&pair[0], &pair[1])).collect();
        leaves = next;
    }
    (leaves[0], mutated)
}

/// The merkle branch proving the leaf at `index`, from the leaf's sibling up.
pub fn merkle_branch(mut leaves: Vec<Hash>, mut index: usize) -> Vec<Hash> {
    let mut branch = Vec::new();
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().unwrap());
        }
        branch.push(leaves[index ^ 1]);
        index /= 2;
        leaves = leaves.chunks_exact(2).map(|pair| merkle_parent(&pair[0], &pair[1])).collect();
    }
    branch
}

/// A hash as it's shown to people: byte-reversed hex.
pub fn to_hex_rev(hash: &Hash) -> String {
    let mut reversed = *hash;
    reversed.reverse();
    hex::encode(reversed)
}

/// Parses byte-reversed hex, as txids and block hashes are written.
pub fn from_hex_rev(s: &str) -> Option<Hash> {
    if s.len() != 64 {
        return None;
    }
    let mut bytes: Hash = hex::decode(s).ok()?.try_into().ok()?;
    bytes.reverse();
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_coinbase_is_its_merkle_root() {
        let txid = from_hex_rev("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b").unwrap();
        assert_eq!(merkle_root(vec![txid]), (txid, false));
    }

    #[test]
    fn duplicate_pair_is_mutated() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(!merkle_root(vec![a, b, b]).1);
        assert!(merkle_root(vec![a, b, b, b]).1);
        // [a, b, c] and [a, b, c, c] have the same root, and the second is mutated.
        let c = [3u8; 32];
        assert_eq!(merkle_root(vec![a, b, c]).0, merkle_root(vec![a, b, c, c]).0);
        assert!(merkle_root(vec![a, b, c, c]).1);
    }

    #[test]
    fn branch_verifies() {
        let leaves: Vec<Hash> = (0..7u8).map(|i| [i; 32]).collect();
        let (root, _) = merkle_root(leaves.clone());
        for index in 0..leaves.len() {
            let mut node = leaves[index];
            let mut at = index;
            for sibling in merkle_branch(leaves.clone(), index) {
                node = if at % 2 == 0 { merkle_parent(&node, &sibling) } else { merkle_parent(&sibling, &node) };
                at /= 2;
            }
            assert_eq!(node, root);
        }
    }
}
