use sha2::{Digest, Sha256};

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return Sha256::digest([]).into();
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::new();
        let mut i = 0;
        while i < layer.len() {
            let a = layer[i];
            let b = if i + 1 < layer.len() { layer[i + 1] } else { a };
            let mut cat = [0u8; 64];
            cat[..32].copy_from_slice(&a);
            cat[32..].copy_from_slice(&b);
            next.push(Sha256::digest(cat).into());
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

/// Inclusion path for leaf `index` under [`merkle_root`]: the sibling hashes from the bottom up.
/// A level where the node is the odd last one (and so is paired with itself) contributes no hash;
/// the verifier knows those levels from the tree size. `None` if `index` is out of range.
pub fn merkle_path(leaves: &[[u8; 32]], index: usize) -> Option<Vec<[u8; 32]>> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    let mut i = index;
    while layer.len() > 1 {
        if i % 2 == 1 {
            path.push(layer[i - 1]);
        } else if i + 1 < layer.len() {
            path.push(layer[i + 1]);
        }
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut j = 0;
        while j < layer.len() {
            let a = layer[j];
            let b = if j + 1 < layer.len() { layer[j + 1] } else { a };
            next.push(pair(&a, &b));
            j += 2;
        }
        layer = next;
        i /= 2;
    }
    Some(path)
}

/// Root implied by `leaf` at `index` in a tree of `size` leaves with inclusion `path`
/// (as made by [`merkle_path`]). `None` when the path has the wrong length for that position.
pub fn root_from_path(leaf: &[u8; 32], index: usize, size: usize, path: &[[u8; 32]]) -> Option<[u8; 32]> {
    if size == 0 || index >= size {
        return None;
    }
    let (mut cur, mut i, mut n, mut used) = (*leaf, index, size, 0usize);
    while n > 1 {
        if i % 2 == 1 {
            cur = pair(path.get(used)?, &cur);
            used += 1;
        } else if i + 1 < n {
            cur = pair(&cur, path.get(used)?);
            used += 1;
        } else {
            cur = pair(&cur, &cur);
        }
        i /= 2;
        n = n.div_ceil(2);
    }
    (used == path.len()).then_some(cur)
}

fn pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut cat = [0u8; 64];
    cat[..32].copy_from_slice(a);
    cat[32..].copy_from_slice(b);
    Sha256::digest(cat).into()
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn every_leaf_of_every_size_proves_to_the_root() {
        for n in 1..=33usize {
            let leaves: Vec<[u8; 32]> = (0..n).map(|i| Sha256::digest((i as u32).to_le_bytes()).into()).collect();
            let root = merkle_root(&leaves);
            for (i, leaf) in leaves.iter().enumerate() {
                let p = merkle_path(&leaves, i).unwrap();
                assert_eq!(root_from_path(leaf, i, n, &p), Some(root), "n={n} i={i}");
                // wrong position or a flipped sibling must not reproduce the root
                if n > 1 {
                    let other = (i + 1) % n;
                    assert_ne!(root_from_path(leaf, other, n, &p), Some(root), "n={n} i={i} moved");
                }
                if let Some(first) = p.first() {
                    let mut bad = p.clone();
                    bad[0] = { let mut x = *first; x[0] ^= 1; x };
                    assert_ne!(root_from_path(leaf, i, n, &bad), Some(root));
                    assert_eq!(root_from_path(leaf, i, n, &p[1..]), None);
                }
            }
            assert!(merkle_path(&leaves, n).is_none());
        }
    }
}
