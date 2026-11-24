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
pub fn root_from_path(
    leaf: &[u8; 32],
    index: usize,
    size: usize,
    path: &[[u8; 32]],
) -> Option<[u8; 32]> {
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

/// Consistency path from a tree of `old` leaves to the tree over all `leaves` (`old` must be a
/// prefix length, `1..=leaves.len()`): the inclusion path of leaf `old - 1` in the **new** tree.
/// Under [`merkle_root`]'s shape, leaf `old - 1` is the last node of every old layer, so the
/// old tree's root depends only on that leaf and the *left* siblings of its path, and those left
/// siblings are complete aligned subtrees over leaves `< old - 1`, identical in both trees. The
/// path's *right* siblings are the new tree's growth. See [`roots_from_consistency`].
pub fn consistency_path(leaves: &[[u8; 32]], old: usize) -> Option<Vec<[u8; 32]>> {
    if old == 0 {
        return None;
    }
    merkle_path(leaves, old - 1)
}

/// `(old_root, new_root)` implied by a consistency path (from [`consistency_path`]) and `leaf`
/// (leaf `old - 1`, which the path starts from). `None` when `old == 0`, `old > new`, or the path
/// has the wrong length for the two sizes. Because both roots are rebuilt from the *same* hashes,
/// matching both against pinned roots shows (under SHA-256 collision resistance and fixed tree
/// shapes for the two sizes) that the first `old` leaves of the new tree are the old tree's leaves.
pub fn roots_from_consistency(
    leaf: &[u8; 32],
    old: usize,
    new: usize,
    path: &[[u8; 32]],
) -> Option<([u8; 32], [u8; 32])> {
    if old == 0 || old > new {
        return None;
    }
    let new_root = root_from_path(leaf, old - 1, new, path)?;
    // Old tree: the node on the path is always the last one of its layer, so a level either takes
    // a left sibling (index odd) or pairs the node with itself (index even, layer size > 1).
    let (mut cur, mut i, mut n, mut used) = (*leaf, old - 1, old, 0usize);
    let mut m = new;
    while m > 1 {
        let left = i % 2 == 1;
        let right = !left && i + 1 < m;
        if n > 1 {
            cur = if left {
                pair(path.get(used)?, &cur)
            } else {
                pair(&cur, &cur)
            };
        }
        if left || right {
            used += 1;
        }
        i /= 2;
        n = n.div_ceil(2);
        m = m.div_ceil(2);
    }
    (used == path.len()).then_some((cur, new_root))
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
            let leaves: Vec<[u8; 32]> = (0..n)
                .map(|i| Sha256::digest((i as u32).to_le_bytes()).into())
                .collect();
            let root = merkle_root(&leaves);
            for (i, leaf) in leaves.iter().enumerate() {
                let p = merkle_path(&leaves, i).unwrap();
                assert_eq!(root_from_path(leaf, i, n, &p), Some(root), "n={n} i={i}");
                // wrong position or a flipped sibling must not reproduce the root
                if n > 1 {
                    let other = (i + 1) % n;
                    assert_ne!(
                        root_from_path(leaf, other, n, &p),
                        Some(root),
                        "n={n} i={i} moved"
                    );
                }
                if let Some(first) = p.first() {
                    let mut bad = p.clone();
                    bad[0] = {
                        let mut x = *first;
                        x[0] ^= 1;
                        x
                    };
                    assert_ne!(root_from_path(leaf, i, n, &bad), Some(root));
                    assert_eq!(root_from_path(leaf, i, n, &p[1..]), None);
                }
            }
            assert!(merkle_path(&leaves, n).is_none());
        }
    }
}

#[cfg(test)]
mod consistency_tests {
    use super::*;

    fn leaves(n: usize, salt: u8) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let mut b = (i as u32).to_le_bytes().to_vec();
                b.push(salt);
                Sha256::digest(&b).into()
            })
            .collect()
    }

    #[test]
    fn every_prefix_of_every_size_is_consistent() {
        for m in 1..=40usize {
            let l = leaves(m, 0);
            let new_root = merkle_root(&l);
            for n in 1..=m {
                let p = consistency_path(&l, n).unwrap();
                assert_eq!(
                    roots_from_consistency(&l[n - 1], n, m, &p),
                    Some((merkle_root(&l[..n]), new_root)),
                    "n={n} m={m}"
                );
            }
        }
    }

    #[test]
    fn fails_closed() {
        for m in 2..=24usize {
            let l = leaves(m, 0);
            for n in 1..m {
                let old_root = merkle_root(&l[..n]);
                let p = consistency_path(&l, n).unwrap();
                // size regression / zero
                assert_eq!(roots_from_consistency(&l[n - 1], m, n, &p), None);
                assert_eq!(roots_from_consistency(&l[n - 1], 0, m, &p), None);
                // not a prefix: the new tree differs at some leaf < n
                for k in 0..n {
                    let mut forked = l.clone();
                    forked[k][0] ^= 1;
                    let fp = consistency_path(&forked, n).unwrap();
                    let r = roots_from_consistency(&forked[n - 1], n, m, &fp).unwrap();
                    assert_eq!(r.1, merkle_root(&forked));
                    assert_ne!(r.0, old_root, "fork at {k} n={n} m={m} looks consistent");
                }
                // tampered hash, wrong leaf, truncated or padded path
                for j in 0..p.len() {
                    let mut bad = p.clone();
                    bad[j][31] ^= 0x80;
                    let r = roots_from_consistency(&l[n - 1], n, m, &bad).unwrap();
                    assert!(r.0 != old_root || r.1 != merkle_root(&l));
                }
                let mut leaf = l[n - 1];
                leaf[0] ^= 1;
                let r = roots_from_consistency(&leaf, n, m, &p).unwrap();
                assert_ne!(r.0, old_root);
                if !p.is_empty() {
                    assert_eq!(roots_from_consistency(&l[n - 1], n, m, &p[1..]), None);
                }
                let mut long = p.clone();
                long.push([7u8; 32]);
                assert_eq!(roots_from_consistency(&l[n - 1], n, m, &long), None);
            }
        }
    }
}
