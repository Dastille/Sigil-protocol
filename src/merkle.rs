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
