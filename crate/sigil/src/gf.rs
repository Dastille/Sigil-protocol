const EXP: [u8; 512] = {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    let mut i = 255;
    while i < 512 {
        exp[i] = exp[i - 255];
        i += 1;
    }
    let _ = log;
    exp
};

const LOG: [u8; 256] = {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    log
};

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

pub fn inv(a: u8) -> u8 {
    assert!(a != 0);
    EXP[255 - LOG[a as usize] as usize]
}

pub fn eval_poly(coeff: &[u8], x: u8) -> u8 {
    let mut y = 0u8;
    for &c in coeff.iter().rev() {
        y = mul(y, x) ^ c;
    }
    y
}

pub fn solve_vandermonde(xs: &[u8], ys: &[u8]) -> Vec<u8> {
    let k = xs.len();
    let mut a = vec![vec![0u8; k + 1]; k];
    for i in 0..k {
        let mut p = 1u8;
        for j in 0..k {
            a[i][j] = p;
            p = mul(p, xs[i]);
        }
        a[i][k] = ys[i];
    }
    for col in 0..k {
        let mut pivot = col;
        while pivot < k && a[pivot][col] == 0 {
            pivot += 1;
        }
        if pivot == k {
            panic!("singular");
        }
        a.swap(col, pivot);
        let invp = inv(a[col][col]);
        for j in col..=k {
            a[col][j] = mul(a[col][j], invp);
        }
        for row in 0..k {
            if row == col {
                continue;
            }
            let f = a[row][col];
            if f == 0 {
                continue;
            }
            for j in col..=k {
                a[row][j] ^= mul(f, a[col][j]);
            }
        }
    }
    (0..k).map(|i| a[i][k]).collect()
}
