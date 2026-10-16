//! RS throughput: `cargo run --release --example rsbench -- <MB> <k> <n> [ref|fast|both]`
//! Erases the first min(n-k, k) data shards before decode (forces real repair).
use sigil::rs_bench::{decode_indexed, encode_shards, kernel_name, reference};
use std::time::Instant;

type Parts = Vec<(usize, Vec<u8>)>;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mb: usize = a.get(1).map_or(1, |s| s.parse().unwrap());
    let k: usize = a.get(2).map_or(12, |s| s.parse().unwrap());
    let n: usize = a.get(3).map_or(16, |s| s.parse().unwrap());
    let which = a.get(4).map_or("both", |s| s.as_str()).to_string();
    let len = mb * 1_000_000;
    let mut x = 0x9e3779b97f4a7c15u64;
    let data: Vec<u8> = (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let mbs = |t: f64| len as f64 / 1e6 / t;
    let drop = (n - k).min(k);
    let run = |name: &str,
               enc: &dyn Fn(&[u8]) -> Vec<Vec<u8>>,
               dec: &dyn Fn(&[(usize, Vec<u8>)]) -> Vec<u8>|
     -> Parts {
        let t = Instant::now();
        let shards = enc(&data);
        let te = t.elapsed().as_secs_f64();
        let parts: Parts = shards.into_iter().enumerate().skip(drop).collect();
        let t = Instant::now();
        let out = dec(&parts);
        let td = t.elapsed().as_secs_f64();
        assert!(out == data, "roundtrip mismatch");
        println!(
            "{name},{mb}MB,{k}/{n},enc {:.2} MB/s ({te:.2}s),dec {:.2} MB/s ({td:.2}s),kernel={}",
            mbs(te),
            mbs(td),
            kernel_name()
        );
        parts
    };
    let mut fast_parts = None;
    if which != "ref" {
        fast_parts = Some(run("fast", &|d| encode_shards(d, k, n), &|p| {
            decode_indexed(p, k, len, true).unwrap()
        }));
    }
    if which != "fast" {
        let rp = run("ref", &|d| reference::encode_shards(d, k, n), &|p| {
            reference::decode_indexed(p, k, len, true).unwrap()
        });
        if let Some(fp) = fast_parts {
            assert!(fp == rp, "fast and reference shards differ");
            println!("shards byte-identical: yes");
        }
    }
}
