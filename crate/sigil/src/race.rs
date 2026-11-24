//! Racing repair work across CPU threads, with a shared way to cancel (std only, no GPU).
//!
//! Two shapes, both deterministic — the answer never depends on the thread count or on
//! which thread finishes first:
//!
//! * [`map_ordered`]: every item must be done (one byte column each in soft repair).
//!   Workers take the next block of items from a shared counter, so a slow region does
//!   not leave the other threads idle; results are put back in item order.
//! * [`race_first`]: candidates in a fixed order, and only the **first** one (lowest
//!   index) that passes is wanted. Workers race through the list; as soon as candidate
//!   `i` passes, nobody starts a candidate after `i`, and running ones after `i` are told
//!   to give up. Every candidate before `i` still runs to the end, so the winner is the
//!   same one a single thread would pick.
//!
//! Both stop all workers at the next item when the repair is asked to stop (Ctrl-C,
//! [`crate::repair_ctl::request_stop`]), or when a worker panics, and then return an
//! error — a partial result is never used as a whole one.

use crate::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Most CPU threads one race uses.
pub(crate) const MAX_THREADS: usize = 8;

/// Memory one race may hold in per-worker copies (decoded payloads), at most.
const MEMORY_BUDGET: usize = 1 << 30;

/// Worker threads for `items` independent jobs that each hold about `bytes_each` bytes
/// while running: at most [`MAX_THREADS`], the CPU count, `items`, and the memory budget.
pub(crate) fn threads_for(items: usize, bytes_each: usize) -> usize {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    let by_mem = MEMORY_BUDGET / bytes_each.max(1);
    cpus.clamp(1, MAX_THREADS).min(items).min(by_mem).max(1)
}

/// Sets the shared cancel flag if its thread unwinds (a panicking worker stops the race).
struct CancelOnPanic<'a>(&'a AtomicBool);

impl Drop for CancelOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}

fn stopped(cancel: &AtomicBool) -> bool {
    cancel.load(Ordering::SeqCst) || crate::repair_ctl::stop_requested()
}

/// Run `work` on `threads` scoped threads (inline when 1) and collect what each returned.
fn run_workers<T: Send>(
    threads: usize,
    cancel: &AtomicBool,
    work: &(dyn Fn() -> Vec<(usize, T)> + Sync),
) -> Result<Vec<(usize, T)>, Error> {
    if threads <= 1 {
        return Ok(work());
    }
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(move || {
                    let _guard = CancelOnPanic(cancel);
                    work()
                })
            })
            .collect();
        let mut out = Vec::new();
        let mut panicked = false;
        for h in handles {
            match h.join() {
                Ok(v) => out.extend(v),
                Err(_) => panicked = true,
            }
        }
        if panicked {
            return Err(Error::Msg("soft repair worker stopped unexpectedly".into()));
        }
        Ok(out)
    })
}

/// `(0..n).map(f)` on up to `threads` threads, results in index order whatever the thread
/// count. Fails (and stops every worker) on a stop request or a worker panic.
pub(crate) fn map_ordered<T, F>(n: usize, threads: usize, f: F) -> Result<Vec<T>, Error>
where
    T: Send,
    F: Fn(usize) -> T + Sync,
{
    let threads = threads.clamp(1, MAX_THREADS).min(n.max(1));
    // Small blocks keep threads busy when columns differ in cost; 16 blocks per thread.
    let grain = (n / (threads * 16)).max(1);
    let next = AtomicUsize::new(0);
    let cancel = AtomicBool::new(false);
    let work = || {
        let mut local = Vec::new();
        loop {
            if stopped(&cancel) {
                break;
            }
            let start = next.fetch_add(grain, Ordering::Relaxed);
            if start >= n {
                break;
            }
            for i in start..(start + grain).min(n) {
                if stopped(&cancel) {
                    return local;
                }
                local.push((i, f(i)));
            }
        }
        local
    };
    let got = run_workers(threads, &cancel, &work)?;
    crate::repair_ctl::check()?;
    if got.len() != n {
        return Err(Error::Msg(
            "soft repair: a worker returned too few results".into(),
        ));
    }
    let mut slots: Vec<Option<T>> = (0..n).map(|_| None).collect();
    for (i, v) in got {
        if let Some(slot) = slots.get_mut(i) {
            *slot = Some(v);
        }
    }
    slots
        .into_iter()
        .collect::<Option<Vec<T>>>()
        .ok_or_else(|| Error::Msg("soft repair: a worker returned too few results".into()))
}

/// The lowest `i < n` for which `f(i, give_up)` returns `Some`, with its value — the same
/// answer a single thread trying `0, 1, 2, …` in order would give, on up to `threads`
/// threads. `give_up()` turns true once a lower candidate has passed (or a stop was asked
/// for); `f` may then return `None` early, since its answer can no longer win. `Ok(None)`
/// when no candidate passes; `Err` on a stop request or a worker panic.
pub(crate) fn race_first<T, F>(n: usize, threads: usize, f: F) -> Result<Option<(usize, T)>, Error>
where
    T: Send,
    F: Fn(usize, &dyn Fn() -> bool) -> Option<T> + Sync,
{
    let threads = threads.clamp(1, MAX_THREADS).min(n.max(1));
    let next = AtomicUsize::new(0);
    let best = AtomicUsize::new(usize::MAX);
    let cancel = AtomicBool::new(false);
    let work = || {
        let mut local = Vec::new();
        loop {
            if stopped(&cancel) {
                break;
            }
            // Indexes are handed out in increasing order, so once one is past the best
            // pass so far, so is every later one.
            let i = next.fetch_add(1, Ordering::SeqCst);
            if i >= n || i > best.load(Ordering::SeqCst) {
                break;
            }
            let give_up = || best.load(Ordering::SeqCst) < i || stopped(&cancel);
            if let Some(v) = f(i, &give_up) {
                best.fetch_min(i, Ordering::SeqCst);
                local.push((i, v));
            }
        }
        local
    };
    let got = run_workers(threads, &cancel, &work)?;
    crate::repair_ctl::check()?;
    Ok(got.into_iter().min_by_key(|(i, _)| *i))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn map_ordered_same_output_any_thread_count() {
        let want: Vec<u64> = (0..5000u64).map(|i| i * i % 977).collect();
        for t in [1, 2, 3, 8] {
            let got = map_ordered(5000, t, |i| (i as u64) * (i as u64) % 977).unwrap();
            assert_eq!(got, want, "threads {t}");
        }
        assert!(map_ordered(0, 4, |i| i).unwrap().is_empty());
    }

    #[test]
    fn race_first_picks_lowest_pass_whatever_the_timing() {
        // Passes at 7, 9, 30; later passes finish faster, so a naive "first to finish"
        // race would often pick 30 or 9.
        let passes = [7usize, 9, 30];
        for t in [1, 2, 4, 8] {
            for _ in 0..5 {
                let r = race_first(40, t, |i, _give_up| {
                    std::thread::sleep(std::time::Duration::from_micros((40 - i as u64) * 50));
                    passes.contains(&i).then_some(i * 10)
                })
                .unwrap();
                assert_eq!(r, Some((7, 70)), "threads {t}");
            }
        }
        assert_eq!(race_first(10, 4, |_, _| None::<u8>).unwrap(), None);
    }

    #[test]
    fn race_first_cancels_later_candidates() {
        let started = AtomicU64::new(0);
        let r = race_first(1000, 4, |i, give_up| {
            started.fetch_add(1, Ordering::SeqCst);
            if i == 0 {
                return Some(());
            }
            // A long candidate that notices it lost and stops early.
            for _ in 0..200 {
                if give_up() {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            None
        })
        .unwrap();
        assert_eq!(r.map(|x| x.0), Some(0));
        // Index 0 wins at once; only candidates already handed out may have started.
        assert!(started.load(Ordering::SeqCst) <= 8, "{started:?}");
    }

    #[test]
    fn worker_panic_is_an_error_not_a_short_result() {
        let r = map_ordered(4000, 4, |i| {
            assert!(i != 1234, "boom");
            i
        });
        assert!(r.is_err());
        let r = race_first(100, 4, |i, _| {
            assert!(i != 50, "boom");
            None::<u8>
        });
        assert!(r.is_err());
    }

    #[test]
    fn threads_for_respects_items_and_memory() {
        assert_eq!(threads_for(1, 10), 1);
        assert_eq!(threads_for(0, 10), 1);
        assert_eq!(threads_for(64, MEMORY_BUDGET), 1);
        assert!(threads_for(64, 1) <= MAX_THREADS);
    }
}
