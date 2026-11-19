//! Stop, progress and the "ask before a long repair" rule for `sigil mend`.
//!
//! The repair loops call [`check`] between units of work (soft-repair columns, chunk
//! stars of a large-file pack). When the CLI has seen Ctrl-C it calls [`request_stop`],
//! the next [`check`] returns an error containing [`STOPPED`], and the caller removes
//! its temporary file, so a stopped repair never leaves an output behind.
//!
//! The thresholds come from the 11 November 2026 wait-UX notes: show progress from about
//! 5–10 seconds, ask (interactive only) when the padded estimate is over about 2 minutes,
//! and unattended runs never ask but skip repairs over a 15-minute budget.
//!
//! State is process-wide (one repair per `sigil` process).
use crate::{Error, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);
static DONE: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);

/// Text every "stopped" error starts with (the CLI maps it to exit 130).
pub const STOPPED: &str = "repair stopped:";

/// Default ask point for interactive runs, in seconds of padded estimate.
pub const ASK_SECS: u64 = 120;

/// Default budget for runs with nobody to ask (scripts, scheduled jobs), in seconds.
pub const UNATTENDED_SECS: u64 = 900;

/// Ask the running repair to stop at its next check. Returns `true` if a stop had already
/// been asked for. Safe to call from a signal handler (one lock-free atomic swap).
pub fn request_stop() -> bool {
    STOP.swap(true, Ordering::SeqCst)
}

/// True once [`request_stop`] was called.
pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Forget an earlier stop request (for tests and long-lived callers).
pub fn clear_stop() {
    STOP.store(false, Ordering::SeqCst);
}

/// `Err` (containing [`STOPPED`]) once a stop was asked for; repair loops call this
/// between units of work.
pub fn check() -> Result<()> {
    if stop_requested() {
        return Err(Error::Msg(format!(
            "{STOPPED} stopped before it finished. Nothing was written; the original is unchanged"
        )));
    }
    Ok(())
}

/// Record that `done` of `total` units (for example chunk stars) are finished.
pub fn set_progress(done: u64, total: u64) {
    TOTAL.store(total, Ordering::Relaxed);
    DONE.store(done.min(total), Ordering::Relaxed);
}

/// `(done, total)` from the last [`set_progress`]; `total` is 0 when no count is known.
pub fn progress() -> (u64, u64) {
    (DONE.load(Ordering::Relaxed), TOTAL.load(Ordering::Relaxed))
}

/// What `mend` should do before it starts, given the padded estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitDecision {
    /// Start without a question.
    Go,
    /// Someone is at a terminal and the estimate is over the ask point: ask first.
    Ask,
    /// Nobody can be asked and the estimate is over the unattended budget: write
    /// nothing and report the estimate (exit 4).
    Skip,
}

/// The ask-or-skip rule. `yes` (`--yes`) always starts; `interactive` means stdin and
/// stderr are terminals and the output is not `--json`.
pub fn decide(
    est_secs: f64,
    interactive: bool,
    yes: bool,
    ask_secs: u64,
    unattended_secs: u64,
) -> WaitDecision {
    if yes {
        WaitDecision::Go
    } else if interactive {
        if est_secs > ask_secs as f64 {
            WaitDecision::Ask
        } else {
            WaitDecision::Go
        }
    } else if est_secs > unattended_secs as f64 {
        WaitDecision::Skip
    } else {
        WaitDecision::Go
    }
}

/// Read a whole-seconds setting from the environment (`SIGIL_MEND_ASK_SECS`,
/// `SIGIL_MEND_UNATTENDED_SECS`). Unset or empty gives `default`; anything that is not a
/// whole number is an error (no silent guess).
pub fn secs_setting(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(v) if v.trim().is_empty() => Ok(default),
        Ok(v) => v.trim().parse::<u64>().map_err(|_| {
            Error::Msg(format!(
                "{name} must be a whole number of seconds (got {v:?})"
            ))
        }),
    }
}

/// Print the question to `err` and read one line from `input`. Only "y" or "yes" (any
/// case) starts the repair; Enter, anything else, end of input or a read error mean no.
pub fn ask_keep_going(
    input: &mut dyn std::io::BufRead,
    err: &mut dyn std::io::Write,
    est_words: &str,
) -> bool {
    let _ = write!(
        err,
        "This repair may take {est_words} (a rough guess, padded high).\n\
         Your file is safe either way: nothing is written until the result passes the full check.\n\
         Keep going? [y/N] "
    );
    let _ = err.flush();
    let mut line = String::new();
    match input.read_line(&mut line) {
        Ok(0) | Err(_) => false,
        Ok(_) => matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
    }
}

/// One plain progress line (no newline). `elapsed` and `est` in seconds; `units` is
/// `(done, total)` when a count is known (total 0 = unknown).
pub fn progress_line(elapsed: f64, est: Option<f64>, units: (u64, u64)) -> String {
    let secs = elapsed.max(0.0) as u64;
    let so_far = if secs < 90 {
        format!("{secs} seconds")
    } else {
        format!("{} minutes", secs / 60)
    };
    let mut s = format!("Repairing… {so_far} so far");
    let (done, total) = units;
    if total > 0 {
        s.push_str(&format!(", {done} of {total} parts done"));
    }
    match est {
        Some(e) if e > elapsed => {
            s.push_str(&format!(
                ", {} left",
                crate::repair_scan::coarse_time(e - elapsed)
            ));
        }
        Some(_) => s.push_str(". Taking longer than first thought; still working"),
        None => {}
    }
    s.push_str(". Ctrl-C stops safely.");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_follows_the_wait_rules() {
        use WaitDecision::*;
        assert_eq!(decide(30.0, true, false, 120, 900), Go);
        assert_eq!(decide(121.0, true, false, 120, 900), Ask);
        assert_eq!(decide(121.0, true, true, 120, 900), Go);
        // Nobody to ask: never Ask; skip only past the unattended budget.
        assert_eq!(decide(121.0, false, false, 120, 900), Go);
        assert_eq!(decide(901.0, false, false, 120, 900), Skip);
        assert_eq!(decide(901.0, false, true, 120, 900), Go);
        assert_eq!(decide(1.0, false, false, 120, 0), Skip);
    }

    #[test]
    fn only_yes_starts_a_long_repair() {
        for (answer, want) in [
            ("y\n", true),
            ("YES\n", true),
            ("\n", false),
            ("n\n", false),
            ("sure\n", false),
            ("", false),
        ] {
            let mut out = Vec::new();
            let got = ask_keep_going(&mut answer.as_bytes(), &mut out, "about 5 minutes");
            assert_eq!(got, want, "{answer:?}");
            let shown = String::from_utf8_lossy(&out);
            assert!(shown.contains("about 5 minutes") && shown.contains("[y/N]"));
        }
    }

    #[test]
    fn progress_line_is_plain_and_honest() {
        let l = progress_line(12.0, Some(200.0), (0, 0));
        assert!(l.contains("left") && l.contains("Ctrl-C"), "{l}");
        let l = progress_line(300.0, Some(200.0), (3, 40));
        assert!(
            l.contains("longer than first thought") && l.contains("3 of 40"),
            "{l}"
        );
    }
}
