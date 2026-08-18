//! Retry with exponential backoff and jitter.
//!
//! Knows nothing about HTTP, Cloudflare, or what it is retrying: it takes something
//! callable and a policy, and returns the last outcome.
//!
//! In the shell version this lived inside the API client, where it could not be tested
//! without a socket. Worse, it communicated through shell variables, so calling it
//! inside a command substitution silently discarded the status and nothing ever
//! retried. Making the outcome a return value makes that failure unrepresentable.
//!
//! The clock is injected. A test asserts on the delays that *would* have been taken
//! without waiting for them, so the retry tests run in microseconds.

use std::time::Duration;

/// How long to wait and how many times. Separate from the loop so a caller can state a
/// policy without restating the mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Total attempts, including the first. 7 means one try and six retries.
    pub max_attempts: u32,
    pub base: Duration,
    pub cap: Duration,
}

/// Ceiling on a server-supplied delay. A server asking a CLI to wait an hour is either
/// broken or hostile, and obeying it is not an option a user would choose.
const MAX_SERVER_HINT: Duration = Duration::from_secs(300);

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_attempts: 7,
            base: Duration::from_secs(1),
            cap: Duration::from_secs(32),
        }
    }
}

impl Policy {
    /// No waiting. For tests, so a retry test does not take thirty seconds.
    pub const fn immediate(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            base: Duration::ZERO,
            cap: Duration::ZERO,
        }
    }

    /// Delay before the retry that follows `attempt` (one-based).
    ///
    /// A server hint always wins: `Retry-After` is the server saying how long it needs,
    /// and guessing over the top of it turns rate limiting into an outage.
    pub fn delay_for(self, attempt: u32, server_hint: Option<Duration>) -> Duration {
        if let Some(hint) = server_hint {
            return hint.min(MAX_SERVER_HINT);
        }
        if self.base.is_zero() {
            return Duration::ZERO;
        }
        let exponent = attempt.saturating_sub(1).min(16);
        self.base.saturating_mul(1u32 << exponent).min(self.cap)
    }
}

/// What one attempt tells the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<T, E> {
    /// Done; stop.
    Done(T),
    /// Failed, but trying again might work.
    Retry { error: E, after: Option<Duration> },
    /// Failed, and trying again cannot help. Stop now.
    Fatal(E),
}

/// Why the loop stopped without succeeding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure<E> {
    Exhausted { error: E, attempts: u32 },
    Fatal(E),
}

impl<E> Failure<E> {
    pub const fn error(&self) -> &E {
        match self {
            Self::Exhausted { error, .. } | Self::Fatal(error) => error,
        }
    }
}

/// Deterministic jitter, derived from the attempt and the process id.
///
/// Jitter exists to stop several processes retrying in lockstep. Deriving it rather than
/// sampling a random source achieves that and keeps the function testable; a `rand`
/// dependency to avoid writing two lines is not a trade worth making.
fn jitter(attempt: u32, span: Duration) -> Duration {
    if span.is_zero() {
        return Duration::ZERO;
    }
    // Widening casts, both infallible: a pid and an attempt count are u32.
    let seed = u64::from(std::process::id())
        .wrapping_mul(2_654_435_761)
        .wrapping_add(u64::from(attempt));
    Duration::from_millis(seed % 1_000).min(span)
}

/// Runs `attempt` until it succeeds, exhausts the budget, or is told to stop.
pub fn run<T, E, F, S>(policy: Policy, mut attempt: F, mut sleep: S) -> Result<T, Failure<E>>
where
    F: FnMut(u32) -> Outcome<T, E>,
    S: FnMut(Duration),
{
    let mut last_error = None;

    for n in 1..=policy.max_attempts {
        match attempt(n) {
            Outcome::Done(value) => return Ok(value),
            Outcome::Fatal(error) => return Err(Failure::Fatal(error)),
            Outcome::Retry { error, after } => {
                last_error = Some(error);
                // No sleep after the final attempt: it delays the error for nothing.
                if n == policy.max_attempts {
                    break;
                }
                let delay = policy.delay_for(n, after);
                sleep(delay + jitter(n, delay));
            }
        }
    }

    Err(Failure::Exhausted {
        error: last_error.expect("loop cannot end without success or a recorded error"),
        attempts: policy.max_attempts,
    })
}

/// The real clock. Separate so `run` has no dependency on it.
pub fn thread_sleep(d: Duration) {
    if !d.is_zero() {
        std::thread::sleep(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn backoff_doubles_then_caps() {
        let p = Policy::default();
        assert_eq!(p.delay_for(1, None), secs(1));
        assert_eq!(p.delay_for(2, None), secs(2));
        assert_eq!(p.delay_for(3, None), secs(4));
        assert_eq!(p.delay_for(4, None), secs(8));
        assert_eq!(p.delay_for(5, None), secs(16));
        assert_eq!(p.delay_for(6, None), secs(32));
        assert_eq!(p.delay_for(7, None), secs(32), "must not exceed the cap");
        assert_eq!(p.delay_for(40, None), secs(32), "must not overflow");
    }

    #[test]
    fn a_server_hint_wins() {
        let p = Policy::default();
        assert_eq!(p.delay_for(5, Some(secs(3))), secs(3));
        assert_eq!(p.delay_for(1, Some(Duration::ZERO)), Duration::ZERO);
    }

    #[test]
    fn an_absurd_server_hint_is_clamped() {
        assert_eq!(
            Policy::default().delay_for(1, Some(secs(86_400))),
            MAX_SERVER_HINT
        );
    }

    #[test]
    fn succeeds_without_sleeping() {
        let calls = RefCell::new(0);
        let r: Result<&str, Failure<()>> = run(
            Policy::immediate(5),
            |_| {
                *calls.borrow_mut() += 1;
                Outcome::Done("ok")
            },
            |_| panic!("must not sleep on success"),
        );
        assert_eq!(r.unwrap(), "ok");
        assert_eq!(*calls.borrow(), 1);
    }

    #[test]
    fn retries_until_success() {
        let calls = RefCell::new(0);
        let r: Result<u32, Failure<&str>> = run(
            Policy::immediate(5),
            |n| {
                *calls.borrow_mut() += 1;
                if n >= 3 {
                    Outcome::Done(n)
                } else {
                    Outcome::Retry {
                        error: "again",
                        after: None,
                    }
                }
            },
            |_| {},
        );
        assert_eq!(r.unwrap(), 3);
        assert_eq!(*calls.borrow(), 3);
    }

    #[test]
    fn gives_up_at_exactly_the_budget() {
        let calls = RefCell::new(0);
        let r: Result<(), Failure<&str>> = run(
            Policy::immediate(4),
            |_| {
                *calls.borrow_mut() += 1;
                Outcome::Retry {
                    error: "nope",
                    after: None,
                }
            },
            |_| {},
        );
        match r {
            Err(Failure::Exhausted { error, attempts }) => {
                assert_eq!(error, "nope");
                assert_eq!(attempts, 4);
            }
            other => panic!("expected exhaustion, got {other:?}"),
        }
        assert_eq!(*calls.borrow(), 4, "the budget, and not one more");
    }

    #[test]
    fn a_fatal_outcome_stops_at_once() {
        let calls = RefCell::new(0);
        let r: Result<(), Failure<&str>> = run(
            Policy::immediate(9),
            |_| {
                *calls.borrow_mut() += 1;
                Outcome::Fatal("credentials rejected")
            },
            |_| panic!("must not sleep before a fatal outcome"),
        );
        assert!(matches!(r, Err(Failure::Fatal("credentials rejected"))));
        assert_eq!(*calls.borrow(), 1);
    }

    #[test]
    fn never_sleeps_after_the_last_attempt() {
        let sleeps = RefCell::new(Vec::new());
        let _: Result<(), Failure<&str>> = run(
            Policy {
                max_attempts: 3,
                base: secs(1),
                cap: secs(30),
            },
            |_| Outcome::Retry {
                error: "x",
                after: None,
            },
            |d| sleeps.borrow_mut().push(d),
        );
        assert_eq!(sleeps.borrow().len(), 2, "3 attempts means 2 waits");
    }

    #[test]
    fn honours_the_server_hint_inside_the_loop() {
        let sleeps = RefCell::new(Vec::new());
        let _: Result<(), Failure<&str>> = run(
            Policy {
                max_attempts: 3,
                base: secs(10),
                cap: secs(60),
            },
            |_| Outcome::Retry {
                error: "x",
                after: Some(secs(1)),
            },
            |d| sleeps.borrow_mut().push(d),
        );
        for d in sleeps.borrow().iter() {
            assert!(
                *d >= secs(1) && *d < secs(2),
                "expected about 1s, got {d:?}"
            );
        }
    }

    #[test]
    fn jitter_never_exceeds_the_delay() {
        for attempt in 1..50 {
            assert!(jitter(attempt, secs(1)) < secs(1));
        }
        assert_eq!(jitter(1, Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn a_single_attempt_policy_does_not_retry() {
        let calls = RefCell::new(0);
        let _: Result<(), Failure<&str>> = run(
            Policy::immediate(1),
            |_| {
                *calls.borrow_mut() += 1;
                Outcome::Retry {
                    error: "x",
                    after: None,
                }
            },
            |_| panic!("must not sleep"),
        );
        assert_eq!(*calls.borrow(), 1);
    }
}
