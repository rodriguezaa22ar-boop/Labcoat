//! Crash points for the crash-injection tests (quality bar item 3).
//!
//! Each multi-file writer calls [`point`] after every step named in the
//! blueprint's transaction-order table. With the `test-support` feature,
//! `LCOAT_TEST_CRASH_AT=<name>` makes the process exit at that step with
//! code 99, so a test can leave the files exactly as a crash would and check
//! what the verifiers say. Without the feature the function is empty and
//! inlined away; a release binary cannot be made to stop here.

/// Exit code of an injected crash.
pub const CRASH_EXIT: i32 = 99;

/// Abort here if the test asked for it. A no-op in release builds.
#[inline]
pub fn point(name: &str) {
    #[cfg(feature = "test-support")]
    {
        if std::env::var("LCOAT_TEST_CRASH_AT").is_ok_and(|v| v == name) {
            eprintln!("lcoat: injected crash at {name}");
            std::process::exit(CRASH_EXIT);
        }
    }
    #[cfg(not(feature = "test-support"))]
    {
        let _ = name;
    }
}
