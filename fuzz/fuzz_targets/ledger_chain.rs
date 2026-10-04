#![no_main]
//! cargo-fuzz harness for the `ledger_chain` target; the invariants live in
//! crates/lcoat-fuzz/src/targets.rs.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    lcoat_fuzz::run_one("ledger_chain", data);
});
