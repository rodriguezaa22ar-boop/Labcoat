#![no_main]
//! cargo-fuzz harness for the `metadata_scan` target; the invariants live in
//! crates/lcoat-fuzz/src/targets.rs.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    lcoat_fuzz::run_one("metadata_scan", data);
});
