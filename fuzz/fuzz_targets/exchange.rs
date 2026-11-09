#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| modelpipe::fuzzing::exchange(data));
