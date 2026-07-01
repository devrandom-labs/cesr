//! Smoke target: proves the bolero harness builds and runs under `cargo test`.

#[test]
fn smoke() {
    bolero::check!().for_each(|input: &[u8]| {
        // Trivial total function: can never panic. Confirms wiring only.
        let _ = input.len();
    });
}
