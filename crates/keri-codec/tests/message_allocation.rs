//! Byte-allocation scaling at the public message parser boundary.
//! The allocator counts requested bytes, including reallocations, on this
//! test thread. Fixtures and wire construction run outside measurement.
#![cfg(feature = "std")]

mod common;

use core::cell::Cell;
use keri_codec::{EventMessage, Message};
use std::alloc::{GlobalAlloc, Layout, System};

use common::{Fallible, Key, genesis};

thread_local! {
    static REQUESTED_BYTES: Cell<usize> = const { Cell::new(0) };
    // A thread can free memory allocated before this counter initialized.
    // Signed accounting keeps that legitimate baseline from underflowing.
    static LIVE_BYTES: Cell<i128> = const { Cell::new(0) };
}

struct Counting;

#[allow(unsafe_code, reason = "test-only allocator instrumentation")]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = REQUESTED_BYTES.try_with(|bytes| bytes.set(bytes.get() + layout.size()));
        let _ = LIVE_BYTES.try_with(|bytes| {
            bytes.set(bytes.get() + i128::try_from(layout.size()).unwrap_or(i128::MAX));
        });
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = LIVE_BYTES.try_with(|bytes| {
            bytes.set(bytes.get() - i128::try_from(layout.size()).unwrap_or(i128::MAX));
        });
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let _ = REQUESTED_BYTES.try_with(|bytes| bytes.set(bytes.get() + size));
        let _ = LIVE_BYTES.try_with(|bytes| {
            bytes.set(
                bytes.get() - i128::try_from(layout.size()).unwrap_or(i128::MAX)
                    + i128::try_from(size).unwrap_or(i128::MAX),
            );
        });
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[test]
fn retaining_one_group_does_not_retain_following_frames() -> Fallible<()> {
    use cesr_stream::V1;
    use cesr_stream::group::{CesrGroup, Groups};

    let one = b"-AAB"
        .iter()
        .copied()
        .chain([b'A'; 88])
        .collect::<Vec<_>>();
    let wire = one.repeat(1024);
    let before = LIVE_BYTES.with(Cell::get);
    let Some(parsed) = Groups::<V1>::over(&wire).next() else {
        return Err("missing group".into());
    };
    let group = parsed?;
    let retained = LIVE_BYTES.with(Cell::get) - before;
    assert!(retained < 1024, "one retained group held {retained} bytes");
    assert!(matches!(group, CesrGroup::ControllerIdxSigs(_)));
    Ok(())
}

#[test]
fn group_remainder_and_truncation_are_exact() -> Fallible<()> {
    use cesr_stream::error::ParseError;
    use cesr_stream::group::CesrGroup;

    let mut wire = b"-AAB".to_vec();
    wire.extend_from_slice(&[b'A'; 88]);
    let first_len = wire.len();
    wire.extend_from_slice(b"-BAB");
    wire.extend_from_slice(&[b'A'; 88]);
    wire.extend_from_slice(b"{\"next\":true}");

    let (_, rest) = CesrGroup::parse(&wire)?;
    assert_eq!(rest, &wire[first_len..]);
    let (_, next) = CesrGroup::parse(rest)?;
    assert_eq!(next, b"{\"next\":true}");

    let partial = &wire[..first_len - 1];
    assert!(matches!(
        CesrGroup::parse(partial),
        Err(ParseError::NeedBytes(1))
    ));
    assert!(CesrGroup::parse(b"-ZZZ").is_err());
    Ok(())
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn requested_bytes<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = REQUESTED_BYTES.with(Cell::get);
    let result = f();
    (result, REQUESTED_BYTES.with(Cell::get) - before)
}

#[test]
fn bare_attachment_groups_scale_by_input_size() -> Fallible<()> {
    let (controller, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&controller, &next)?;
    let signature = controller.sign(&icp.bytes, 0)?.to_qb64();
    let mut measured = Vec::new();
    for count in [64, 256, 1024] {
        let mut wire = icp.bytes.clone();
        for _ in 0..count {
            wire.extend_from_slice(b"-AAB");
            wire.extend_from_slice(signature.as_bytes());
        }
        let (parsed, bytes) =
            requested_bytes(|| EventMessage::parse(&wire, common::message_limits()));
        let (message, remainder) = parsed?;
        assert!(remainder.is_empty());
        assert_eq!(message.sigs().len(), count);
        measured.push((wire.len(), bytes));
    }
    assert!(
        measured[2].1 <= measured[1].1 * 6,
        "requested bytes grew faster than input: {measured:?}"
    );
    Ok(())
}

#[test]
fn framed_generic_messages_scale_by_input_size() -> Fallible<()> {
    let (controller, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&controller, &next)?;
    let signature = controller.sign(&icp.bytes, 0)?.to_qb64();
    let mut one = icp.bytes;
    one.extend_from_slice(b"-VAX-AAB");
    one.extend_from_slice(signature.as_bytes());
    let mut measured = Vec::new();
    for count in [64, 256] {
        let batch = one.repeat(count);
        let (parsed, bytes) = requested_bytes(|| -> Fallible<usize> {
            let mut rest = batch.as_slice();
            let mut messages = 0;
            while !rest.is_empty() {
                let (_, remainder) = Message::parse(rest, common::message_limits())?;
                rest = remainder;
                messages += 1;
            }
            Ok(messages)
        });
        assert_eq!(parsed?, count);
        measured.push((batch.len(), bytes));
    }
    assert!(
        measured[1].1 <= measured[0].1 * 6,
        "requested bytes grew faster than input: {measured:?}"
    );
    Ok(())
}

#[test]
fn message_tail_and_truncated_attachment_preserve_boundaries() -> Fallible<()> {
    let (controller, next) = (Key::new()?, Key::new()?);
    let icp = genesis(&controller, &next)?;
    let signature = controller.sign(&icp.bytes, 0)?.to_qb64();
    let mut complete = icp.bytes.clone();
    complete.extend_from_slice(b"-VAX-AAB");
    complete.extend_from_slice(signature.as_bytes());

    let mut batch = complete.clone();
    batch.extend_from_slice(&icp.bytes);
    batch.extend_from_slice(b"-AAB");
    let (parsed, tail) = Message::parse(&batch, common::message_limits())?;
    let Message::Event(first) = parsed else {
        return Err("expected key event".into());
    };
    assert_eq!(first.body(), icp.bytes);
    assert_eq!(tail, &batch[complete.len()..]);
    assert!(Message::parse(tail, common::message_limits()).is_err());
    assert!(EventMessage::parse(tail, common::message_limits()).is_err());
    Ok(())
}
