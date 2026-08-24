#![no_main]
// fuzz_emplace — drives bumpalo's in-place-construction API (Bump::emplace_slice /
// EmplaceSlice / EmplaceStr): copy_slice / clone_slice / try_* / push / extend / shrink /
// reserve / write_iter. This is precisely the surface where fitzgen/bumpalo commit 0db6ccb
// ("Fix out-of-bounds write in EmplaceSlice::try_{copy,clone}_slice", PR #335) found and
// fixed a real memory-safety bug shortly before this port, so it's high-value to keep under
// continuous fuzzing rather than a one-off regression test. Every op checks the resulting
// slice/string content against an independently-tracked expected value, so a corrupted write
// is caught even on a build without ASan.
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{self, Arbitrary};

use bumpalo::Bump;

#[derive(Arbitrary, Debug)]
enum SliceOp {
    /// EmplaceSlice::copy_slice from a Copy source.
    CopySlice(Vec<u32>),
    /// EmplaceSlice::try_copy_slice (the exact path PR #335 fixed).
    TryCopySlice(Vec<u32>),
    /// EmplaceSlice::clone_slice from a Clone (non-Copy-shaped) source.
    CloneSlice(Vec<StringWrap>),
    /// EmplaceSlice::try_clone_slice.
    TryCloneSlice(Vec<StringWrap>),
    /// Build via push/reserve/shrink, then compare against a plain Vec model.
    PushReserveShrink(Vec<u32>, u16, u16),
    /// EmplaceSlice::write_iter.
    WriteIter(Vec<u32>),
    /// EmplaceStr push/push_str/write_str round-trip.
    Str(Vec<String>),
}

// A tiny non-Copy wrapper so clone_slice exercises the Clone (not memcpy) path.
#[derive(Arbitrary, Debug, Clone, PartialEq)]
struct StringWrap(String);

const CAP: usize = 1 << 14; // bound element counts so a single input can't blow up run time

fuzz_target!(|ops: Vec<SliceOp>| {
    let bump = Bump::new();

    for op in ops.into_iter().take(64) {
        match op {
            SliceOp::CopySlice(data) => {
                if data.len() > CAP {
                    continue;
                }
                let place = bump.emplace_slice::<u32>();
                let r = place.copy_slice(&data);
                assert_eq!(r, &data[..]);
            }
            SliceOp::TryCopySlice(data) => {
                if data.len() > CAP {
                    continue;
                }
                let place = bump.emplace_slice::<u32>();
                match place.try_copy_slice(&data) {
                    Ok(r) => assert_eq!(r, &data[..]),
                    Err(_) => {}
                }
            }
            SliceOp::CloneSlice(data) => {
                if data.len() > CAP {
                    continue;
                }
                let place = bump.emplace_slice::<StringWrap>();
                let r = place.clone_slice(&data);
                assert_eq!(r, &data[..]);
            }
            SliceOp::TryCloneSlice(data) => {
                if data.len() > CAP {
                    continue;
                }
                let place = bump.emplace_slice::<StringWrap>();
                match place.try_clone_slice(&data) {
                    Ok(r) => assert_eq!(r, &data[..]),
                    Err(_) => {}
                }
            }
            SliceOp::PushReserveShrink(data, reserve_extra, shrink_to) => {
                if data.len() > CAP {
                    continue;
                }
                let mut place = bump.emplace_slice_with_capacity::<u32>(0);
                place.reserve((reserve_extra as usize) % 4096);
                for v in &data {
                    place.push(*v);
                }
                assert_eq!(place.as_slice(), &data[..]);
                let target = (shrink_to as usize) % (data.len() + 1);
                place.shrink(target);
                // shrink() only ever trims spare CAPACITY — it must never drop below `len()`
                // elements (the doc contract), so content is unchanged either way.
                assert_eq!(place.as_slice(), &data[..]);
                assert!(place.capacity() >= place.len());
            }
            SliceOp::WriteIter(data) => {
                if data.len() > CAP {
                    continue;
                }
                let place = bump.emplace_slice::<u32>();
                let r = place.write_iter(data.iter().copied());
                assert_eq!(r, &data[..]);
            }
            SliceOp::Str(chunks) => {
                let mut expected = std::string::String::new();
                let mut place = bump.emplace_str_with_capacity(0);
                for c in chunks.into_iter().take(64) {
                    if expected.len() + c.len() > CAP {
                        break;
                    }
                    place.push_str(&c);
                    expected.push_str(&c);
                }
                assert_eq!(place.as_str(), expected.as_str());
            }
        }
    }
});
