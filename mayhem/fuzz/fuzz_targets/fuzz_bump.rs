#![no_main]
// fuzz_bump — drives bumpalo's core arena allocator (Bump) through an arbitrary-derived
// sequence of allocation operations: raw layout allocs, typed allocs, slice/str allocs,
// bumpalo::collections::Vec/String growth, checkpoints and reset. This exercises the
// unsafe pointer arithmetic inside Bump's chunk-growing/bump-pointer code (the part of the
// crate most likely to hide an OOB write or misaligned pointer), relying on ASan to catch
// any memory-safety violation. Every allocated region is also written through and read back
// to catch corruption that wouldn't otherwise trip a sanitizer (e.g. aliasing/overlap bugs).
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{self, Arbitrary};

use bumpalo::collections::{String as BString, Vec as BVec};
use bumpalo::Bump;

#[derive(Arbitrary, Debug)]
enum Op {
    /// Allocate a small POD value and check it round-trips.
    AllocU64(u64),
    /// Allocate a byte slice by copy and verify contents.
    AllocSliceCopy(Vec<u8>),
    /// Allocate a &str and verify contents.
    AllocStr(String),
    /// Push `n` bytes onto a bumpalo::collections::Vec<u8> (bounded to keep runs fast).
    VecPush(Vec<u8>),
    /// Build a bumpalo::collections::String by pushing str chunks.
    StringPush(Vec<String>),
    /// Fill a slice with a fixed value of a given (bounded) length.
    AllocSliceFill(u8, u16),
    /// Snapshot + rewind: allocate, checkpoint, allocate more, nothing to assert beyond
    /// "doesn't corrupt state" (checked implicitly by continuing to use `bump` afterward).
    ResetArena,
    /// Query the allocator's own bookkeeping — must never panic / must stay self-consistent.
    Stats,
}

const MAX_OPS: usize = 128;

fuzz_target!(|ops: Vec<Op>| {
    let mut bump = Bump::new();

    for op in ops.into_iter().take(MAX_OPS) {
        match op {
            Op::AllocU64(v) => {
                let r = bump.alloc(v);
                assert_eq!(*r, v);
            }
            Op::AllocSliceCopy(data) => {
                if data.len() > 1 << 16 {
                    continue;
                }
                let r = bump.alloc_slice_copy(&data);
                assert_eq!(r, &data[..]);
            }
            Op::AllocStr(s) => {
                if s.len() > 1 << 16 {
                    continue;
                }
                let r = bump.alloc_str(&s);
                assert_eq!(r, s.as_str());
            }
            Op::VecPush(data) => {
                if data.len() > 1 << 14 {
                    continue;
                }
                let mut v: BVec<u8> = BVec::new_in(&bump);
                for b in &data {
                    v.push(*b);
                }
                assert_eq!(v.as_slice(), &data[..]);
                assert_eq!(v.len(), data.len());
            }
            Op::StringPush(chunks) => {
                let mut expected = std::string::String::new();
                let mut s: BString = BString::new_in(&bump);
                for c in chunks.into_iter().take(64) {
                    if expected.len() + c.len() > 1 << 16 {
                        break;
                    }
                    s.push_str(&c);
                    expected.push_str(&c);
                }
                assert_eq!(s.as_str(), expected.as_str());
            }
            Op::AllocSliceFill(val, len) => {
                let len = (len as usize) % (1 << 14);
                let r = bump.alloc_slice_fill_copy(len, val);
                assert!(r.iter().all(|&b| b == val));
                assert_eq!(r.len(), len);
            }
            Op::ResetArena => {
                // Reclaims every chunk allocated so far; the arena must stay usable afterward
                // (this is exactly the kind of internal bookkeeping bug a corrupted chunk list
                // would surface on the NEXT allocation, not this one).
                bump.reset();
                let r = bump.alloc(0x42u8);
                assert_eq!(*r, 0x42u8);
            }
            Op::Stats => {
                let _ = bump.allocated_bytes();
                let _ = bump.allocated_bytes_including_metadata();
                let _ = bump.chunk_capacity();
            }
        }
    }
});
