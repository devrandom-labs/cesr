"""Executable A10 signature-filter comparison against pinned keripy verifySigs.

Run with keripy de59bc7d834955c5b0273c62f6b8b6a0df150dc3 on PYTHONPATH.
The Rust public regressions use independent real Ed25519 signatures for the
same cases; this script checks the reference's full-qb64 dedup and index rules.
"""

from keri.core.eventing import verifySigs
from keri.core.signing import Signer


raw = b"a10 exact signed bytes"
owner = Signer(raw=bytes([1] * 32))
impostor = Signer(raw=bytes([2] * 32))
valid = owner.sign(raw, index=0)
invalid = impostor.sign(raw, index=0)


def check(name, sigs, expected_qb64, expected_indices):
    verified, indices = verifySigs(raw, sigs, [owner.verfer])
    actual_qb64 = [sig.qb64 for sig in verified]
    assert actual_qb64 == expected_qb64, (name, actual_qb64)
    assert indices == expected_indices, (name, indices)
    print(f"{name}: verified={len(verified)} indices={indices}")


check("exact_duplicates", [valid] * 256, [valid.qb64], [0])
check("invalid_first_valid_later", [invalid, valid], [valid.qb64], [0])
out_of_range = owner.sign(raw, index=9)
check("out_of_range_skipped", [out_of_range, valid], [valid.qb64], [0])

current_only = owner.sign(raw, index=0, only=True)
ondex_zero = owner.sign(raw, index=0, ondex=0)
ondex_one = owner.sign(raw, index=0, ondex=1)
assert len({current_only.qb64, ondex_zero.qb64, ondex_one.qb64}) == 3
check(
    "distinct_ondex_same_current_index",
    [current_only, ondex_one, ondex_zero],
    [current_only.qb64, ondex_one.qb64, ondex_zero.qb64],
    [0, 0, 0],
)
