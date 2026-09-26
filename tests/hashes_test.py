# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib_ecc.hashes` module."""

import hashlib
from hashlib import sha256
from typing import Any

import pytest

from btclib_ecc.exceptions import BTClibEccTypeError
from btclib_ecc.hashes import _assert_valid_hf


@pytest.mark.parametrize(
    "hf",
    [sha256(), hashlib.sha256(b"already fed"), b"\x00", None, 42],
    ids=["a-digest-object", "a-fed-digest", "octets", "None", "an-int"],
)
def test_a_hash_function_that_is_not_one_is_refused(hf: Any) -> None:
    """`sha256()` where `sha256` belongs is the caller error this names.

    A BTClibEccTypeError and not a BTClibEccValueError, which is
    what the five boolean verifications rely on: theirs is an `except
    (ValueError, BTClibEccRuntimeError)`, so a value error here would be
    reported as a signature that does not verify rather than reaching the caller
    who made the mistake.
    """
    with pytest.raises(BTClibEccTypeError, match="not a hash function"):
        _assert_valid_hf(hf)


def test_a_hash_function_that_is_one_passes() -> None:
    """The control, over the three shapes a caller can legitimately pass."""
    for hf in (sha256, hashlib.sha512, lambda: hashlib.sha256()):  # noqa: PLW0108
        _assert_valid_hf(hf)
