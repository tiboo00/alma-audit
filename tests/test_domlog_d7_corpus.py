"""AISO-119 v1.2 detection contract §4.5.4 — D7 31-case self-test corpus.

This is the **regression lock** for the D7 (domlog filename anomaly)
detector. The contract defines a specific 31-case raw-input → final-result
table that the detector MUST satisfy verbatim. Cases #11–#13 are
explicit false-positive regressions from v1.0 (the `re.IGNORECASE` bug);
cases #29–#31 are the explicit v1.2 trade-off (all-uppercase hostdzi-style
inputs are NOT detected because case-1 requires a lowercase prefix).

Flipping any case from "expected" to "actual" without a v1.3 spec is a
regression. The detector module ships this parametrize list and asserts
all 31 cases in a single run.
"""

from __future__ import annotations

import pytest

from alma_audit.analyzers.domlog_inventory import _matches_contract_pattern


# (input, expected_match, note)
# True  → §4.5.2 regex MUST match the input after §4.5.1 normalisation.
# False → MUST NOT match.
# The "input" column is the RAW input as the §4.5.4 corpus specifies;
# §4.5.1 normalisation (cPanel-suffix strip, percent-decode, control-char
# handling) runs internally and is NOT visible at the test layer.
D7_CORPUS: list[tuple[str, bool, str]] = [
    ("hostdziAAAAAA", True, "case-1 lower-prefix + UPPER run (parent example)"),
    ("hostdziAABBCCDD", True, "case-1 lower-prefix + UPPER run"),
    ("fooooBBBBBB", True, "case-1 lower-prefix + UPPER run"),
    ("foo.zip", True, "case-6 abused TLD .zip"),
    ("bar.tk", True, "case-6 abused TLD .tk"),
    ("xn--ab.com", True, "case-3 short punycode + TLD"),
    ("xn--abcdefghijklmnopqrstuvwxyz.zz", True, "case-5 long string containing xn--"),
    ("AaBbCcDdEeFfGgHhIiJj1234567890", True, "case-2 long mixed-case alphanumeric"),
    ("AbCdEfGhIjKlMnOpQrSt", True, "case-2 long mixed-case"),
    ("123.foo", True, "case-4 pure-numeric hostname"),
    # ---- v1.0 FP regressions — cases #11-13 MUST stay False ----
    ("abcdefghijklmnopqrst.com", False, "v1.0 FP: long lowercase domain"),
    ("abcdefghijklmnopqrst", False, "v1.0 FP: long lowercase alphanumeric"),
    ("normaldomainabcdefghijkl.com", False, "v1.0 FP: long lowercase domain"),
    ("zmrk2md30edvm", False, "cPanel account subdir, allowed"),
    ("hostdzire.com", False, "normal domain"),
    ("hostdzire.com-ssl_log", False, "normal cPanel filename (pre-norm)"),
    ("hostdzire.com", False, "normal cPanel filename (post-norm)"),
    ("bfiber.co.in", False, "normal domain"),
    ("bfiberco", False, "normal account"),
    ("example.com", False, "normal domain"),
    ("localhost", False, "localhost"),
    ("aaaaaaaaaaaaaaaaaaaaaaaaaa.com", False, "long lowercase domain"),
    ("example12345678901234567890.com", False, "mixed but no UPPER"),
    ("HOSTDZIRE.COM", False, "uppercase normal domain"),
    ("aaaaaaaaaaaaaaaaaaaaaaaaaaaa", False, "all-lower >= 20 chars"),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAA", False, "all-UPPER >= 20 chars"),
    ("1234567890", False, "pure numeric no TLD"),
    ("Foo-Bar-BBBBBBB", False, "lowercase reversion after UPPER — not case-1"),
    # ---- v1.2 trade-offs — cases #29-31 MUST stay False ----
    ("HOSTDZIREAAAAAA", False, "v1.2 trade-off: all-uppercase hostdzi-style prefix"),
    ("FOOBARAAAAAAA", False, "v1.2 trade-off: all-uppercase hostdzi-style"),
    ("HOSTDZIREAAAAA.com", False, "v1.2 trade-off: all-uppercase hostdzi-style with TLD"),
]


@pytest.mark.parametrize(
    ("raw_input", "expected", "note"),
    D7_CORPUS,
    ids=[f"case-{i+1:02d}" for i in range(len(D7_CORPUS))],
)
def test_d7_corpus_matches_contract(raw_input: str, expected: bool, note: str) -> None:
    """All 31 §4.5.4 cases pass verbatim — raw input → final result contract."""
    actual = _matches_contract_pattern(raw_input)
    assert actual is expected, (
        f"D7 corpus regression: input={raw_input!r} "
        f"expected={expected} actual={actual} note={note!r}"
    )


def test_d7_corpus_has_exactly_31_cases() -> None:
    """Sanity: corpus size matches the v1.2 contract (28 in v1.1, 31 in v1.2).

    If you add or remove a case, you MUST bump the contract version and
    update the changelog in `detection_contract.md`.
    """
    assert len(D7_CORPUS) == 31, (
        f"D7 corpus must have 31 cases per AISO-119 v1.2 §4.5.4; got {len(D7_CORPUS)}"
    )


def test_d7_corpus_regression_lock_cases_11_to_13() -> None:
    """Cases #11-#13 are the v1.0 re.IGNORECASE regressions.

    If any of these flips to True, a future change has reintroduced case
    folding in the D7 path. Per the contract, that is a blocking
    regression.
    """
    for i in (10, 11, 12):  # 0-indexed: corpus[10] = case #11
        raw_input, expected, note = D7_CORPUS[i]
        assert expected is False, f"case #{i+1} must stay False: {raw_input}"
        assert _matches_contract_pattern(raw_input) is False, (
            f"v1.0 regression re-introduced for case #{i+1}: {raw_input}"
        )


def test_d7_corpus_trade_off_cases_29_to_31() -> None:
    """Cases #29-#31 are the v1.2 all-uppercase trade-off.

    These MUST stay False until a v1.3 spec adds a case-1b detector. A
    naive all-uppercase long-string detector would flip these to True
    and the regression would slip through if not for this lock.
    """
    for i in (28, 29, 30):  # 0-indexed: corpus[28] = case #29
        raw_input, expected, note = D7_CORPUS[i]
        assert expected is False, f"case #{i+1} must stay False (v1.2 trade-off): {raw_input}"
        assert _matches_contract_pattern(raw_input) is False, (
            f"v1.2 trade-off violated for case #{i+1}: {raw_input}"
        )