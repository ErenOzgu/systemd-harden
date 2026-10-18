import re

from systemd_harden.catalogue import CATALOGUE, KEYS, by_key
from systemd_harden.probe import SCALAR_KEYS


def test_keys_are_unique_and_in_order():
    assert len(KEYS) == len(set(KEYS)) == len(CATALOGUE)
    assert KEYS == tuple(d.key for d in CATALOGUE)
    assert by_key("UMask").key == "UMask"


def test_every_line_is_a_key_value_pair_for_the_directive():
    for d in CATALOGUE:
        assert d.why.endswith(".") and len(d.why) > 20, d.key
        assert d.candidates, d.key
        first_keys = d.candidates[0].keys()
        assert d.key in first_keys, d.key
        for c in d.candidates:
            assert c.since > 0
            assert c.lines, d.key
            for line in c.lines:
                assert re.fullmatch(r"[A-Za-z]+=[^\s=][^=]*|[A-Za-z]+=", line), line


def test_no_directive_is_listed_twice_with_the_same_lines():
    seen = set()
    for d in CATALOGUE:
        for c in d.candidates:
            assert c.lines not in seen, c.lines
            seen.add(c.lines)


def test_only_directives_systemctl_show_reports_as_one_word_are_compared():
    for key in SCALAR_KEYS:
        assert any(key in c.keys() for d in CATALOGUE for c in d.candidates), key
    for d in CATALOGUE:
        for c in d.candidates:
            for line in c.lines:
                k, _, v = line.partition("=")
                if k in SCALAR_KEYS:
                    assert " " not in v, line
