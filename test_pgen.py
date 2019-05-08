"""Testing for pgen.py using pytest"""
from argparse import Namespace
from pgen import get_longpass, SALT_SPLIT_AT_BYTES


SALTS = {
    "standard": b"x" * SALT_SPLIT_AT_BYTES * 10,
}
NAMESPACES = {
    "standard": Namespace(
        add=False,
        modify_pepper=False,
        hash_method="sha512",
        encoding_method="b85encode",
    ),
}
CONFIGS = {
    "standard": {
        "length": 20,
        "encoding": "b85encode"
    },
}


def test_longpass():
    """Ensure that fixed inputs give fixed longpasses"""
    for case in (
        {
            "domain": "example.com",
            "shortpass": "sh0rtp4ss",
            "checksum": "Zw<R0F3G5LE6~wss{$P8",
            "longpass": "x)w8#7PFm4K|c1bot^YD",
            "namespace": NAMESPACES["standard"],
            "config": CONFIGS["standard"],
            "salt": SALTS["standard"],
        },
        {
            "domain": "example.ca",
            "shortpass": "sh0rtp4ss",
            "checksum": "Fz$S(dErvPHw!^S1*kV?",
            "longpass": "7E~wmSt%*<#}F@&n<Ri{",
            "namespace": NAMESPACES["standard"],
            "config": CONFIGS["standard"],
            "salt": SALTS["standard"],
        },
    ):
        assert get_longpass(  # nosec
            case["domain"],
            case["shortpass"],
            case["salt"],
            {case["checksum"]: case["config"]},
            case["namespace"],
        ) == case["longpass"]
