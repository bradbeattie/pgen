#!/usr/bin/env python3

from getpass import getpass
from argparse import ArgumentParser, Namespace
import base64
import hashlib
import json
import logging
import os
import secrets


SHORT_SALT_BYTES = 10000
DEFAULT_SALT_FILENAME = "~/.pgen.salt"
DEFAULT_CHECKSUM_FILENAME = "~/.pgen.checksums"


def parse_args():
    parser = ArgumentParser(description="Generate a password")
    parser.add_argument("domains", nargs="+")
    parser.add_argument("--add", action="store_true", help="Record unrecognized domains")
    parser.add_argument("--pepper", action="store_true", help="Modify domain-specific salts")
    parser.add_argument("--salt", dest="salt_filename", default=DEFAULT_SALT_FILENAME, help=f"Where the salt is stored, defaults to {DEFAULT_SALT_FILENAME}")
    parser.add_argument("--checksum", dest="checksums_filename", default=DEFAULT_CHECKSUM_FILENAME, help=f"Where known checksums are stored, defaults to {DEFAULT_CHECKSUM_FILENAME}")
    parser.add_argument("--hash-method", default="sha512", help=", ".join(hashlib.algorithms_guaranteed))
    parser.add_argument("--encoding-method", default="b85encode", help=", ".join(f"{p}encode" for p in ("b16", "b32", "b64", "b85", "a85")))
    parser.add_argument("--shortpass", help="Command-line provided shortpass, preferably for debugging purposes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug statements")
    return parser.parse_args()


def read_salt(salt_filename: str) -> bytes:
    logging.debug(f"Salt: Reading from {salt_filename}")
    try:
        salt = open(os.path.expanduser(salt_filename), mode="rb").read()
    except FileNotFoundError:
        logging.warning(f"Salt: Generating new salt into {salt_filename}")
        salt = secrets.token_bytes(1024 * 1024)
        open(os.path.expanduser(salt_filename), mode="wb").write(salt)
    if len(salt) < SHORT_SALT_BYTES * 2:
        raise Exception("Salt is unusually short")
    logging.debug(f"Salt: Read salt that smells like {smell(salt)}")
    return salt


def smell(b: bytes) -> str:
    return base64.b85encode(hashlib.sha512(b).digest()).decode()[:8]


def read_checksums(checksums_filename: str) -> dict:
    logging.debug(f"Checksums: Reading from {checksums_filename}")
    try:
        checksums = json.loads(open(os.path.expanduser(checksums_filename), mode="rb").read())
    except FileNotFoundError:
        logging.warning(f"Checksums: File {checksums_filename} not found")
        checksums = {}
    logging.debug(f"Checksums: Read {len(checksums)} checksums")
    return checksums


def write_checksums(checksums_filename: str, checksums: dict) -> None:
    logging.debug(f"Writing checksums to {checksums_filename}")
    with open(os.path.expanduser(checksums_filename), mode="w") as checksums_file:
        checksums_file.write(json.dumps(checksums, indent=4, sort_keys=True))


def get_digest(args: Namespace, *digest_args) -> bytes:
    prehash = b"".join(
        arg.encode() if isinstance(arg, str) else arg
        for arg in list(digest_args)
    )
    if len(prehash) < SHORT_SALT_BYTES:
        raise Exception("Digest args are unusually short")
    return getattr(hashlib, args.hash_method)(prehash).digest()


def get_checksum(args: Namespace, domain: str, shortpass: str, salt: bytes) -> str:
    digest = get_digest(args, domain, shortpass, salt)
    checksum = base64.b85encode(digest).decode()[:20]
    logging.debug(f"{domain}: Checksum computed: {checksum}")
    return checksum


def get_longpass(args: Namespace, domain: str, shortpass: str, salt: bytes, config: dict) -> str:
    digest = get_digest(args, domain, shortpass, salt, config.get("pepper", ""))
    encoding = getattr(base64, config["encoding"])(digest).decode()
    return "".join((
        config.get("prefix", ""),
        encoding[:config.get("length", 20)],
        config.get("suffix", ""),
    ))


def handle_domain(domain: str, shortpass: str, salt: bytes, checksums: dict, args: Namespace) -> str:
    shortsalt, longsalt = salt[:SHORT_SALT_BYTES], salt[SHORT_SALT_BYTES:]
    checksum = get_checksum(args, domain, shortpass, shortsalt)
    config = checksums.get(checksum)

    if args.add:
        if config:
            logging.warning(f"{domain}: Checksum already present")
        else:
            config = {
                "encoding": args.encoding_method,
                "length": 20,
            }
            checksums[checksum] = config
            logging.info(f"{domain}: Checksum added")

    if not config:
        raise Exception(f"{domain}: Checksum not found")

    if args.pepper:
        logging.debug(f"{domain}: Pepper modified")
        config["pepper"] = base64.b64encode(secrets.token_bytes(4))[:4].decode()

    logging.debug(f"{domain}: {config}")
    return get_longpass(args, domain, shortpass, longsalt, config)


def display_results(results: dict) -> None:
    width = max(map(len, results))
    for domain, longpass in results.items():
        print(f"""{domain:>{width}}: {longpass}""")


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(
        format="%(levelname)9s: %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    try:

        if args.shortpass:
            logging.warning(f"Careful! Shell histories log command-line parameters, like {args.shortpass}")
            shortpass = args.shortpass
        else:
            shortpass = getpass("Password? ")
            if args.add:
                assert shortpass == getpass("Password (confirm)? ")

        salt = read_salt(args.salt_filename)
        checksums = read_checksums(args.checksums_filename)

        results = {}
        for domain in sorted(args.domains):
            try:
                results[domain] = handle_domain(domain, shortpass, salt, checksums, args)
            except Exception as e:
                logging.error(e)
        if results:
            display_results(results)

        if args.add or args.pepper and results:
            write_checksums(args.checksums_filename, checksums)

    except KeyboardInterrupt:
        print()
