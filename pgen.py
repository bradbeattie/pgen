#!/usr/bin/env python3
"""
    Generates hash-based domain-unique passwords.
"""
from argparse import ArgumentParser, Namespace
from getpass import getpass
import base64
import hashlib
import json
import logging
import os
import secrets


SCRIPT_LENGTH_MAX = 200  # Don't bump this
SHORT_SALT_BYTES = 10000
DEFAULT_SALT_FILENAME = "~/.pgen.salt"
DEFAULT_CHECKSUM_FILENAME = "~/.pgen.checksums"


def parse_args() -> Namespace:
    """Converts command-line arguments into an argparse.Namespace object"""
    parser = ArgumentParser(description="Generate a password")
    parser.add_argument("domains", nargs="+")
    parser.add_argument("--add", action="store_true", help="Record unrecognized domains")
    parser.add_argument("--modify-pepper", action="store_true", help="Modify domain-specific salts")
    parser.add_argument("--salt", dest="salt_filename", default=DEFAULT_SALT_FILENAME, help=f"Where the salt is stored, defaults to {DEFAULT_SALT_FILENAME}")
    parser.add_argument("--checksum", dest="checksums_filename", default=DEFAULT_CHECKSUM_FILENAME, help=f"Where known checksums are stored, defaults to {DEFAULT_CHECKSUM_FILENAME}")
    parser.add_argument("--hash", dest="hash_method", default="sha512", help=", ".join(hashlib.algorithms_guaranteed))
    parser.add_argument("--encoding", dest="encoding_method", default="b85encode", help=", ".join(f"{p}encode" for p in ("b16", "b32", "b64", "b85", "a85")))
    parser.add_argument("--shortpass", help="Command-line provided shortpass, preferably for debugging purposes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug statements")
    return parser.parse_args()


def main():
    """Main logic, stringing the other helper functions together"""

    # Initial setup
    args = parse_args()
    logging.basicConfig(
        format="%(levelname)9s: %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    ensure_script_is_simple()

    # Get the shortpass from either args or by prompting the user
    if args.shortpass:
        logging.warning(f"Careful! Shell histories log command-line parameters, like {args.shortpass}")
        shortpass = args.shortpass
    else:
        shortpass = getpass("Password? ")
        if args.add and shortpass != getpass("Password (confirm)? "):
            raise Exception("Provided passwords didn't match")

    # Read in disk-stored values
    salt = read_salt(args.salt_filename)
    checksums = read_checksums(args.checksums_filename)

    # Iterate over all domains, get the long passwords, and display them
    results = {}
    for domain in sorted(args.domains):
        try:
            results[domain] = get_longpass(domain, shortpass, salt, checksums, args)
        except Exception as e:
            logging.error(e)
    if results:
        display_results(results)

    # Write any config changes back to disk
    if args.add or args.modify_pepper and results:
        write_checksums(args.checksums_filename, checksums)


def ensure_script_is_simple():
    """Warn the user if the script grows beyond a defined threshold of lines"""
    lines = len(open(__file__).readlines())
    if lines > SCRIPT_LENGTH_MAX:
        logging.warning(f"""This script has {lines} lines. If it grows too complex, new users may not be able to easily audit it.""")
    else:
        logging.debug(f"""This script has {lines} lines.""")


def smell(b: bytes) -> str:
    """Given some bytes, return a short human-recognizable hash"""
    return base64.b85encode(hashlib.sha512(b).digest()).decode()[:8]


def read_salt(salt_filename: str) -> bytes:
    """Given a filename, returns a large salt, generating one if necessary"""
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


def read_checksums(checksums_filename: str) -> dict:
    """Given a filename, returns a list of known checkums and their configurations"""
    logging.debug(f"Checksums: Reading from {checksums_filename}")
    try:
        checksums = json.loads(open(os.path.expanduser(checksums_filename), mode="rb").read())
    except FileNotFoundError:
        logging.warning(f"Checksums: File {checksums_filename} not found")
        checksums = {}
    logging.debug(f"Checksums: Read {len(checksums)} checksums")
    return checksums


def write_checksums(checksums_filename: str, checksums: dict) -> None:
    """Rewrites the checksums file with the most recent checksum content"""
    logging.debug(f"Writing checksums to {checksums_filename}")
    with open(os.path.expanduser(checksums_filename), mode="w") as checksums_file:
        checksums_file.write(json.dumps(checksums, indent=4, sort_keys=True))


def get_digest(args: Namespace, *digest_args) -> bytes:
    """Using the preferred hashing method, combines any and returns a digest"""
    prehash = b"".join(
        arg.encode() if isinstance(arg, str) else arg
        for arg in list(digest_args)
    )
    if len(prehash) < SHORT_SALT_BYTES:
        raise Exception("Digest args are unusually short")
    return getattr(hashlib, args.hash_method)(prehash).digest()


def get_longpass(domain: str, shortpass: str, salt: bytes, checksums: dict, args: Namespace) -> str:
    """Returns a long, complex, and unique password"""

    # Split the salt in two
    shortsalt, longsalt = salt[:SHORT_SALT_BYTES], salt[SHORT_SALT_BYTES:]

    # Compute the checksum
    digest = get_digest(args, domain, shortpass, shortsalt)
    checksum = base64.b85encode(digest).decode()[:20]
    logging.debug(f"{domain}: Checksum computed: {checksum}")

    # Using the checksum, get or create a config
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

    # If requested, modify the config's pepper
    if args.modify_pepper:
        logging.debug(f"{domain}: Pepper modified")
        config["pepper"] = base64.b64encode(secrets.token_bytes(4))[:4].decode()

    # Now having obtained a config, generate and return a longpass
    logging.debug(f"{domain}: {config}")
    digest = get_digest(args, domain, shortpass, longsalt, config.get("pepper", ""))
    encoding = getattr(base64, config["encoding"])(digest).decode()
    return "".join((
        config.get("prefix", ""),
        encoding[:config.get("length", 20)],
        config.get("suffix", ""),
    ))


def display_results(results: dict) -> None:
    """Prints out all generated passwords"""
    if len(results) > 1:
        width = max(map(len, results))
        for domain, longpass in results.items():
            print(f"""{domain:>{width}}: {longpass}""")
    else:
        # This edgecase has been separated out such that users might
        # easily pipe single-domain passwords into their clipboard with
        # whatever scripts their OS prefers (e.g. pbcopy, xclip, etc).
        print("".join(results.values()))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
