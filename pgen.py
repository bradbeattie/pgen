#!/usr/bin/env python3
"""Generates hash-based domain-unique passwords."""
from argparse import ArgumentParser, Namespace
from getpass import getpass
import base64
import hashlib
import json
import logging
import os
import re
import secrets


SCRIPT_MAX_ROWS = 200  # Don't bump this
SCRIPT_MAX_BYTES = 8000  # Don't bump this
SALT_SPLIT_AT_BYTES = 10000
DEFAULT_SALT_FILENAME = "~/.pgen.salt"
DEFAULT_CONFIGS_FILENAME = "~/.pgen.checksums"


def parse_args() -> Namespace:
    """Converts command-line arguments into an argparse.Namespace object"""
    parser = ArgumentParser(description="Generate a password")
    parser.add_argument("domains", nargs="+")
    parser.add_argument("--add", action="store_true", help="Record unrecognized domains")
    parser.add_argument("--modify-pepper", action="store_true", help="Modify domain-specific salts")
    parser.add_argument("--salt", dest="salt_filename", default=DEFAULT_SALT_FILENAME, help=f"Where the salt is stored, defaults to {DEFAULT_SALT_FILENAME}")
    parser.add_argument("--checksum", dest="configs_filename", default=DEFAULT_CONFIGS_FILENAME, help=f"Where known configs are stored, defaults to {DEFAULT_CONFIGS_FILENAME}")
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
        shortpass = args.shortpass
        logging.warning(f"Careful! Shell histories log command-line parameters, like {shortpass}")
    else:
        shortpass = getpass("Password? ")
        if args.add and shortpass != getpass("Password (confirm)? "):
            raise Exception("Provided passwords didn't match")

    # Read in disk-stored values
    salt = read_salt(args.salt_filename)
    configs = read_configs(args.configs_filename)

    # Iterate over all domains, get the long passwords, and display them
    results = {}
    for domain in sorted(args.domains):
        try:
            results[domain] = get_longpass(domain, shortpass, salt, configs, args)
        except Exception as e:
            logging.error(e)
    if results:
        display_results(results)

    # Write any config changes back to disk
    if (args.add or args.modify_pepper) and results:
        write_configs(args.configs_filename, configs)


def ensure_script_is_simple():
    """Warn the user if the script grows beyond a defined threshold of lines"""
    content = open(__file__).read()
    content_bytes = len(content)
    content_lines = len(content.splitlines())  # or use tokenize to not penalize comments?
    if content_bytes > SCRIPT_MAX_BYTES or content_lines > SCRIPT_MAX_ROWS:
        logging.warning(f"""
            This script has {content_bytes} bytes and {content_lines} lines.
            If it grows too complex, new users may not be able to easily audit it.
        """)


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
    if len(salt) < SALT_SPLIT_AT_BYTES * 10:
        raise Exception("Salt is unusually short")
    logging.debug(f"Salt: Read salt that smells like {smell(salt)}")
    return salt


def read_configs(configs_filename: str) -> dict:
    """Given a filename, returns a dict of checksums-to-configs"""
    logging.debug(f"Checksums: Reading from {configs_filename}")
    try:
        configs = json.loads(open(os.path.expanduser(configs_filename), mode="rb").read())
    except FileNotFoundError:
        logging.warning(f"Checksums: File {configs_filename} not found")
        configs = {}
    logging.debug(f"Checksums: Read {len(configs)} configs")
    return configs


def write_configs(configs_filename: str, configs: dict) -> None:
    """Rewrites the configs file with the most recent checksum content"""
    logging.debug(f"Writing configs to {configs_filename}")
    with open(os.path.expanduser(configs_filename), mode="w") as configs_file:
        configs_file.write(json.dumps(configs, indent=4, sort_keys=True))


def get_digest(args: Namespace, *blocks) -> bytes:
    """Using the preferred hashing method, combines the given blocks and returns a digest"""
    prehash = b"".join(
        block.encode() if isinstance(block, str) else block
        for block in list(blocks)
    )
    if len(prehash) < SALT_SPLIT_AT_BYTES:
        raise Exception("Combined blocks are unusually short")
    return getattr(hashlib, args.hash_method)(prehash).digest()


def get_config(args: Namespace, configs: dict, domain: str, shortpass: str, shortsalt: bytes):
    """Given a domain, shortpass, and salt, get or create a config"""

    # Compute the checksum
    digest = get_digest(args, domain, shortpass, shortsalt)
    checksum = base64.b85encode(digest).decode()[:20]
    logging.debug(f"{domain}: Checksum computed: {checksum}")

    # Get or create a config
    config = configs.get(checksum)
    if config and args.add:
        logging.warning(f"{domain}: Checksum already present")
    elif not config:
        if not args.add:
            raise Exception(f"{domain}: Checksum not found")
        config = {
            "encoding": args.encoding_method,
            "length": 20,
        }
        configs[checksum] = config
        logging.info(f"{domain}: Checksum added")

    # If requested, modify the config's pepper
    if args.modify_pepper:
        logging.debug(f"{domain}: Pepper modified")
        config["pepper"] = base64.b64encode(secrets.token_bytes(4))[:4].decode()

    logging.debug(f"{domain}: {config}")
    return config


def get_longpass(domain: str, shortpass: str, salt: bytes, configs: dict, args: Namespace) -> str:
    """Returns a long, complex, and unique password"""
    shortsalt, longsalt = salt[:SALT_SPLIT_AT_BYTES], salt[SALT_SPLIT_AT_BYTES:]
    config = get_config(args, configs, domain, shortpass, shortsalt)
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
