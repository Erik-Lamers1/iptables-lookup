#!/usr/bin/env python3

import logging
from pathlib import Path
from typing import Union, List, Dict
from argparse import ArgumentParser, Namespace
from ipaddress import ip_address

logger = logging.getLogger("iptables-lookup")


def get_lines_from_file(path: Union[Path, str]) -> List[str]:
    with open(path) as fh:
        return fh.read().splitlines()


def parse_lines(lines: List[str]) -> List[Dict[str, Union[str, int]]]:
    results = []
    for line in lines:
        src = None
        dst = None
        proto = None
        port = None
        line = line.split()
        for item in line:
            try:
                t, v = item.split(":")
            except ValueError:
                logger.warning(f"Unable to parse {line} no in correct format (TYPE:VALUE)")
                continue
            t, v = [x.upper() for x in [t, v]]
            if t == "SRC":
                try:
                    src = ip_address(v)
                except ValueError:
                    logger.warning(f"SRC {v} is not a valid IP")
                    continue
            elif t == "DST":
                try:
                    dst = ip_address(v)
                except ValueError:
                    logger.warning(f"DST {v} is not a valid IP")
                    continue
            elif t == "PROTO":
                proto = v.lower()
            elif t == "PORT":
                try:
                    port = int(v)
                except ValueError:
                    logger.warning(f"PORT {v} is not a number")
                    continue
        if any((src, dst, proto, port)):
            results.append({"SRC": src, "DST": dst, "PROTO": proto, "PORT": port})
        else:
            logger.warning(f"No valid keywords (SRC, DST, PROTO, PORT) found in line; {line}, skipping")
    return results


def parse_tcpdump(lines: List[str]) -> List[Dict[str, Union[str, int]]]:


def parse_args(args: list = None) -> Namespace:
    parser = ArgumentParser(description="Tool for tracing traffic through IPtables and show matching rules for this traffic")

    inpt = parser.add_argument_group("Input options")
    inpt_opts = inpt.add_mutually_exclusive_group(required=True)
    inpt_opts.add_argument("-s", "--single", nargs="*", help="Parse a single packet from the command line (format; SRC:0.0.0.0 DST:0.0.0.0 PROTO:TCP PORT:443)")
    inpt_opts.add_argument("-f", "--file", type=Path, help="Parse a file with packets per line (format; SRC:0.0.0.0 DST:0.0.0.0 PROTO:TCP PORT:443)")
    inpt_opts.add_argument("-d", "--tcpdump", type=Path, help="Parse TCPdump file (currently only quick format is supported '-q')")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debugging output")

    return parser.parse_args(args=args)


def main(args: list = None) -> None:
    args = parse_args(args=args)
    logging.basicConfig(format="%(asctime)s [%(name)8s] [%(levelname)s] %(message)s", level=logging.DEBUG if args.verbose else logging.INFO)

    # Get the input
    if args.file:
        lines = get_lines_from_file(args.file)




if __name__ == '__main__':
    main()
