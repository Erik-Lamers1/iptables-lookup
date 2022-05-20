#!/usr/bin/env python3

import logging
import ipaddress as ip
from socket import getservbyname
from dataclasses import dataclass
from pathlib import Path
from typing import Union, List, Dict, Optional, Tuple
from argparse import ArgumentParser, Namespace
from subprocess import check_output, CalledProcessError

IPTABLES_STD_TARGETS = (
    "ACCEPT",
    "DROP",
    "REJECT",
    "RETURN",
    "LOG",
    "AUDIT",
    "CHECKSUM",
    "CLASSIFY",
    "CLUSTERIP",
    "CONNMARK",
    "CONNSECMARK",
    "CT",
    "DNAT",
    "DNPT",
    "DSCP",
    "ECN",
    "HL",
    "HMARK",
    "IDLETIMER",
    "LED",
    "MARK",
    "MASQUERADE",
    "MIRROR",
    "NETMAP",
    "NFLOG",
    "NFQUEUE",
    "NOTRACK",
    "RATEEST",
    "REDIRECT",
    "SAME",
    "SECMARK",
    "SET",
    "SNAT",
    "SNPT",
    "TCPMSS",
    "TCPOPTSTRIP",
    "TEE",
    "TOS",
    "TPROXY",
    "TRACE",
    "TTL",
    "ULOG",
)
END_PROCESSING = (
    "ACCEPT",
    "DROP",
    "REJECT",
)
logger = logging.getLogger("iptables-lookup")


def parse_args(args: list = None) -> Namespace:
    parser = ArgumentParser(description="Tool for tracing traffic through IPtables and show matching rules for this traffic")

    inpt = parser.add_argument_group("Input options")
    inpt_opts = inpt.add_mutually_exclusive_group(required=True)
    inpt_opts.add_argument(
        "-s", "--single", nargs="*", help="Parse a single packet from the command line (format; SRC:0.0.0.0 DST:0.0.0.0 PROTO:TCP PORT:443)"
    )
    inpt_opts.add_argument(
        "-f", "--file", type=Path, help="Parse a file with packets per line (format; SRC:0.0.0.0 DST:0.0.0.0 PROTO:TCP PORT:443)"
    )
    inpt_opts.add_argument("-d", "--tcpdump", type=Path, help="Parse TCPdump file (currently only quick format is supported '-q')")

    parser.add_argument(
        "-i",
        "--iptables-file",
        type=Path,
        help="Load IPtables rules from this file, fetched `iptables-save` command if this option is omitted",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debugging output")

    return parser.parse_args(args=args)


def get_lines_from_file(path: Union[Path, str]) -> List[str]:
    logger.debug(f"Getting lines from {path}")
    with open(path) as fh:
        return fh.read().splitlines()


def parse_lines(lines: List[str]) -> List[Dict[str, Union[str, int, ip.IPv4Address, ip.IPv6Address]]]:
    results = []
    for line in lines:
        src = None
        dst = None
        proto = None
        port = None
        for item in line.split():
            try:
                t, v = item.split(":")
            except ValueError:
                logger.warning(f"Unable to parse {line} no in correct format (TYPE:VALUE)")
                continue
            t, v = [x.upper() for x in [t, v]]
            if t == "SRC":
                try:
                    src = ip.ip_address(v)
                except ValueError:
                    logger.warning(f"SRC {v} is not a valid IP")
                    continue
            elif t == "DST":
                try:
                    dst = ip.ip_address(v)
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


def parse_tcpdump(lines: List[str]) -> List[Dict[str, Union[str, int, ip.IPv4Address, ip.IPv6Address]]]:
    results = []
    for line in lines:
        # Format 11:47:12.100115 IP 1.1.1.1.42217 > 2.2.2.2.57896: tcp 31
        item = line.split()[2:]
        if len(item) != 5:
            logger.warning(f"Incorrect TCPdump format for {line}, remember to use TCPdump ASCII output with -q")
            continue
        # Get the dest port
        port = item[2].split(".")[-1][:-1]
        # If needed, translate the name of the protocol to it's port number
        if not port.isnumeric():
            try:
                port = getservbyname(port)
            except OSError:
                logger.warning(f"Unknown protocol name: {port} for: {line}, skipping")
                continue
        results.append(
            {
                "SRC": ip.ip_address(".".join(item[0].split(".")[:-1])),
                "DST": ip.ip_address(".".join(item[2].split(".")[:-1])),
                "PROTO": item[3],
                "PORT": port,
            }
        )
    return results


@dataclass
class IPtablesRule:
    target: str
    raw_rule_id: int = 0
    in_if: str = None
    out_if: str = None
    src_ip: Union[ip.IPv4Network, ip.IPv6Network] = None
    dst_ip: Union[ip.IPv4Network, ip.IPv6Network] = None
    proto: str = None
    port: Union[int, List[int]] = None

    def __repr__(self) -> str:
        port = self.port
        if self.port and len(self.port) > 3:
            # noinspection PyTypeChecker
            self.port = f"{port[0]}..{port[-1]}"
        items = {k: v for k, v in vars(self).items() if v}
        self.port = port
        return f"{self.__class__.__name__}: {items}"


class IPtables:
    def __init__(self, iptables_file: Optional[Union[str, Path]] = None) -> None:
        self.rules: dict = {}
        self.default_chains: set = {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}
        self.raw_rules: List[str] = get_lines_from_file(iptables_file) if iptables_file else self.load_rules_from_iptables_save()
        self.process_raw_iptables_rules()

    @staticmethod
    def match_source(packet: Dict[str, Union[None, ip.IPv4Address, ip.IPv6Address]], rule: IPtablesRule) -> Tuple[bool, bool]:
        """
        :return: bool: match needed, bool: match found
        """
        if rule.src_ip:
            return (True, True) if packet.get("SRC") and packet["SRC"] in rule.src_ip else (True, False)
        else:
            return False, False

    @staticmethod
    def match_destination(packet: Dict[str, Union[None, ip.IPv4Address, ip.IPv6Address]], rule: IPtablesRule) -> Tuple[bool, bool]:
        """
        :return: bool: match needed, bool: match found
        """
        if rule.dst_ip:
            return (True, True) if packet.get("DST") and packet["DST"] in rule.dst_ip else (True, False)
        else:
            return False, False

    @staticmethod
    def match_proto(packet: Dict[str, Union[None, ip.IPv4Address, ip.IPv6Address]], rule: IPtablesRule) -> Tuple[bool, bool]:
        """
        :return: bool: match needed, bool: match found
        """
        if rule.proto:
            return (True, True) if packet.get("PROTO") and packet["PROTO"] == rule.proto else (True, False)
        else:
            return False, False

    @staticmethod
    def match_port(packet: Dict[str, Union[None, ip.IPv4Address, ip.IPv6Address]], rule: IPtablesRule) -> Tuple[bool, bool]:
        """
        :return: bool: match needed, bool: match found
        """
        if rule.port:
            return (True, True) if packet.get("PORT") and packet["PORT"] in rule.port else (True, False)
        else:
            return False, False

    @staticmethod
    def load_rules_from_iptables_save() -> List[str]:
        try:
            return check_output(["iptables-save"]).decode("utf-8").splitlines()
        except CalledProcessError as e:
            logger.error(f"Unable to load iptables rules, got error: {e}")
            raise OSError("IPtables rule load failed") from e

    def process_iptables_port(self, port):
        ports = []
        try:
            if "," in port:
                for p in port.split(","):
                    if ":" in p:
                        ports.extend(self.process_iptables_port(p))
                    else:
                        ports.append(int(p))
            elif ":" in port:
                start, end = port.split(":")
                for p in range(int(start), int(end) + 1):
                    ports.append(p)
            else:
                ports.append(int(port))
        except ValueError:
            logger.error(f"Unable to convert {port} port list to list of integers")
        return ports

    def process_iptables_rule(self, idx: int, rule: str) -> IPtablesRule:
        rule = rule.split()
        result = IPtablesRule(target=rule[-1], raw_rule_id=idx)
        for idx, item in enumerate(rule):
            if item == "-i":
                result.in_if = rule[idx + 1]
            elif item == "-o":
                result.out_if = rule[idx + 1]
            elif item == "-s":
                result.src_ip = ip.ip_network(rule[idx + 1])
            elif item == "-d":
                result.dst_ip = ip.ip_network(rule[idx + 1])
            elif item == "-p":
                result.proto = rule[idx + 1]
            elif item == "--dport":
                result.proto = self.process_iptables_port(rule[idx + 1])
            elif item == "--dports":
                result.proto = self.process_iptables_port(rule[idx + 1])
        return result

    def process_raw_iptables_rules(self) -> None:
        processed_rules = {}
        table = None
        for idx, rule in enumerate(self.raw_rules):
            # Skip comments
            if rule.startswith("#"):
                continue
            # Table change
            elif rule.startswith("*"):
                table = rule[1:]
                if table not in processed_rules:
                    processed_rules[table] = {}
            # Chain
            elif rule.startswith(":"):
                rule = rule.split()
                chain_name = rule[0][1:]
                processed_rules[table][chain_name] = {"rules": []}
                if chain_name in self.default_chains:
                    processed_rules[table][chain_name]["policy"] = rule[1]
            # Rule
            elif rule.startswith("-A"):
                chain_name = rule.split()[1]
                processed_rules[table][chain_name]["rules"].append(self.process_iptables_rule(idx, rule))
        self.rules = processed_rules

    def find_match_rules(
        self, packet: Dict[str, Union[str, int, ip.IPv4Address, ip.IPv6Address]], table="filter", match_chain="INPUT"
    ) -> Union[List[Union[IPtablesRule, str]]]:
        # Right now we only search in the filter table
        matches = []
        for rule in self.rules[table][match_chain]["rules"]:
            src_rule, src_match = self.match_source(packet, rule)
            dst_rule, dst_match = self.match_destination(packet, rule)
            proto_rule, proto_match = self.match_proto(packet, rule)
            port_rule, proto_match = self.match_port(packet, rule)
            # Combine it all
            print(rule)
            print(proto_match, proto_rule)
            if src_rule and not src_match or dst_rule and not dst_match or proto_rule and not proto_match or port_rule and not proto_match:
                # No match
                continue
            else:
                # MATCH
                if rule.target in IPTABLES_STD_TARGETS:
                    matches.append(rule)
                else:
                    if rule.target in END_PROCESSING:
                        return matches
                # Recurse into myself with the new target
                # First do a sanity check if the chain reference exists
                if rule.target in self.rules[table]:
                    rec_matches = self.find_match_rules(packet, table=table, match_chain=rule.target)
                    if rec_matches:
                        matches.extend(rec_matches)
        # No end processing matches found, return policy, if any
        if "policy" in self.rules[table][match_chain]:
            return [f"Policy match: {self.rules[table][match_chain]['policy']}"]


def main(args: list = None) -> None:
    args = parse_args(args=args)
    logging.basicConfig(format="%(asctime)s [%(name)8s] [%(levelname)s] %(message)s", level=logging.DEBUG if args.verbose else logging.INFO)

    # Get the input
    sources = []
    if args.file:
        sources = parse_lines(get_lines_from_file(args.file))
    elif args.single:
        sources = parse_lines([" ".join(args.single)])
    elif args.tcpdump:
        sources = parse_tcpdump(get_lines_from_file(args.tcpdump))

    logger.debug("Loading IPtables rules")
    iptables = IPtables(iptables_file=args.iptables_file)

    logger.info(f"Calculating matches for {len(sources)} source packets")
    for source in sources:
        matches = iptables.find_match_rules(source)
        if matches:
            logger.info(f"Found the following matches in matching order for; {source}")
            for match in matches:
                print(match)
        else:
            logger.warning(f"No matches found for; {source}")


if __name__ == "__main__":
    main()
