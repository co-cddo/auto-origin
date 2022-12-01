import json
import re

from threading import Thread

from dns_tools import get_txts, get_mxs
from socket_checker import smtp_tls_check


ALLOWED_DOMAINS = [".gov.uk"]

_mx_cache = {}


def get_mx_records(hostname: str) -> list:
    global _mx_cache

    if hostname not in _mx_cache:
        _mx_cache[hostname] = {"hostname": hostname}

    if "list" not in _mx_cache[hostname]:
        raw_mx_records = get_mxs(hostname)
        raw_mx_records.sort()

        try:
            san_mxs = [
                rec.split(" ")[1].strip(".").strip()
                for rec in raw_mx_records
                if " " in rec and rec.split(" ")[1].strip(".").strip()
            ]
        except:
            san_mxs = []

        _mx_cache[hostname].update(
            {
                "list": san_mxs,
                "raw": raw_mx_records,
            }
        )
    return _mx_cache[hostname]["list"]


def host_valid(hostname: str) -> bool:
    if not hostname or type(hostname) != str:
        return False
    hostname = hostname.lower().strip()

    for a in ALLOWED_DOMAINS:
        if hostname.endswith(a):
            return True

    return False


def get_mta_sts_txt(hostname: str = None, timeout: int = 2) -> dict:
    global _mx_cache
    _mta_sts = None

    if not hostname or type(hostname) != str:
        return {}

    hostname = hostname.lower().strip().strip(".")

    if not host_valid(hostname):
        return {}

    if hostname.startswith("_mta-sts."):
        _mta_sts = hostname
    elif hostname.startswith("mta-sts."):
        _mta_sts = f"_{hostname}"
    else:
        _mta_sts = f"_mta-sts.{hostname}"

    if "hostname" in _mx_cache:
        _mx_cache[hostname].update({"_mta-sts": _mta_sts, "hostname": hostname})
    else:
        _mx_cache[hostname] = {"_mta-sts": _mta_sts, "hostname": hostname}

    hostname = _mta_sts[9:]

    if _mta_sts is not None:
        mx_records = get_mx_records(hostname)

        regex_discovery = (
            r"v=stsv1;\s*id=['\"]?[0-9]*?mo(?P<mode>a|e|t|n)(?:dma(?P<maxage>[0-9]+))?"
        )
        txts = get_txts(_mta_sts)
        if len(txts) == 1:
            txt = txts[0].lower()
            parsed = re.search(regex_discovery, txt)
            if parsed:
                mode = parsed.group("mode")
                if mode == "a":
                    mode = "auto"
                elif mode == "e":
                    mode = "enforce"
                elif mode == "t":
                    mode = "testing"
                else:
                    mode = "none"
                _mx_cache[hostname].update(
                    {
                        "mode": get_mode(hostname, timeout),
                        "maxage": parsed.group("maxage"),
                        "mx_records": mx_records,
                        "raw": txt,
                    }
                )

    return _mx_cache[hostname]


def get_mode(hostname: str, timeout: int = 2) -> list:
    global _mx_cache

    if (
        "tls_fetched" not in _mx_cache[hostname]
        or not _mx_cache[hostname]["tls_fetched"]
    ):
        _mx_cache[hostname]["tls_fetched"] = True

        if len(_mx_cache[hostname]["list"]) == 0:
            _mx_cache[hostname]["mode"] = "none"
        else:
            records_support_tls = []
            try:
                counter = 0
                threads = []
                for mx in _mx_cache[hostname]["list"]:
                    counter += 1
                    process = Thread(
                        target=smtp_tls_check,
                        args=[mx, timeout, False, counter, records_support_tls],
                    )
                    process.start()
                    threads.append(process)
                for process in threads:
                    process.join()
            except Exception as e:
                print(e, str(e))

            if len(records_support_tls) > 0 and all(records_support_tls):
                _mx_cache[hostname]["mode"] = "enforce"
            else:
                _mx_cache[hostname]["mode"] = "testing"

    return _mx_cache[hostname]["mode"]


def get_txt_file(hostname: str = None) -> tuple:
    txt = "# Not configured\r\n"

    cache = 60

    parsed_hostname = get_mta_sts_txt(hostname)

    if "hostname" in parsed_hostname:
        txt += f"""\r\n# Didn't find a valid TXT record at "_mta-sts.{parsed_hostname['hostname']}"
# Set your "_mta-sts" record in the following format (using only alphanumeric characters)
# [date]mo(a|n|t|e)dma[max_age_seconds]
#
# where:
#    - [date] is optional
#    - mo is required and equals mode:
#        - a: auto (tries to test MX records and sets mode)
#        - e: enforce
#        - t: testing
#        - n: none (will default to this if no MX records found)
#    - dma[max_age_seconds] is optional
#
# Examples:
#  - "20221201motdma86401" (testing with a max-age of one day and one second)
#  - "moa" (auto mode using max-age defaults)
#  - "20221201moedma3600" (enforce mode with max-age of one hour)
#
# Full DNS zone file example:
# _mta-sts 60 TXT "v=STSv1; id=20221201moa"
"""

        if "mode" in parsed_hostname:
            if parsed_hostname["maxage"] is None:
                parsed_hostname["maxage"] = (
                    1209600 if parsed_hostname["mode"] == "enforce" else 86401
                )

            txt = "version: STSv1\r\n"

            mx_records = (
                parsed_hostname["mx_records"] if "mx_records" in parsed_hostname else []
            )
            if len(mx_records) > 0:
                txt += f"mode: {parsed_hostname['mode']}\r\n"
            else:
                txt += f"mode: none\r\n"
            for mx in mx_records:
                txt += f"mx: {mx}\r\n"

            cache = parsed_hostname["maxage"]
            txt += f"max_age: {parsed_hostname['maxage']}\r\n"

    return (cache, txt)
