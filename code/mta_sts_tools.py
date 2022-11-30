import json
import re

from threading import Thread

from dns_tools import get_cnames, get_mxs
from socket_checker import smtp_tls_check


ALLOWED_DOMAINS = [".gov.uk"]

_mx_cache = {}


def get_mx_records(hostname: str) -> list:
    global _mx_cache
    if hostname not in _mx_cache:
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

        _mx_cache[hostname] = {
            "list": san_mxs,
            "raw": raw_mx_records,
            "mode": "none",
            "tls_fetched": False,
        }

    print(json.dumps(_mx_cache[hostname], default=str))
    return _mx_cache[hostname]["list"]


def host_valid(hostname: str) -> bool:
    if not hostname or type(hostname) != str:
        return False
    hostname = hostname.lower().strip()

    for a in ALLOWED_DOMAINS:
        if hostname.endswith(a):
            return True

    return False


def get_mta_sts_cname(hostname: str = None) -> str:
    if not hostname or type(hostname) != str:
        return False
    hostname = hostname.lower().strip().strip(".")

    cnames = get_cnames(hostname)
    if len(cnames) == 1 and re.search(
        r"\.mta-sts\.(?:nonprod-)service\.security\.gov\.uk", cnames[0]
    ):
        return cnames[0].lower().strip().strip(".")
    return None


def parse_mta_sts(hostname: str, check_suffix: bool = True) -> dict:
    res = {"valid": False}
    if not hostname or type(hostname) != str:
        return res
    hostname = hostname.lower().strip()

    if check_suffix:
        if not host_valid(hostname):
            return res

    split_hostname = hostname.split(".")
    if not check_suffix or len(split_hostname) == 7:
        if split_hostname[1] in ["auto", "testing", "enforce", "none"]:
            res["mode"] = split_hostname[1]
            res["max_age"] = None

            raw_domain = None
            if re.search(r"\d+_[a-z]", split_hostname[0]):
                split_key = split_hostname[0].split("_", 1)
                res["max_age"] = int(split_key[0])
                raw_domain = split_key[1]
            else:
                raw_domain = split_hostname[0]

            if raw_domain and "__" in raw_domain:
                raw_domain = raw_domain.replace("__", ".")
                if host_valid(raw_domain):
                    res["domain"] = raw_domain
                    res["valid"] = True
                    res["mx_records"] = get_mx_records(raw_domain)

    return res


def get_mode(hostname: str, timeout: int = 2) -> list:
    global _mx_cache

    if not _mx_cache[hostname]["tls_fetched"]:
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
