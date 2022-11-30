import os
import re
import subprocess

from os.path import exists
from time import sleep

from dns_tools import get_cnames, get_as

nginx_conf = "/etc/nginx/sites-enabled/default"
ssl_cert_re = r"\s*ssl_certificate\s+/etc/letsencrypt/live/([^/]+)"

valid_cname_endings = [
    "auto-origin.nonprod-service.security.gov.uk",
    "auto-origin.service.security.gov.uk",
    "mta-sts.nonprod-service.security.gov.uk",
    "mta-sts.service.security.gov.uk",
]


def sites_enabled() -> list:
    sites = []

    if exists(nginx_conf):
        with open(nginx_conf, "r") as reader:
            lines = [line.rstrip() for line in reader]
        reader.close()

        for line in lines:
            match = re.match(ssl_cert_re, line)
            if match:
                sites.append(match.group(1))

    return sites


def check_for_certificate(host: str = None) -> bool:
    if host is None or type(host) != str:
        return False
    return host in sites_enabled()


def check_for_cname(host: str = None) -> bool:
    if host is None or type(host) != str:
        return False

    cnames = get_cnames(host)

    if len(cnames) == 1:
        cname = cnames[0].strip(".")
        for v in valid_cname_endings:
            if cname.endswith(v):
                return True

    return False


def create_certbot_entry(host: str = None, alt_checks: list = []) -> bool:
    if host is None or type(host) != str:
        return False

    if check_for_certificate(host):
        return True

    if not check_for_cname(host):
        alt_check = False
        for ac in alt_checks:
            if check_for_cname(ac):
                alt_check = True
        if not alt_check:
            return False

    ls_output = subprocess.Popen(["sudo", "certbot", "--nginx", "-n", "-d", host])
    ls_output.communicate()

    print("ls_output:", ls_output)

    sleep(1)

    return check_for_certificate(host)
