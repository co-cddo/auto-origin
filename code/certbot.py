import os
import re
import subprocess

from os.path import exists
from time import sleep

from dns_tools import get_cnames
from generate_nginx_site import create_site

nginx_confs = "/etc/nginx/sites-enabled"
ssl_cert_re = r"\s*ssl_certificate\s+/etc/letsencrypt/live/([^/]+)"

valid_cname_endings = [
    "auto-origin.nonprod-service.security.gov.uk",
    "auto-origin.service.security.gov.uk",
    "mta-sts.nonprod-service.security.gov.uk",
    "mta-sts.service.security.gov.uk",
]


def check_for_certificate(host: str = None) -> bool:
    if host is None or type(host) != str:
        return False

    return exists(f"{nginx_confs}/{host}.conf")


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

    ls_output = subprocess.Popen(
        [
            "sudo",
            "certbot",
            "certonly",
            "--webroot",
            "--webroot-path",
            "/var/www/certbot",
            "-n",
            "-d",
            host,
        ]
    )
    ls_output.communicate()
    print("ls_output:", ls_output)
    sleep(1)

    resp = create_site(host)
    if resp["new"]:
        sleep(1)
        subprocess.Popen(["sudo", "/usr/sbin/nginx", "-s", "reload"])

    return check_for_certificate(host)
