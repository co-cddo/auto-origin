import os
import re
from os.path import exists

destination = "/etc/nginx/sites-available"
destination_enabled = "/etc/nginx/sites-enabled"
nginx_site_template = "/var/auto-origin/code/nginx-site-template.conf"
domain_key = "{DOMAIN}"


def create_site(domain: str = None) -> bool:
    if domain is None or type(domain) != str:
        return False

    domain = domain.lower().strip().strip(".")
    if not domain:
        return False

    destination_conf = f"{destination}/{domain}.conf"
    res = False

    if exists(destination_conf):
        res = True

    if not res and exists(nginx_site_template):
        with open(nginx_site_template, "r") as reader:
            lines = [line.replace(domain_key, domain) for line in reader]
        reader.close()

        with open(destination_conf, "a") as fw:
            fw.writelines(lines)

        if exists(destination_conf):
            res = True

    if res:
        destination_enabled_conf = f"{destination_enabled}/{domain}.conf"
        os.symlink(destination_conf, destination_enabled_conf)

    return res
