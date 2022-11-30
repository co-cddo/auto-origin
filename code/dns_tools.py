import dns.resolver
import dns.reversename

resolver = dns.resolver.Resolver()

resolver_defaults = {"lifetime": 3, "raise_on_no_answer": False}

allowed_exceptions = [
    dns.resolver.NXDOMAIN,
    dns.resolver.LifetimeTimeout,
]


def handle_exception(e):
    if type(e) not in allowed_exceptions:
        print(
            "type(e):",
            type(e),
            allowed_exceptions,
            [type(a) for a in allowed_exceptions],
        )
        raise e


def get_as(domain: str) -> list:
    dnsresults = []
    try:
        dnsresults = resolver.resolve(domain, "A", **resolver_defaults)
    except Exception as e:
        handle_exception(e)
    return (
        [d.to_text().strip('"').strip("'") for d in dnsresults if d]
        if dnsresults
        else []
    )


def get_cnames(domain: str) -> list:
    dnsresults = []
    try:
        dnsresults = resolver.resolve(domain, "CNAME", **resolver_defaults)
    except Exception as e:
        handle_exception(e)
    return (
        [d.to_text().strip('"').strip("'") for d in dnsresults if d]
        if dnsresults
        else []
    )


def get_txts(domain: str) -> list:
    dnsresults = []
    try:
        dnsresults = resolver.resolve(domain, "TXT", **resolver_defaults)
    except Exception as e:
        handle_exception(e)
    return (
        [d.to_text().strip('"').strip("'") for d in dnsresults if d]
        if dnsresults
        else []
    )


def get_mxs(domain: str) -> list:
    dnsresults = []
    try:
        dnsresults = resolver.resolve(domain, "MX", **resolver_defaults)
    except Exception as e:
        handle_exception(e)
    return (
        [d.to_text().strip('"').strip("'") for d in dnsresults if d]
        if dnsresults
        else []
    )
