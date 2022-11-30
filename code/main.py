import os

from flask import Flask, request, make_response, redirect

app = Flask(__name__)

from certbot import create_certbot_entry
from mta_sts_tools import get_mode, parse_mta_sts, get_mta_sts_cname, host_valid

DEFAULT_REDIRECT_URL = "https://www.gov.uk"
TIMEOUT = int(os.getenv("TIMEOUT", "2"))
PORT = int(os.getenv("PORT", "5001"))


def get_valid_host() -> str:
    host = None
    if "x-forwarded-host" in request.headers:
        host = request.headers["x-forwarded-host"]
    elif "true-host" in request.headers:
        host = request.headers["true-host"]
    elif "host" in request.headers:
        host = request.headers["host"]
    return host if host_valid(host) else None


@app.route("/")
def root():
    vh = get_valid_host()
    if vh is not None:
        cce = create_certbot_entry(vh)

    # get from redirect DNS TXT record?
    # get txt records, if record starts "_ao=", check if redirect URL is in allowed list, use that?

    return redirect(DEFAULT_REDIRECT_URL)


@app.route("/tls-status")
def tlsstatus():
    vh = get_valid_host()
    if vh is not None:
        cce = create_certbot_entry(vh)
        return f"TLS-OK {vh}" if cce else f"TLS-FAIL {vh}"
    return "TLS-FAIL"


@app.route("/mta-sts.txt")
@app.route("/.well-known/mta-sts.txt")
def mtaststxt():
    txt = "Not Found"
    mx_records = []
    valid_hostname = get_valid_host()
    if valid_hostname is not None:
        mta_sts_record = get_mta_sts_cname(valid_hostname)
        parsed_hostname = parse_mta_sts(mta_sts_record)
        if not parsed_hostname["valid"] and "domain" in request.args:
            try:
                tmp_max_age = (
                    int(request.args.get("max-age"))
                    if "max-age" in request.args
                    else int(request.args.get("max_age"))
                    if "max_age" in request.args
                    else None
                )

                tmp_host = f"{tmp_max_age}_" if tmp_max_age is not None else ""
                tmp_host += request.args["domain"].strip().lower().replace(".", "__")
                tmp_host += "."
                tmp_host += (
                    request.args.get("mode") if "mode" in request.args else "auto"
                )

                parsed_hostname = parse_mta_sts(tmp_host, check_suffix=False)
            except Exception as e:
                print(e)
        # end if parsed_hostname["valid"]

        if parsed_hostname["valid"]:
            cce = create_certbot_entry(parsed_hostname["domain"])
            print(f"Certificate exists for {parsed_hostname['domain']}:", cce)

            if parsed_hostname["mode"] == "auto":
                parsed_hostname["mode"] = get_mode(parsed_hostname["domain"])

            if parsed_hostname["max_age"] is None:
                parsed_hostname["max_age"] = (
                    1209600 if parsed_hostname["mode"] == "enforce" else 86401
                )

            if parsed_hostname["mode"] == "auto":
                parsed_hostname["mode"] = get_mode(parsed_hostname["domain"])

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

            txt += f"max_age: {parsed_hostname['max_age']}\r\n"
        # end if parsed_hostname["valid"]

    # end if valid_hostname is not None

    resp = make_response(txt, (404 if "Not Found" in txt else 200))
    resp.headers[
        "Cache-Control"
    ] = f"public, max-age={parsed_hostname.get('max_age', '60')}"
    resp.headers["Content-Type"] = "text/plain"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
