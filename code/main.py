import os

from flask import Flask, request, make_response, redirect

app = Flask(__name__)

from certbot import create_certbot_entry
from mta_sts_tools import get_txt_file, host_valid

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
    redirect_url = DEFAULT_REDIRECT_URL

    vh = get_valid_host()
    if vh is not None:
        try:
            cce = create_certbot_entry(vh)
        except Exception as e:
            print("mtaststxt:e:", e)
        if vh.startswith("mta-sts."):
            redirect_url = "/.well-known/mta-sts.txt"

    # get from redirect DNS TXT record?
    # get txt records, if record starts "_ao=", check if redirect URL is in allowed list, use that?
    return redirect(redirect_url)


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
    cache = 60
    txt = "# Invalid Domain\r\n"
    vh = get_valid_host()

    if vh is not None:
        try:
            cce = create_certbot_entry(vh)
        except Exception as e:
            print("mtaststxt:e:", e)

        cache, txt = get_txt_file(vh)

    resp = make_response(txt, (200 if txt.startswith("version:") else 404))
    resp.headers["Cache-Control"] = f"public, max-age={cache}"
    resp.headers["Content-Type"] = "text/plain"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
