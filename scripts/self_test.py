import re
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar


BASE = "http://127.0.0.1:5000"


def fetch(opener, path: str) -> str:
    return opener.open(f"{BASE}{path}").read().decode("utf-8")


def main() -> None:
    cj = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    html = fetch(opener, "/")
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert m, "CSRF token not found in form"
    csrf = m.group(1)

    payload = "<script>alert(1)</script><b>hello</b>"
    data = urllib.parse.urlencode({"csrf_token": csrf, "name": "Attacker", "message": payload}).encode()
    req = urllib.request.Request(f"{BASE}/sign", data=data, method="POST")
    opener.open(req).read()

    html2 = fetch(opener, "/")
    print("Contains <script> tag in HTML:", "<script" in html2)
    print("Contains <b> tag in HTML:", "<b>" in html2)
    print("Contains 'hello' in HTML:", "hello" in html2)


if __name__ == "__main__":
    main()
