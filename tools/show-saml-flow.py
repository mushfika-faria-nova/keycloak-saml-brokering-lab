#!/usr/bin/env python3
"""Log in once through the SAML flow, like a browser would, and print the two SAML messages.

Usage: python3 tools/show-saml-flow.py [username] [password]
       python3 tools/show-saml-flow.py --tamper    (changes the NameID after signing; the app must reject it)
Needs the lab running (docker compose up). Python standard library only.
"""
import base64, hashlib, html, http.cookiejar, os, re, sys, urllib.error, urllib.parse, urllib.request
import xml.dom.minidom

TAMPER = "--tamper" in sys.argv
args = [a for a in sys.argv[1:] if a != "--tamper"]
USER = args[0] if args else "demouser"
PASSWORD = args[1] if len(args) > 1 else "demouser123"
APP = "http://localhost:8280/realms/app"


class LocalhostPolicy(http.cookiejar.DefaultCookiePolicy):
    def return_ok_secure(self, cookie, request):  # browsers treat http://localhost as secure
        return True


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


jar = http.cookiejar.CookieJar(policy=LocalhostPolicy())
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)


def request(url, form=None):
    data = urllib.parse.urlencode(form).encode() if form else None
    try:
        r = opener.open(urllib.request.Request(url, data=data))
        return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def follow(url, form=None):
    status, headers, body = request(url, form)
    while status in (301, 302, 303):
        url = urllib.parse.urljoin(url, headers["Location"])
        status, headers, body = request(url)
    return url, status, body


def auto_post_form(body):
    action = html.unescape(re.search(r'<form[^>]*action="([^"]+)"', body).group(1))
    fields = {m.group(1): html.unescape(m.group(2)) for m in re.finditer(r'name="([^"]+)"\s+value="([^"]*)"', body)}
    return action, fields


def pretty(xml_text):
    out = xml.dom.minidom.parseString(xml_text).toprettyxml(indent="  ")
    out = re.sub(r"(<(?:dsig:)?(?:SignatureValue|X509Certificate|DigestValue)[^>]*>)([^<]{24})[^<]*", r"\1\2...", out)
    return "\n".join(line for line in out.splitlines() if line.strip())


# The app's own login uses OIDC with PKCE; kc_idp_hint skips its login page and goes straight to SAML.
verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
start = f"{APP}/protocol/openid-connect/auth?" + urllib.parse.urlencode({
    "client_id": "account-console", "redirect_uri": f"{APP}/account/", "response_type": "code",
    "scope": "openid", "kc_idp_hint": "corp-saml", "code_challenge": challenge, "code_challenge_method": "S256"})

print("1. Browser opens the app (SP). The app answers with a self-posting form holding an AuthnRequest.")
_, _, body = follow(start)
action, fields = auto_post_form(body)
print("\n----- AuthnRequest (SP -> IdP) -----\n" + pretty(base64.b64decode(fields["SAMLRequest"]).decode()))

print(f"\n2. Browser posts it to the IdP: {action}\n   The IdP shows its login page.")
_, _, body = follow(action, fields)
login_action = html.unescape(re.search(r'id="kc-form-login"[^>]*action="([^"]+)"', body).group(1))

print(f"3. User logs in at the IdP as '{USER}'. The IdP answers with a self-posting form holding a signed Response.")
_, _, body = follow(login_action, {"username": USER, "password": PASSWORD})
if "SAMLResponse" not in body:
    sys.exit("Login failed: check the username and password.")
action, fields = auto_post_form(body)
print("\n----- Response with Assertion (IdP -> SP) -----\n" + pretty(base64.b64decode(fields["SAMLResponse"]).decode()))

if TAMPER:
    signed = base64.b64decode(fields["SAMLResponse"]).decode()
    fields["SAMLResponse"] = base64.b64encode(signed.replace(f">{USER}</saml:NameID>", ">admin</saml:NameID>").encode()).decode()
    print("\n   --tamper: changed the NameID to 'admin' after the IdP signed it.")
print(f"\n4. Browser posts the Response to the app's ACS URL: {action}")
url, status, body = follow(action, fields)
if url.startswith(f"{APP}/account/") and "code=" in url:
    print("5. The app checked the assertion and logged the user in. It sent the browser back with a login code. Done.")
else:
    error = re.search(r'id="kc-error-message".*?<p[^>]*>(.*?)</p>', body, re.S)
    if error:
        print(f"5. The app rejected it (status {status}): {error.group(1).strip()}")
        sys.exit(0)
    title = re.search(r"<title>(.*?)</title>", body, re.S)
    print(f"5. The app answered with status {status}: {title.group(1).strip() if title else url}")
