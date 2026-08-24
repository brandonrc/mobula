#!/usr/bin/env python3
"""Scripted oauth2 browser flow to prove group-gating on a NebariApp-gated
dashboard: log a user in through Keycloak and report the final status the
gateway returns for the app URL. team-b user (bob) -> 200; team-a user
(alice) -> 403 (group not in auth.groups=[team-b]). Run from grace host."""
import sys, ssl, re, http.cookiejar, urllib.request, urllib.parse

APP = sys.argv[1] if len(sys.argv) > 1 else "https://bobdask.100-89-230-107.sslip.io/"
USER = sys.argv[2] if len(sys.argv) > 2 else "bob"
PW = sys.argv[3] if len(sys.argv) > 3 else "Spike#123"

ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    urllib.request.HTTPSHandler(context=ctx),
)
op.addheaders = [("User-Agent", "spike-curl")]

# 1. hit the app -> redirected through oauth2 to the Keycloak login page
r = op.open(APP, timeout=30)
html = r.read().decode("utf-8", "replace")
# 2. extract the login form action from the Keycloak page
m = re.search(r'action="([^"]+)"', html)
if not m:
    print(f"{USER}: no login form (final url {r.geturl()}, status {r.status})"); sys.exit()
action = m.group(1).replace("&amp;", "&")
# 3. POST credentials; cookies carry the keycloak auth session
data = urllib.parse.urlencode({"username": USER, "password": PW}).encode()
try:
    r2 = op.open(urllib.request.Request(action, data=data), timeout=30)
    print(f"{USER}: final status {r2.status} at {r2.geturl()}")
except urllib.error.HTTPError as e:
    print(f"{USER}: final status {e.code} at {e.url}")
