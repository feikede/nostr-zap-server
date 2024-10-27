import json
import logging
import os
import re
import sys
import threading
import time
import urllib.parse
from pathlib import Path

import requests
from flask import Flask
from flask import request
from flask_cors import CORS
from waitress import serve

from lnd_helper import LndHelper
from nostr_helper import NostrHelper

app = Flask("nip57Server")
CORS(app)


def check_nip05_rules(name: str) -> bool:
    pattern = r"^[-a-z0-9._]+$"
    return re.match(pattern, name.lower()) is not None


def cleanup_cron():
    time.sleep(113)  # whatever...
    lnd_helper.cleanup_invoice_cache()
    threading.Thread(target=cleanup_cron, daemon=True).start()


def _get_nip57_metadata(username: str) -> str:
    parsed_url = urllib.parse.urlparse(LNURL_ORIGIN)
    return f"[[\"text/identifier\", \"{username}@{parsed_url.netloc}\"], [\"text/plain\", \"Sats for {username}\"]]"


@app.get('/.well-known/lnurlp/<string:username>')
def lnurlp(username):
    app_logger.debug("got lnurlp request for: " + username)
    if check_nip05_rules(username) is not True:
        app_logger.warning(f"WARN: {username} is not a valid NIP-05 name")
        return {"status": "ERROR", "reason": "User unknown"}, 404

    if users.get(username) is None:
        app_logger.debug(f"DEBUG: {username} is not in users.json list")
    return {
        "callback": f"{LNURL_ORIGIN}/lnurlp/invoice/{username}",
        "maxSendable": int(MAX_SENDABLE),
        "minSendable": int(MIN_SENDABLE),
        "metadata": _get_nip57_metadata(username),
        "tag": "payRequest",
        "allowsNostr": True,
        "commentAllowed": 255,
        "status": "OK",
        "nostrPubkey": nostr_helper.get_zapper_hexpub(),
        "server_version": NIP57S_VERSION,
        "payerData": {"name": {"mandatory": False}, "email": {"mandatory": False}, "pubkey": {"mandatory": False}},
    }


@app.get('/lnurlp/state')
def state():
    return lnd_helper.lnd_state()


@app.get('/lnurlp/set_clearnet')
def set_clearnet():
    app_logger.debug("got set_clearnet request")

    secret = request.args.get(key='secret', type=str)
    if secret is None:
        return {"status": "ERROR", "reason": "No secret given"}, 403

    ipv4 = request.args.get(key='ipv4', type=str)
    if ipv4 is None:
        return {"status": "ERROR", "reason": "No valid IP given"}, 400

    port = request.args.get(key='port', type=int)
    if port is None:
        port = lnd_helper.DYNIP_PORT

    tls_verify = request.args.get(key='tls_verify', type=str)
    if tls_verify is None:
        tls_verify = lnd_helper.TLS_VERIFY
    elif tls_verify.lower() == "false":
        requests.packages.urllib3.disable_warnings()
        tls_verify = False

    return lnd_helper.set_clearnet(ipv4=ipv4, secret=secret, port=port, tls_verify=tls_verify)


@app.get('/lnurlp/invoice/<string:username>')
def invoice(username):
    amount = request.args.get(key='amount', type=int)
    if amount is None:
        return {"status": "ERROR", "reason": "No valid amount given"}, 400

    nostr = request.args.get(key='nostr', type=str)
    # lnaddress wallet sends like GET /lnurlp/invoice/cygus44?amount=110000&nonce=9b007a33fdc65&comment=hey
    if nostr is None:
        # assume it's a ln address request, just deliver invoice, no 9735 event needed
        app_logger.info(f"got lightning invoice request for {username} amount {str(amount)} msats")
        bech32_invoice = lnd_helper.fetch_invoice_for_nostr(amount, _get_nip57_metadata(username))
        if bech32_invoice == "":
            app_logger.error("LND did not provide an invoice")
            return {"status": "ERROR", "reason": "LND did not provide an invoice"}, 500
        return {"status": "OK", "pr": bech32_invoice["payment_request"], "routes": []}

    app_logger.info(f"got nostr invoice request for {username} amount {str(amount)} msats")
    if not nostr_helper.check_9734_event(nostr, amount):
        app_logger.warning("nostr event is not a valid kind 9734")
        return {"status": "ERROR", "reason": "nostr event is not a valid kind 9734"}, 400

    bech32_invoice = lnd_helper.fetch_invoice_for_nostr(amount, urllib.parse.unquote_plus(nostr))
    if bech32_invoice == "":
        app_logger.error("LND did not provide an invoice")
        return {"status": "ERROR", "reason": "LND did not provide an invoice"}, 500

    lnd_helper.cache_payment(bech32_invoice["add_index"], urllib.parse.unquote_plus(nostr))
    lnd_helper.start_invoice_listener()

    return {"status": "OK", "pr": bech32_invoice["payment_request"], "routes": []}


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="[%(asctime)s - %(levelname)s] %(message)s")
    logging.getLogger().setLevel(logging.INFO)

    app_logger = logging.getLogger("nip57Server")
    LNURL_ORIGIN = os.environ.get("LNURL_ORIGIN", "http://localhost:8080")
    SERVER_PORT = os.environ.get("SERVER_PORT", "8080")
    MIN_SENDABLE = os.environ.get("MIN_SENDABLE", 1000)
    MAX_SENDABLE = os.environ.get("MAX_SENDABLE", 1000000000)
    NIP57S_VERSION = "NIP57S V3.0.1"
    users_file = Path("users.json")
    if users_file.is_file():
        app_logger.debug("Loading file users.json")
        with open('users.json', 'r') as user_names_file:
            users: dict = json.load(user_names_file)
        app_logger.debug(f"Found {len(users)} users in users.json")
    else:
        users: dict = {}
        app_logger.debug("no users.json file found")
    mutex = threading.Lock()
    nostr_helper: NostrHelper = NostrHelper(app_logger, mutex)
    lnd_helper: LndHelper = LndHelper(app_logger, nostr_helper, mutex)

    app_logger.info(f"nip57_server {NIP57S_VERSION} starting on port " + str(SERVER_PORT))
    app_logger.info("author contact: nostr:npub18w02exnj7l27t3t0hyxrnfxa8f05dep58nny7z4vur2plsd2gzxqp2hej9")
    app_logger.info("GitHub: https://github.com/feikede/nostr-zap-server")
    app_logger.info("A server to receive lightning lnaddress payments to my own self-custodial LND server.")
    app_logger.info("A server to receive nostr nip-57 zaps to my own self-custodial LND server.")
    app_logger.info("This software is provided AS IS without any warranty. Use it at your own risk.")
    app_logger.info(f"Config LNURL_ORIGIN: {LNURL_ORIGIN}")
    app_logger.info(f"Config MIN_SENDABLE: {MIN_SENDABLE}")
    app_logger.info(f"Config MAX_SENDABLE: {MAX_SENDABLE}")
    app_logger.info(f"Config DEFAULT_RELAYS: {nostr_helper.DEFAULT_RELAYS}")
    app_logger.info(f"Config SOCKS5H_PROXY: {lnd_helper.SOCKS5H_PROXY}")
    app_logger.info(f"Config LND_RESTADDR: {lnd_helper.LND_RESTADDR[:16]}...")
    app_logger.info(f"Config INVOICE_MACAROON: {lnd_helper.INVOICE_MACAROON[:14]}...")
    app_logger.info(f"Config ZAPPER_KEY: {os.environ.get("ZAPPER_KEY")[:14]}...")
    app_logger.info(f"Config DYNIP_SECRET: {lnd_helper.DYNIP_SECRET[:3]}...")
    app_logger.info(f"Config TLS_VERIFY: {lnd_helper.TLS_VERIFY}")
    app_logger.info(f"Config ACCOUNTING_SECRET: {nostr_helper.ACCOUNTING_SECRET[:6]}...")
    app_logger.info(f"Config ACCOUNTING_URL: {nostr_helper.ACCOUNTING_URL}")

    threading.Thread(target=cleanup_cron, daemon=True).start()
    serve(app, host="0.0.0.0", port=SERVER_PORT)
