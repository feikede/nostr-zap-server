import json
import logging
import os
import ssl
import urllib.parse
from threading import Lock

import requests
from nostr.event import Event
from nostr.key import PublicKey, PrivateKey
from nostr.relay import Relay
from nostr.relay_manager import RelayManager, RelayPolicy


class XRelay(Relay):
    def __init__(self, url, policy, message_pool, options):
        super().__init__(url, policy, message_pool, options)
        self._event = None
        self._logger = None

    def set_on_open_event(self, event: Event, logger: logging.Logger):
        self._event = event
        self._logger = logger

    def _on_open(self, class_obj):
        self.connected = True
        if self._event is not None:
            message = self._event.to_message()
            self._logger.debug(f"Publishing on {self.url}")
            self.publish(message)
            self._logger.debug(f"Closing {self.url}")
            self.close()


class XRelayManager(RelayManager):
    def add_x_relay(self, url: str, event: Event, logger: logging.Logger):
        policy = RelayPolicy(True, True)
        relay = XRelay(url, policy, self.message_pool, {})
        relay.set_on_open_event(event, logger)
        self.relays[url] = relay


class NostrHelper:
    DEFAULT_RELAYS = [
        "wss://nostr.mom/",
        "wss://relay.damus.io/",
        "wss://nos.lol/"
    ]
    ACCOUNTING_URL = os.environ.get("ACCOUNTING_URL", "")
    ACCOUNTING_SECRET = os.environ.get("ACCOUNTING_SECRET", "please_set")

    def __init__(self, logger: logging.Logger, mutex: Lock):
        self._logger = logger
        self._mutex = mutex
        self._private_key = PrivateKey(bytes.fromhex(os.environ.get("ZAPPER_KEY")))
        self._public_key = self._private_key.public_key

    def _count_tags(self, tags: list[list[str]], tag: str) -> int:
        return sum(1 for inner_tags in tags if inner_tags[0] == tag)

    def _get_tag(self, tags: list[list[str]], tag: str) -> list[str]:
        if not tags:
            return []
        return next((inner_tags for inner_tags in tags if inner_tags[0] == tag), [])

    def get_zapper_hexpub(self):
        return self._public_key.hex()

    def check_9734_event(self, nostr_json_encoded: str, amount: int) -> bool:
        """
        Check event for https://github.com/nostr-protocol/nips/blob/master/57.md App D
        :param amount: amount in msat
        :param nostr_json_encoded: Urlencoded kind 9734 event
        :return: true if event is valid, else false
        """
        try:
            nostr_json = urllib.parse.unquote_plus(nostr_json_encoded)
            nostr = json.loads(nostr_json)
        except ValueError:
            return False

        required_keys = {"kind", "tags", "sig", "pubkey", "id"}
        if not required_keys.issubset(nostr) or nostr["kind"] != 9734:
            return False

        if self._count_tags(nostr["tags"], "p") != 1 or self._count_tags(nostr["tags"], "e") > 1:
            return False
        if self._count_tags(nostr["tags"], "amount") == 1:
            amount_tag = self._get_tag(nostr["tags"], "amount")
            if int(amount_tag[1]) != amount:
                return False

        pub_key = PublicKey(bytes.fromhex(nostr["pubkey"]))
        return pub_key.verify_signed_message_hash(nostr["id"], nostr["sig"])

    def get_relays_from_9734(self, event_9734_json) -> list[str]:
        nostr_9734 = json.loads(event_9734_json)
        if self._count_tags(nostr_9734["tags"], "relays") != 1:
            return []
        relay_tag = self._get_tag(nostr_9734["tags"], "relays")
        return relay_tag[1:]

    def add_default_relays(self, relays: list[str]):
        for relay in self.DEFAULT_RELAYS:
            if relay not in relays:
                relays.append(relay)
        return relays

    def send_to_accounting(self, amount: int, src_hexpub: str, dest_hexpub: str, created_at: int, event_9735_id: str):
        data = {
            "amount": amount,
            "srcHexpub": src_hexpub,
            "destHexpub": dest_hexpub,
            "createdAt": created_at,
            "eventId": event_9735_id
        }
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "NIP5S_SECRET": self.ACCOUNTING_SECRET
        }
        json_data = json.dumps(data)
        self._logger.debug("Sending to ACCOUNTING: ")
        self._logger.debug(json_data)
        self._post_to_accounting(json_data, headers)

    def _post_to_accounting(self, json_data, headers):
        if self.ACCOUNTING_URL == "":
            return
        try:
            with requests.Session() as session:
                response = session.post(
                    self.ACCOUNTING_URL + "/v1/nip5s-admin/n5posting",
                    headers=headers,
                    data=json_data,
                    timeout=5
                )
                self._log_response(response)
        except requests.RequestException as e:
            self._logger.error(f"ERROR General Error to ACCOUNTING_URL: {str(e)}")

    def _log_response(self, response):
        if response.status_code != 200:
            self._logger.error("No 200 from lnd: ")
            self._logger.error(response.json())
            self._logger.error(response.headers)
        else:
            self._logger.debug("LND response " + str(response.json()))

    def confirm_payment(self, idx, event_9734_json, lnd_invoice_json):
        self._logger.debug(f"Creating event kind 9735 for idx {idx}")
        self._logger.debug(f"Have 9734 Event: {event_9734_json}")
        self._logger.debug(f"Have LND invoice: {lnd_invoice_json}")

        nostr_9734 = json.loads(event_9734_json)
        lnd_invoice = json.loads(lnd_invoice_json)

        nostr_event_tags = [
            ["description", event_9734_json],
            ["bolt11", lnd_invoice["payment_request"]],
            self._get_tag(nostr_9734["tags"], "p")
        ]

        nostr_event_tags.extend(self._get_optional_tags(nostr_9734))

        nostr_event = Event(
            content="",
            kind=9735,
            public_key=self._public_key.hex(),
            tags=nostr_event_tags,
            created_at=int(lnd_invoice["settle_date"])
        )
        self._private_key.sign_event(nostr_event)
        self._logger.debug(json.dumps(nostr_event.to_message()))

        relays = self.add_default_relays(self.get_relays_from_9734(event_9734_json))
        self.send_event_9735(relays, nostr_event)

        self._confirm_to_accounting(nostr_9734, lnd_invoice)

    def _get_optional_tags(self, nostr_9734):
        optional_tags = []
        if self._count_tags(nostr_9734["tags"], "e") == 1:
            optional_tags.append(self._get_tag(nostr_9734["tags"], "e"))
        if self._count_tags(nostr_9734["tags"], "a") == 1:
            optional_tags.append(self._get_tag(nostr_9734["tags"], "a"))
        return optional_tags

    def _confirm_to_accounting(self, nostr_9734, lnd_invoice):
        src = nostr_9734["pubkey"]
        dest = self._get_tag(nostr_9734["tags"], "p")[1]
        created_at = nostr_9734["created_at"]
        amount = lnd_invoice['value_msat']
        self.send_to_accounting(
            amount=int(amount),
            src_hexpub=src,
            dest_hexpub=dest,
            created_at=created_at,
            event_9735_id=""
        )

    def send_event_9735(self, relays: list[str], event: Event):
        self._logger.info("Sending 9735 event to relays now")
        relay_manager = XRelayManager()
        for relay in relays:
            relay_manager.add_x_relay(relay, event, self._logger)
        relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})
