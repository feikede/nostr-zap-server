import json
import threading
import unittest
from unittest.mock import MagicMock, patch

import lnd_helper


class TestLndHelper(unittest.TestCase):

    def setUp(self):
        self.logger = MagicMock()
        self.nostr_helper = MagicMock()
        self.mutex = MagicMock()
        self.lnd_helper = lnd_helper.LndHelper(self.logger, self.nostr_helper, self.mutex)

    def test_set_clearnet_feature_not_available(self):
        self.lnd_helper.DYNIP_SECRET = ''
        response, status_code = self.lnd_helper.set_clearnet('ipv4', 'secret', 8080, 'tls_verify')
        self.assertEqual(status_code, 403)
        self.assertEqual(response, {"status": "ERROR", "reason": "Feature not available"})

    def test_set_clearnet_invalid_secret(self):
        self.lnd_helper.DYNIP_SECRET = 'secret1'
        response, status_code = self.lnd_helper.set_clearnet('ipv4', 'secret2', 8080, 'tls_verify')
        self.assertEqual(status_code, 403)
        self.assertEqual(response, {"status": "ERROR", "reason": "Denied"})

    def test_set_clearnet_invalid_ipv4(self):
        self.lnd_helper.DYNIP_SECRET = 'secret'
        self.lnd_helper._validate_ip_address = MagicMock(return_value=False)
        response, status_code = self.lnd_helper.set_clearnet('invalid_ipv4', 'secret', 8080, 'tls_verify')
        self.assertEqual(status_code, 403)
        self.assertEqual(response, {"status": "ERROR", "reason": "Denied"})

    def test_set_clearnet_successful_without_reconnect(self):
        self.lnd_helper.DYNIP_SECRET = 'secret'
        self.lnd_helper._validate_ip_address = MagicMock(return_value=True)
        response, status_code = self.lnd_helper.set_clearnet('ipv4', 'secret', 8080, 'tls_verify')
        self.assertEqual(status_code, 204)
        self.assertEqual(response, {})

    def test_set_clearnet_successful_with_reconnect(self):
        self.lnd_helper.LND_RESTADDR = 'old_addr'
        self.lnd_helper.DYNIP_SECRET = 'secret'
        self.lnd_helper._validate_ip_address = MagicMock(return_value=True)
        self.lnd_helper._listen_for_invoices = MagicMock()
        self.lnd_helper.start_invoice_listener = MagicMock()
        response, status_code = self.lnd_helper.set_clearnet('ipv4', 'secret', 8080, 'tls_verify')
        self.lnd_helper.start_invoice_listener.assert_called_once()
        self.assertEqual(self.lnd_helper.LND_RESTADDR, 'https://ipv4:8080')
        self.assertEqual(status_code, 204)
        self.assertEqual(response, {})

    def test_validate_ip_address_with_valid_ip(self):
        self.assertTrue(self.lnd_helper._validate_ip_address("192.168.1.1"))

    def test_validate_ip_address_with_invalid_ip(self):
        self.assertFalse(self.lnd_helper._validate_ip_address("192.168.1.256"))

    def test_validate_ip_address_with_non_string(self):
        self.assertFalse(self.lnd_helper._validate_ip_address(42))

    def test_validate_ip_address_with_int_string(self):
        self.assertFalse(self.lnd_helper._validate_ip_address("42"))

    def test_validate_ip_address_with_empty_string(self):
        self.assertFalse(self.lnd_helper._validate_ip_address(""))

    def test_validate_ip_address_with_ipv6(self):
        self.assertTrue(self.lnd_helper._validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))

    @patch('time.time')
    def test_cleanup_invoice_cache(self, mock_time):
        # setting up some mock invoice cache data
        self.lnd_helper._invoice_cache = {
            "first_invoice": {"timestamp": 1000, "idx": "first_invoice"},
            "second_invoice": {"timestamp": 2000, "idx": "second_invoice"}
        }
        mock_time.return_value = 3000
        self.lnd_helper.CACHE_TIMEOUT = 1500
        # run the function to be tested
        self.lnd_helper.cleanup_invoice_cache()
        # verify log messages
        self.logger.debug.assert_any_call('running cleanup_invoice_cache in thread ' + str(threading.get_native_id()))
        self.logger.debug.assert_called_with('After: Invoice cache length is 1')
        self.logger.info.assert_called_with('Cleaned 1 from invoice cache')
        # assert the cache is cleaned
        self.assertEqual(len(self.lnd_helper._invoice_cache), 1)

    def test_post_process_payment_invoice_cache_empty(self):
        self.lnd_helper._invoice_cache = {}
        raw_result = json.dumps({"result": "test"})
        expected_result = False
        self.assertEqual(self.lnd_helper.post_process_payment(raw_result), expected_result)

    def test_post_process_payment_no_result_in_response(self):
        self.lnd_helper._invoice_cache = {"test": "test"}
        raw_result = json.dumps({"test": "test"})
        expected_result = True
        self.assertEqual(self.lnd_helper.post_process_payment(raw_result), expected_result)

    def test_post_process_payment_settled_false(self):
        self.lnd_helper._invoice_cache = {"test": "test"}
        raw_result = json.dumps({"result": {"settled": False, "value_msat": "test", "add_index": "test"}})
        expected_result = True
        self.assertEqual(self.lnd_helper.post_process_payment(raw_result), expected_result)

    def test_post_process_payment_no_settled_value(self):
        self.lnd_helper._invoice_cache = {"test": "test"}
        raw_result = json.dumps({"result": {"value_msat": "test", "add_index": "test"}})
        expected_result = True
        self.assertEqual(self.lnd_helper.post_process_payment(raw_result), expected_result)

    def test_post_process_payment_no_value_msat(self):
        self.lnd_helper._invoice_cache = {"test": "test"}
        raw_result = json.dumps({"result": {"settled": True, "add_index": "test"}})
        expected_result = True
        self.assertEqual(self.lnd_helper.post_process_payment(raw_result), expected_result)

    def test_post_process_payment_no_add_index(self):
        self.lnd_helper._invoice_cache = {"test": "test"}
        raw_result = json.dumps({"result": {"settled": True, "value_msat": "test"}})
        expected_result = True
        self.assertEqual(self.lnd_helper.post_process_payment(raw_result), expected_result)

    def test_post_process_payment_idx_not_in_invoice_cache(self):
        self.lnd_helper._invoice_cache = {"test": "test"}
        raw_result = json.dumps({"result": {"settled": True, "value_msat": "test", "add_index": "missing"}})
        expected_result = True
        self.assertEqual(self.lnd_helper.post_process_payment(raw_result), expected_result)

    def test_post_process_payment_success_with_invoice_cache_remaining(self):
        self.lnd_helper._invoice_cache = {"remaining": "test", "1": {"event": "Test"}}
        raw_result = json.dumps({"result": {"settled": True, "value_msat": "test", "add_index": "1"}})
        expected_result = True
        self.assertEqual(self.lnd_helper.post_process_payment(raw_result), expected_result)

    def test_post_process_payment_success_no_invoice_cache_remaining(self):
        self.lnd_helper.cache_payment("2", '{"event": "Test"}')
        self.assertEqual(len(self.lnd_helper._invoice_cache), 1)
        raw_result = json.dumps({"result": {"settled": True, "value_msat": "test", "add_index": "2"}})
        expected_result = False
        result = self.lnd_helper.post_process_payment(raw_result)
        self.assertEqual(result, expected_result)


if __name__ == '__main__':
    unittest.main()
