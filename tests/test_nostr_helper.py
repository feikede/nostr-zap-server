import os
import unittest
from unittest.mock import MagicMock

from nostr_helper import NostrHelper

good_9734_event = '{"id":"d3aff0a277695bae9d247764ed7d13cb6a2878e263f556c1e6e6bb33d8e9f993","pubkey":"01d0bbf9537ef1fd0ddf815f41c1896738f6a3a0f600f51c782b7d8891130d4c","created_at":1729943980,"kind":9734,"tags":[["e","0d7366570d9bef36f80d981cb8c72ec5116082c89bacc189e74f4b82ea63fa11"],["p","7b394902eeadb8370931f1903d00569545e84113fb6a09634664763be232009c"],["relays","wss://relay.damus.io","wss://nostr.wine"]],"content":"","sig":"61dc3612da4e036bd1a5ab79419224b8f6b4cd713c79e96f2ce3729243098dacac5dc48fbb53660a89c668550ac35f22fef109891413346accb6faa00f710849"}'
missing_id_9734_event = '{"pubkey":"01d0bbf9537ef1fd0ddf815f41c1896738f6a3a0f600f51c782b7d8891130d4c","created_at":1729943980,"kind":9734,"tags":[["e","0d7366570d9bef36f80d981cb8c72ec5116082c89bacc189e74f4b82ea63fa11"],["p","7b394902eeadb8370931f1903d00569545e84113fb6a09634664763be232009c"],["relays","wss://relay.damus.io","wss://nostr.wine"]],"content":"","sig":"61dc3612da4e036bd1a5ab79419224b8f6b4cd713c79e96f2ce3729243098dacac5dc48fbb53660a89c668550ac35f22fef109891413346accb6faa00f710849"}'
bad_signature_9734_event = '{"id":"d3aff0a277695bae9d247764ed7d13cb6a2878e263f556c1e6e6bb33d8e9f993","pubkey":"01d0bbf9537ef1fd0ddf815f41c1896738f6a3a0f600f51c782b7d8891130d4c","created_at":1729943980,"kind":9734,"tags":[["e","0d7366570d9bef36f80d981cb8c72ec5116082c89bacc189e74f4b82ea63fa11"],["p","7b394902eeadb8370931f1903d00569545e84113fb6a09634664763be232009c"],["relays","wss://relay.damus.io","wss://nostr.wine"]],"content":"","sig":"71dc3612da4e036bd1a5ab79419224b8f6b4cd713c79e96f2ce3729243098dacac5dc48fbb53660a89c668550ac35f22fef109891413346accb6faa00f710849"}'
bad_amount_9734_event = '{"id":"d3aff0a277695bae9d247764ed7d13cb6a2878e263f556c1e6e6bb33d8e9f993","pubkey":"01d0bbf9537ef1fd0ddf815f41c1896738f6a3a0f600f51c782b7d8891130d4c","created_at":1729943980,"kind":9734,"tags":[["e","0d7366570d9bef36f80d981cb8c72ec5116082c89bacc189e74f4b82ea63fa11"],["p","7b394902eeadb8370931f1903d00569545e84113fb6a09634664763be232009c"],["amount", "20"],["relays","wss://relay.damus.io","wss://nostr.wine"]],"content":"","sig":"71dc3612da4e036bd1a5ab79419224b8f6b4cd713c79e96f2ce3729243098dacac5dc48fbb53660a89c668550ac35f22fef109891413346accb6faa00f710849"}'
good_amount_9734_event = '{"id":"d3aff0a277695bae9d247764ed7d13cb6a2878e263f556c1e6e6bb33d8e9f993","pubkey":"01d0bbf9537ef1fd0ddf815f41c1896738f6a3a0f600f51c782b7d8891130d4c","created_at":1729943980,"kind":9734,"tags":[["e","0d7366570d9bef36f80d981cb8c72ec5116082c89bacc189e74f4b82ea63fa11"],["p","7b394902eeadb8370931f1903d00569545e84113fb6a09634664763be232009c"],["amount", "21"],["relays","wss://relay.damus.io","wss://nostr.wine"]],"content":"","sig":"71dc3612da4e036bd1a5ab79419224b8f6b4cd713c79e96f2ce3729243098dacac5dc48fbb53660a89c668550ac35f22fef109891413346accb6faa00f710849"}'


class TestNostrHelper(unittest.TestCase):

    def setUp(self):
        self.logger = MagicMock()
        self.mutex = MagicMock()
        # any random hex-pk needed here
        os.environ.setdefault("ZAPPER_KEY", "89aaabf16ed0d5fe4d721f114e95791583b5388b9e93181f826b8533a0d1176a")
        self.nostr_helper = NostrHelper(self.logger, self.mutex)

    def test_count_tags(self):
        tags1 = [["tag1"], ["tag2"], ["tag3"]]
        self.assertEqual(self.nostr_helper._count_tags(tags1, "tag1"), 1)

        tags2 = [["tag1"], ["tag1"], ["tag3"]]
        self.assertEqual(self.nostr_helper._count_tags(tags2, "tag1"), 2)

        self.assertEqual(self.nostr_helper._count_tags(tags1, "non_existing_tag"), 0)

        self.assertEqual(self.nostr_helper._count_tags([], "tag1"), 0)

    def test_get_tag_with_existing_tag(self):
        tags = [['tag1', 'value1'], ['tag2', 'value2'], ['tag3', 'value3']]
        tag = 'tag2'
        result = self.nostr_helper._get_tag(tags, tag)
        self.assertEqual(result, ['tag2', 'value2'])

    def test_get_tag_with_non_existing_tag(self):
        tags = [['tag1', 'value1'], ['tag2', 'value2'], ['tag3', 'value3']]
        tag = 'tag4'
        result = self.nostr_helper._get_tag(tags, tag)
        self.assertEqual(result, [])

    def test_get_tag_with_empty_tags_list(self):
        tags = []
        tag = 'tag1'
        result = self.nostr_helper._get_tag(tags, tag)
        self.assertEqual(result, [])

    def test_get_tag_with_none_tag(self):
        tags = [['tag1', 'value1'], ['tag2', 'value2'], ['tag3', 'value3']]
        tag = None
        result = self.nostr_helper._get_tag(tags, tag)
        self.assertEqual(result, [])

    def test_get_tag_with_none_tags_list(self):
        tags = None
        tag = 'tag1'
        result = self.nostr_helper._get_tag(tags, tag)
        self.assertEqual(result, [])

    def test_check_9734_event_with_good_event(self):
        result = self.nostr_helper.check_9734_event(good_9734_event, 21)
        self.assertTrue(result)

    def test_check_9734_event_with_bad_signature_event(self):
        result = self.nostr_helper.check_9734_event(bad_signature_9734_event, 21)
        self.assertFalse(result)

    def test_check_9734_event_with_bad_amount_event(self):
        result = self.nostr_helper.check_9734_event(bad_amount_9734_event, 21)
        self.assertFalse(result)

    def test_check_9734_event_with_missing_id_event(self):
        result = self.nostr_helper.check_9734_event(missing_id_9734_event, 21)
        self.assertFalse(result)

    def test_get_relays_from_9734(self):
        result = self.nostr_helper.get_relays_from_9734(good_9734_event)
        self.assertEqual(result, ["wss://relay.damus.io", "wss://nostr.wine"])


if __name__ == '__main__':
    unittest.main()
