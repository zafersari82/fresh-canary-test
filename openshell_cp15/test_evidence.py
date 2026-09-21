import copy
import hashlib
import json
import unittest

from evidence import verify


def digest(value, sort=False):
    return hashlib.sha256(json.dumps(value, sort_keys=sort, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def fixture():
    intent = dict(surface='connect', host='host.openshell.internal', port=8080,
                  matched_policy='cp15', binary_path='/usr/bin/python3', binary_pid=100)
    permit = dict(schema='blackbox.openshell.durable-egress-permit.v2',
                  operation_id='11111111-1111-4111-8111-111111111111', sandbox_id='sandbox-1',
                  supervisor_session_id='session-1', supervisor_session_epoch=1,
                  policy_generation=0, **intent, intent_sha256=digest(intent, True), committed_unix_ns=123)
    permit['record_sha256'] = digest(permit, True)
    commitment = dict(journal_schema='blackbox.openshell.journal-record.v1', sequence=1,
                      prev_record_sha256='0'*64, permit=permit)
    row = dict(journal_schema=commitment['journal_schema'], sequence=1,
               prev_record_sha256='0'*64, **permit, journal_record_sha256=digest(commitment))
    witness = dict(schema='blackbox.openshell.high-water-witness.v1', sequence=1,
                   head_record_sha256=row['journal_record_sha256'], updated_unix_ns=124)
    witness['witness_sha256'] = digest(witness)
    return row, witness


def encode(row, witness):
    return (json.dumps(row).encode()+b'\n', json.dumps(witness).encode()+b'\n')


class EvidenceTests(unittest.TestCase):
    def test_valid_exact_rust_contract(self):
        self.assertEqual(verify(*encode(*fixture()), 'sandbox-1')['count'], 1)

    def test_payload_mutation_with_unchanged_hashes_rejected(self):
        row, witness = fixture()
        row['host'] = 'other.example'
        with self.assertRaisesRegex(ValueError, 'intent'):
            verify(*encode(row, witness), 'sandbox-1')

    def test_permit_identity_mutation_rejected(self):
        row, witness = fixture()
        row['supervisor_session_id'] = 'other'
        with self.assertRaisesRegex(ValueError, 'record commitment'):
            verify(*encode(row, witness), 'sandbox-1')

    def test_stored_hash_pointer_equality_is_insufficient(self):
        row, witness = fixture()
        row['journal_record_sha256'] = '1'*64
        witness['head_record_sha256'] = '1'*64
        with self.assertRaisesRegex(ValueError, 'journal commitment'):
            verify(*encode(row, witness), 'sandbox-1')

    def test_empty_journal_cannot_pass_with_preserved_witness(self):
        _, witness = fixture()
        with self.assertRaises(ValueError):
            verify(b'', json.dumps(witness).encode(), 'sandbox-1')

    def test_wrong_sandbox_rejected(self):
        with self.assertRaisesRegex(ValueError, 'sandbox'):
            verify(*encode(*fixture()), 'sandbox-2')

    def test_duplicate_json_field_rejected(self):
        journal, witness = encode(*fixture())
        journal = journal.replace(b'{', b'{"sequence":1,', 1)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            verify(journal, witness, 'sandbox-1')

    def test_torn_tail_rejected_without_repairing_evidence(self):
        journal, witness = encode(*fixture())
        with self.assertRaisesRegex(ValueError, 'newline'):
            verify(journal.rstrip(b'\n'), witness, 'sandbox-1')

    def test_witness_mutation_rejected(self):
        row, witness = fixture()
        witness['updated_unix_ns'] += 1
        with self.assertRaisesRegex(ValueError, 'witness commitment'):
            verify(*encode(row, witness), 'sandbox-1')

    def test_missing_witness_rejected(self):
        journal, _ = encode(*fixture())
        with self.assertRaises(ValueError):
            verify(journal, b'', 'sandbox-1')

    def test_boolean_sequence_rejected(self):
        row, witness = fixture()
        row['sequence'] = True
        with self.assertRaises(ValueError):
            verify(*encode(row, witness), 'sandbox-1')

    def test_unknown_field_rejected(self):
        row, witness = fixture()
        row['unbound'] = 'hidden'
        with self.assertRaisesRegex(ValueError, 'fields'):
            verify(*encode(row, witness), 'sandbox-1')

    def test_replay_sequence_rejected(self):
        journal, witness = encode(*fixture())
        with self.assertRaisesRegex(ValueError, 'sequence'):
            verify(journal+journal, witness, 'sandbox-1')


if __name__ == '__main__':
    unittest.main()
