#!/usr/bin/env python3
"""Read-only CP14 commitment verification; never mints a completeness certificate."""
import argparse
import hashlib
import json
from pathlib import Path
import uuid

PERMIT_KEYS = ('schema', 'operation_id', 'sandbox_id', 'supervisor_session_id',
               'supervisor_session_epoch', 'policy_generation', 'surface', 'host',
               'port', 'matched_policy', 'binary_path', 'binary_pid',
               'intent_sha256', 'committed_unix_ns', 'record_sha256')
INTENT_KEYS = ('surface', 'host', 'port', 'matched_policy', 'binary_path', 'binary_pid')
ROW_KEYS = {'journal_schema', 'sequence', 'prev_record_sha256',
            'journal_record_sha256', *PERMIT_KEYS}
WITNESS_KEYS = ('schema', 'sequence', 'head_record_sha256', 'updated_unix_ns')
GENESIS = '0' * 64


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON field: {key}')
        result[key] = value
    return result


def parse(raw):
    try:
        value = json.loads(raw, object_pairs_hook=strict_object,
                           parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f'invalid JSON: {exc}') from exc
    if not isinstance(value, dict):
        raise ValueError('expected a JSON object')
    return value


def digest(value, sort=False):
    encoded = json.dumps(value, sort_keys=sort, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uint(value, bits=64):
    return type(value) is int and 0 <= value < 2**bits


def verify(journal: bytes, witness: bytes, sandbox_id: str) -> dict:
    require(bool(journal), 'empty journal is not runtime evidence')
    require(journal.endswith(b'\n'), 'journal must end with a newline')
    records = []
    seen = set()
    previous = GENESIS
    for expected, line in enumerate(journal.splitlines(), 1):
        row = parse(line)
        require(set(row) == ROW_KEYS, 'unsupported journal fields')
        require(row['journal_schema'] == 'blackbox.openshell.journal-record.v1', 'journal schema')
        require(uint(row['sequence']) and row['sequence'] == expected, 'journal sequence')
        require(row['prev_record_sha256'] == previous, 'journal predecessor')
        permit = {key: row[key] for key in PERMIT_KEYS}
        require(permit['schema'] == 'blackbox.openshell.durable-egress-permit.v2', 'permit schema')
        require(permit['sandbox_id'] == sandbox_id and bool(sandbox_id), 'wrong sandbox identity')
        for key in ('operation_id', 'supervisor_session_id', 'host', 'binary_path', 'matched_policy'):
            require(isinstance(permit[key], str) and bool(permit[key]), f'invalid {key}')
        try:
            uuid.UUID(permit['operation_id'])
        except (ValueError, AttributeError) as exc:
            raise ValueError('invalid operation_id') from exc
        require(permit['operation_id'] not in seen, 'replayed operation_id')
        require(permit['surface'] in ('connect', 'forward_http', 'transparent_tcp'), 'surface')
        for key in ('supervisor_session_epoch', 'policy_generation', 'committed_unix_ns'):
            require(uint(permit[key]), f'invalid {key}')
        require(uint(permit['port'], 16) and permit['port'] > 0, 'invalid port')
        require(permit['binary_pid'] is None or uint(permit['binary_pid'], 32), 'invalid binary_pid')
        intent = {key: permit[key] for key in INTENT_KEYS}
        require(digest(intent, True) == permit['intent_sha256'], 'intent commitment mismatch')
        unsigned = {key: permit[key] for key in PERMIT_KEYS[:-1]}
        require(digest(unsigned, True) == permit['record_sha256'], 'record commitment mismatch')
        commitment = dict(journal_schema=row['journal_schema'], sequence=expected,
                          prev_record_sha256=previous, permit=permit)
        require(digest(commitment) == row['journal_record_sha256'], 'journal commitment mismatch')
        seen.add(permit['operation_id'])
        previous = row['journal_record_sha256']
        records.append(row)
    high = parse(witness)
    require(set(high) == {*WITNESS_KEYS, 'witness_sha256'}, 'unsupported witness fields')
    require(high['schema'] == 'blackbox.openshell.high-water-witness.v1', 'witness schema')
    require(uint(high['sequence']) and uint(high['updated_unix_ns']), 'invalid witness sequence or time')
    require(digest({key: high[key] for key in WITNESS_KEYS}) == high['witness_sha256'],
            'witness commitment mismatch')
    require(high['sequence'] == len(records), 'witness sequence mismatch')
    require(high['head_record_sha256'] == previous, 'witness head mismatch')
    return dict(count=len(records), head=previous, records=records,
                claim='RAW_COMMITMENTS_VERIFIED', coverage='NOT_ESTABLISHED',
                outcome='OUTCOME_UNKNOWN', authenticated_witness=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--journal', required=True, type=Path)
    parser.add_argument('--witness', required=True, type=Path)
    parser.add_argument('--sandbox-id', required=True)
    args = parser.parse_args()
    try:
        result = verify(args.journal.read_bytes(), args.witness.read_bytes(), args.sandbox_id)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'CP15 evidence rejected: {exc}\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
