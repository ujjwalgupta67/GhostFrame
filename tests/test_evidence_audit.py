from __future__ import annotations

from dataclasses import replace

import pytest

from ghostframe.evidence import AuditChain, AuditEvent, GENESIS_PREVIOUS_HASH, MalformedEvidenceError, verify_audit_chain
from ghostframe.evidence.audit import MAX_AUDIT_EVENTS
from tests.evidence_support import completed_record, valid_audit_chain


def test_valid_chain_genesis_and_externally_bound_head():
    chain = valid_audit_chain()
    assert chain.events[0].previous_event_hash == GENESIS_PREVIOUS_HASH
    local = verify_audit_chain(chain)
    assert local.valid and not local.tail_bound
    assert "tail truncation" in local.detail
    bound = verify_audit_chain(chain, expected_head=chain.head_hash)
    assert bound.valid and bound.tail_bound


def test_modified_event_and_event_hash_detected():
    chain = valid_audit_chain()
    changed = replace(chain.events[1], event_type="EVIDENCE_CREATED")
    result = verify_audit_chain(AuditChain(chain.operation_commitment, chain.events[:1] + (changed,) + chain.events[2:]))
    assert not result.valid and "Invalid audit-event hash" in result.detail


def test_deleted_middle_duplicated_reordered_and_sequence_gap_detected():
    chain = valid_audit_chain()
    variants = [
        chain.events[:1] + chain.events[2:],
        chain.events[:2] + (chain.events[1],) + chain.events[2:],
        (chain.events[1], chain.events[0]) + chain.events[2:],
        chain.events[:2] + (replace(chain.events[2], index=9),) + chain.events[3:],
    ]
    for events in variants:
        assert not verify_audit_chain(AuditChain(chain.operation_commitment, tuple(events))).valid


def test_incorrect_previous_hash_wrong_operation_and_expected_head_detected():
    chain = valid_audit_chain()
    wrong_previous = replace(chain.events[1], previous_event_hash=GENESIS_PREVIOUS_HASH)
    assert not verify_audit_chain(AuditChain(chain.operation_commitment, (chain.events[0], wrong_previous) + chain.events[2:])).valid
    wrong_operation = "f" * 64
    wrong_event = replace(chain.events[0], operation_commitment=wrong_operation)
    assert not verify_audit_chain(AuditChain(chain.operation_commitment, (wrong_event,) + chain.events[1:])).valid
    assert not verify_audit_chain(chain, expected_head="f" * 64).valid


def test_empty_chain_and_truncated_tail_limitation():
    record = completed_record()
    empty = AuditChain(record.public_operation_commitment)
    assert not verify_audit_chain(empty).valid
    chain = valid_audit_chain(record)
    truncated = AuditChain(chain.operation_commitment, chain.events[:-1])
    local = verify_audit_chain(truncated)
    assert local.valid and not local.tail_bound
    external = verify_audit_chain(truncated, expected_head=chain.head_hash)
    assert not external.valid and external.tail_bound


def test_audit_round_trip_and_malformed_event_controlled():
    chain = valid_audit_chain()
    restored = AuditChain.from_dict(chain.to_dict())
    assert restored == chain
    malformed = chain.events[0].to_dict(); malformed.pop("event_hash")
    with pytest.raises(MalformedEvidenceError):
        AuditEvent.from_dict(malformed)


def test_audit_events_store_commitments_not_sensitive_payloads():
    chain = valid_audit_chain()
    serialized = str(chain.to_dict())
    assert "Synthetic Person" not in serialized
    assert "docProps" not in serialized
    assert all(event.payload_commitment is None or len(event.payload_commitment) == 64 for event in chain.events)


def test_audit_event_count_is_bounded_before_parsing_or_append():
    chain = valid_audit_chain()
    oversized = chain.to_dict()
    oversized["events"] = oversized["events"] * (MAX_AUDIT_EVENTS // len(chain.events) + 1)
    with pytest.raises(MalformedEvidenceError, match="cannot exceed"):
        AuditChain.from_dict(oversized)
    at_limit = AuditChain(chain.operation_commitment, (chain.events[0],) * MAX_AUDIT_EVENTS)
    with pytest.raises(ValueError, match="cannot exceed"):
        at_limit.append("EVIDENCE_CREATED")
