"""Only allowlisted metadata crosses the persistence boundary."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import text

from gateway.detection import profile_checksum
from gateway.protocol import GatewayError


def snapshot(engine, policy_id=None):
    with engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn:  # noqa: SIM117 - keep snapshot transaction boundary explicit
        with conn.begin():
            provider = conn.execute(text("SELECT * FROM provider_config WHERE singleton")).mappings().first()
            if policy_id is None:
                policy = (
                    conn.execute(
                        text(
                            "SELECT p.* FROM active_policy a JOIN policy_versions p ON p.id=a.policy_version_id WHERE a.singleton"
                        )
                    )
                    .mappings()
                    .first()
                )
            else:
                policy = (
                    conn.execute(text("SELECT * FROM policy_versions WHERE id=:id"), {"id": policy_id})
                    .mappings()
                    .first()
                )
            if provider is None or policy is None:
                raise GatewayError(503, "configuration_not_ready")
            deployed_checksum = conn.execute(
                text("SELECT bundle_checksum FROM detector_profile_versions WHERE id=:id"),
                {"id": policy["detector_profile_id"]},
            ).scalar_one()
            if deployed_checksum != profile_checksum():
                raise GatewayError(503, "detector_profile_mismatch")
            rules = dict(
                conn.execute(
                    text("SELECT category,action FROM policy_rules WHERE policy_version_id=:id"),
                    {"id": policy["id"]},
                ).all()
            )
            if len(rules) != 7:
                raise GatewayError(503, "configuration_not_ready")
            entries = (
                conn.execute(
                    text("""SELECT e.category,e.entry_value FROM dictionary_entries e
                JOIN policy_dictionaries p ON p.dictionary_version_id=e.dictionary_version_id
                WHERE p.policy_version_id=:id ORDER BY e.id"""),
                    {"id": policy["id"]},
                )
                .mappings()
                .all()
            )
            return {
                "policy": dict(policy),
                "provider": dict(provider),
                "actions": rules,
                "dictionaries": [dict(e) for e in entries],
            }


def record(
    engine,
    identity,
    snap,
    request_id,
    body,
    size,
    state,
    decision=None,
    counts=None,
    code=None,
    duration_ms=None,
):
    event_id = uuid4()
    provider = snap["provider"]
    deadline = (
        datetime.now(UTC) + timedelta(seconds=provider["total_timeout_seconds"] + 60)
        if state == "forwarding_intent"
        else None
    )
    with engine.begin() as conn:
        conn.execute(
            text("""INSERT INTO audit_events
            (id,request_id,external_identity_id,integration_id,user_id,policy_version_id,
             provider_config_revision,provider_label,state,decision,model,stream,request_bytes,
             message_count,duration_ms,safe_error_code,outcome_deadline_at)
            VALUES (:id,:request_id,:external_identity_id,:integration_id,:user_id,:policy_version_id,
             :revision,:label,:state,:decision,:model,:stream,:size,:count,:duration,:code,:deadline)"""),
            {
                "id": event_id,
                "request_id": request_id,
                "external_identity_id": identity["external_identity_id"],
                "integration_id": identity["integration_id"],
                "user_id": identity["user_id"],
                "policy_version_id": snap["policy"]["id"],
                "revision": provider["revision"],
                "label": provider["provider_label"],
                "state": state,
                "decision": decision,
                "model": body["model"],
                "stream": body.get("stream", False),
                "size": size,
                "count": len(body["messages"]),
                "duration": duration_ms,
                "code": code,
                "deadline": deadline,
            },
        )
        conn.execute(
            text(
                "INSERT INTO audit_event_states (audit_event_id,sequence,state,safe_error_code) VALUES (:id,1,:state,:code)"
            ),
            {"id": event_id, "state": state, "code": code},
        )
        for category, count in (counts or {}).items():
            conn.execute(
                text(
                    "INSERT INTO audit_findings (audit_event_id,category,action,finding_count) VALUES (:id,:category,:action,:count)"
                ),
                {"id": event_id, "category": category, "action": snap["actions"][category], "count": count},
            )
    return event_id


def finalize(
    engine, event_id, state, *, chunks=0, code=None, duration_ms=None, status=None, first_byte_ms=None
):
    with engine.begin() as conn:
        changed = conn.execute(
            text("""UPDATE audit_events SET state=:state,output_chunks_forwarded=:chunks,
             safe_error_code=:code,duration_ms=:duration,provider_http_status=:status,first_byte_ms=:first
             WHERE id=:id AND state='forwarding_intent' RETURNING id"""),
            {
                "id": event_id,
                "state": state,
                "chunks": chunks,
                "code": code,
                "duration": duration_ms,
                "status": status,
                "first": first_byte_ms,
            },
        ).first()
        if changed is None:
            raise GatewayError(503, "audit_finalization_failed")
        conn.execute(
            text(
                "INSERT INTO audit_event_states (audit_event_id,sequence,state,safe_error_code) VALUES (:id,2,:state,:code)"
            ),
            {"id": event_id, "state": state, "code": code},
        )


def maintenance(engine):
    with engine.begin() as conn:
        stale = conn.execute(
            text("""UPDATE audit_events SET state='unknown',safe_error_code='unknown_outcome'
            WHERE state='forwarding_intent' AND outcome_deadline_at < now() RETURNING id""")
        ).all()
        for (event_id,) in stale:
            conn.execute(
                text(
                    "INSERT INTO audit_event_states (audit_event_id,sequence,state,safe_error_code) VALUES (:id,2,'unknown','unknown_outcome')"
                ),
                {"id": event_id},
            )
        conn.execute(
            text("""DELETE FROM audit_events WHERE state<>'forwarding_intent' AND occurred_at <
            now() - ((SELECT retention_days FROM audit_retention_settings WHERE singleton) * interval '1 day')""")
        )
        conn.execute(
            text("""DELETE FROM external_identities e WHERE revoked_at IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM audit_events a WHERE a.external_identity_id=e.id)""")
        )
