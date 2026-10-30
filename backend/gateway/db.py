"""PostgreSQL migration and out-of-band bootstrap. No global connections."""
import hashlib
import re
import uuid
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url

from .security import digest, hash_password

CATEGORIES = ("API_KEY", "ACCESS_TOKEN", "JWT", "EMAIL", "PHONE", "IP_ADDRESS", "INTERNAL_HOSTNAME")
DEFAULT_ACTIONS = {category: ("BLOCK" if category in CATEGORIES[:3] else "MASK") for category in CATEGORIES}
ADMIN_LOCK = 71800301
VERSION_LOCK = 71800302


def make_engine(settings) -> Engine:
    if not settings.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise ValueError("PostgreSQL is required.")
    url = make_url(settings.database_url).set(drivername="postgresql+psycopg")
    return create_engine(url, pool_pre_ping=True, hide_parameters=True)


def migrate(engine: Engine):
    """Apply checked-in SQL atomically using a separate schema-owning credential."""
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(71800300)"))
        connection.exec_driver_sql("CREATE TABLE IF NOT EXISTS gateway_migrations "
                                   "(version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz DEFAULT now())")
        directory = Path(__file__).parent / "migrations"
        if not directory.is_dir():
            directory = Path(__file__).parents[1] / "migrations"
        paths = sorted(directory.glob("[0-9]*.sql"))
        if not paths:
            raise RuntimeError("Packaged database migrations are missing.")
        for path in paths:
            source = path.read_text(encoding="utf-8")
            checksum = hashlib.sha256(source.encode()).hexdigest()
            installed = connection.execute(text("SELECT checksum FROM gateway_migrations WHERE version=:version"),
                                           {"version": path.name}).scalar_one_or_none()
            if installed is not None:
                if installed != checksum:
                    raise RuntimeError("Installed migration checksum mismatch.")
                continue
            # psycopg executes a migration as a script, including dollar-quoted functions.
            with connection.connection.driver_connection.cursor() as cursor:
                cursor.execute(source, prepare=False)
            connection.execute(text("INSERT INTO gateway_migrations(version, checksum) VALUES (:version,:checksum)"),
                               {"version": path.name, "checksum": checksum})


def bootstrap(engine, settings, username, password, integration_key, external_subject="demo-user"):
    if not re.fullmatch(r"[a-z0-9._@+-]{1,128}", username):
        raise ValueError("Username must use normalized lowercase account characters.")
    if len(integration_key) < 32 or not 1 <= len(external_subject) <= 255:
        raise ValueError("Integration key or external subject is invalid.")
    provider = {"base_url": "https://demo.invalid/v1" if settings.demo_mode else settings.provider_base_url,
                "provider_label": "Local simulator" if settings.demo_mode else settings.provider_label,
                "credential_ref": settings.provider_secret_ref,
                "models": ["demo-model"] if settings.demo_mode else [settings.provider_model]}
    from .provider import validate_provider_settings
    validate_provider_settings(settings, provider)
    encoded = hash_password(password)
    admin_id, user_id, integration_id, profile_id, policy_id = (uuid.uuid4() for _ in range(5))
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK})
        if connection.execute(text("SELECT EXISTS (SELECT 1 FROM users)")).scalar():
            raise ValueError("Installation is already bootstrapped; use reset-admin to replace a password.")
        connection.execute(text("INSERT INTO users(id,username,display_name,role) VALUES (:id,:username,:name,'admin')"),
                           {"id": admin_id, "username": username, "name": username})
        connection.execute(text("INSERT INTO admin_credentials(user_id,password_hash) VALUES (:id,:hash)"),
                           {"id": admin_id, "hash": encoded})
        connection.execute(text("INSERT INTO users(id,username,display_name,role) VALUES (:id,:username,'Demo user','user')"),
                           {"id": user_id, "username": "demo-user" if username != "demo-user" else "demo-chat-user"})
        connection.execute(text("INSERT INTO trusted_identity_settings(jwt_secret_ref) VALUES ('identity-default')"))
        connection.execute(text("INSERT INTO client_integrations(id,name,bearer_key_hash) VALUES (:id,'Open WebUI',:hash)"),
                           {"id": integration_id, "hash": digest(integration_key)})
        connection.execute(text("INSERT INTO external_identities(id,integration_id,user_id,external_subject) "
                                "VALUES (:id,:integration,:user,:subject)"),
                           {"id": uuid.uuid4(), "integration": integration_id, "user": user_id, "subject": external_subject})
        from .detection import profile_checksum
        checksum = profile_checksum()
        connection.execute(text("INSERT INTO detector_profile_versions(id,profile_name,version,bundle_checksum) "
                                "VALUES (:id,'baseline',1,:checksum)"), {"id": profile_id, "checksum": checksum})
        connection.execute(text("INSERT INTO policy_versions(id,version,detector_profile_id,created_by_user_id) "
                                "VALUES (:id,1,:profile,:admin)"),
                           {"id": policy_id, "profile": profile_id, "admin": admin_id})
        connection.execute(text("INSERT INTO policy_rules(policy_version_id,category,action) VALUES (:id,:category,:action)"),
                           [{"id": policy_id, "category": category, "action": action} for category, action in DEFAULT_ACTIONS.items()])
        connection.execute(text("UPDATE policy_versions SET status='published',published_at=now(),published_by_user_id=:admin "
                                "WHERE id=:id"), {"id": policy_id, "admin": admin_id})
        connection.execute(text("INSERT INTO active_policy(policy_version_id,updated_by_user_id) VALUES (:id,:admin)"),
                           {"id": policy_id, "admin": admin_id})
        connection.execute(text("INSERT INTO provider_config(base_url,provider_label,credential_ref,allowed_models,updated_by_user_id) "
                                "VALUES (:url,:label,:ref,:models,:admin)"),
                           {"url": provider["base_url"], "label": provider["provider_label"], "ref": provider["credential_ref"],
                            "models": provider["models"], "admin": admin_id})
        connection.execute(text("INSERT INTO pseudonym_settings(hmac_key_ref) VALUES ('pseudonym-default')"))
        connection.execute(text("INSERT INTO audit_retention_settings(updated_by_user_id) VALUES (:admin)"), {"admin": admin_id})
    return {"admin_id": str(admin_id), "user_id": str(user_id), "integration_id": str(integration_id), "policy_version_id": str(policy_id)}


def reset_admin(engine, username: str, password: str):
    encoded = hash_password(password)
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": ADMIN_LOCK})
        user_id = connection.execute(text("SELECT id FROM users WHERE username=:username AND role='admin' AND enabled FOR UPDATE"),
                                     {"username": username}).scalar_one_or_none()
        if user_id is None:
            raise ValueError("Enabled administrator not found.")
        connection.execute(text("INSERT INTO admin_credentials(user_id,password_hash) VALUES (:id,:hash) "
                                "ON CONFLICT(user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash,changed_at=now()"),
                           {"id": user_id, "hash": encoded})
        connection.execute(text("UPDATE admin_sessions SET revoked_at=now() WHERE user_id=:id AND revoked_at IS NULL"), {"id": user_id})


def upgrade_detector(engine, username="admin"):
    """Install S2 explicitly, preserving published S1/prototype policies and audit anchors."""
    from .detection.analyzer import previous_profile_checksums, profile_checksum

    checksum = profile_checksum()
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": VERSION_LOCK})
        admin = connection.execute(text("SELECT id FROM users WHERE username=:name AND enabled AND role='admin'"),
                                   {"name": username}).scalar_one_or_none()
        if admin is None:
            raise ValueError("Enabled administrator not found.")
        current = connection.execute(text(
            "SELECT a.policy_version_id,a.revision,p.detector_profile_id,d.profile_name,d.bundle_checksum "
            "FROM active_policy a JOIN policy_versions p ON p.id=a.policy_version_id "
            "JOIN detector_profile_versions d ON d.id=p.detector_profile_id WHERE a.singleton FOR UPDATE OF a"
        )).mappings().one_or_none()
        if current is None:
            raise ValueError("Installation is not bootstrapped.")
        if current["bundle_checksum"] == checksum:
            return {"status": "current", "policy_version_id": str(current["policy_version_id"]),
                    "revision": current["revision"]}
        if current["profile_name"] != "baseline" or current["bundle_checksum"] not in previous_profile_checksums().values():
            raise ValueError("Active detector bundle is not a reviewed previous baseline; review the upgrade manually.")
        profile_id = connection.execute(text(
            "SELECT id FROM detector_profile_versions WHERE profile_name='baseline' AND bundle_checksum=:checksum "
            "ORDER BY version DESC LIMIT 1"), {"checksum": checksum}).scalar_one_or_none()
        if profile_id is None:
            profile_id = uuid.uuid4()
            connection.execute(text(
                "INSERT INTO detector_profile_versions(id,profile_name,version,bundle_checksum) "
                "SELECT :id,'baseline',COALESCE(max(version),0)+1,:checksum "
                "FROM detector_profile_versions WHERE profile_name='baseline'"),
                {"id": profile_id, "checksum": checksum})
        policy_id = uuid.uuid4()
        params = {"id": policy_id, "old": current["policy_version_id"], "profile": profile_id, "admin": admin}
        connection.execute(text(
            "INSERT INTO policy_versions(id,version,based_on_id,detector_profile_id,created_by_user_id) "
            "SELECT :id,COALESCE(max(version),0)+1,:old,:profile,:admin FROM policy_versions"), params)
        connection.execute(text(
            "INSERT INTO policy_rules(policy_version_id,category,action) "
            "SELECT :id,category,action FROM policy_rules WHERE policy_version_id=:old"), params)
        connection.execute(text(
            "INSERT INTO policy_dictionaries(policy_version_id,dictionary_version_id) "
            "SELECT :id,dictionary_version_id FROM policy_dictionaries WHERE policy_version_id=:old"), params)
        connection.execute(text(
            "UPDATE policy_versions SET status='published',published_at=now(),published_by_user_id=:admin WHERE id=:id"),
            params)
        connection.execute(text(
            "UPDATE active_policy SET policy_version_id=:id,revision=revision+1,updated_at=now(),updated_by_user_id=:admin "
            "WHERE singleton"), params)
        return {"status": "upgraded", "policy_version_id": str(policy_id), "revision": current["revision"] + 1}
