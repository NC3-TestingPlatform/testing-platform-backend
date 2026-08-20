"""Live verification of the domain-verification check (US #263 / B6b).

Runs a real uvicorn against the migrated local PostgreSQL and drives the whole
flow over HTTP. This exists because the in-process `TestClient` cannot catch the
class of bug this story is most exposed to: a response that leaves before its
transaction commits, or a read issued in the window where the RLS context is
already dead. Both look fine in-process and fail in production.

Committed rather than left in a scratch directory so B11, which re-checks
verification before an intrusive launch, does not repeat the archaeology.

How a *successful* verification is exercised without owning a zone: the check
resolves `challenge.record_name` and compares `challenge.verification_token`
against the TXT RRset it finds. So the script reads a TXT record that genuinely
exists (`_dmarc.nc3.lu`), then points a real challenge row at that name with that
value as its token. Every code path above the DNS boundary is the production one.

Usage:  DATABASE_URL=postgresql+psycopg://... python scripts/live_verify_b6b.py

Exit codes: 0 every check passed, 1 a check failed, 2 the probe could not run.
"""

import json
import os
import socket
import subprocess
import sys
import time
import uuid
from typing import Any

import httpx
import sqlalchemy as sa
from uuid6 import uuid7

# At module level, unlike the other application imports here, because the entry
# point below has to name these exceptions in an `except` clause.
from nc3_testing_platform.core import dns_utils

RESOLVERS = json.dumps(
    [
        {
            "address": "158.64.1.29",
            "transport": "dot",
            "port": 853,
            "tls_hostname": "dnspub.restena.lu",
        }
    ]
)
PROBE_NAME = "_dmarc.nc3.lu"
ABSENT_NAME = "_nc3-verify-does-not-exist.nc3.lu"
OWNER_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://postgres:postgres@localhost:5432/nc3_testing_platform",
)

passed: list[str] = []
failed: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    """Record one assertion, printing it as it happens."""
    (passed if ok else failed).append(name)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{f' — {detail}' if detail else ''}")


def free_port() -> int:
    """A port the kernel says is free right now."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def totp_now(secret_b32: str) -> str:
    """A current TOTP code, using the application's own implementation."""
    import base64

    from nc3_testing_platform.domains.auth import totp

    secret = base64.b32decode(secret_b32, casefold=True)
    return totp.code_at(secret, totp.step_at(time.time()))


class Client:
    """Carries the session cookie by hand.

    The cookie is `__Host-` prefixed and therefore `Secure`, so httpx refuses to
    replay it over plain HTTP. Production is behind TLS; here the header is set
    manually rather than weakening the cookie for a test.
    """

    def __init__(self, base: str) -> None:
        self.base = base
        self.cookie: str | None = None

    def request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        """Issue one request, replaying the session cookie by hand."""
        headers = dict(kw.pop("headers", {}))
        if self.cookie:
            headers["Cookie"] = self.cookie
        response = httpx.request(
            method, f"{self.base}{path}", headers=headers, timeout=40.0, **kw
        )
        for raw in response.headers.get_list("set-cookie"):
            if raw.startswith("__Host-"):
                self.cookie = raw.split(";", 1)[0]
        return response

    def post(self, path: str, **kw: Any) -> httpx.Response:
        """POST with the session cookie attached."""
        return self.request("POST", path, **kw)


def read_probe_token() -> str:
    """The exact TXT value published at the probe name, read via the app's boundary."""
    from nc3_testing_platform.core.settings import DnsResolverConfig

    resolver = DnsResolverConfig(
        address="158.64.1.29",
        transport="dot",
        port=853,
        tls_hostname="dnspub.restena.lu",
    )
    outcomes = dns_utils.resolve_txt(PROBE_NAME, resolvers=[resolver], timeout=10.0)
    for outcome in outcomes:
        for strings in outcome.strings:
            return b"".join(strings).decode()
    raise RuntimeError(f"no TXT record at {PROBE_NAME}: {outcomes}")


def account_statements(base: str) -> list[dict[str, str]]:
    """Every active account-level statement, answered by key and exact version.

    Read from the API rather than hardcoded: registration is refused while any
    active statement is unanswered, so a seeded statement added later would
    silently break this script if the list were a literal.
    """
    listed = httpx.get(f"{base}/api/v1/statements", timeout=20.0)
    listed.raise_for_status()
    payload = listed.json()
    items = payload["items"] if isinstance(payload, dict) else payload
    return [
        {"statement_key": item["statement_key"], "version": item["version"]}
        for item in items
        if item.get("required_context_type") in (None, "")
    ]


def register(client: Client, tag: str) -> str:
    """Register, enrol MFA and step up. Returns the account's email."""
    # `.lu` rather than `.invalid`: the registration schema validates the address,
    # and a reserved TLD is refused.
    email = f"b6b-{tag}@example.lu"
    password = "Correct-Horse-Battery-9!"
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "statement_responses": account_statements(client.base),
        },
    )
    if response.status_code >= 400:
        raise RuntimeError(f"register failed: {response.status_code} {response.text}")
    # Registration provisions the account; it does not open a session. The cookie
    # arrives from login.
    logged_in = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    if logged_in.status_code >= 400:
        raise RuntimeError(f"login failed: {logged_in.status_code} {logged_in.text}")
    # Enrolment re-authenticates with the password, so a stolen cookie cannot plant
    # an attacker-controlled factor.
    enrol = client.post("/api/v1/auth/mfa/enroll", json={"password": password})
    secret = enrol.json().get("secret_base32") if enrol.status_code < 400 else None
    if not secret:
        raise RuntimeError(f"no secret_base32 in enrolment: {enrol.status_code} {enrol.text}")
    confirm = client.post(
        "/api/v1/auth/mfa/confirm", json={"totp_code": totp_now(secret)}
    )
    if confirm.status_code >= 400:
        raise RuntimeError(f"mfa confirm failed: {confirm.status_code} {confirm.text}")
    # No separate step-up: confirming enrolment stamps the calling session assured,
    # because possession was just proven. Calling /mfa/verify here would also be
    # refused by the replay guard, which spends a TOTP step once.
    return email


def seed_asset(engine: sa.Engine, email: str, value: str) -> uuid.UUID:
    """Insert a domain asset as the owner role; asset creation is still a mock."""
    asset_id = uuid7()
    with engine.begin() as conn:
        org_id = conn.execute(
            sa.text("SELECT organization_id FROM app_user WHERE email = :e"),
            {"e": email},
        ).scalar_one()
        conn.execute(
            sa.text(
                "INSERT INTO asset (id, organization_id, asset_type, value, origin,"
                " regression_alerts_enabled, created_at, updated_at) VALUES"
                " (:id, :org, 'domain', :value, 'added', false, now(), now())"
            ),
            {"id": asset_id, "org": org_id, "value": value},
        )
    return asset_id


def point_challenge(
    engine: sa.Engine, asset_id: uuid.UUID, name: str, token: str
) -> None:
    """Aim an existing challenge at a real record, as the owner role."""
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "UPDATE domain_verification_challenge"
                "   SET record_name = :name, verification_token = :token"
                " WHERE asset_id = :asset"
            ),
            {"name": name, "token": token, "asset": asset_id},
        )


def expire_challenge(engine: sa.Engine, asset_id: uuid.UUID) -> None:
    """Push the token's expiry into the past."""
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "UPDATE domain_verification_challenge"
                "   SET token_expires_at = now() - interval '1 day'"
                " WHERE asset_id = :asset"
            ),
            {"asset": asset_id},
        )


def start_server(port: int) -> subprocess.Popen[str]:
    """Boot uvicorn with a single verified resolver configured."""
    env = {
        **os.environ,
        "DATABASE_URL": OWNER_URL,
        "VERIFICATION_RESOLVERS": RESOLVERS,
        "VERIFICATION_RESOLVER_QUORUM": "1",
        # Registration wraps the organization KEK, so it refuses to run without a
        # master key. Synthetic and local-only: this script writes throwaway rows
        # to a dev database, and a real key must never appear in a repository.
        "APP_ENCRYPTION_MASTER_KEY": os.environ.get(
            "APP_ENCRYPTION_MASTER_KEY", "00" * 32
        ),
    }
    return subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "nc3_testing_platform.main:app",
            "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def await_ready(base: str, server: subprocess.Popen[str]) -> None:
    """Poll the liveness probe until the server answers."""
    for _ in range(60):
        try:
            if httpx.get(f"{base}/api/v1/healthz", timeout=2.0).status_code < 500:
                return
        except Exception:
            time.sleep(0.5)
    out = server.stdout.read() if server.stdout else ""
    raise RuntimeError(f"server never became ready:\n{out[-2000:]}")


def main() -> int:
    """Drive the flow and report."""
    token = read_probe_token()
    print(f"probe token from {PROBE_NAME}: {token[:32]}…")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    server = start_server(port)
    try:
        await_ready(base, server)
        # Anything below that raises prints the server's own log first: a bare 500
        # from the API says nothing, and the traceback is on the other side.
        engine = sa.create_engine(OWNER_URL)
        tag = uuid.uuid4().hex[:8]
        domain = f"nc3-b6b-{tag}.example.invalid"

        # --- organization A: the happy path -------------------------------
        a = Client(base)
        email_a = register(a, f"a-{tag}")
        asset_a = seed_asset(engine, email_a, domain)
        started = a.post(
            f"/api/v1/assets/{asset_a}/verification",
            json={"requested_scope": "exact"},
        )
        check("challenge created (201)", started.status_code == 201, started.text[:120])

        # Nothing published yet: the ordinary outcome, and a result rather than a fault.
        point_challenge(engine, asset_a, ABSENT_NAME, token)
        miss = a.post(f"/api/v1/assets/{asset_a}/verification/checks")
        miss_body = miss.json() if miss.status_code < 500 else {}
        miss_code = (miss_body.get("challenge") or {}).get("failure_code")
        check("unpublished record → 200", miss.status_code == 200, miss.text[:120])
        check(
            "unpublished record → a dns.* failure_code",
            bool(miss_code) and str(miss_code).startswith("dns."),
            str(miss_code),
        )

        # Published: it must verify and name the organization.
        point_challenge(engine, asset_a, PROBE_NAME, token)
        hit = a.post(f"/api/v1/assets/{asset_a}/verification/checks")
        hit_body = hit.json() if hit.status_code < 500 else {}
        check("published record → 200", hit.status_code == 200, hit.text[:160])
        check(
            "published record → status verified",
            hit_body.get("status") == "verified",
            json.dumps(hit_body)[:160],
        )
        check(
            "success clears the previous failure_code",
            (hit_body.get("challenge") or {}).get("failure_code") in (None, ""),
            str((hit_body.get("challenge") or {}).get("failure_code")),
        )
        check(
            "the token is never echoed without no-store",
            hit.headers.get("cache-control") == "no-store",
            str(hit.headers.get("cache-control")),
        )
        with engine.begin() as conn:
            row = conn.execute(
                sa.text(
                    "SELECT dv.value, dv.dnssec_validated, dv.corroborating_answers,"
                    " dv.resolvers, dv.verified_by_user_id IS NOT NULL AS attributed,"
                    " o.name AS org_name, o.named_at IS NOT NULL AS named"
                    " FROM domain_verification dv"
                    " JOIN organization o ON o.id = dv.organization_id"
                    " WHERE dv.asset_id = :a"
                ),
                {"a": asset_a},
            ).one()
        check("proof carries the asset's own value", row.value == domain, row.value)
        check(
            "provenance recorded",
            row.corroborating_answers >= 1 and bool(row.resolvers),
            f"{row.corroborating_answers} answer(s) from {row.resolvers}",
        )
        check("proof attributed to the verifying user", bool(row.attributed))
        check(
            "first verification named the organization",
            bool(row.named) and row.org_name == domain,
            str(row.org_name),
        )

        # --- organization B: the claim is already taken -------------------
        b = Client(base)
        email_b = register(b, f"b-{tag}")
        asset_b = seed_asset(engine, email_b, domain)
        b.post(
            f"/api/v1/assets/{asset_b}/verification", json={"requested_scope": "exact"}
        )
        point_challenge(engine, asset_b, PROBE_NAME, token)
        lost = b.post(f"/api/v1/assets/{asset_b}/verification/checks")
        lost_body = lost.json() if lost.status_code < 500 else {}
        check("second organization refused (409)", lost.status_code == 409, lost.text[:160])
        check(
            "refusal carries the domain-claim-lost problem type",
            "domain-claim-lost" in str(lost_body.get("type")),
            str(lost_body.get("type")),
        )
        check(
            "refusal does not name the other organization",
            "organization" not in str(lost_body.get("detail", "")).lower()
            or domain not in str(lost_body.get("detail", "")),
            str(lost_body.get("detail"))[:100],
        )
        with engine.begin() as conn:
            stamped = conn.execute(
                sa.text(
                    "SELECT failure_code, last_recheck_at IS NOT NULL AS checked"
                    " FROM domain_verification_challenge WHERE asset_id = :a"
                ),
                {"a": asset_b},
            ).one()
            leaked = conn.execute(
                sa.text("SELECT count(*) FROM domain_verification WHERE asset_id = :a"),
                {"a": asset_b},
            ).scalar_one()
        check(
            "the refusal was stamped on the challenge",
            stamped.failure_code == "claim.lost" and bool(stamped.checked),
            str(stamped.failure_code),
        )
        check("no proof row written for the loser", leaked == 0, str(leaked))

        # --- an expired token refuses -------------------------------------
        expire_challenge(engine, asset_b)
        expired = b.post(f"/api/v1/assets/{asset_b}/verification/checks")
        check("expired token → 409", expired.status_code == 409, expired.text[:120])

        # --- the role gate --------------------------------------------------
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "UPDATE app_user SET organization_role = 'member' WHERE email = :e"
                ),
                {"e": email_b},
            )
        demoted = b.post(f"/api/v1/assets/{asset_b}/verification/checks")
        check("non-admin refused (403)", demoted.status_code == 403, demoted.text[:120])
    except Exception:
        if server.stdout is not None:
            server.terminate()
            try:
                server.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                server.kill()
            print("\n--- server log (tail) ---")
            print((server.stdout.read() or "")[-3000:])
        raise
    finally:
        server.terminate()
        try:
            server.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            server.kill()

    total = len(passed) + len(failed)
    print(f"\n{len(passed)}/{total} checks passed")
    if failed:
        print("failed: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    # A DNS, HTTP, readiness or API-setup failure is the platform failing to run
    # the probe, not the probe finding a defect, and the two must not share an
    # exit code: 1 means checks failed, 2 means the run never happened. The DNS
    # boundary's refusals are named explicitly because they descend from
    # `Exception`, not from `RuntimeError`.
    try:
        raise SystemExit(main())
    except (
        httpx.HTTPError,
        RuntimeError,
        dns_utils.DnsNotConfiguredError,
        dns_utils.DnsCapacityError,
    ) as exc:
        # The class only. A `RuntimeError` raised here carries `response.text` or
        # the captured server log, and this output lands in a shared terminal and
        # in CI: the queried domain is personal data and must not leak there. The
        # detail is already in the server log the failure path prints.
        print(
            f"live verification could not run: {type(exc).__name__}", file=sys.stderr
        )
        raise SystemExit(2) from exc
