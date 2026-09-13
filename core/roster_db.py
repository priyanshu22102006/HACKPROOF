"""Registration and Roster Database for HACKPROOF.

Replaces single-file hardcoded JSON rosters with a relational SQLite storage layer
supporting multiple teams, members, cryptographic signing keys (OpenPGP & SSH),
and hardware device fingerprints.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
import re
import sqlite3
import sys
from typing import Any

# Private key markers to guarantee private keys are never stored
PRIVATE_KEY_MARKERS = (
    "PRIVATE KEY BLOCK",
    "OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
)


class RosterDBError(Exception):
    """Base exception for roster database errors."""
    pass


@dataclass
class Team:
    team_id: str
    name: str
    project_name: str | None = None
    repo_url: str | None = None
    baseline_commit: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Member:
    member_id: str
    team_id: str
    display_name: str
    email: str
    github_login: str | None = None
    declared_non_coding_role: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Key:
    key_id: str
    member_id: str
    key_type: str  # 'openpgp' | 'ssh'
    fingerprint: str
    public_key: str
    status: str = "active"  # 'active' | 'revoked' | 'expired'
    registered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str | None = None
    revoked_at: str | None = None


@dataclass
class Device:
    device_id: str
    member_id: str
    device_fingerprint: str  # sha256 hardware hash
    hostname: str | None = None
    platform: str | None = None  # 'Darwin', 'Linux', 'Windows', etc.
    registered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen_at: str | None = None


@dataclass
class GitHubEvent:
    id: int | None
    delivery_guid: str
    event_type: str
    repo_name: str
    before_sha: str | None
    after_sha: str | None
    forced: bool
    github_created_at: str | None
    server_received_at: str
    drift_seconds: float | None
    payload: dict


def normalize_fingerprint(value: str | None) -> str:
    """Normalize GPG hex fingerprint or OpenSSH SHA256 fingerprint."""
    if not value:
        return ""
    raw = str(value).strip()
    if raw.startswith("SHA256:"):
        return raw
    cleaned = re.sub(r"[\s:]", "", raw).upper()
    if cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    return cleaned if re.fullmatch(r"[0-9A-F]{8,40}", cleaned) else raw


def assert_public_only(blob: str, label: str = "key material") -> None:
    """Refuse to accept private key blocks."""
    upper = (blob or "").upper()
    for marker in PRIVATE_KEY_MARKERS:
        if marker in upper:
            raise RosterDBError(
                f"Refusing registration: {label} contains private key material ({marker}). "
                "Only public keys may be registered with HACKPROOF."
            )


class RosterDatabase:
    """SQLite database manager for multi-team registration and rosters."""

    SCHEMA = """
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS teams (
        team_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        project_name TEXT,
        repo_url TEXT,
        baseline_commit TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS members (
        member_id TEXT PRIMARY KEY,
        team_id TEXT NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
        display_name TEXT NOT NULL,
        email TEXT NOT NULL,
        github_login TEXT,
        declared_non_coding_role TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS keys (
        key_id TEXT PRIMARY KEY,
        member_id TEXT NOT NULL REFERENCES members(member_id) ON DELETE CASCADE,
        key_type TEXT NOT NULL,
        fingerprint TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        registered_at TEXT NOT NULL,
        expires_at TEXT,
        revoked_at TEXT
    );

    CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        member_id TEXT NOT NULL REFERENCES members(member_id) ON DELETE CASCADE,
        device_fingerprint TEXT NOT NULL,
        hostname TEXT,
        platform TEXT,
        registered_at TEXT NOT NULL,
        last_seen_at TEXT
    );

    CREATE TABLE IF NOT EXISTS github_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        delivery_guid TEXT UNIQUE,
        event_type TEXT NOT NULL,
        repo_name TEXT NOT NULL,
        before_sha TEXT,
        after_sha TEXT,
        forced INTEGER DEFAULT 0,
        github_created_at TEXT,
        server_received_at TEXT NOT NULL,
        drift_seconds REAL,
        payload_json TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_members_team ON members(team_id);
    CREATE INDEX IF NOT EXISTS idx_members_email ON members(email);
    CREATE INDEX IF NOT EXISTS idx_keys_fingerprint ON keys(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_devices_member ON devices(member_id);
    CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(device_fingerprint);
    CREATE INDEX IF NOT EXISTS idx_events_repo ON github_events(repo_name);
    CREATE INDEX IF NOT EXISTS idx_events_type ON github_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_guid ON github_events(delivery_guid);
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.init_schema()

    def get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON;")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def init_schema(self) -> None:
        conn = self.get_connection()
        conn.executescript(self.SCHEMA)
        conn.commit()

    # --- Teams -----------------------------------------------------------------

    def add_team(
        self,
        team_id: str,
        name: str,
        project_name: str | None = None,
        repo_url: str | None = None,
        baseline_commit: str | None = None,
        created_at: str | None = None,
    ) -> Team:
        team_id = team_id.strip()
        name = name.strip()
        if not team_id:
            raise RosterDBError("team_id cannot be empty")
        if not name:
            raise RosterDBError("team name cannot be empty")

        created = created_at or datetime.now(timezone.utc).isoformat()
        conn = self.get_connection()
        try:
            conn.execute(
                """
                INSERT INTO teams (team_id, name, project_name, repo_url, baseline_commit, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (team_id, name, project_name, repo_url, baseline_commit, created),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise RosterDBError(f"Team '{team_id}' already exists") from exc

        return Team(
            team_id=team_id,
            name=name,
            project_name=project_name,
            repo_url=repo_url,
            baseline_commit=baseline_commit,
            created_at=created,
        )

    def get_team(self, team_id: str) -> Team | None:
        conn = self.get_connection()
        cur = conn.execute("SELECT * FROM teams WHERE team_id = ?", (team_id.strip(),))
        row = cur.fetchone()
        if not row:
            return None
        return Team(
            team_id=row["team_id"],
            name=row["name"],
            project_name=row["project_name"],
            repo_url=row["repo_url"],
            baseline_commit=row["baseline_commit"],
            created_at=row["created_at"],
        )

    def list_teams(self) -> list[Team]:
        conn = self.get_connection()
        cur = conn.execute("SELECT * FROM teams ORDER BY team_id ASC")
        return [
            Team(
                team_id=row["team_id"],
                name=row["name"],
                project_name=row["project_name"],
                repo_url=row["repo_url"],
                baseline_commit=row["baseline_commit"],
                created_at=row["created_at"],
            )
            for row in cur.fetchall()
        ]

    def delete_team(self, team_id: str) -> bool:
        conn = self.get_connection()
        cur = conn.execute("DELETE FROM teams WHERE team_id = ?", (team_id.strip(),))
        conn.commit()
        return cur.rowcount > 0

    # --- Members ---------------------------------------------------------------

    def add_member(
        self,
        member_id: str,
        team_id: str,
        display_name: str,
        email: str,
        github_login: str | None = None,
        declared_non_coding_role: str | None = None,
        created_at: str | None = None,
    ) -> Member:
        member_id = member_id.strip()
        team_id = team_id.strip()
        display_name = display_name.strip()
        email = email.strip().lower()

        if not member_id:
            raise RosterDBError("member_id cannot be empty")
        if not display_name:
            raise RosterDBError("display_name cannot be empty")
        if not email:
            raise RosterDBError("email cannot be empty")

        if not self.get_team(team_id):
            raise RosterDBError(f"Team '{team_id}' does not exist")

        created = created_at or datetime.now(timezone.utc).isoformat()
        clean_github = github_login.strip().lstrip("@") if github_login else None

        conn = self.get_connection()
        try:
            conn.execute(
                """
                INSERT INTO members (member_id, team_id, display_name, email, github_login, declared_non_coding_role, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (member_id, team_id, display_name, email, clean_github, declared_non_coding_role, created),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise RosterDBError(f"Member '{member_id}' already exists") from exc

        return Member(
            member_id=member_id,
            team_id=team_id,
            display_name=display_name,
            email=email,
            github_login=clean_github,
            declared_non_coding_role=declared_non_coding_role,
            created_at=created,
        )

    def get_member(self, member_id: str) -> Member | None:
        conn = self.get_connection()
        cur = conn.execute("SELECT * FROM members WHERE member_id = ?", (member_id.strip(),))
        row = cur.fetchone()
        if not row:
            return None
        return Member(
            member_id=row["member_id"],
            team_id=row["team_id"],
            display_name=row["display_name"],
            email=row["email"],
            github_login=row["github_login"],
            declared_non_coding_role=row["declared_non_coding_role"],
            created_at=row["created_at"],
        )

    def get_members(self, team_id: str) -> list[Member]:
        conn = self.get_connection()
        cur = conn.execute("SELECT * FROM members WHERE team_id = ? ORDER BY member_id ASC", (team_id.strip(),))
        return [
            Member(
                member_id=row["member_id"],
                team_id=row["team_id"],
                display_name=row["display_name"],
                email=row["email"],
                github_login=row["github_login"],
                declared_non_coding_role=row["declared_non_coding_role"],
                created_at=row["created_at"],
            )
            for row in cur.fetchall()
        ]

    # --- Keys ------------------------------------------------------------------

    def add_key(
        self,
        key_id: str,
        member_id: str,
        key_type: str,
        fingerprint: str,
        public_key: str,
        status: str = "active",
        registered_at: str | None = None,
        expires_at: str | None = None,
        revoked_at: str | None = None,
    ) -> Key:
        key_id = key_id.strip()
        member_id = member_id.strip()
        norm_fp = normalize_fingerprint(fingerprint)

        if not key_id:
            raise RosterDBError("key_id cannot be empty")
        if not norm_fp:
            raise RosterDBError("fingerprint cannot be empty or invalid")
        if not public_key:
            raise RosterDBError("public_key cannot be empty")

        assert_public_only(public_key, f"Key '{key_id}'")

        if not self.get_member(member_id):
            raise RosterDBError(f"Member '{member_id}' does not exist")

        # Global uniqueness check across all teams & members
        existing_owner = self.resolve_key_owner(norm_fp)
        if existing_owner and existing_owner[0].member_id != member_id:
            other_member, other_team = existing_owner
            raise RosterDBError(
                f"Fingerprint {norm_fp} is already registered to member '{other_member.member_id}' "
                f"in team '{other_team.team_id}'. Two participants cannot share one key."
            )

        registered = registered_at or datetime.now(timezone.utc).isoformat()
        conn = self.get_connection()
        try:
            conn.execute(
                """
                INSERT INTO keys (key_id, member_id, key_type, fingerprint, public_key, status, registered_at, expires_at, revoked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (key_id, member_id, key_type.lower(), norm_fp, public_key.strip(), status, registered, expires_at, revoked_at),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise RosterDBError(f"Key with ID '{key_id}' or fingerprint '{norm_fp}' already exists") from exc

        return Key(
            key_id=key_id,
            member_id=member_id,
            key_type=key_type.lower(),
            fingerprint=norm_fp,
            public_key=public_key.strip(),
            status=status,
            registered_at=registered,
            expires_at=expires_at,
            revoked_at=revoked_at,
        )

    def get_keys(self, member_id: str) -> list[Key]:
        conn = self.get_connection()
        cur = conn.execute("SELECT * FROM keys WHERE member_id = ? ORDER BY key_id ASC", (member_id.strip(),))
        return [
            Key(
                key_id=row["key_id"],
                member_id=row["member_id"],
                key_type=row["key_type"],
                fingerprint=row["fingerprint"],
                public_key=row["public_key"],
                status=row["status"],
                registered_at=row["registered_at"],
                expires_at=row["expires_at"],
                revoked_at=row["revoked_at"],
            )
            for row in cur.fetchall()
        ]

    def resolve_key_owner(self, fingerprint: str) -> tuple[Member, Team] | None:
        """Find the member and team that registered a given key fingerprint."""
        norm_fp = normalize_fingerprint(fingerprint)
        if not norm_fp:
            return None
        conn = self.get_connection()
        cur = conn.execute(
            """
            SELECT m.*, t.team_id as t_id, t.name as t_name, t.project_name, t.repo_url, t.baseline_commit, t.created_at as t_created
            FROM keys k
            JOIN members m ON k.member_id = m.member_id
            JOIN teams t ON m.team_id = t.team_id
            WHERE k.fingerprint = ?
            """,
            (norm_fp,),
        )
        row = cur.fetchone()
        if not row:
            return None
        member = Member(
            member_id=row["member_id"],
            team_id=row["team_id"],
            display_name=row["display_name"],
            email=row["email"],
            github_login=row["github_login"],
            declared_non_coding_role=row["declared_non_coding_role"],
            created_at=row["created_at"],
        )
        team = Team(
            team_id=row["t_id"],
            name=row["t_name"],
            project_name=row["project_name"],
            repo_url=row["repo_url"],
            baseline_commit=row["baseline_commit"],
            created_at=row["t_created"],
        )
        return member, team

    # --- Devices ---------------------------------------------------------------

    def add_device(
        self,
        device_id: str,
        member_id: str,
        device_fingerprint: str,
        hostname: str | None = None,
        platform: str | None = None,
        registered_at: str | None = None,
        last_seen_at: str | None = None,
    ) -> Device:
        device_id = device_id.strip()
        member_id = member_id.strip()
        dfp = device_fingerprint.strip()

        if not device_id:
            raise RosterDBError("device_id cannot be empty")
        if not dfp:
            raise RosterDBError("device_fingerprint cannot be empty")

        if not self.get_member(member_id):
            raise RosterDBError(f"Member '{member_id}' does not exist")

        registered = registered_at or datetime.now(timezone.utc).isoformat()
        conn = self.get_connection()
        try:
            conn.execute(
                """
                INSERT INTO devices (device_id, member_id, device_fingerprint, hostname, platform, registered_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (device_id, member_id, dfp, hostname, platform, registered, last_seen_at),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise RosterDBError(f"Device '{device_id}' already exists") from exc

        return Device(
            device_id=device_id,
            member_id=member_id,
            device_fingerprint=dfp,
            hostname=hostname,
            platform=platform,
            registered_at=registered,
            last_seen_at=last_seen_at,
        )

    def get_devices(self, member_id: str) -> list[Device]:
        conn = self.get_connection()
        cur = conn.execute("SELECT * FROM devices WHERE member_id = ? ORDER BY device_id ASC", (member_id.strip(),))
        return [
            Device(
                device_id=row["device_id"],
                member_id=row["member_id"],
                device_fingerprint=row["device_fingerprint"],
                hostname=row["hostname"],
                platform=row["platform"],
                registered_at=row["registered_at"],
                last_seen_at=row["last_seen_at"],
            )
            for row in cur.fetchall()
        ]

    def resolve_device_owner(self, device_fingerprint: str) -> list[tuple[Member, Team]]:
        """Find the member(s) and team(s) that registered a device fingerprint."""
        dfp = device_fingerprint.strip()
        if not dfp:
            return []
        conn = self.get_connection()
        cur = conn.execute(
            """
            SELECT m.*, t.team_id as t_id, t.name as t_name, t.project_name, t.repo_url, t.baseline_commit, t.created_at as t_created
            FROM devices d
            JOIN members m ON d.member_id = m.member_id
            JOIN teams t ON m.team_id = t.team_id
            WHERE d.device_fingerprint = ?
            """,
            (dfp,),
        )
        results = []
        for row in cur.fetchall():
            member = Member(
                member_id=row["member_id"],
                team_id=row["team_id"],
                display_name=row["display_name"],
                email=row["email"],
                github_login=row["github_login"],
                declared_non_coding_role=row["declared_non_coding_role"],
                created_at=row["created_at"],
            )
            team = Team(
                team_id=row["t_id"],
                name=row["t_name"],
                project_name=row["project_name"],
                repo_url=row["repo_url"],
                baseline_commit=row["baseline_commit"],
                created_at=row["t_created"],
            )
            results.append((member, team))
        return results

    # --- GitHub Events (Server Plane) ------------------------------------------

    def record_github_event(
        self,
        delivery_guid: str,
        event_type: str,
        repo_name: str,
        payload: dict,
        before_sha: str | None = None,
        after_sha: str | None = None,
        forced: bool = False,
        github_created_at: str | None = None,
        server_received_at: str | None = None,
    ) -> GitHubEvent:
        delivery_guid = delivery_guid.strip()
        event_type = event_type.strip().lower()
        repo_name = repo_name.strip()
        received_at = server_received_at or datetime.now(timezone.utc).isoformat()

        drift_seconds = None
        if github_created_at:
            try:
                g_dt = datetime.fromisoformat(github_created_at.replace("Z", "+00:00"))
                s_dt = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
                drift_seconds = round((s_dt - g_dt).total_seconds(), 3)
            except Exception:
                pass

        payload_json = json.dumps(payload, default=str)
        conn = self.get_connection()
        try:
            cur = conn.execute(
                """
                INSERT INTO github_events (
                    delivery_guid, event_type, repo_name, before_sha, after_sha, forced,
                    github_created_at, server_received_at, drift_seconds, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(delivery_guid) DO UPDATE SET
                    server_received_at = excluded.server_received_at,
                    drift_seconds = excluded.drift_seconds,
                    payload_json = excluded.payload_json
                """,
                (
                    delivery_guid,
                    event_type,
                    repo_name,
                    before_sha,
                    after_sha,
                    1 if forced else 0,
                    github_created_at,
                    received_at,
                    drift_seconds,
                    payload_json,
                ),
            )
            conn.commit()
            event_id = cur.lastrowid
        except Exception as exc:
            raise RosterDBError(f"Failed to record github event: {exc}") from exc

        return GitHubEvent(
            id=event_id,
            delivery_guid=delivery_guid,
            event_type=event_type,
            repo_name=repo_name,
            before_sha=before_sha,
            after_sha=after_sha,
            forced=forced,
            github_created_at=github_created_at,
            server_received_at=received_at,
            drift_seconds=drift_seconds,
            payload=payload,
        )

    def get_github_events(
        self,
        repo_name: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[GitHubEvent]:
        conn = self.get_connection()
        query = "SELECT * FROM github_events WHERE 1=1"
        params: list[Any] = []
        if repo_name:
            query += " AND repo_name = ?"
            params.append(repo_name.strip())
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.strip().lower())
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cur = conn.execute(query, params)
        events = []
        for row in cur.fetchall():
            try:
                payload = json.loads(row["payload_json"])
            except Exception:
                payload = {}
            events.append(
                GitHubEvent(
                    id=row["id"],
                    delivery_guid=row["delivery_guid"],
                    event_type=row["event_type"],
                    repo_name=row["repo_name"],
                    before_sha=row["before_sha"],
                    after_sha=row["after_sha"],
                    forced=bool(row["forced"]),
                    github_created_at=row["github_created_at"],
                    server_received_at=row["server_received_at"],
                    drift_seconds=row["drift_seconds"],
                    payload=payload,
                )
            )
        return events

    def detect_force_pushes(self, repo_name: str) -> list[GitHubEvent]:
        conn = self.get_connection()
        cur = conn.execute(
            """
            SELECT * FROM github_events
            WHERE repo_name = ? AND forced = 1
            ORDER BY id DESC
            """,
            (repo_name.strip(),),
        )
        events = []
        for row in cur.fetchall():
            try:
                payload = json.loads(row["payload_json"])
            except Exception:
                payload = {}
            events.append(
                GitHubEvent(
                    id=row["id"],
                    delivery_guid=row["delivery_guid"],
                    event_type=row["event_type"],
                    repo_name=row["repo_name"],
                    before_sha=row["before_sha"],
                    after_sha=row["after_sha"],
                    forced=True,
                    github_created_at=row["github_created_at"],
                    server_received_at=row["server_received_at"],
                    drift_seconds=row["drift_seconds"],
                    payload=payload,
                )
            )
        return events

    # --- Import / Export -------------------------------------------------------

    def export_team_roster(self, team_id: str) -> dict:
        """Export a team's records into standard HACKPROOF roster.json format."""
        team = self.get_team(team_id)
        if not team:
            raise RosterDBError(f"Team '{team_id}' not found")

        members_list = []
        for m in self.get_members(team_id):
            keys = self.get_keys(m.member_id)
            devices = self.get_devices(m.member_id)

            m_dict: dict[str, Any] = {
                "member_id": m.member_id,
                "name": m.display_name,
                "display_name": m.display_name,
                "email": m.email,
                "emails": [m.email],
                "keys": [
                    {
                        "key_id": k.key_id,
                        "type": k.key_type,
                        "key_type": k.key_type,
                        "fingerprint": k.fingerprint,
                        "public_key": k.public_key,
                        "status": k.status,
                        "registered_at": k.registered_at,
                        "expires_at": k.expires_at,
                        "revoked_at": k.revoked_at,
                    }
                    for k in keys
                ],
                "devices": [
                    {
                        "device_id": d.device_id,
                        "device_fingerprint": d.device_fingerprint,
                        "hostname": d.hostname,
                        "platform": d.platform,
                    }
                    for d in devices
                ],
            }
            if m.github_login:
                m_dict["github_login"] = m.github_login
            if m.declared_non_coding_role:
                m_dict["declared_non_coding_role"] = m.declared_non_coding_role
            members_list.append(m_dict)

        return {
            "team_id": team.team_id,
            "team_name": team.name,
            "project_name": team.project_name,
            "repo_url": team.repo_url,
            "baseline_commit": team.baseline_commit,
            "members": members_list,
        }

    def import_team_roster(self, roster_data: dict | str) -> Team:
        """Import a legacy or exported roster dict (or file path) into the database."""
        if isinstance(roster_data, str):
            with open(roster_data, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = roster_data

        if not isinstance(data, dict):
            raise RosterDBError("Roster data must be a dictionary")

        team_id = str(data.get("team_id") or "team-default").strip()
        team_name = str(data.get("team_name") or data.get("name") or team_id).strip()
        project_name = data.get("project_name")
        repo_url = data.get("repo_url")
        baseline_commit = data.get("baseline_commit")

        existing_team = self.get_team(team_id)
        if not existing_team:
            team = self.add_team(
                team_id=team_id,
                name=team_name,
                project_name=project_name,
                repo_url=repo_url,
                baseline_commit=baseline_commit,
            )
        else:
            team = existing_team

        raw_members = data.get("members", [])
        for idx, m_raw in enumerate(raw_members):
            member_id = str(m_raw.get("member_id") or m_raw.get("id") or f"{team_id}-m{idx+1}").strip()
            display_name = str(m_raw.get("display_name") or m_raw.get("name") or member_id).strip()
            
            emails = m_raw.get("emails") or ([m_raw["email"]] if m_raw.get("email") else [])
            primary_email = emails[0].strip().lower() if emails else f"{member_id}@{team_id}.test"

            github_login = m_raw.get("github_login")
            role = m_raw.get("declared_non_coding_role")

            member = self.get_member(member_id)
            if not member:
                member = self.add_member(
                    member_id=member_id,
                    team_id=team_id,
                    display_name=display_name,
                    email=primary_email,
                    github_login=github_login,
                    declared_non_coding_role=role,
                )

            keys = m_raw.get("keys", [])
            if isinstance(keys, dict):
                keys = [keys]
            for kidx, k_raw in enumerate(keys):
                k_id = str(k_raw.get("key_id") or f"{member_id}-k{kidx+1}")
                k_type = str(k_raw.get("key_type") or k_raw.get("type") or "openpgp")
                fp = str(k_raw.get("fingerprint") or "")
                pub = str(k_raw.get("public_key") or "")
                status = str(k_raw.get("status") or "active")

                if fp and pub:
                    norm_fp = normalize_fingerprint(fp)
                    existing = self.resolve_key_owner(norm_fp)
                    if not existing:
                        self.add_key(
                            key_id=k_id,
                            member_id=member_id,
                            key_type=k_type,
                            fingerprint=norm_fp,
                            public_key=pub,
                            status=status,
                        )

            devices = m_raw.get("devices", [])
            for didx, d_raw in enumerate(devices):
                d_id = str(d_raw.get("device_id") or f"{member_id}-d{didx+1}")
                dfp = str(d_raw.get("device_fingerprint") or "")
                hostname = d_raw.get("hostname")
                plat = d_raw.get("platform")
                if dfp:
                    try:
                        self.add_device(
                            device_id=d_id,
                            member_id=member_id,
                            device_fingerprint=dfp,
                            hostname=hostname,
                            platform=plat,
                        )
                    except RosterDBError:
                        pass

        return team

    def export_all(self, out_dir: str) -> list[str]:
        """Export all registered teams into individual JSON roster files in out_dir."""
        os.makedirs(out_dir, exist_ok=True)
        paths = []
        for team in self.list_teams():
            data = self.export_team_roster(team.team_id)
            path = os.path.join(out_dir, f"{team.team_id}.roster.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            paths.append(path)
        return paths


# --- CLI ----------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hackproof-roster",
        description="HACKPROOF multi-team roster database management tool.",
    )
    parser.add_argument(
        "--db",
        default="hackproof.db",
        help="path to SQLite database file (default: hackproof.db)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    subparsers.add_parser("init", help="Initialize schema in the database")

    # team add / list
    team_p = subparsers.add_parser("team", help="Manage teams")
    team_sub = team_p.add_subparsers(dest="subcommand", required=True)
    t_add = team_sub.add_parser("add", help="Add a new team")
    t_add.add_argument("team_id", help="Unique team identifier (e.g. team-07)")
    t_add.add_argument("--name", required=True, help="Team display name")
    t_add.add_argument("--project", default=None, help="Project name")
    t_add.add_argument("--repo", default=None, help="Repository URL")
    t_add.add_argument("--baseline", default=None, help="Baseline organizer template commit SHA")
    team_sub.add_parser("list", help="List all registered teams")

    # member add / list
    mem_p = subparsers.add_parser("member", help="Manage team members")
    mem_sub = mem_p.add_subparsers(dest="subcommand", required=True)
    m_add = mem_sub.add_parser("add", help="Add a team member")
    m_add.add_argument("team_id", help="Team ID")
    m_add.add_argument("member_id", help="Unique member identifier")
    m_add.add_argument("--name", required=True, help="Full display name")
    m_add.add_argument("--email", required=True, help="Primary email address")
    m_add.add_argument("--github", default=None, help="GitHub username")
    m_add.add_argument("--role", default=None, help="Declared role (e.g. Designer, Non-coding)")

    m_list = mem_sub.add_parser("list", help="List members for a team")
    m_list.add_argument("team_id", help="Team ID")

    # key add
    key_p = subparsers.add_parser("key", help="Register public keys")
    key_sub = key_p.add_subparsers(dest="subcommand", required=True)
    k_add = key_sub.add_parser("add", help="Add a public key for a member")
    k_add.add_argument("member_id", help="Member ID")
    k_add.add_argument("--type", choices=("openpgp", "ssh"), default="openpgp", help="Key type")
    k_add.add_argument("--fingerprint", required=True, help="Hex or SSH fingerprint")
    k_add.add_argument("--key-file", help="Path to public key file (.asc, .pub)")
    k_add.add_argument("--key-text", help="Raw public key text")

    # device add
    dev_p = subparsers.add_parser("device", help="Register devices")
    dev_sub = dev_p.add_subparsers(dest="subcommand", required=True)
    d_add = dev_sub.add_parser("add", help="Register a device fingerprint")
    d_add.add_argument("member_id", help="Member ID")
    d_add.add_argument("device_fingerprint", help="SHA256 device fingerprint hash")
    d_add.add_argument("--hostname", default=None, help="Device hostname")
    d_add.add_argument("--platform", default=None, help="OS platform (macOS, Linux, etc.)")

    # import
    imp_p = subparsers.add_parser("import", help="Import a legacy roster.json file")
    imp_p.add_argument("roster_file", help="Path to roster.json")

    # export
    exp_p = subparsers.add_parser("export", help="Export a team roster as JSON")
    exp_p.add_argument("team_id", help="Team ID to export")
    exp_p.add_argument("--out", default=None, help="Output JSON file path (default: stdout)")

    # export-all
    exp_all_p = subparsers.add_parser("export-all", help="Export all teams into a directory")
    exp_all_p.add_argument("out_dir", help="Output directory path")

    # list summary
    subparsers.add_parser("list", help="Display overview of all teams and members")

    args = parser.parse_args(argv)
    db = RosterDatabase(args.db)

    try:
        if args.command == "init":
            print(f"Initialized HACKPROOF roster schema in {args.db}")
            return 0

        elif args.command == "team":
            if args.subcommand == "add":
                t = db.add_team(
                    team_id=args.team_id,
                    name=args.name,
                    project_name=args.project,
                    repo_url=args.repo,
                    baseline_commit=args.baseline,
                )
                print(f"Registered team '{t.team_id}' ({t.name})")
            elif args.subcommand == "list":
                teams = db.list_teams()
                print(f"Registered Teams ({len(teams)}):")
                for t in teams:
                    mems = db.get_members(t.team_id)
                    print(f"  • {t.team_id:<14} {t.name:<25} ({len(mems)} members) repo: {t.repo_url or '(none)'}")

        elif args.command == "member":
            if args.subcommand == "add":
                m = db.add_member(
                    member_id=args.member_id,
                    team_id=args.team_id,
                    display_name=args.name,
                    email=args.email,
                    github_login=args.github,
                    declared_non_coding_role=args.role,
                )
                print(f"Added member '{m.member_id}' ({m.display_name}) to team '{m.team_id}'")
            elif args.subcommand == "list":
                mems = db.get_members(args.team_id)
                print(f"Members in Team '{args.team_id}' ({len(mems)}):")
                for m in mems:
                    keys = db.get_keys(m.member_id)
                    devs = db.get_devices(m.member_id)
                    login = f"@{m.github_login}" if m.github_login else ""
                    print(f"  • {m.member_id:<12} {m.display_name:<20} {m.email:<25} {login:<15} [{len(keys)} key(s), {len(devs)} device(s)]")

        elif args.command == "key":
            if args.subcommand == "add":
                pub = ""
                if args.key_file:
                    with open(args.key_file, "r", encoding="utf-8") as kf:
                        pub = kf.read()
                elif args.key_text:
                    pub = args.key_text
                else:
                    raise RosterDBError("Either --key-file or --key-text must be provided")

                k = db.add_key(
                    key_id=f"{args.member_id}-k{len(db.get_keys(args.member_id))+1}",
                    member_id=args.member_id,
                    key_type=args.type,
                    fingerprint=args.fingerprint,
                    public_key=pub,
                )
                print(f"Registered {k.key_type} key for member '{k.member_id}': {k.fingerprint}")

        elif args.command == "device":
            if args.subcommand == "add":
                d = db.add_device(
                    device_id=f"{args.member_id}-d{len(db.get_devices(args.member_id))+1}",
                    member_id=args.member_id,
                    device_fingerprint=args.device_fingerprint,
                    hostname=args.hostname,
                    platform=args.platform,
                )
                print(f"Registered device for member '{d.member_id}': {d.device_fingerprint[:16]}... ({d.hostname or 'unknown'})")

        elif args.command == "import":
            team = db.import_team_roster(args.roster_file)
            mems = db.get_members(team.team_id)
            print(f"Imported roster from '{args.roster_file}' -> Team '{team.team_id}' ({len(mems)} members)")

        elif args.command == "export":
            roster = db.export_team_roster(args.team_id)
            formatted = json.dumps(roster, indent=2)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(formatted + "\n")
                print(f"Exported team '{args.team_id}' roster to {args.out}")
            else:
                print(formatted)

        elif args.command == "export-all":
            paths = db.export_all(args.out_dir)
            print(f"Exported {len(paths)} team rosters to directory '{args.out_dir}':")
            for p in paths:
                print(f"  • {p}")

        elif args.command == "list":
            teams = db.list_teams()
            print("=" * 70)
            print(f" HACKPROOF MULTI-TEAM REGISTRATION DATABASE ({args.db})")
            print("=" * 70)
            if not teams:
                print("  No teams registered yet. Use 'hackproof-roster team add' or 'hackproof-roster import'.")
            for t in teams:
                mems = db.get_members(t.team_id)
                print(f"\n📁 Team: {t.name} (ID: {t.team_id})")
                if t.project_name:
                    print(f"   Project: {t.project_name}")
                if t.repo_url:
                    print(f"   Repo: {t.repo_url}")
                print(f"   Members ({len(mems)}):")
                for m in mems:
                    keys = db.get_keys(m.member_id)
                    devs = db.get_devices(m.member_id)
                    key_info = ", ".join(f"{k.key_type}:{k.fingerprint[:8]}..." for k in keys) or "no keys"
                    print(f"     👤 {m.display_name} <{m.email}> [{key_info}] ({len(devs)} device(s))")
            print("\n" + "=" * 70)

        return 0

    except RosterDBError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
