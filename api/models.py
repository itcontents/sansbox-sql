from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


DBName = str
TableName = str


_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
_MAX_NAME_LEN = 64


def _validate_name(value: str, kind: str) -> str:
    if not value or len(value) > _MAX_NAME_LEN or not _NAME_RE.match(value):
        raise ValueError(f"invalid {kind} name: {value!r}")
    return value


class DBSpec(BaseModel):
    """A target DB in a sandbox session.

    `tables` controls what gets dumped from prod and restored into the sandbox.
    - omitted / null / empty list / "all"  ->  dump the entire DB
    - list of table names                  ->  dump only those tables
    """

    name: DBName
    tables: list[TableName] | Literal["all"] | None = None

    @field_validator("name")
    @classmethod
    def _name_ok(cls, v: str) -> str:
        return _validate_name(v, "db")

    @field_validator("tables", mode="before")
    @classmethod
    def _normalise_tables(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            if v == "all":
                return "all"
            v = [v]
        if isinstance(v, list):
            if not v:
                raise ValueError("tables must be non-empty if provided (or omit/'all' for full DB)")
            seen: set[str] = set()
            for t in v:
                if not isinstance(t, str):
                    raise ValueError("each table must be a string")
                _validate_name(t, "table")
                if t in seen:
                    raise ValueError(f"duplicate table: {t}")
                seen.add(t)
            return v
        raise ValueError("tables must be a list of strings or 'all'")

    @property
    def is_full(self) -> bool:
        return self.tables is None or self.tables == "all" or self.tables == []

    @property
    def table_list(self) -> list[str] | None:
        """Return concrete table list, or None if this spec means 'full DB'."""
        if self.is_full:
            return None
        if self.tables == "all":
            return None
        return list(self.tables)  # type: ignore[arg-type]


class CreateSessionRequest(BaseModel):
    ticket: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    dbs: list[DBSpec] = Field(..., min_length=1, max_length=10)

    @field_validator("dbs", mode="before")
    @classmethod
    def _accept_legacy_strings(cls, v):
        if not isinstance(v, list):
            return v
        out = []
        for item in v:
            if isinstance(item, str):
                out.append({"name": item})
            elif isinstance(item, dict):
                out.append(item)
            else:
                raise ValueError("each db must be a string or {name, tables}")
        return out

    @field_validator("dbs")
    @classmethod
    def _unique_dbs(cls, v: list[DBSpec]) -> list[DBSpec]:
        names = [d.name for d in v]
        if len(set(names)) != len(names):
            raise ValueError("dbs must be unique")
        return v


class DatabaseInfo(BaseModel):
    name: DBName
    user: str
    password: str
    tables: list[TableName] | None = None  # null when full DB


class CreateSessionResponse(BaseModel):
    session_id: str
    api_host: str
    mysql_host: str
    mysql_port: int
    expires_at: datetime
    max_extended_until: datetime
    ca_url: str
    databases: list[DatabaseInfo]


class SessionView(BaseModel):
    session_id: str
    ticket: str
    status: Literal["starting", "ready", "expired", "nuked", "error"]
    api_host: str
    mysql_host: str
    mysql_port: int
    expires_at: datetime
    max_extended_until: datetime
    ttl_extended: bool
    ca_url: str
    databases: list[DatabaseInfo]


class ResetTTLResponse(BaseModel):
    session_id: str
    expires_at: datetime
    max_extended_until: datetime
    reset_used: bool


class DeleteResponse(BaseModel):
    session_id: str
    status: Literal["nuked"]


class TicketClosedRequest(BaseModel):
    ticket: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    session_id: str = Field(..., min_length=8)


class TicketClosedResponse(BaseModel):
    ticket: str
    session_id: str
    status: Literal["nuked", "already_nuked"]


class ErrorBody(BaseModel):
    detail: str
