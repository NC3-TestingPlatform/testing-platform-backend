"""Declarative base and the column vocabulary shared by every domain's models.

Three conventions from data-model §1 live here so no model can drift from them:
primary keys are UUIDv7 (creation-ordered, so keyset pagination works on `id`),
timestamps are UTC `timestamptz`, and every `str` column is PostgreSQL `text`.

Constraint names follow a fixed convention because Alembic autogenerate (issue
#6) matches constraints by name; an unnamed constraint gets a random PostgreSQL
identifier that can never be diffed again.

The PostgreSQL enum types of data-model §2 are declared once here and shared:
two tables using one type must hold the same `sa.Enum` object, or DDL emission
tries to create the type twice.
"""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from uuid6 import uuid7

from nc3_testing_platform.core import enums

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for every table in the v4 data model."""

    metadata = sa.MetaData(naming_convention=_NAMING_CONVENTION)
    type_annotation_map = {
        uuid.UUID: sa.Uuid(),
        datetime: sa.DateTime(timezone=True),
        str: sa.Text(),
        dict[str, Any]: JSONB(),
        list[Any]: JSONB(),
    }


def uuid_pk() -> Mapped[uuid.UUID]:
    """A UUIDv7 primary key column, generated application-side.

    Application-side so the identifier exists before the flush, and version 7 so
    primary-key order is creation order (data-model §1).
    """
    return mapped_column(primary_key=True, default=uuid7)


def _db_enum(enum_cls: type[StrEnum], name: str) -> sa.Enum:
    """A PostgreSQL enum type carrying the member values, not the member names."""
    return sa.Enum(
        enum_cls, name=name, values_callable=lambda e: [member.value for member in e]
    )


# Data-model §2, one PostgreSQL type per row of the enumeration tables.
ORGANIZATION_ROLE = _db_enum(enums.OrganizationRole, "organization_role")
KEY_SCOPE = _db_enum(enums.KeyScope, "key_scope")
ASSET_TYPE = _db_enum(enums.AssetType, "asset_type")
ASSET_ORIGIN = _db_enum(enums.AssetOrigin, "asset_origin")
VERIFICATION_SCOPE = _db_enum(enums.VerificationScope, "verification_scope")
DNS_RECORD_TYPE = _db_enum(enums.DnsRecordType, "dns_record_type")
STATEMENT_RESPONSE_KIND = _db_enum(
    enums.StatementResponseKind, "statement_response_kind"
)
SCAN_SOURCE = _db_enum(enums.ScanSource, "scan_source")
SCAN_JOB_STATUS = _db_enum(enums.ScanJobStatus, "scan_job_status")
SCAN_MODULE = _db_enum(enums.ScanModule, "scan_module")
SCAN_CLASSIFICATION = _db_enum(enums.ScanClassification, "scan_classification")
SCAN_TASK_STATUS = _db_enum(enums.ScanTaskStatus, "scan_task_status")
SCAN_GRADE = _db_enum(enums.ScanGrade, "scan_grade")
FINDING_SEVERITY = _db_enum(enums.FindingSeverity, "finding_severity")
FINDING_STATUS = _db_enum(enums.FindingStatus, "finding_status")
API_KEY_SCOPE = _db_enum(enums.ApiKeyScope, "api_key_scope")
REPORT_TIER = _db_enum(enums.ReportTier, "report_tier")
TECHNICAL_REPORT_VIEW = _db_enum(enums.TechnicalReportView, "technical_report_view")
REPORT_FORMAT = _db_enum(enums.ReportFormat, "report_format")
REPORT_LANGUAGE = _db_enum(enums.ReportLanguage, "report_language")
FEED_FORMAT = _db_enum(enums.FeedFormat, "feed_format")
