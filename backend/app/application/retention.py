from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import Engine, bindparam, text


@dataclass(frozen=True, slots=True)
class RetentionPlan:
    cutoff: datetime
    capture_ids: list[str]
    analysis_ids: list[str]
    capture_files: list[Path]
    analysis_directories: list[Path]


class RetentionService:
    def __init__(self, engine: Engine, captures_dir: Path, analyses_dir: Path) -> None:
        self._engine = engine
        self._captures_dir = captures_dir.resolve()
        self._analyses_dir = analyses_dir.resolve()

    def plan(self, retention_days: int, now: datetime | None = None) -> RetentionPlan:
        cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
        with self._engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT c.id, c.stored_filename, a.id AS analysis_id "
                    "FROM captures c LEFT JOIN analyses a ON a.capture_id = c.id "
                    "WHERE c.created_at < :cutoff AND NOT EXISTS ("
                    "SELECT 1 FROM analyses active WHERE active.capture_id = c.id "
                    "AND active.status IN ('queued', 'running'))"
                ),
                {"cutoff": cutoff},
            ).mappings()
            materialized = list(rows)
        capture_ids = sorted({str(row["id"]) for row in materialized})
        filenames = sorted({str(row["stored_filename"]) for row in materialized})
        analysis_ids = sorted(
            {str(row["analysis_id"]) for row in materialized if row["analysis_id"] is not None}
        )
        return RetentionPlan(
            cutoff=cutoff,
            capture_ids=capture_ids,
            analysis_ids=analysis_ids,
            capture_files=[self._captures_dir / name for name in filenames],
            analysis_directories=[self._analyses_dir / value for value in analysis_ids],
        )

    def apply(self, plan: RetentionPlan) -> None:
        if plan.analysis_ids:

            def statement(sql: str):
                return text(sql).bindparams(bindparam("ids", expanding=True))

            with self._engine.begin() as connection:
                for table in (
                    "validation_audit",
                    "validations",
                    "enrichments",
                    "findings",
                    "network_events",
                    "network_flows",
                    "detections",
                    "normalizations",
                    "analyzer_runs",
                ):
                    column = "validation_id" if table == "validation_audit" else "analysis_id"
                    if table == "validation_audit":
                        connection.execute(
                            statement(
                                "DELETE FROM validation_audit WHERE validation_id IN ("
                                "SELECT id FROM validations WHERE analysis_id IN :ids)"
                            ),
                            {"ids": plan.analysis_ids},
                        )
                    else:
                        connection.execute(
                            statement(f"DELETE FROM {table} WHERE {column} IN :ids"),
                            {"ids": plan.analysis_ids},
                        )
                connection.execute(
                    statement("DELETE FROM analyses WHERE id IN :ids"),
                    {"ids": plan.analysis_ids},
                )
        if plan.capture_ids:
            with self._engine.begin() as connection:
                connection.execute(
                    text("DELETE FROM captures WHERE id IN :ids").bindparams(
                        bindparam("ids", expanding=True)
                    ),
                    {"ids": plan.capture_ids},
                )
        for path in plan.capture_files:
            _safe_file_delete(path, self._captures_dir)
        for path in plan.analysis_directories:
            _safe_directory_delete(path, self._analyses_dir)


def _safe_file_delete(path: Path, root: Path) -> None:
    resolved = path.resolve()
    if resolved.parent != root:
        raise ValueError("Capture cleanup target escaped the captures directory")
    resolved.unlink(missing_ok=True)


def _safe_directory_delete(path: Path, root: Path) -> None:
    resolved = path.resolve()
    if resolved.parent != root:
        raise ValueError("Analysis cleanup target escaped the analyses directory")
    if resolved.is_dir():
        shutil.rmtree(resolved)
