from __future__ import annotations

import argparse

from backend.app.application.retention import RetentionService
from backend.app.core.config import Settings
from backend.app.infrastructure.database import create_database_engine, initialize_database


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview or apply PCAP retention cleanup")
    parser.add_argument("--days", type=int, default=None)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    settings = Settings.from_env()
    engine = create_database_engine(settings.database_path)
    initialize_database(engine)
    service = RetentionService(engine, settings.captures_dir, settings.analyses_dir)
    plan = service.plan(args.days or settings.retention_days)
    print(f"cutoff={plan.cutoff.isoformat()}")
    print(f"captures={len(plan.capture_ids)} analyses={len(plan.analysis_ids)}")
    for path in [*plan.capture_files, *plan.analysis_directories]:
        print(path)
    if args.apply:
        service.apply(plan)
        print("cleanup=applied")
    else:
        print("cleanup=dry-run (use --apply to confirm)")
    engine.dispose()


if __name__ == "__main__":
    main()
