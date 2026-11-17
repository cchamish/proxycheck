"""Management command to purge expired restricted provider fields from ToolsDB L2 cache."""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from detector.l2_cache import purge_expired_provider_fields


class Command(BaseCommand):
    help = "Purges restricted provider entries exceeding their retention window from ToolsDB L2 cache."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--batch-size",
            type=int,
            default=500,
            dest="batch_size",
            help="Maximum number of indexed cache rows inspected per query batch (default: 500).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            dest="dry_run",
            help="Scan and report expired provider entries without modifying ToolsDB rows.",
        )

    def handle(self, *args, **options) -> None:
        raw_batch = options.get("batch_size")
        batch_size = 500 if raw_batch is None else int(raw_batch)
        if batch_size < 1:
            raise CommandError("The --batch-size argument must be a positive integer.")
        dry_run = bool(options.get("dry_run"))

        summary = purge_expired_provider_fields(batch_size=batch_size, dry_run=dry_run)
        if summary.get("failed"):
            raise CommandError("Failed to purge ToolsDB L2 cache rows due to a database error.")

        scanned = summary["scanned"]
        updated = summary["updated"]
        purged = summary["purged_providers"]
        if dry_run:
            self.stdout.write(
                f"Dry run completed: scanned {scanned} rows, "
                f"{updated} rows require cleanup ({purged} expired provider entries)."
            )
            return

        self.stdout.write(
            self.style.SUCCESS(
                f"Purged {purged} expired provider entries across {updated} rows (scanned {scanned} rows)."
            )
        )
