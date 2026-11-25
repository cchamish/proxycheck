"""Hourly management command to synchronise cross-wiki rangeblock aggregates from Wiki Replicas."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from detector.rangeblock.sync import (
    _DEFAULT_BATCH_SIZE,
    _DEFAULT_MAX_SECONDS_PER_WIKI,
    WorldBlockSynchronizer,
)


class Command(BaseCommand):
    """Synchronises active rangeblocks and incremental block logs across Wikimedia projects."""

    help = "Synchronises cross-wiki active blocks and incremental block log counts from Wiki Replicas into ToolsDB."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--wikis", type=str, default="", help="Comma-separated wiki dbnames to sync.")
        parser.add_argument(
            "--sections", type=str, default="", help="Comma-separated Wiki Replicas sections (e.g. s1,s3)."
        )
        parser.add_argument("--batch-size", type=int, default=_DEFAULT_BATCH_SIZE, help="Log ID chunk size per query.")
        parser.add_argument(
            "--max-seconds-per-wiki",
            type=int,
            default=_DEFAULT_MAX_SECONDS_PER_WIKI,
            help="Maximum seconds spent in the incremental log loop per wiki target.",
        )
        parser.add_argument(
            "--full-active-reconcile",
            action="store_true",
            help="Force full streaming mark-and-sweep reconciliation of active blocks.",
        )
        parser.add_argument(
            "--exclude-wikis",
            type=str,
            default="",
            help="Comma-separated wiki dbnames to exclude from syncing (in addition to RANGEBLOCK_REALTIME_WIKIS).",
        )
        parser.add_argument(
            "--include-realtime-wikis",
            action="store_true",
            help="Do not automatically exclude RANGEBLOCK_REALTIME_WIKIS from syncing.",
        )
        parser.add_argument(
            "--purge-excluded",
            action="store_true",
            help="Delete existing ToolsDB aggregate and sync-state rows for excluded wikis in bounded batches.",
        )
        parser.add_argument("--dry-run", action="store_true", help="Inspect counts without modifying ToolsDB.")

    def handle(self, *args, **options) -> None:
        WorldBlockSynchronizer(stdout=self.stdout, stderr=self.stderr, style=self.style).run(**options)
