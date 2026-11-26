"""Management command to safely download and atomically replace offline intelligence databases."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from detector.offline.updaters import OfflineDbUpdater


class Command(BaseCommand):
    help = "Downloads and atomically replaces local offline threat intelligence databases and prefix indexes."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--sources",
            nargs="+",
            default=["all"],
            help=(
                "Sources to update: all, stopforumspam, maxmind, shared_cidrs, privacy_relays, "
                "ipsum_drop, tor_onionoo, bgp_tools, openasn, mobile_carriers (space or comma separated)."
            ),
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Bypass local file modification time cooldown checks (still uses conditional requests).",
        )
        parser.add_argument(
            "--skip-listed-1",
            action="store_true",
            help="Skip StopForumSpam 1-day hourly incremental feed and only update toxic CIDR plus 90-day feed.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Check local file ages and report planned actions without downloading or writing files.",
        )
        parser.add_argument(
            "--timeout",
            type=float,
            default=60.0,
            help="HTTP read timeout in seconds for archive downloads (default: 60).",
        )
        parser.add_argument(
            "--data-dir",
            default="",
            help="Override destination directory for offline databases (defaults to TOOL_DATA_DIR/data).",
        )

    def handle(self, *args, **options) -> None:
        OfflineDbUpdater(stdout=self.stdout, stderr=self.stderr, style=self.style).run(**options)
