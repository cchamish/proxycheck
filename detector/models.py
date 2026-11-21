"""Persistent ToolsDB cache models for normalised IP intelligence snapshots."""

from __future__ import annotations

from django.db import models


class IpIntelligenceCache(models.Model):
    """Stores compressed and compliance-sanitised online IP intelligence snapshots."""

    ip_bin = models.BinaryField(max_length=16, unique=True)
    ip_version = models.PositiveSmallIntegerField()
    canonical_ip = models.CharField(max_length=45, unique=True)
    schema_version = models.PositiveSmallIntegerField(default=1)
    query_mode = models.CharField(max_length=8, default="full")
    payload_compressed = models.BinaryField()
    provider_fetched_map = models.JSONField(default=dict)
    valid_commercial_count = models.PositiveSmallIntegerField(default=0)
    has_degraded_sources = models.BooleanField(default=False)
    fetched_at = models.DateTimeField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "detector_ip_cache"
        indexes = [
            models.Index(fields=["fetched_at"], name="idx_detector_fetched_at"),
        ]

    def __str__(self) -> str:
        return f"{self.canonical_ip} ({self.query_mode})"


class RangeblockAggregate(models.Model):
    """Stores per-wiki aggregated IP and CIDR block statistics synchronised from Wiki Replicas."""

    wiki_dbname = models.CharField(max_length=64)
    target_cidr = models.CharField(max_length=64)
    ip_version = models.PositiveSmallIntegerField()
    cidr_prefix = models.PositiveSmallIntegerField(null=True, blank=True)
    range_start_bin = models.BinaryField(max_length=16)
    range_end_bin = models.BinaryField(max_length=16)
    block_count = models.PositiveIntegerField(default=0)
    has_active = models.BooleanField(default=False)
    active_expiry = models.DateTimeField(null=True, blank=True)
    active_indefinite = models.BooleanField(default=False)
    last_blocked_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "detector_rangeblock_agg"
        constraints = [
            models.UniqueConstraint(fields=["wiki_dbname", "target_cidr"], name="uniq_rb_agg_wiki_target"),
        ]
        indexes = [
            models.Index(fields=["ip_version", "target_cidr"], name="idx_rb_agg_ver_target"),
            models.Index(fields=["wiki_dbname", "has_active"], name="idx_rb_agg_wiki_active"),
        ]

    def __str__(self) -> str:
        return f"{self.wiki_dbname}:{self.target_cidr}"


class RangeblockSyncState(models.Model):
    """Tracks incremental block-log synchronisation watermarks for each Wikimedia database."""

    wiki_dbname = models.CharField(max_length=64, unique=True)
    wiki_domain = models.CharField(max_length=255, blank=True, default="")
    last_log_id = models.BigIntegerField(default=0)
    last_log_timestamp = models.CharField(max_length=14, blank=True, default="")
    synced_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "detector_rangeblock_sync_state"

    def __str__(self) -> str:
        return f"{self.wiki_dbname} (log_id={self.last_log_id})"
