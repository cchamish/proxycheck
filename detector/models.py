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
