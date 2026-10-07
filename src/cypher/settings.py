"""Loads and validates config/cypher.toml into typed settings objects.

Nothing else in the codebase should read cypher.toml directly — go through
load_settings() so every module sees the same validated config.
"""
from __future__ import annotations

from pathlib import Path

import toml
from pydantic import BaseModel, Field


class SourcesSettings(BaseModel):
    auth_log: str = "/var/log/auth.log"
    syslog: str = "/var/log/syslog"
    web_access_log: str = "/var/log/nginx/access.log"


class StorageSettings(BaseModel):
    sqlite_path: str = "./data/cypher.db"
    parquet_dir: str = "./data/processed"


class ThresholdSettings(BaseModel):
    low: int = 30
    medium: int = 60
    high: int = 80
    critical: int = 95


class DetectSettings(BaseModel):
    rules_dir: str = "./config/rules.d"
    window_seconds: int = 60
    score_weight_rules: float = 0.5
    score_weight_ml: float = 0.5
    thresholds: ThresholdSettings = Field(default_factory=ThresholdSettings)


class MLSettings(BaseModel):
    model_dir: str = "./data/models"
    isolation_forest_contamination: float = 0.02
    autoencoder_enabled: bool = False
    retrain_interval_hours: int = 24


class RespondSettings(BaseModel):
    enabled: bool = True
    backend: str = "nftables"
    block_ttl_seconds: int = 3600
    max_blocks_per_hour: int = 20
    allowlist_file: str = "./config/allowlist.toml"
    socket_path: str = "/run/cypher/responder.sock"


class APISettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    session_secret_env: str = "CYPHER_SESSION_SECRET"


class GeoSettings(BaseModel):
    geolite_db: str = "./data/geo/GeoLite2-City.mmdb"


class MitreSettings(BaseModel):
    attack_json: str = "./data/mitre/enterprise-attack.json"


class GeneralSettings(BaseModel):
    mode: str = "dry_run"           # "dry_run" | "active"
    data_dir: str = "./data"
    timezone: str = "local"


class Settings(BaseModel):
    general: GeneralSettings = Field(default_factory=GeneralSettings)
    sources: SourcesSettings = Field(default_factory=SourcesSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    detect: DetectSettings = Field(default_factory=DetectSettings)
    ml: MLSettings = Field(default_factory=MLSettings)
    respond: RespondSettings = Field(default_factory=RespondSettings)
    api: APISettings = Field(default_factory=APISettings)
    geo: GeoSettings = Field(default_factory=GeoSettings)
    mitre: MitreSettings = Field(default_factory=MitreSettings)

    @property
    def is_dry_run(self) -> bool:
        return self.general.mode != "active"


def load_settings(config_path: str | Path = "config/cypher.toml") -> Settings:
    """Read the TOML config file and return a validated Settings object.

    Falls back to defaults for any section that's missing, so a minimal
    config file still produces a fully usable Settings instance.
    """
    path = Path(config_path)
    if not path.exists():
        return Settings()
    raw = toml.load(path)
    return Settings.model_validate(raw)
