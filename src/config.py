"""Legacy import shim for ``wardsoar.core.config``.

Re-exports the canonical module so ``from src.config import ...``
keeps working during the monorepo migration. Remove once every
caller has switched to ``wardsoar.core.config``.
"""

from __future__ import annotations

from wardsoar.core.config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_WHITELIST_PATH,
    AppConfig,
    WhitelistConfig,
    get_app_dir,
    get_bundle_dir,
    get_data_dir,
    load_config,
    load_env,
    load_whitelist,
)

__all__ = [
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_WHITELIST_PATH",
    "AppConfig",
    "WhitelistConfig",
    "get_app_dir",
    "get_bundle_dir",
    "get_data_dir",
    "load_config",
    "load_env",
    "load_whitelist",
]
