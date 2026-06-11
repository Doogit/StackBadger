"""Provider manifest dataclass for multi-stack fingerprinting.

The ``ProviderManifest`` captures which third-party providers were detected
in a target application's client-side JS bundles.  It is populated by
``discover.detect_providers()`` and consumed by the profile assembler and
conftest marker gating.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProviderManifest:
    """Detected provider fingerprints from client JS bundle scanning.

    Attributes:
        auth: Authentication provider identifier, e.g. ``"firebase"``,
              ``"clerk"``, ``"supabase-auth"``, ``"nextauth"``, or None.
        database: Database provider, e.g. ``"firestore"``, ``"supabase"``,
                  or None.
        storage: Storage provider, e.g. ``"firebase"``, ``"supabase"``,
                 ``"s3"``, ``"r2"``, or None.
        payments: Payment provider names detected (e.g. ``["paddle"]``).
        s3_compatible: True when storage is S3 or R2 (both use the S3 API).
        extracted_config: Raw config values extracted from bundles.  Keys:
            ``firebase_api_key``, ``firebase_project_id``,
            ``supabase_project_ref``, ``cognito_user_pool_id``,
            ``cognito_app_client_id``, ``service_role_key_found`` (bool),
            ``paddle_client_token``.
    """

    auth: str | None = None
    database: str | None = None
    storage: str | None = None
    payments: list[str] = field(default_factory=list)
    s3_compatible: bool = False
    extracted_config: dict[str, Any] = field(default_factory=dict)
