from __future__ import annotations

import os
import pathlib
from collections.abc import Mapping


DOCKER_ENDPOINT_VARIABLES = (
    "DOCKER_API_VERSION",
    "DOCKER_CERT_PATH",
    "DOCKER_CONTEXT",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
)


def docker_environment(
    host: str | pathlib.Path, *, base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = dict(os.environ if base is None else base)
    for key in DOCKER_ENDPOINT_VARIABLES:
        environment.pop(key, None)
    value = str(host)
    environment["DOCKER_HOST"] = value if "://" in value else f"unix://{value}"
    return environment
