"""
Context object to hold shared application state and avoid parameter drilling.
"""
from dataclasses import dataclass
from typing import Any
import pynetbox
from pynetbox.core.api import Record

from custom_types import Roles


@dataclass
class AppContext:
    """Holds shared application context to avoid passing many parameters."""
    nb: pynetbox.api
    nb_ubiquity: list[Record | Any] | Record | Any
    tenant: Any
    roles: dict[Roles, pynetbox.core.response.Record | None]
    netbox_url: str
    netbox_token: str
    config: dict

