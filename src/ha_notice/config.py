"""Config loading: password-database home, drop-ins and strict YAML (issue #8).

``load(gateway, path)`` finds the home through the gateway (never ``HOME`` or ``XDG_*``), reads
the main file and ``config.d/*.yaml`` beside it in lexical order, parses each with a hardened
PyYAML loader and returns the merged known keys. Every file read goes through the gateway.

Rules kept here (docs/interface.md, Config):

- The loader is ``SafeLoader``'s machinery with its own resolvers and constructors: the only
  booleans are ``true`` and ``false``, the only numbers are decimal integers and decimal floats
  (``1.5``), so ``no``, ``010``, ``1:30``, ``0x10``, ``1_0``, ``1e3``, ``.inf`` and ``.nan``
  stay strings. Duplicate keys, anchors, explicit tags and aliases are refused (an alias bomb is
  refused at the first alias, so it cannot expand). Text is decoded as UTF-8 here, so no encoding is
  sniffed.
- Any failure to read or parse a file (also ``RecursionError`` and ``MemoryError``) is
  ``ConfigError`` whose key is the file path; the YAML error text, which quotes the file, is
  never kept, not even as ``__cause__``.
- An unknown key is refused before its value is examined, by ``output.safe_key``.
- Only the type of each known key is checked here. TODO(#9): the grammar and range of the
  durations, ``level_prefix``, ``default_group`` and ``max_chars``; TODO(#10): ``base_url``,
  ``token_env`` and ``ca_file``; TODO(#16): ``link_hosts``.
- The token is never read here.
"""

from __future__ import annotations

import math
import os.path
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import yaml

from ha_notice.gateway import Gateway, HomeLookupError, SourceError
from ha_notice.output import ErrorResult, build_error, safe_key

__all__ = ["KNOWN_KEYS", "MAX_FILE_BYTES", "Config", "ConfigError", "load"]

MAX_FILE_BYTES = 65536
KNOWN_KEYS = (
    "enabled",
    "base_url",
    "service",
    "token_env",
    "allow_insecure_http",
    "ca_file",
    "link_hosts",
    "level_prefix",
    "default_group",
    "max_chars",
    "timeout",
    "connect_timeout",
    "log",
)
_BOOL_KEYS = frozenset({"enabled", "allow_insecure_http", "log"})
_STR_KEYS = frozenset({"base_url", "service", "token_env", "ca_file", "default_group"})
_DURATION_KEYS = frozenset({"timeout", "connect_timeout"})
_LEVELS = frozenset({"info", "warn", "action", "error"})


class ConfigError(Exception):
    """The config cannot be used. ``key`` is the ``details.key`` of the ``config_invalid`` error
    (a plain key name or ``?``, ``home``, ``--config`` or a file path); ``error`` is the
    ready-made result (exit 2). The message is fixed."""

    def __init__(self, key: str) -> None:
        super().__init__("invalid configuration")
        self.error: ErrorResult = build_error("config_invalid", key=key)
        self.key: str = self.error.envelope["error"]["details"]["key"]


@dataclass
class Config:
    """The merged known keys that were present (defaults are applied by the users of a key) and
    the home directory the config was found from."""

    values: dict[str, Any] = field(default_factory=dict)
    home: str = ""


# --- the strict loader -----------------------------------------------------------------------

# PyYAML's resolver uses ``match`` (anchored at the start only), so each pattern ends in ``\Z``.
_INT = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_FLOAT = re.compile(r"-?(?:0|[1-9][0-9]*)\.[0-9]+\Z")
_BOOL = re.compile(r"(?:true|false)\Z")
_NULL = re.compile(r"(?:~|null|Null|NULL|)\Z")


def _construct_bool(loader: yaml.SafeLoader, node: yaml.Node) -> bool:
    text = loader.construct_scalar(node)  # pyright: ignore[reportArgumentType]
    if not isinstance(text, str) or not _BOOL.fullmatch(text):
        raise ValueError("not a boolean")
    return text == "true"


def _construct_int(loader: yaml.SafeLoader, node: yaml.Node) -> int:
    text = loader.construct_scalar(node)  # pyright: ignore[reportArgumentType]
    if not isinstance(text, str) or not _INT.fullmatch(text):
        raise ValueError("not an integer")
    return int(text)  # a huge value raises ValueError (digit limit)


def _construct_float(loader: yaml.SafeLoader, node: yaml.Node) -> float:
    text = loader.construct_scalar(node)  # pyright: ignore[reportArgumentType]
    if not isinstance(text, str) or not _FLOAT.fullmatch(text):
        raise ValueError("not a decimal float")
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("not finite")
    return value


def _construct_map(loader: yaml.SafeLoader, node: yaml.Node) -> Iterator[dict[Any, Any]]:
    data: dict[Any, Any] = {}
    yield data
    for key_node, value_node in node.value:  # pyright: ignore[reportAttributeAccessIssue]
        key = loader.construct_object(key_node, deep=True)
        hash(key)  # a list or mapping as a key raises TypeError
        if key in data:
            raise ValueError("duplicate key")
        data[key] = loader.construct_object(value_node, deep=True)


class _StrictLoader(yaml.SafeLoader):
    yaml_implicit_resolvers: dict[Any, Any] = {}
    yaml_constructors = {  # pyright: ignore[reportIncompatibleVariableOverride]
        "tag:yaml.org,2002:null": yaml.SafeLoader.construct_yaml_null,
        "tag:yaml.org,2002:bool": _construct_bool,
        "tag:yaml.org,2002:int": _construct_int,
        "tag:yaml.org,2002:float": _construct_float,
        "tag:yaml.org,2002:str": yaml.SafeLoader.construct_yaml_str,
        "tag:yaml.org,2002:seq": yaml.SafeLoader.construct_yaml_seq,
        "tag:yaml.org,2002:map": _construct_map,
        None: yaml.SafeLoader.construct_undefined,
    }
    yaml_multi_constructors = {}  # pyright: ignore[reportIncompatibleVariableOverride]

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise ValueError("aliases are not allowed")
        event = self.peek_event()
        if getattr(event, "anchor", None) is not None:
            raise ValueError("anchors are not allowed")
        if getattr(event, "tag", None) is not None:
            raise ValueError("explicit tags are not allowed")
        return super().compose_node(parent, index)


_StrictLoader.add_implicit_resolver("tag:yaml.org,2002:bool", _BOOL, list("tf"))
_StrictLoader.add_implicit_resolver("tag:yaml.org,2002:int", _INT, list("-0123456789"))
_StrictLoader.add_implicit_resolver("tag:yaml.org,2002:float", _FLOAT, list("-0123456789"))
_StrictLoader.add_implicit_resolver("tag:yaml.org,2002:null", _NULL, ["~", "n", "N", ""])

_FAILED = object()


def _parse(raw: bytes) -> object:
    """The YAML document, or ``_FAILED``. Nothing about the failure is kept."""
    try:
        loader = _StrictLoader(raw.decode("utf-8"))
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()
    except Exception:  # YAMLError, ValueError, RecursionError, MemoryError...: all one outcome
        return _FAILED


# --- validation and merge --------------------------------------------------------------------


def _number(value: object) -> bool:
    return type(value) is int or (type(value) is float and math.isfinite(value))


def _type_ok(key: str, value: object) -> bool:
    if key in _BOOL_KEYS:
        return type(value) is bool
    if key in _STR_KEYS:
        return type(value) is str
    if key == "max_chars":
        return type(value) is int
    if key in _DURATION_KEYS:
        return _number(value) or type(value) is str
    if key == "link_hosts":
        return type(value) is list and all(type(item) is str for item in value)
    # level_prefix: a map of the four levels to strings (the unknown-member case is checked by
    # the caller, which needs a different key).
    return type(value) is dict and all(type(v) is str for v in value.values())


def _check_document(doc: object) -> str | None:
    """The ``details.key`` of the first problem in one file's mapping, or ``None``."""
    if type(doc) is not dict:
        return ""
    for name in doc:  # unknown keys first, before any value is looked at
        if name not in KNOWN_KEYS:
            return safe_key(name) if type(name) is str else "?"
    for name, value in doc.items():
        if not _type_ok(name, value):
            return name
        if name == "level_prefix" and not set(value) <= _LEVELS:
            return name
    return None


def _merge(into: dict[str, Any], doc: dict[str, Any]) -> None:
    for name, value in doc.items():
        if name == "level_prefix":
            into.setdefault(name, {}).update(value)
        elif name == "link_hosts":
            into[name] = list(value)
        else:
            into[name] = value


def _load_file(gateway: Gateway, path: str, into: dict[str, Any]) -> bool:
    """Merge one file into ``into``; ``False`` when the file does not exist. Raises ConfigError."""
    try:
        raw = gateway.read_config(path, MAX_FILE_BYTES)
    except SourceError:
        raw = _FAILED
    if raw is None:
        return False
    doc = _FAILED if raw is _FAILED else _parse(raw)  # pyright: ignore[reportArgumentType]
    # The raises are outside every except block: no exception context carries the YAML text.
    if doc is _FAILED:
        raise ConfigError(path)
    problem = _check_document(doc)
    if problem == "":
        raise ConfigError(path)  # the top level is not a mapping
    if problem is not None:
        raise ConfigError(problem)
    _merge(into, doc)  # pyright: ignore[reportArgumentType]
    return True


def load(gateway: Gateway, path: str | None = None) -> Config:
    """Load and merge the config. ``path`` is the ``--config`` value (``None`` when absent; an
    empty string is a path like any other). Raises ``ConfigError``."""
    home: str | None = None
    try:
        home = gateway.home_dir()
    except HomeLookupError:
        pass
    if home is None:
        raise ConfigError("home")
    if path is None:
        main = os.path.join(home, ".config", "ha-notice", "config.yaml")
    else:
        main = path
    values: dict[str, Any] = {}
    if not _load_file(gateway, main, values) and path is not None:
        raise ConfigError("--config")
    dropins = os.path.join(os.path.dirname(main), "config.d")
    try:
        names = gateway.list_config_dir(dropins)
    except SourceError:
        names = None
    if names is None:
        raise ConfigError(dropins)
    for name in names:
        # A listed drop-in that is missing (a dangling symlink, or removed since the listing)
        # cannot be read: config_invalid naming it.
        full = os.path.join(dropins, name)
        if not _load_file(gateway, full, values):
            raise ConfigError(full)
    return Config(values=values, home=home)
