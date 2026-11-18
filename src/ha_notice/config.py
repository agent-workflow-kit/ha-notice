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
- The type of each known key is checked first, then its grammar and range (issue #9):
  durations (``(0|[1-9][0-9]*)(\\.[0-9]+)?(ms|s|m)?`` of at most 64 characters, or a finite number
  of seconds, compared exactly in ``Fraction``s, so ``1e3``, ``1:30``, ``.nan`` and a bool are
  refused), ``level_prefix`` members (at most 16 characters that the sanitizer's title rule leaves
  unchanged), ``default_group`` and
  ``max_chars``. Every pattern is a full match (``re.fullmatch``, never ``$``). The error names the
  key and never the value. TODO(#10): ``base_url``, ``token_env`` and ``ca_file`` grammars;
  TODO(#16): ``link_hosts``.
- The token is never read here.
"""

from __future__ import annotations

import math
import os.path
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any

import yaml

from ha_notice.gateway import Gateway, HomeLookupError, SourceError
from ha_notice.output import ErrorResult, build_error, safe_key

__all__ = ["DEFAULTS", "KNOWN_KEYS", "MAX_FILE_BYTES", "Config", "ConfigError", "load"]

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

# The defaults of the keys that have one (the required base_url and service, and the unset ca_file,
# link_hosts and default_group, have none). Equal to config.example.yaml and schemas/config.json.
DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "token_env": "HA_TOKEN",
    "allow_insecure_http": False,
    "level_prefix": {"info": "", "warn": "WARN:", "action": "ACTION:", "error": "ERROR:"},
    "max_chars": 1000,
    "timeout": "10s",
    "connect_timeout": "3s",
    "log": True,
}
_RANGES: dict[str, tuple[Fraction, Fraction]] = {  # seconds, inclusive
    "timeout": (Fraction(1), Fraction(120)),
    "connect_timeout": (Fraction(1), Fraction(30)),
}
MAX_CHARS_RANGE = (100, 2000)
PREFIX_MAX = 16


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

    # Accessors apply the defaults. ``load`` has validated every value, so none of them can fail.

    @property
    def enabled(self) -> bool:
        return bool(self.values.get("enabled", DEFAULTS["enabled"]))

    @property
    def log(self) -> bool:
        return bool(self.values.get("log", DEFAULTS["log"]))

    @property
    def timeout(self) -> float:
        """The deadline of a send, in seconds."""
        return _seconds_float(self.values.get("timeout", DEFAULTS["timeout"]))

    @property
    def connect_timeout(self) -> float:
        """The limit of the connect phase, in seconds (not yet capped by the time left)."""
        return _seconds_float(self.values.get("connect_timeout", DEFAULTS["connect_timeout"]))

    @property
    def max_chars(self) -> int:
        return int(self.values.get("max_chars", DEFAULTS["max_chars"]))

    @property
    def default_group(self) -> str | None:
        return self.values.get("default_group")

    @property
    def level_prefix(self) -> dict[str, str]:
        """The prefix of each of the four levels (a copy)."""
        return {**DEFAULTS["level_prefix"], **self.values.get("level_prefix", {})}


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


# --- grammar and range of the known keys (issue #9) ------------------------------------------

# No leading zero, so a quoted ``"010"`` is refused like the bare ``010`` (which the loader leaves a
# string). A string longer than DURATION_MAX_CHARS is refused, whatever the interpreter's limit.
DURATION_MAX_CHARS = 64
DURATION_RE = re.compile(r"((?:0|[1-9][0-9]*)(?:\.[0-9]+)?)(ms|s|m)?")
GROUP_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_UNIT = {None: Fraction(1), "s": Fraction(1), "ms": Fraction(1, 1000), "m": Fraction(60)}
# Sanitizer table (docs/interface.md): the listed Cf and default-ignorable characters it removes.
_REMOVED = frozenset(
    [0x00AD, 0x061C, 0x180E, 0x200B, 0x200E, 0x200F, 0xFEFF, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800]
    + list(range(0x202A, 0x202F))
    + list(range(0x2060, 0x2070))
    + list(range(0xFFF9, 0xFFFC))
    + list(range(0xE0000, 0xE0080))
    + list(range(0xE0100, 0xE01F0))
    + list(range(0x180B, 0x180E))
    + [0x180F]
)
_REMOVED_CATEGORIES = frozenset({"Cc", "Cs", "Co", "Cn", "Zl", "Zp"})
_EMPTY_CATEGORIES = frozenset({"Mn", "Mc", "Me"})


def _seconds(value: object) -> Fraction | None:
    """The exact number of seconds of a duration value, or ``None`` when it is not one. A bool is
    never a number, and a string is read only by the grammar (never ``float()``)."""
    if type(value) is int:
        return Fraction(value)
    if type(value) is float:
        return Fraction(value) if math.isfinite(value) else None
    if type(value) is str:
        match = DURATION_RE.fullmatch(value) if len(value) <= DURATION_MAX_CHARS else None
        if match is None:
            return None
        return Fraction(match.group(1)) * _UNIT[match.group(2)]
    return None


def _seconds_float(value: object) -> float:
    seconds = _seconds(value)
    if seconds is None:  # load() validated the value, so this is a programming error
        raise ValueError("not a duration")
    return float(seconds)


def duration_ok(key: str, value: object) -> bool:
    seconds = _seconds(value)
    lo, hi = _RANGES[key]
    return seconds is not None and lo <= seconds <= hi


def group_ok(value: str) -> bool:
    return GROUP_RE.fullmatch(value) is not None


def prefix_ok(value: str) -> bool:
    """A ``level_prefix`` member: at most 16 code points that the title rule (sanitizer steps 1 to
    5) leaves unchanged, and that are not an empty title. The sanitizer itself is #13's; this is
    its title rule restated for a prefix. TODO(#13): call the sanitizer instead, once it exists."""
    if len(value) > PREFIX_MAX:
        return False
    for ch in value:
        if ord(ch) in _REMOVED or unicodedata.category(ch) in _REMOVED_CATEGORIES:
            return False
    if value != value.strip() or "  " in value:
        return False
    return not value or any(
        not ch.isspace() and unicodedata.category(ch) not in _EMPTY_CATEGORIES for ch in value
    )


def _grammar_ok(key: str, value: Any) -> bool:
    if key in _DURATION_KEYS:
        return duration_ok(key, value)
    if key == "max_chars":
        return MAX_CHARS_RANGE[0] <= value <= MAX_CHARS_RANGE[1]
    if key == "default_group":
        return group_ok(value)
    if key == "level_prefix":
        return all(prefix_ok(v) for v in value.values())
    return True  # TODO(#10): base_url, token_env, ca_file; TODO(#16): link_hosts


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
        if not _grammar_ok(name, value):
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
