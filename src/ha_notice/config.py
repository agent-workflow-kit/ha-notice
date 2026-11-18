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
  unchanged, judged by ``payload.sanitize_title`` itself), ``link_hosts`` (1 to 32 lowercase host
  names of at least two labels), ``default_group`` and ``max_chars``. Every pattern is a full
  match (``re.fullmatch``, never ``$``). The error names the key and never the value.
  ``base_url``, ``service``, ``token_env`` and ``ca_file`` follow (issue #10, below).
- The token is never read by ``load``; ``Config.read_token`` reads it from the injected
  environment mapping, from the variable ``token_env`` names and no other.
"""

from __future__ import annotations

import ipaddress
import math
import os.path
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any

import yaml

from ha_notice.gateway import Gateway, HomeLookupError, SourceError
from ha_notice.output import ErrorResult, build_error, safe_key
from ha_notice.payload import has_lone_surrogate, is_empty_text, sanitize_title

__all__ = [
    "DEFAULTS",
    "KNOWN_KEYS",
    "MAX_CA_FILE_BYTES",
    "MAX_FILE_BYTES",
    "BaseUrl",
    "Config",
    "ConfigError",
    "CredentialError",
    "load",
    "parse_base_url",
]

MAX_FILE_BYTES = 65536
MAX_CA_FILE_BYTES = 4 * 1024 * 1024
TOKEN_MAX_CHARS = 4096
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


class CredentialError(Exception):
    """The token is missing or malformed (exit 12 ``credential_invalid``, ``details.env`` the
    variable name). Holds the name only, never the value."""

    def __init__(self, env: str) -> None:
        super().__init__("the credential is missing or invalid")
        self.env: str = env
        self.error: ErrorResult = build_error("credential_invalid", env=env)


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
    def link_hosts(self) -> tuple[str, ...] | None:
        """The allowed link hosts, or ``None`` when unset (no restriction). Match with
        ``link.link_host_allowed``; ``validate_notification`` takes this as ``link_hosts``."""
        hosts = self.values.get("link_hosts")
        return None if hosts is None else tuple(hosts)

    @property
    def level_prefix(self) -> dict[str, str]:
        """The prefix of each of the four levels (a copy)."""
        return {**DEFAULTS["level_prefix"], **self.values.get("level_prefix", {})}

    @property
    def base_url(self) -> BaseUrl | None:
        """The parsed ``base_url``, or ``None`` when it is not set."""
        text = self.values.get("base_url")
        return None if text is None else parse_base_url(text)

    @property
    def base_url_text(self) -> str | None:
        """The normalized ``base_url`` (lowercase scheme and host, no trailing slash)."""
        parsed = self.base_url
        return None if parsed is None else parsed.text

    @property
    def service(self) -> str | None:
        return self.values.get("service")

    @property
    def token_env(self) -> str:
        return str(self.values.get("token_env", DEFAULTS["token_env"]))

    @property
    def allow_insecure_http(self) -> bool:
        return bool(self.values.get("allow_insecure_http", DEFAULTS["allow_insecure_http"]))

    @property
    def ca_file(self) -> str | None:
        return self.values.get("ca_file")

    def check_destination(self) -> None:
        """A send needs ``base_url`` and ``service`` (a dry run needs neither). Raises
        ``ConfigError`` naming the first missing key."""
        for name in ("base_url", "service"):
            if name not in self.values:
                raise ConfigError(name)

    def check_ca_file(self, gateway: Gateway) -> None:
        """``ca_file``, when set, must be a readable regular file of at most MAX_CA_FILE_BYTES
        (4 MiB).
        Only readability is checked here; loading the certificates is #22's. Raises
        ``ConfigError`` (key ``ca_file``); nothing about the failure is kept."""
        path = self.ca_file
        if path is None:
            return
        try:
            data = gateway.read_config(path, MAX_CA_FILE_BYTES)
        except SourceError:
            data = None
        if data is None:  # missing, or any read failure; raised outside the handler
            raise ConfigError("ca_file")

    def read_token(self, env: Mapping[str, str]) -> str:
        """The token from the variable named by ``token_env`` in ``env`` (the process environment
        the CLI was given), trimmed with ``str.strip``: 1 to 4096 characters, each U+0021 to
        U+007E. Raises ``CredentialError``, which never holds the value."""
        name = self.token_env
        if not token_env_ok(name):  # whatever way this Config was built, only HA_ names are read
            raise CredentialError(name)
        raw = env.get(name)
        token = raw.strip() if isinstance(raw, str) else ""
        if not (1 <= len(token) <= TOKEN_MAX_CHARS and TOKEN_RE.fullmatch(token)):
            raise CredentialError(name)
        return token


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
LINK_HOSTS_MAX = 32
LINK_HOST_MAX_CHARS = 253
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# At least two lowercase ASCII labels; the length is capped before the pattern runs.
LINK_HOST_RE = re.compile(rf"(?:{_LABEL}\.)+{_LABEL}")


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
    """A ``level_prefix`` member: at most 16 code points that the sanitizer's title rule (steps 1
    to 5, except that a surrogate is removed rather than refused) leaves unchanged, and that are
    not an empty title (only marks and whitespace). The empty string is the ``info`` default."""
    if len(value) > PREFIX_MAX or has_lone_surrogate(value):
        return False
    return sanitize_title(value) == value and (value == "" or not is_empty_text(value))


def link_host_entry_ok(value: str) -> bool:
    """A ``link_hosts`` entry: lowercase, at least two labels, at most 253 characters."""
    return len(value) <= LINK_HOST_MAX_CHARS and LINK_HOST_RE.fullmatch(value) is not None


def _grammar_ok(key: str, value: Any) -> bool:
    if key in _DURATION_KEYS:
        return duration_ok(key, value)
    if key == "max_chars":
        return MAX_CHARS_RANGE[0] <= value <= MAX_CHARS_RANGE[1]
    if key == "default_group":
        return group_ok(value)
    if key == "level_prefix":
        return all(prefix_ok(v) for v in value.values())
    if key == "link_hosts":
        return 1 <= len(value) <= LINK_HOSTS_MAX and all(link_host_entry_ok(v) for v in value)
    if key == "base_url":
        return parse_base_url(value) is not None
    if key == "service":
        return service_ok(value)
    if key == "token_env":
        return token_env_ok(value)
    if key == "ca_file":
        return ca_file_ok(value)
    return True


# --- base_url, service, token_env, ca_file (issue #10) ----------------------------------------

BASE_URL_MAX_CHARS = 2048
# docs/interface.md, Home Assistant edge. Full match only: no character class here matches LF, and
# ``re.fullmatch`` anchors both ends. ``[0-9]`` and ``[A-Za-z0-9]`` are spelled out (never ``\d`` or
# ``\w``) so no other script's digits or letters match.
_BASE_URL_RE = re.compile(
    r"(?P<scheme>[Hh][Tt][Tt][Pp][Ss]?)://"
    r"(?P<host>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[(?P<v6>[0-9A-Fa-f:.]+)\])"
    r"(?::(?P<port>[0-9]{1,5}))?"
    r"(?P<prefix>(?:/[A-Za-z0-9._~-]+)*)"
    r"/*"
)
SERVICE_RE = re.compile(r"[a-z0-9_]{1,64}")
TOKEN_ENV_RE = re.compile(r"HA_[A-Z0-9_]{1,60}")
TOKEN_RE = re.compile(r"[\x21-\x7e]+")
CA_FILE_RE = re.compile(r"/[^\x00-\x1f\x7f]{0,4095}")


@dataclass(frozen=True)
class BaseUrl:
    """A validated ``base_url``. ``host`` is lowercase (an IPv6 literal without brackets),
    ``port_text`` the port as written (``None`` when absent), ``prefix`` the path prefix without a
    trailing slash (``""`` or ``/a/b``)."""

    scheme: str
    host: str
    port_text: str | None
    prefix: str
    ipv6: bool

    @property
    def port(self) -> int:
        if self.port_text is not None:
            return int(self.port_text)
        return 443 if self.scheme == "https" else 80

    @property
    def authority(self) -> str:
        """The Host header value: the host (bracketed for IPv6) and the port as written."""
        host = f"[{self.host}]" if self.ipv6 else self.host
        return host if self.port_text is None else f"{host}:{self.port_text}"

    @property
    def text(self) -> str:
        return f"{self.scheme}://{self.authority}{self.prefix}"

    @property
    def probe_path(self) -> str:
        return f"{self.prefix}/api/"

    def request_path(self, service: str) -> str:
        """The request path for a validated ``service``; never a double or trailing slash."""
        if not service_ok(service):
            raise ValueError("not a service name")
        return f"{self.prefix}/api/services/notify/{service}"


def parse_base_url(text: object) -> BaseUrl | None:
    """The parts of a ``base_url``, or ``None`` when it does not match the grammar as a whole
    (after one trailing ``/`` run), has a port outside 1 to 65535, a ``.`` or ``..`` segment or an
    IPv6 literal that is not an address. The text between brackets must be a valid IPv6 address
    (``ipaddress.IPv6Address``); the schema pattern is looser because it cannot express that. The
    scheme is matched ASCII-only (``[Hh][Tt][Tt][Pp][Ss]?``) and is ``http`` or ``https`` after
    lowercasing; whether ``http`` is allowed is judged in ``load``."""
    if type(text) is not str or len(text) > BASE_URL_MAX_CHARS:
        return None
    match = _BASE_URL_RE.fullmatch(text)
    if match is None:
        return None
    port = match.group("port")
    if port is not None and not 1 <= int(port) <= 65535:
        return None
    prefix = match.group("prefix")
    if any(seg in (".", "..") for seg in prefix.split("/")):
        return None
    host = match.group("host")
    v6 = match.group("v6")
    if v6 is not None:
        try:
            ipaddress.IPv6Address(v6)
        except ValueError:
            return None
        host = v6
    scheme = match.group("scheme").lower()
    if scheme not in ("http", "https"):  # defence in depth: the pattern is ASCII-only
        return None
    return BaseUrl(scheme, host.lower(), port, prefix, v6 is not None)


def service_ok(value: str) -> bool:
    return SERVICE_RE.fullmatch(value) is not None


def token_env_ok(value: str) -> bool:
    return TOKEN_ENV_RE.fullmatch(value) is not None


def ca_file_ok(value: str) -> bool:
    return CA_FILE_RE.fullmatch(value) is not None


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
    # http needs allow_insecure_http, which any file may set: checked on the merged values.
    parsed = parse_base_url(values["base_url"]) if "base_url" in values else None
    if (
        parsed is not None
        and parsed.scheme == "http"
        and values.get("allow_insecure_http") is not True
    ):
        raise ConfigError("base_url")
    return Config(values=values, home=home)
