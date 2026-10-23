from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lab"))

from profile import ProfileError, load_profile, require_verified, validate_profile  # noqa: E402
from verify_docker import (  # noqa: E402
    VerificationError,
    verify_container,
    verify_image,
    verify_network,
)
from verify_observation import verify as verify_observation  # noqa: E402


PROFILE_NAMES = {
    "php-8.2.34-apache-amd64-pure-http-oom": "php-8.2.34-apache-amd64-pure-http-oom.json",
    "php-8.3.35-apache-amd64-r0-spray": "php-8.3.35-apache-amd64-r0-spray.json",
    "php-8.4.26-apache-amd64-fixed-carrier": "php-8.4.26-apache-amd64-fixed.json",
    "php-8.5.11-apache-amd64-r0-spray": "php-8.5.11-apache-amd64-r0-spray.json",
}


class ReleaseProfileTests(unittest.TestCase):
    def test_exact_allow_list_profiles_are_verified(self) -> None:
        actual = {}
        candidates = {}
        for path in sorted((ROOT / "profiles").glob("*.json")):
            profile = load_profile(path)
            if profile.raw["verification"]["state"] == "verified":
                require_verified(profile)
                actual[profile.id] = path.name
            else:
                with self.assertRaises(ProfileError):
                    require_verified(profile)
                candidates[profile.id] = path.name
        self.assertEqual(actual, PROFILE_NAMES)
        self.assertEqual(candidates, {})

    def test_adaptive_profiles_have_evidence_backed_shapes(self) -> None:
        p83 = load_profile(ROOT / "profiles" / PROFILE_NAMES["php-8.3.35-apache-amd64-r0-spray"])
        p85 = load_profile(ROOT / "profiles" / PROFILE_NAMES["php-8.5.11-apache-amd64-r0-spray"])
        for profile in (p83, p85):
            self.assertEqual(profile.raw["request_recipe"]["stage2"]["strategy"], "adaptive-window-v1")
            self.assertEqual(profile.raw["request_recipe"]["stage2"]["window"], "0x20000")
            self.assertEqual(profile.raw["request_recipe"]["stage2"]["arrays"], 150)
        stage83 = p83.raw["request_recipe"]["stage3"]
        self.assertEqual(stage83["r0_search"]["page_lo"], "0x74000")
        self.assertEqual(stage83["spray"]["count"], 400)
        self.assertEqual(stage83["pre_session_fields"]["count"], 0)
        stage85 = p85.raw["request_recipe"]["stage3"]
        self.assertEqual(stage85["r0_search"]["page_lo"], "0x73000")
        self.assertEqual(stage85["spray"]["count"], 128)
        self.assertEqual(stage85["pre_session_fields"]["count"], 1)
        self.assertEqual(stage85["pre_session_fields"]["value_len"], 19)
        self.assertEqual(stage85["spray"]["count"] - stage85["pre_session_fields"]["count"], 127)

    def test_request_recipe_safety_bounds_fail_closed(self) -> None:
        base_path = ROOT / "profiles" / PROFILE_NAMES["php-8.4.26-apache-amd64-fixed-carrier"]
        base = json.loads(base_path.read_text(encoding="utf-8"))
        mutations = (
            ("huge_mb", lambda value: value["request_recipe"].__setitem__("huge_mb", 65)),
            ("rotate_fillers", lambda value: value["request_recipe"].__setitem__("rotate_fillers", 4097)),
            ("stage1.fillers", lambda value: value["request_recipe"]["stage1"].__setitem__("fillers", 998)),
            ("pad", lambda value: value["request_recipe"]["stage3"]["pads"][0].__setitem__("repeat", 513)),
            ("carrier", lambda value: value["request_recipe"]["stage3"].__setitem__("carrier_copies", 513)),
        )
        for label, mutate in mutations:
            value = json.loads(json.dumps(base))
            mutate(value)
            with self.subTest(label=label), self.assertRaises(ProfileError):
                validate_profile(value)

    def test_execute_data_runtime_cache_requires_pointer_width(self) -> None:
        base_path = ROOT / "profiles" / PROFILE_NAMES["php-8.4.26-apache-amd64-fixed-carrier"]
        value = json.loads(base_path.read_text(encoding="utf-8"))
        # Schema v1's call_info compatibility key is written as the 8-byte
        # zend_execute_data.run_time_cache pointer by exploit.py.
        value["abi"]["zend_execute_data"]["call_info"] = "0x4c"
        with self.assertRaisesRegex(ProfileError, "call_info exceeds structure size"):
            validate_profile(value)

    def test_observation_must_match_profile_and_allow_list(self) -> None:
        path = ROOT / "profiles" / PROFILE_NAMES["php-8.3.35-apache-amd64-r0-spray"]
        profile = load_profile(path)
        observation = {
            "php": dict(profile.raw["build"]["php"]),
            "runtime": dict(profile.raw["runtime"]),
        }
        image = profile.raw["build"]["image"]
        with tempfile.TemporaryDirectory() as directory:
            observed = Path(directory) / "observed.json"
            observed.write_text(json.dumps(observation), encoding="utf-8")
            self.assertEqual(
                verify_observation(path, observed, profile.id, image["repo_digest"], image["image_id"]),
                observation["runtime"],
            )
            observation["runtime"]["workers"] = 2
            observed.write_text(json.dumps(observation), encoding="utf-8")
            with self.assertRaisesRegex(ProfileError, "runtime settings"):
                verify_observation(path, observed, profile.id, image["repo_digest"], image["image_id"])


class DockerVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ref = "php@sha256:" + "1" * 64
        self.image_id = "sha256:" + "2" * 64
        self.network = "p2s-net-test"

    def test_image_and_internal_network(self) -> None:
        image = {
            "Id": self.image_id,
            "Os": "linux",
            "Architecture": "amd64",
            "RepoDigests": [self.ref],
        }
        self.assertEqual(verify_image(image, self.ref, self.image_id), self.image_id)
        verify_network(
            {"Name": self.network, "Internal": True, "Ingress": False, "Scope": "local"},
            self.network,
        )
        with self.assertRaises(VerificationError):
            verify_network(
                {"Name": self.network, "Internal": False, "Ingress": False, "Scope": "local"},
                self.network,
            )

    def test_container_rejects_ports_and_wrong_volume_mode(self) -> None:
        data = {
            "Name": "/target",
            "Image": self.image_id,
            "Config": {"Image": self.ref, "User": "65532:65532"},
            "Platform": "linux",
            "State": {"Running": True},
            "HostConfig": {"NetworkMode": self.network, "PortBindings": None},
            "NetworkSettings": {
                "Ports": {"80/tcp": None},
                "Networks": {self.network: {"IPAddress": "172.31.0.2", "GlobalIPv6Address": ""}},
            },
            "Mounts": [
                {"Type": "volume", "Name": "proof", "Destination": "/out", "RW": True}
            ],
        }
        self.assertEqual(
            verify_container(
                data, "target", self.image_id, self.ref, self.network, True,
                "proof", "/out", "rw", "65532:65532",
            ),
            ["172.31.0.2"],
        )
        data["Config"]["User"] = "0:0"
        with self.assertRaisesRegex(VerificationError, "non-privileged"):
            verify_container(
                data, "target", self.image_id, self.ref, self.network, True,
                "proof", "/out", "rw", "65532:65532",
            )
        data["Config"]["User"] = "65532:65532"
        data["HostConfig"]["PortBindings"] = {"80/tcp": [{"HostPort": "8080"}]}
        with self.assertRaisesRegex(VerificationError, "published"):
            verify_container(data, "target", self.image_id, self.ref, self.network, True, "proof", "/out", "rw")


class RunnerStaticTests(unittest.TestCase):
    def test_runner_has_no_target_or_command_input(self) -> None:
        text = (ROOT / "run-local-docker-lab.sh").read_text(encoding="utf-8")
        self.assertIn("if (( $# != 0 ));", text)
        self.assertIn("--proof-target /out/p", text)
        self.assertNotIn("--cmd", text)
        self.assertNotRegex(text, r"(?:^|\s)--publish(?:\s|=)")
        self.assertNotRegex(text, r"(?:^|\s)-p\s")
        self.assertIn("network create --internal", text)
        self.assertIn("cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini", text)
        self.assertRegex(text, r'python@sha256:[0-9a-f]{64}')
        self.assertIn("--user 65532:65532", text)
        self.assertNotIn('$(id -u)', text)

    def test_runner_pins_each_profile_file_hash(self) -> None:
        text = (ROOT / "run-local-docker-lab.sh").read_text(encoding="utf-8")
        import hashlib

        for filename in PROFILE_NAMES.values():
            digest = hashlib.sha256((ROOT / "profiles" / filename).read_bytes()).hexdigest()
            self.assertIn(f'PROFILE_SHA256="{digest}"', text)
        self.assertIn("refusing modified profile file", text)
        copy_pos = text.index('cp -- "$profile_path" "$scratch_dir/in/profile.json"')
        hash_pos = text.index('sha256sum -- "$scratch_dir/in/profile.json"')
        self.assertLess(copy_pos, hash_pos)

    def test_php82_verified_profile_is_runner_allow_listed(self) -> None:
        names = "\n".join(path.name for path in (ROOT / "profiles").glob("*.json"))
        self.assertNotRegex(names, r"php-(?:7\.2|8\.1)")
        self.assertIn(PROFILE_NAMES["php-8.2.34-apache-amd64-pure-http-oom"], names)
        runner = (ROOT / "run-local-docker-lab.sh").read_text(encoding="utf-8")
        verified_block = runner.split("readonly -a VERIFIED_PROFILE_IDS=(", 1)[1].split(")", 1)[0]
        self.assertIn("php-8.2.34-apache-amd64-pure-http-oom", verified_block)
        support = (ROOT / "SUPPORT.md").read_text(encoding="utf-8")
        for version in ("PHP 7.2.34", "PHP 8.1.34", "PHP 8.2.34"):
            self.assertIn(version, support)
        self.assertIn("must not be interpreted as “not vulnerable”", support)

    def test_framework_documentation_matches_release_profiles_and_abi_name(self) -> None:
        framework = (ROOT / "FRAMEWORK.md").read_text(encoding="utf-8")
        self.assertNotIn("the one included runnable", framework)
        self.assertIn("PHP 8.2.34, 8.3.35, 8.4.26, and 8.5.11", framework)
        self.assertIn("zend_execute_data.run_time_cache", framework)
        schema = json.loads((ROOT / "profile-v1.schema.json").read_text(encoding="utf-8"))
        description = schema["$defs"]["abi"]["properties"]["zend_execute_data"]["description"]
        self.assertIn("run_time_cache", description)


class LegacyScopeProbeStaticTests(unittest.TestCase):
    def test_legacy_probe_is_benign_pinned_and_internal_only(self) -> None:
        legacy = ROOT.parent / "legacy-scope-probe"
        runner = (legacy / "run-local-docker-lab.sh").read_text(encoding="utf-8")
        client = (legacy / "probe.py").read_text(encoding="utf-8")
        self.assertIn("if (( $# != 0 ));", runner)
        self.assertIn("network create --internal", runner)
        self.assertIn("published_ports=false", runner)
        self.assertIn("rce_tested=false", runner)
        self.assertNotRegex(runner, r"(?:^|\s)--publish(?:\s|=)")
        self.assertNotIn("--cmd", runner)
        self.assertNotIn("system(", client)
        self.assertNotIn("subprocess", client)
        self.assertIn("host must be a private Docker address", client)

        versions = (
            "5.4.45", "5.5.38", "5.6.40", "7.0.33", "7.1.33",
            "7.2.34", "7.3.33", "7.4.33", "8.0.30", "8.1.34",
        )
        for version in versions:
            self.assertIn(f"php-{version}-apache-surface", runner)
            self.assertIn(f"VERSION={version}", runner)
        self.assertEqual(len(re.findall(r"IMAGE='[^']+@sha256:[0-9a-f]{64}'", runner)), 10)
        self.assertEqual(len(re.findall(r"IMAGE_ID='sha256:[0-9a-f]{64}'", runner)), 10)

    def test_legacy_evidence_labels_surface_not_rce(self) -> None:
        release_root = ROOT.parents[1]
        evidence = (release_root / "evidence" / "legacy-runtime-matrix.txt").read_text(
            encoding="utf-8"
        )
        report = (release_root / "docs" / "LEGACY-RUNTIME-MATRIX.md").read_text(
            encoding="utf-8"
        )
        for version in (
            "5.4.45", "5.5.38", "5.6.40", "7.0.33", "7.1.33",
            "7.2.34", "7.3.33", "7.4.33", "8.0.30", "8.1.34",
        ):
            self.assertIn(version, evidence)
            self.assertIn(version, report)
        self.assertIn("not RCE evidence", evidence)
        self.assertIn("does not demonstrate either CVE end to end", report)


class LegacyCalibratedRCEStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.legacy = ROOT.parent / "legacy-calibrated-rce"
        self.raw = self.legacy / "raw-key-partial-bucket"
        self.php81 = self.legacy / "php-8.1.34"

    def test_dispatcher_and_child_allow_lists_are_closed(self) -> None:
        dispatcher = (self.legacy / "run-local-docker-lab.sh").read_text(encoding="utf-8")
        self.assertIn("if (( $# != 0 ));", dispatcher)
        self.assertIn("profiles=(raw-key-partial-bucket php-8.1.34)", dispatcher)
        self.assertIn("raw-key-partial-bucket|php-8.1.34", dispatcher)
        self.assertNotIn("php-7.4.33/run-local-docker-lab.sh", dispatcher)

        raw_runner = (self.raw / "run-local-docker-lab.sh").read_text(encoding="utf-8")
        self.assertIn("if (( $# != 0 ));", raw_runner)
        for profile in ("php-7.3.33", "php-7.4.33", "php-8.0.30"):
            self.assertIn(f'"{profile}"', raw_runner)
        self.assertIn("refusing unknown raw-key profile ID", raw_runner)
        self.assertEqual(
            len(re.findall(r'(?:php|python)@sha256:[0-9a-f]{64}', raw_runner)),
            4,
        )

    def test_legacy_runners_are_internal_fixed_command_labs(self) -> None:
        fixed_users = {self.raw: "65532:65532", self.php81: "65534:65534"}
        for directory, fixed_user in fixed_users.items():
            runner = (directory / "run-local-docker-lab.sh").read_text(encoding="utf-8")
            with self.subTest(directory=directory.name):
                self.assertIn("network create --internal", runner)
                self.assertNotRegex(runner, r"(?:^|\s)--publish(?:\s|=)")
                self.assertNotRegex(runner, r"(?:^|\s)-p\s")
                self.assertIn("--read-only", runner)
                self.assertIn("--cap-drop ALL", runner)
                self.assertIn(f"--user {fixed_user}", runner)
                self.assertIn("local /proc calibration requires root", runner)

        raw_probe = (self.raw / "probe.py").read_text(encoding="utf-8")
        php81_probe = (self.php81 / "exploit.py").read_text(encoding="utf-8")
        self.assertIn('PROOF_COMMAND = b"id>/out/p\\x00"', raw_probe)
        self.assertIn('FIXED_COMMAND = b"id>/out/p"', php81_probe)
        self.assertIn("require_isolated_target()", raw_probe)
        self.assertIn("require_isolated_target()", php81_probe)
        self.assertNotIn("--cmd", raw_probe)
        self.assertNotIn("--cmd", php81_probe)

        php81_runner = (self.php81 / "run-local-docker-lab.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("rm -f /out/p", php81_runner)
        self.assertIn("test ! -e /out/p", php81_runner)
        self.assertIn("cleanup_failed", php81_runner)

    def test_legacy_runners_reject_non_unix_endpoint_before_daemon_info(self) -> None:
        for path in (
            self.raw / "run-local-docker-lab.sh",
            self.php81 / "run-local-docker-lab.sh",
            ROOT / "run-local-docker-lab.sh",
            ROOT.parent / "legacy-scope-probe" / "run-local-docker-lab.sh",
            ROOT.parent / "run-wsl-docker-lab.sh",
        ):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("DOCKER_CONTEXT", text)
                self.assertIn("DOCKER_HOST", text)
                rejection_match = re.search(
                    r"refusing non-(?:Unix|local) Docker endpoint", text
                )
                daemon_info_match = re.search(
                    r'(?m)^\s*"?\$DOCKER_BIN"? info', text
                )
                self.assertIsNotNone(rejection_match)
                self.assertIsNotNone(daemon_info_match)
                assert rejection_match is not None
                assert daemon_info_match is not None
                rejection = rejection_match.start()
                daemon_info = daemon_info_match.start()
                self.assertLess(rejection, daemon_info)

    def test_public_evidence_states_proc_calibration_limit(self) -> None:
        release_root = ROOT.parents[1]
        report = (release_root / "docs" / "LEGACY-RCE-VALIDATION.md").read_text(
            encoding="utf-8"
        )
        evidence = (release_root / "evidence" / "legacy-rce" / "README.md").read_text(
            encoding="utf-8"
        )
        for text in (report, evidence):
            self.assertIn("/proc", text)
            self.assertRegex(text, r"HTTP-only|HTTP only")
        for version in ("7.3.33", "7.4.33", "8.0.30", "8.1.34"):
            self.assertIn(version, report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
