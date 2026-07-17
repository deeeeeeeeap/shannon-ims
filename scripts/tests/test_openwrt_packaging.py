from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OPENWRT = ROOT / "packaging" / "openwrt"


class OpenWrtPackagingContractTest(unittest.TestCase):
    def test_release_does_not_ship_an_unverified_openwrt_wrapper(self) -> None:
        notice = OPENWRT / "README.md"
        self.assertTrue(notice.is_file(), "OpenWrt support policy must be explicit")

        content = notice.read_text(encoding="utf-8")
        self.assertIn("Not supported", content)
        self.assertIn("不受支持", content)

        deployable = [
            path
            for path in OPENWRT.rglob("*")
            if path.is_file() and path != notice
        ]
        self.assertEqual(
            deployable,
            [],
            "unsupported OpenWrt packaging must not retain deployable init/config files",
        )


if __name__ == "__main__":
    unittest.main()
