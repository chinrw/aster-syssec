from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from aster_syssec import __version__

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class VersionTests(unittest.TestCase):
    def test_v04_package_versions_stay_in_sync(self) -> None:
        main_project = tomllib.loads(
            (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        lab_project = tomllib.loads(
            (PROJECT_ROOT / "packages/aster-syssec-lab/pyproject.toml").read_text(
                encoding="utf-8"
            )
        )["project"]
        flake = (PROJECT_ROOT / "flake.nix").read_text(encoding="utf-8")

        self.assertEqual(__version__, "0.4.0")
        self.assertEqual(main_project["version"], __version__)
        self.assertEqual(lab_project["version"], __version__)
        self.assertEqual(lab_project["dependencies"], [f"aster-syssec=={__version__}"])
        self.assertEqual(flake.count(f'version = "{__version__}";'), 2)


if __name__ == "__main__":
    unittest.main()
