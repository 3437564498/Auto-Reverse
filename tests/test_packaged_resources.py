from importlib.resources import files
from pathlib import Path


def test_packaged_machine_helpers_match_the_versioned_header():
    packaged = files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes()
    header = Path(__file__).resolve().parents[1] / "include/auto_reverse/machine_helpers.hpp"
    assert packaged == header.read_bytes()


def test_packaged_ghidra_exporter_and_pin_match_the_versioned_resources():
    root = Path(__file__).resolve().parents[1]
    for bundled, source in [
        ("ExportRawPcode.java", "ExportRawPcode.java"),
        ("ghidra-toolchain-pin.json", "toolchain-pin.json"),
    ]:
        packaged = files("auto_reverse").joinpath("resources", bundled).read_bytes()
        assert packaged == (root / "integrations" / "ghidra" / source).read_bytes()
