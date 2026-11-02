import json
import shutil
import tempfile
from pathlib import Path

from exposure_radio.pipeline import DEMO_CURR, DEMO_PREV, run_cycle
from exposure_radio.policy import Memory


def demo_cycle(**kw):
    kw.setdefault("memory", Memory())
    kw.setdefault("commit", False)
    return run_cycle(**kw)


class TempCopy:
    """Copy a demo snapshot so a test can damage it."""

    def __init__(self, source: Path = DEMO_CURR):
        self.source = source

    def __enter__(self) -> Path:
        self.dir = Path(tempfile.mkdtemp(prefix="er-test-"))
        target = self.dir / self.source.name
        shutil.copytree(self.source, target)
        return target

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)


def edit_json(path: Path, fn) -> None:
    data = json.loads(path.read_text())
    data = fn(data) or data
    path.write_text(json.dumps(data))


__all__ = ["demo_cycle", "TempCopy", "edit_json", "DEMO_PREV", "DEMO_CURR"]
