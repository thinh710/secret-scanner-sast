from __future__ import annotations

from pathlib import Path
import pathspec


class IgnoreFilter:
    def __init__(self, base_path, extra_patterns=None):
        self.base_path = Path(base_path).resolve()
        patterns = self._load_defaults()
        if extra_patterns:
            patterns.extend(extra_patterns)
        self.spec = pathspec.PathSpec.from_lines("gitwildmatch", patterns)

    def _load_defaults(self):
        default_file = Path(__file__).parent.parent / "config" / "default_ignore.txt"
        if default_file.exists():
            with open(default_file, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return []

    def is_ignored(self, path):
        try:
            rel_path = path.relative_to(self.base_path)
        except ValueError:
            return True
        return self.spec.match_file(str(rel_path.as_posix()))
