from __future__ import annotations

import math


def get_language_from_extension(file_path):
    ext = file_path.suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".php": "php",
        ".java": "java",
        ".rb": "ruby",
        ".go": "go",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
        ".cs": "csharp",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".html": "html",
        ".htm": "html",
        ".xml": "xml",
        ".json": "json",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".sh": "shell",
        ".bash": "shell",
        ".ps1": "powershell",
    }
    return mapping.get(ext, "unknown")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def keyword_nearby(line: str, keywords: list[str], start: int, end: int, window: int = 120) -> bool:
    if not keywords:
        return True
    s = max(0, start - window)
    e = min(len(line), end + window)
    ctx = line[s:e].lower()
    return any((k or "").lower() in ctx for k in keywords)
