"""Shared filesystem helpers for checks. Never follows symlinks below the root."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator


def _guard_root(root: Path) -> bool:
    """The root must exist and must not itself be a symlink (discovery resolved it)."""
    return root.exists() and not root.is_symlink()


def _prune(d: Path, root: Path, dirnames: list[str], exclude: set[str], exclude_root: set[str]) -> None:
    banned = exclude | (exclude_root if d == root else set())
    dirnames[:] = [n for n in dirnames if n not in banned and not (d / n).is_symlink()]


def walk_files(root: Path, exclude: set[str], max_depth: int = 4, exclude_root: set[str] = frozenset()) -> Iterator[Path]:
    root = Path(root)
    if not _guard_root(root):
        return
    if root.is_file():
        yield root
        return
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        d = Path(dirpath)
        if len(d.parts) - base_depth >= max_depth:
            dirnames[:] = []
        _prune(d, root, dirnames, exclude, exclude_root)
        for fn in filenames:
            p = d / fn
            if p.is_symlink():
                continue
            yield p


def walk_entries(root: Path, exclude: set[str], max_depth: int = 3, exclude_root: set[str] = frozenset()) -> Iterator[Path]:
    """Files *and* directories below root (not root itself)."""
    root = Path(root)
    if not _guard_root(root) or not root.is_dir():
        return
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        d = Path(dirpath)
        if len(d.parts) - base_depth >= max_depth:
            dirnames[:] = []
        _prune(d, root, dirnames, exclude, exclude_root)
        for n in dirnames:
            yield d / n
        for fn in filenames:
            p = d / fn
            if not p.is_symlink():
                yield p


def rel(home: Path, p: Path) -> str:
    try:
        return str(p.relative_to(home))
    except ValueError:
        return str(p)
