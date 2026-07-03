from __future__ import annotations

from pathlib import Path

from tests import shell_harness


def test_resolve_bash_prefers_non_windowsapps_path(monkeypatch):
    monkeypatch.setattr(shell_harness.shutil, "which", lambda _: r"C:\msys64\usr\bin\bash.exe")
    assert shell_harness.resolve_bash() == r"C:\msys64\usr\bin\bash.exe"


def test_resolve_bash_prefers_git_bash_when_windowsapps_wins(monkeypatch):
    monkeypatch.setattr(
        shell_harness.shutil,
        "which",
        lambda _: r"C:\Users\JustD\AppData\Local\Microsoft\WindowsApps\bash.exe",
    )
    monkeypatch.setattr(
        shell_harness,
        "_git_bash_candidates",
        lambda: [r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"],
    )
    monkeypatch.setattr(Path, "exists", lambda self: str(self) == r"C:\Program Files\Git\bin\bash.exe")
    assert shell_harness.resolve_bash() == r"C:\Program Files\Git\bin\bash.exe"


def test_resolve_bash_falls_back_to_windowsapps_when_no_git_bash_exists(monkeypatch):
    windowsapps = r"C:\Users\JustD\AppData\Local\Microsoft\WindowsApps\bash.exe"
    monkeypatch.setattr(shell_harness.shutil, "which", lambda _: windowsapps)
    monkeypatch.setattr(shell_harness, "_git_bash_candidates", lambda: [r"C:\Program Files\Git\bin\bash.exe"])
    monkeypatch.setattr(Path, "exists", lambda self: False)
    assert shell_harness.resolve_bash() == windowsapps
