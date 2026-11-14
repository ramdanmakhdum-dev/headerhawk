"""Plugin interface + feature flags. Setiap detector baru adalah subclass Plugin
yang didaftarkan lewat @register. Arsitektur lama (scanner.analyze untuk header
inti) TIDAK diubah — plugin ini menambah, bukan menggantikan.

Kontrak keamanan untuk SEMUA plugin:
- run() hanya boleh membaca data dari ScanContext atau lewat ctx.probe*() —
  tidak ada akses jaringan lain yang diizinkan.
- ctx.probe*() hanya mendukung GET/HEAD read-only ke IP yang sudah divalidasi
  SSRF-safe oleh scanner, tanpa redirect, tanpa payload di body request.
- Satu plugin yang error TIDAK BOLEH menggagalkan keseluruhan scan.
"""
import os
from dataclasses import dataclass
from typing import Callable, List, Optional


@dataclass
class ScanContext:
    url: str                 # URL akhir (setelah redirect) yang dipindai
    ip: str                  # IP yang sudah divalidasi publik & dipakai konek
    hostname: str
    port: int
    scheme: str
    status_code: int
    headers: object           # httpx.Headers dari permintaan utama
    probe_with_headers: Callable[[dict], object]       # (extra_headers) -> httpx.Headers
    probe_path: Callable[[str], "tuple[object, int]"]  # (path) -> (headers, status)


class Plugin:
    id: str = "base"
    name: str = "Base Plugin"
    owasp_refs: List[str] = []
    default_enabled: bool = True

    def run(self, ctx: ScanContext) -> list:
        raise NotImplementedError


_REGISTRY: dict = {}


def register(plugin_cls):
    _REGISTRY[plugin_cls.id] = plugin_cls()
    return plugin_cls


def _flag_overrides() -> dict:
    """FEATURE_FLAGS env, contoh: '-tls,+exposed-files' mematikan tls,
    menyalakan exposed-files secara eksplisit. Default tiap plugin dipakai
    kalau tidak disebut."""
    raw = os.environ.get("FEATURE_FLAGS", "")
    out = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith("-"):
            out[part[1:]] = False
        elif part.startswith("+"):
            out[part[1:]] = True
        else:
            out[part] = True
    return out


def enabled_plugins() -> List[Plugin]:
    overrides = _flag_overrides()
    return [p for pid, p in _REGISTRY.items() if overrides.get(pid, p.default_enabled)]


def run_all(ctx: ScanContext) -> "tuple[list, list]":
    """Jalankan semua plugin aktif. Return (findings, plugin_errors) — error satu
    plugin tidak pernah menghentikan plugin lain atau scan utama."""
    findings, errors = [], []
    for plugin in enabled_plugins():
        try:
            for f in (plugin.run(ctx) or []):
                f.plugin_id = plugin.id
                findings.append(f)
        except Exception as e:
            errors.append({"plugin": plugin.id, "error": str(e)[:200]})
    return findings, errors
