"""Model temuan terstruktur, dipakai semua plugin. Severity/Confidence mengikuti
istilah umum OWASP; CVSS dihitung di tempat lain (risk engine, belum ada di fase ini)."""
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Confidence(str, Enum):
    """TENTATIVE = indikasi tak langsung (mis. dari kode status saja).
    FIRM = terverifikasi dari nilai respons aktual. CONFIRMED = dibuktikan dengan
    permintaan tambahan yang spesifik (mis. refleksi CORS)."""
    TENTATIVE = "Tentative"
    FIRM = "Firm"
    CONFIRMED = "Confirmed"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    remediation: str
    evidence: dict = field(default_factory=dict)
    owasp_refs: list = field(default_factory=list)
    plugin_id: str = ""

    def to_dict(self):
        return {
            "id": self.id, "title": self.title,
            "severity": self.severity.value, "confidence": self.confidence.value,
            "description": self.description, "remediation": self.remediation,
            "evidence": self.evidence, "owasp_refs": self.owasp_refs,
            "plugin": self.plugin_id,
        }
