"""TLS/SSL Security Analyzer. Pasif: hanya membuka koneksi TLS standar ke IP
yang sama yang sudah divalidasi SSRF-safe, membaca sertifikat & versi
protokol yang dipilih server — ini yang terjadi tiap kali browser membuka
situs HTTPS, bukan fuzzing atau downgrade attack."""
import socket
import ssl
from datetime import datetime, timezone

from findings import Confidence, Finding, Severity
from plugins import Plugin, ScanContext, register

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
EXPIRY_WARN_DAYS = 14


@register
class TLSAnalyzer(Plugin):
    id = "tls"
    name = "TLS/SSL Security Analyzer"
    owasp_refs = ["WSTG-CRYP-01", "ASVS 9.1"]

    def run(self, ctx: ScanContext) -> list:
        if ctx.scheme != "https":
            return [Finding(
                id="tls-not-used", title="Situs tidak menggunakan HTTPS",
                severity=Severity.HIGH, confidence=Confidence.FIRM,
                description="Koneksi awal menggunakan HTTP polos, bukan HTTPS.",
                evidence={"scheme": ctx.scheme},
                remediation="Aktifkan HTTPS dan redirect semua trafik HTTP ke HTTPS.",
                owasp_refs=self.owasp_refs)]

        findings = []
        try:
            sslctx = ssl.create_default_context()
            with socket.create_connection((ctx.ip, ctx.port), timeout=6) as sock:
                with sslctx.wrap_socket(sock, server_hostname=ctx.hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    version = tls_sock.version()
        except Exception as e:
            # Gagal probe TLS tambahan tidak boleh menggagalkan scan utama —
            # situs tetap bisa diakses lewat httpx walau socket TLS mentah gagal.
            return [Finding(
                id="tls-probe-failed", title="Pemeriksaan TLS tidak dapat diselesaikan",
                severity=Severity.INFO, confidence=Confidence.TENTATIVE,
                description=f"Tidak bisa membuka koneksi TLS langsung untuk diperiksa: {e}",
                evidence={}, remediation="Tidak ada tindakan; periksa manual bila perlu.",
                owasp_refs=self.owasp_refs)]

        if version in WEAK_PROTOCOLS:
            findings.append(Finding(
                id="tls-weak-protocol", title=f"Protokol TLS usang digunakan ({version})",
                severity=Severity.HIGH, confidence=Confidence.FIRM,
                description=f"Server bernegosiasi menggunakan {version}, yang sudah dianggap "
                             "tidak aman dan ditinggalkan oleh browser modern.",
                evidence={"negotiated_protocol": version},
                remediation="Nonaktifkan TLS 1.0/1.1/SSLv3 di server, wajibkan minimal TLS 1.2.",
                owasp_refs=self.owasp_refs))

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(Finding(
                        id="tls-cert-expired", title="Sertifikat TLS sudah kedaluwarsa",
                        severity=Severity.CRITICAL, confidence=Confidence.FIRM,
                        description=f"Sertifikat kedaluwarsa pada {not_after}.",
                        evidence={"not_after": not_after},
                        remediation="Segera perbarui sertifikat TLS.", owasp_refs=self.owasp_refs))
                elif days_left < EXPIRY_WARN_DAYS:
                    findings.append(Finding(
                        id="tls-cert-expiring-soon", title="Sertifikat TLS akan segera kedaluwarsa",
                        severity=Severity.MEDIUM, confidence=Confidence.FIRM,
                        description=f"Sertifikat kedaluwarsa dalam {days_left} hari ({not_after}).",
                        evidence={"not_after": not_after, "days_left": days_left},
                        remediation="Perbarui sertifikat sebelum kedaluwarsa, idealnya otomatis "
                                     "(mis. certbot/ACME).", owasp_refs=self.owasp_refs))
            except ValueError:
                pass
        return findings
