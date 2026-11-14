"""Common Sensitive File Exposure Check. Pasif: HEAD read-only ke daftar path
tetap yang umum berisi data sensitif. Tidak pernah mengunduh isi berkas,
tidak pernah mencoba membaca/menebak konten — ini pengecekan "ada/tidak",
teknik standar di setiap scanner konfigurasi (termasuk securityheaders.com,
Nuclei config templates, dsb), bukan eksploitasi path traversal."""
from findings import Confidence, Finding, Severity
from plugins import Plugin, ScanContext, register

SENSITIVE_PATHS = ["/.env", "/.git/HEAD", "/.git/config", "/.DS_Store",
                   "/wp-config.php.bak", "/config.php.bak", "/.aws/credentials"]


@register
class ExposedFilesDetector(Plugin):
    id = "exposed-files"
    name = "Common Sensitive File Exposure Check"
    owasp_refs = ["WSTG-CONF-04", "ASVS 1.4.4"]

    def run(self, ctx: ScanContext) -> list:
        findings = []
        for path in SENSITIVE_PATHS:
            try:
                _, status = ctx.probe_path(path)
            except Exception:
                continue
            if status == 200:
                findings.append(Finding(
                    id=f"exposed-file:{path}", title=f"Berkas berpotensi sensitif terekspos: {path}",
                    severity=Severity.HIGH, confidence=Confidence.TENTATIVE,
                    description=("Server merespons 200 OK untuk path ini. Tidak ada konten "
                                 "yang diambil atau dibaca — hanya status respons HEAD. "
                                 "Beberapa server mengembalikan 200 untuk semua path (soft-404), "
                                 "jadi verifikasi manual tetap diperlukan sebelum dilaporkan."),
                    evidence={"path": path, "status": status},
                    remediation="Blokir akses publik ke berkas ini di level web server, "
                                 "atau pindahkan keluar dari webroot.",
                    owasp_refs=self.owasp_refs))
        return findings
