"""CORS Security Analyzer. Pasif: hanya membaca header dari respons normal,
plus satu permintaan GET tambahan dengan header Origin kustom untuk menguji
apakah server me-refleksikan origin asing — ini permintaan HTTP biasa yang
dikirim browser mana pun, bukan payload serangan."""
from findings import Confidence, Finding, Severity
from plugins import Plugin, ScanContext, register

PROBE_ORIGIN = "https://headerhawk-cors-probe.invalid"


@register
class CORSAnalyzer(Plugin):
    id = "cors"
    name = "CORS Security Analyzer"
    owasp_refs = ["WSTG-CLNT-07", "ASVS 13.2.1"]

    def run(self, ctx: ScanContext) -> list:
        findings = []
        acao = ctx.headers.get("access-control-allow-origin")
        acac = (ctx.headers.get("access-control-allow-credentials") or "").lower()

        if acao == "*" and acac == "true":
            findings.append(Finding(
                id="cors-wildcard-credentials", title="CORS: wildcard origin dengan credentials",
                severity=Severity.HIGH, confidence=Confidence.FIRM,
                description=("Access-Control-Allow-Origin: * dikombinasikan dengan "
                              "Access-Control-Allow-Credentials: true. Browser modern menolak "
                              "kombinasi literal ini, tapi konfigurasi semacam ini biasanya "
                              "menandakan server me-refleksikan origin apa pun secara dinamis."),
                evidence={"access-control-allow-origin": acao, "access-control-allow-credentials": acac},
                remediation="Validasi Origin terhadap allowlist eksplisit; jangan pernah "
                             "gabungkan wildcard dengan credentials.",
                owasp_refs=self.owasp_refs))
        elif acao == "*":
            findings.append(Finding(
                id="cors-wildcard", title="CORS: semua origin diizinkan",
                severity=Severity.LOW, confidence=Confidence.FIRM,
                description=("Access-Control-Allow-Origin: * mengizinkan permintaan cross-origin "
                              "dari domain mana pun. Wajar untuk API publik tanpa data sensitif, "
                              "tapi berisiko bila endpoint ini mengembalikan data milik pengguna."),
                evidence={"access-control-allow-origin": acao},
                remediation="Batasi ke origin yang memang perlu mengakses API ini, kecuali "
                             "endpoint memang dimaksudkan publik sepenuhnya.",
                owasp_refs=self.owasp_refs))

        try:
            probed = ctx.probe_with_headers({"Origin": PROBE_ORIGIN})
        except Exception:
            probed = None
        if probed is not None:
            reflected = probed.get("access-control-allow-origin")
            reflect_cred = (probed.get("access-control-allow-credentials") or "").lower()
            if reflected == PROBE_ORIGIN:
                sev = Severity.CRITICAL if reflect_cred == "true" else Severity.HIGH
                findings.append(Finding(
                    id="cors-reflects-arbitrary-origin",
                    title="CORS: server me-refleksikan origin arbitrer" +
                          (" dengan credentials" if sev == Severity.CRITICAL else ""),
                    severity=sev, confidence=Confidence.CONFIRMED,
                    description=(f"Mengirim header 'Origin: {PROBE_ORIGIN}' (domain yang jelas "
                                 "tidak valid) membuat server membalas Access-Control-Allow-Origin "
                                 "dengan nilai yang sama persis. Ini berarti SEMBARANG origin "
                                 "diizinkan membaca respons" +
                                 (" TERMASUK dengan cookie/sesi pengguna (credentials: true)."
                                  if sev == Severity.CRITICAL else ".")),
                    evidence={"probe_origin": PROBE_ORIGIN, "reflected_as": reflected,
                              "credentials": reflect_cred},
                    remediation="Ganti logika reflect-origin dengan pengecekan terhadap "
                                 "allowlist domain yang eksplisit di server.",
                    owasp_refs=self.owasp_refs))
        return findings
