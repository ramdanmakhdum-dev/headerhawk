        let chartInstance = null;
        let currentUrl = "";

        // Semua data dari server/situs target dianggap tidak tepercaya.
        const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
        const $ = id => document.getElementById(id);

        async function startScan() {
            const url = $('url-input').value.trim();
            if (!url) return alert("Masukkan URL dulu!");
            currentUrl = url;

            $('loader').style.display = 'block';
            $('result-container').style.display = 'none';
            $('ai-output').style.display = 'none';

            try {
                const response = await fetch(`/scan?url=${encodeURIComponent(url)}`);
                const data = await response.json();
                if (data.detail) {
                    alert("Error: " + data.detail);
                    return;
                }
                renderResult(data);
            } catch (err) {
                alert("Gagal terhubung ke server.");
            } finally {
                $('loader').style.display = 'none';
            }
        }

        function renderResult(data) {
            $('result-container').style.display = 'flex';

            $('score-val').innerText = data.score;
            $('grade-val').innerText = "Grade " + data.grade;
            const color = data.score >= 75 ? '#10b981' : (data.score >= 50 ? '#f59e0b' : '#ef4444');
            $('grade-val').style.color = color;

            if (chartInstance) chartInstance.destroy();
            chartInstance = new Chart($('scoreChart').getContext('2d'), {
                type: 'doughnut',
                data: { datasets: [{ data: [data.score, 100 - data.score], backgroundColor: [color, '#334155'], borderWidth: 0 }] },
                options: { cutout: '75%', plugins: { legend: { display: false }, tooltip: { enabled: false } } }
            });

            const ip = data.ip_info || {};
            $('ip-info-box').innerHTML = `
                <p><span>IP Address</span> <b>${esc(ip.query || '-')}</b></p>
                <p><span>Country</span> <b>${esc(ip.country || '-')}</b></p>
                <p><span>City</span> <b>${esc(ip.city || '-')}</b></p>
                <p><span>ISP</span> <b>${esc(ip.isp || '-')}</b></p>`;

            $('vt-info-box').innerHTML = `<i class="fa-solid fa-shield-virus"></i> ${esc(data.virustotal || 'Tidak ada data')}`;

            // Defensif: tetap jalan walau backend belum kirim field baru.
            const found = data.found_headers || {};
            const weak = data.weak_headers || {};
            const missing = data.missing_headers || [];
            const cookies = data.cookie_issues || [];

            let html = '';
            for (const key of Object.keys(found)) {
                const issues = weak[key];
                const badge = issues ? '<span class="badge yellow">Lemah</span>' : '<span class="badge green">Aman</span>';
                const note = issues ? `<small style="color:#f59e0b">${esc(issues.join('; '))}</small>` : '';
                html += `<p style="flex-direction:column"><span style="display:flex;justify-content:space-between;width:100%;gap:8px">${esc(key)} ${badge}</span>${note}</p>`;
            }
            missing.forEach(m => {
                html += `<p><span>${esc(m)}</span> <span class="badge red">Hilang</span></p>`;
            });
            if (cookies.length) {
                html += `<p style="flex-direction:column"><span style="display:flex;justify-content:space-between;width:100%">cookie <span class="badge yellow">${cookies.length} masalah</span></span>` +
                        `<small style="color:#f59e0b">${cookies.map(esc).join('<br>')}</small></p>`;
            }
            $('headers-box').innerHTML = html;
        }

        async function requestAIFix() {
            if (!currentUrl) return;
            const btn = $('btn-ai');
            const out = $('ai-output');
            const pw = $('ai-password').value;
            if (!pw) { out.style.display = 'block'; out.textContent = 'Masukkan password AI dulu.'; return; }

            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> AI Sedang Menganalisis...';
            btn.disabled = true;
            out.style.display = 'block';
            out.textContent = "Menghubungi Cyber Security Expert AI...";

            try {
                const response = await fetch(`/explain?url=${encodeURIComponent(currentUrl)}`, { headers: { 'X-AI-Password': pw } });
                const resData = await response.json();
                if (resData.detail) {
                    out.textContent = "Error: " + resData.detail;
                } else {
                    // Output AI bisa dipengaruhi isi situs target: wajib disanitasi.
                    out.innerHTML = DOMPurify.sanitize(marked.parse(resData.explanation || ''));
                }
            } catch (err) {
                out.textContent = "Gagal mendapatkan analisis AI.";
            } finally {
                btn.innerHTML = '<i class="fa-solid fa-robot"></i> Minta Analisis & Perbaikan AI';
                btn.disabled = false;
            }
        }
    
$('scan-btn').addEventListener('click', startScan);
$('url-input').addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
$('btn-ai').addEventListener('click', requestAIFix);
