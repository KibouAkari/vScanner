const form = document.getElementById("scanForm");
const targetInput = document.getElementById("target");
const profileSelect = document.getElementById("profile");
const portStrategySelect = document.getElementById("portStrategy");
const scanButton = document.getElementById("scanButton");
const statusPill = document.getElementById("statusPill");
const resultOutput = document.getElementById("resultOutput");
const errorBox = document.getElementById("errorBox");
const riskSummary = document.getElementById("riskSummary");
const scanMeta = document.getElementById("scanMeta");
const ipButton = document.getElementById("ipButton");
const exportPdfButton = document.getElementById("exportPdfButton");
const kpiEngine = document.getElementById("kpiEngine");
const kpiPorts = document.getElementById("kpiPorts");
const kpiFindings = document.getElementById("kpiFindings");
const kpiRiskLevel = document.getElementById("kpiRiskLevel");
const riskChart = document.getElementById("riskChart");

let lastScanResult = null;

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLORS = {
    critical: "#ff4b68",
    high: "#ff8e4a",
    medium: "#f0c45f",
    low: "#64ccff",
    info: "#8ea3be",
};

function setStatus(status, text) {
    statusPill.className = `pill ${status}`;
    statusPill.textContent = text;
}

function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
}

function clearError() {
    errorBox.classList.add("hidden");
    errorBox.textContent = "";
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function getRiskLevel(summary = {}) {
    if ((summary.critical || 0) > 0) {
        return "Kritisch";
    }
    if ((summary.high || 0) > 0) {
        return "Hoch";
    }
    if ((summary.medium || 0) > 0) {
        return "Mittel";
    }
    if ((summary.low || 0) > 0) {
        return "Niedrig";
    }
    return "Info";
}

function renderRiskSummary(summary = {}) {
    riskSummary.innerHTML = "";

    SEVERITY_ORDER.forEach((key) => {
        const value = Number(summary[key] || 0);
        const row = document.createElement("div");
        row.className = "risk-item";
        row.innerHTML = `<span>${key.toUpperCase()}</span><strong>${value}</strong>`;
        riskSummary.appendChild(row);
    });
}

function drawRiskChart(summary = {}) {
    const ctx = riskChart.getContext("2d");
    const width = riskChart.width;
    const height = riskChart.height;
    ctx.clearRect(0, 0, width, height);

    const values = SEVERITY_ORDER.map((key) => Number(summary[key] || 0));
    const total = values.reduce((acc, n) => acc + n, 0);

    if (total === 0) {
        ctx.fillStyle = "#8ea3be";
        ctx.font = "14px Outfit";
        ctx.fillText("Keine Findings", 106, 115);
        return;
    }

    let start = -Math.PI / 2;
    const centerX = 110;
    const centerY = 110;
    const radius = 72;

    values.forEach((value, index) => {
        const key = SEVERITY_ORDER[index];
        if (value <= 0) {
            return;
        }

        const angle = (value / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radius, start, start + angle);
        ctx.closePath();
        ctx.fillStyle = SEVERITY_COLORS[key];
        ctx.fill();
        start += angle;
    });

    ctx.beginPath();
    ctx.arc(centerX, centerY, 36, 0, Math.PI * 2);
    ctx.fillStyle = "#07101b";
    ctx.fill();

    ctx.fillStyle = "#d6e8ff";
    ctx.font = "700 17px Space Grotesk";
    ctx.fillText(String(total), centerX - 10, centerY + 6);

    ctx.font = "12px Outfit";
    let legendY = 42;
    SEVERITY_ORDER.forEach((key) => {
        const value = Number(summary[key] || 0);
        ctx.fillStyle = SEVERITY_COLORS[key];
        ctx.fillRect(206, legendY, 10, 10);
        ctx.fillStyle = "#c5dbf5";
        ctx.fillText(`${key.toUpperCase()} ${value}`, 221, legendY + 9);
        legendY += 23;
    });
}

function renderMeta(meta = {}) {
    scanMeta.innerHTML = "";
    const lines = [
        `Ziel: ${meta.target || "-"}`,
        `Typ: ${meta.target_type || "-"}`,
        `Profil: ${meta.profile || "-"}`,
        `Port-Abdeckung: ${meta.port_strategy || "-"}`,
        `Engine: ${meta.engine || "-"}`,
        `Start: ${meta.started_at || "-"}`,
        `Ende: ${meta.finished_at || "-"}`,
    ];

    lines.forEach((line) => {
        const el = document.createElement("div");
        el.textContent = line;
        scanMeta.appendChild(el);
    });
}

function renderKpis(data) {
    const hosts = data.hosts || [];
    const openPortCount = hosts.reduce((acc, host) => {
        const openPorts = (host.ports || []).filter((p) => p.state === "open");
        return acc + openPorts.length;
    }, 0);

    const riskLevel = getRiskLevel(data.risk_summary || {});

    kpiEngine.textContent = data.meta?.engine || "-";
    kpiPorts.textContent = String(openPortCount);
    kpiFindings.textContent = String(data.total_findings || 0);
    kpiRiskLevel.textContent = riskLevel;
}

function renderPorts(openPorts) {
    if (!openPorts.length) {
        return '<p class="empty-hint">Keine offenen Ports erkannt.</p>';
    }

    const items = openPorts
        .map((p) => {
            const title = [p.name, p.product, p.version].filter(Boolean).join(" ");
            const banner = p.banner ? `<div class="mono">Banner: ${escapeHtml(p.banner)}</div>` : "";
            return `
                <li class="port-item">
                    <strong class="mono">${escapeHtml(p.protocol)}/${escapeHtml(p.port)}</strong>
                    <div>${escapeHtml(title || "Service unbekannt")}</div>
                    ${banner}
                </li>
            `;
        })
        .join("");

    return `<ul class="port-list">${items}</ul>`;
}

function renderFindings(findings) {
    if (!findings.length) {
        return '<p class="empty-hint">Keine zusätzlichen Findings erkannt.</p>';
    }

    const items = findings
        .slice(0, 60)
        .map((finding) => {
            const sev = (finding.severity || "info").toLowerCase();
            return `
                <li class="finding-item sev-${escapeHtml(sev)}">
                    <div class="finding-title">
                        <span class="tag">${escapeHtml(sev.toUpperCase())}</span>
                        <span>${escapeHtml(finding.title || "Finding")}</span>
                    </div>
                    <div>${escapeHtml(finding.evidence || "-")}</div>
                </li>
            `;
        })
        .join("");

    return `<ul class="finding-list">${items}</ul>`;
}

function renderWebEvidence(evidenceList) {
    if (!evidenceList.length) {
        return '<p class="empty-hint">Keine Web-Evidence erkannt.</p>';
    }

    const items = evidenceList
        .map((entry) => {
            const title = entry.title ? `<div>Titel: ${escapeHtml(entry.title)}</div>` : "";
            const loginCount = entry.login_pages ? entry.login_pages.length : 0;
            return `
                <li class="web-item">
                    <div><strong>Port ${escapeHtml(entry.port)}</strong> · Status ${escapeHtml(entry.status)}</div>
                    <div class="mono">${escapeHtml(entry.url || "-")}</div>
                    ${title}
                    <div>Login-Seiten: ${escapeHtml(loginCount)}</div>
                </li>
            `;
        })
        .join("");

    return `<ul class="web-list">${items}</ul>`;
}

function renderHost(host) {
    const openPorts = (host.ports || []).filter((entry) => entry.state === "open");
    const findings = host.findings || [];
    const webEvidence = host.web_evidence || [];

    const hostnames = host.hostnames && host.hostnames.length ? host.hostnames.join(", ") : "-";

    return `
        <article class="host-card">
            <div class="host-head">
                <h4 class="host-title">${escapeHtml(host.host)} <span class="tag">${escapeHtml(host.state || "unknown")}</span></h4>
                <span class="tag">Open Ports: ${escapeHtml(openPorts.length)}</span>
            </div>
            <div>Hostnames: ${escapeHtml(hostnames)}</div>
            <div>Reverse DNS: ${escapeHtml(host.reverse_dns || "-")}</div>
            <section>
                <div class="section-title">Offene Ports</div>
                ${renderPorts(openPorts)}
            </section>
            <section>
                <div class="section-title">Findings</div>
                ${renderFindings(findings)}
            </section>
            <section>
                <div class="section-title">Web Evidence</div>
                ${renderWebEvidence(webEvidence)}
            </section>
        </article>
    `;
}

function renderResult(data) {
    const hosts = data.hosts || [];

    if (hosts.length === 0) {
        resultOutput.innerHTML = '<p class="empty-hint">Keine Hosts erkannt. Prüfe Ziel und Berechtigung.</p>';
    } else {
        const cards = hosts.map((host) => renderHost(host)).join("");
        resultOutput.innerHTML = cards;
    }

    renderRiskSummary(data.risk_summary || {});
    drawRiskChart(data.risk_summary || {});
    renderMeta(data.meta || {});
    renderKpis(data);
}

async function exportPdfReport() {
    if (!lastScanResult) {
        showError("Kein Scan-Ergebnis vorhanden.");
        return;
    }

    clearError();
    exportPdfButton.disabled = true;
    exportPdfButton.textContent = "Export läuft...";

    try {
        const response = await fetch("/api/report/pdf", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ scan_result: lastScanResult }),
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || "PDF-Export fehlgeschlagen.");
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "vscanner-report.pdf";
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        showError(error.message || "PDF-Export fehlgeschlagen.");
    } finally {
        exportPdfButton.disabled = false;
        exportPdfButton.textContent = "PDF-Report exportieren";
    }
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();

    const payload = {
        target: targetInput.value.trim(),
        profile: profileSelect.value,
        port_strategy: portStrategySelect.value,
    };

    setStatus("running", "Scanning");
    scanButton.disabled = true;
    exportPdfButton.disabled = true;
    scanButton.textContent = "Scanne...";
    resultOutput.innerHTML = '<p class="empty-hint">Scan läuft. Je nach Profil kann das etwas dauern.</p>';

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Unbekannter Fehler");
        }

        lastScanResult = data;
        exportPdfButton.disabled = false;
        renderResult(data);
        setStatus("done", "Fertig");
    } catch (error) {
        showError(error.message || "Scan fehlgeschlagen.");
        setStatus("idle", "Fehler");
        resultOutput.innerHTML = "";
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Scan starten";
    }
});

ipButton.addEventListener("click", async () => {
    clearError();
    try {
        const response = await fetch("/api/client-ip");
        const data = await response.json();
        alert(`Erkannte IP: ${data.ip || "unbekannt"}`);
    } catch (error) {
        showError("IP konnte nicht geladen werden.");
    }
});

exportPdfButton.addEventListener("click", exportPdfReport);

renderRiskSummary({});
drawRiskChart({});
renderKpis({});
