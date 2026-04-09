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
const severityFilter = document.getElementById("severityFilter");
const findingSearch = document.getElementById("findingSearch");
const kpiEngine = document.getElementById("kpiEngine");
const kpiPorts = document.getElementById("kpiPorts");
const kpiFindings = document.getElementById("kpiFindings");
const kpiRiskLevel = document.getElementById("kpiRiskLevel");
const riskChart = document.getElementById("riskChart");

let lastScanResult = null;

const ORDER = ["critical", "high", "medium", "low"];
const COLORS = {
    critical: "#ff4b68",
    high: "#ff8e4a",
    medium: "#f0c45f",
    low: "#64ccff",
};

function esc(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function setStatus(status, text) {
    statusPill.className = `pill ${status}`;
    statusPill.textContent = text;
}

function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove("hidden");
}

function clearError() {
    errorBox.classList.add("hidden");
    errorBox.textContent = "";
}

function normalizeSeverity(raw) {
    const sev = String(raw || "").toLowerCase();
    return ORDER.includes(sev) ? sev : "low";
}

function riskLevel(summary = {}) {
    if ((summary.critical || 0) > 0) {
        return "Critical";
    }
    if ((summary.high || 0) > 0) {
        return "High";
    }
    if ((summary.medium || 0) > 0) {
        return "Medium";
    }
    return "Low";
}

function drawRiskChart(summary = {}) {
    const ctx = riskChart.getContext("2d");
    const width = riskChart.width;
    const height = riskChart.height;
    ctx.clearRect(0, 0, width, height);

    const values = ORDER.map((k) => Number(summary[k] || 0));
    const total = values.reduce((acc, v) => acc + v, 0);

    if (total === 0) {
        ctx.fillStyle = "#8ea3be";
        ctx.font = "14px Outfit";
        ctx.fillText("Keine Findings", 106, 115);
        return;
    }

    let start = -Math.PI / 2;
    const centerX = 104;
    const centerY = 110;
    const radius = 70;

    ORDER.forEach((key, index) => {
        const value = Number(summary[key] || 0);
        if (value <= 0) {
            return;
        }
        const angle = (value / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radius, start, start + angle);
        ctx.closePath();
        ctx.fillStyle = COLORS[key];
        ctx.fill();
        start += angle;
    });

    ctx.beginPath();
    ctx.arc(centerX, centerY, 35, 0, Math.PI * 2);
    ctx.fillStyle = "#07101b";
    ctx.fill();

    ctx.fillStyle = "#d8e9ff";
    ctx.font = "700 16px Space Grotesk";
    ctx.fillText(String(total), centerX - 8, centerY + 5);

    ctx.font = "12px Outfit";
    let y = 52;
    ORDER.forEach((key) => {
        const val = Number(summary[key] || 0);
        ctx.fillStyle = COLORS[key];
        ctx.fillRect(198, y, 10, 10);
        ctx.fillStyle = "#c7dcf5";
        ctx.fillText(`${key.toUpperCase()} ${val}`, 214, y + 9);
        y += 22;
    });
}

function renderRiskSummary(summary = {}) {
    riskSummary.innerHTML = "";
    ORDER.forEach((key) => {
        const row = document.createElement("div");
        row.className = "risk-item";
        row.innerHTML = `<span>${key.toUpperCase()}</span><strong>${summary[key] || 0}</strong>`;
        riskSummary.appendChild(row);
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
        `Nmap-Command: ${lastScanResult?.nmap?.command || "-"}`,
        `Start: ${meta.started_at || "-"}`,
        `Ende: ${meta.finished_at || "-"}`,
    ];

    lines.forEach((line) => {
        const div = document.createElement("div");
        div.textContent = line;
        scanMeta.appendChild(div);
    });
}

function renderKpis(data) {
    const hosts = data.hosts || [];
    const openPorts = hosts.reduce((acc, host) => acc + Number(host.open_port_count || 0), 0);
    const rLevel = riskLevel(data.risk_summary || {});

    kpiEngine.textContent = data.meta?.engine || "-";
    kpiPorts.textContent = String(openPorts);
    kpiFindings.textContent = String(data.total_findings || 0);
    kpiRiskLevel.textContent = rLevel;
}

function filteredFindings() {
    if (!lastScanResult) {
        return [];
    }

    const selectedSeverity = severityFilter.value;
    const term = findingSearch.value.trim().toLowerCase();

    return (lastScanResult.finding_items || []).filter((item) => {
        const sev = normalizeSeverity(item.severity);
        if (selectedSeverity !== "all" && sev !== selectedSeverity) {
            return false;
        }

        if (!term) {
            return true;
        }

        const text = `${item.host} ${item.title} ${item.evidence} ${item.type}`.toLowerCase();
        return text.includes(term);
    });
}

function renderHostQuickSummary(hosts) {
    if (!hosts.length) {
        return "";
    }

    const items = hosts
        .map((host) => {
            const name = esc(host.host);
            const portCount = Number(host.open_port_count || 0);
            const findingCount = Number(host.finding_count || 0);
            return `<li class="port-item"><strong>${name}</strong> · Open Ports: ${portCount} · Findings: ${findingCount}</li>`;
        })
        .join("");

    return `
        <div>
            <div class="section-title">Host-Übersicht</div>
            <ul class="port-list">${items}</ul>
        </div>
    `;
}

function renderFindingsTable(items) {
    if (!items.length) {
        return '<p class="empty-hint">Für den aktuellen Filter wurden keine Findings gefunden.</p>';
    }

    const rows = items
        .slice(0, 800)
        .map((item) => {
            const sev = normalizeSeverity(item.severity);
            return `
                <tr>
                    <td><span class="sev-pill sev-${esc(sev)}">${esc(sev)}</span></td>
                    <td class="mono">${esc(item.host || "-")}</td>
                    <td>${esc(item.title || "-")}</td>
                    <td>${esc(item.evidence || "-")}</td>
                    <td>${esc(item.type || "-")}</td>
                </tr>
            `;
        })
        .join("");

    return `
        <div class="table-wrap">
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Host</th>
                        <th>Titel</th>
                        <th>Evidence</th>
                        <th>Typ</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

function renderResult() {
    const data = lastScanResult;
    const hosts = data.hosts || [];
    const summary = data.risk_summary || {};
    const selected = filteredFindings();

    const text = `Risk Level: ${riskLevel(summary)} · Findings gesamt: ${data.total_findings || 0} · Angezeigt: ${selected.length}`;

    resultOutput.innerHTML = `
        <div class="summary-banner">${esc(text)}</div>
        ${renderFindingsTable(selected)}
        ${renderHostQuickSummary(hosts)}
    `;

    renderRiskSummary(summary);
    drawRiskChart(summary);
    renderMeta(data.meta || {});
    renderKpis(data);
}

function buildPrintableReportHtml(data) {
    const summary = data.risk_summary || {};
    const findings = data.finding_items || [];
    const meta = data.meta || {};

    const findingRows = findings
        .slice(0, 600)
        .map((item) => {
            const sev = normalizeSeverity(item.severity);
            return `
                <tr>
                    <td>${esc(sev.toUpperCase())}</td>
                    <td>${esc(item.host || "-")}</td>
                    <td>${esc(item.title || "-")}</td>
                    <td>${esc(item.evidence || "-")}</td>
                </tr>
            `;
        })
        .join("");

    return `
<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>vScanner Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 24px; color: #1a2433; }
h1 { margin: 0 0 10px; }
.meta { margin-bottom: 12px; }
.grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 14px; }
.box { border: 1px solid #bccbe0; padding: 8px; border-radius: 6px; }
.table { width: 100%; border-collapse: collapse; font-size: 12px; }
.table th, .table td { border: 1px solid #c2d1e5; text-align: left; padding: 6px; vertical-align: top; }
.table th { background: #e9f1fb; }
</style>
</head>
<body>
<h1>vScanner Security Report</h1>
<div class="meta">Target: <strong>${esc(meta.target || "-")}</strong> | Risk Level: <strong>${esc((meta.risk_level || "low").toUpperCase())}</strong> | Profile: <strong>${esc(meta.profile || "-")}</strong></div>
<div class="meta">Start: ${esc(meta.started_at || "-")} | End: ${esc(meta.finished_at || "-")} | Engine: ${esc(meta.engine || "-")}</div>
<div class="grid">
    <div class="box">Critical: <strong>${summary.critical || 0}</strong></div>
    <div class="box">High: <strong>${summary.high || 0}</strong></div>
    <div class="box">Medium: <strong>${summary.medium || 0}</strong></div>
    <div class="box">Low: <strong>${summary.low || 0}</strong></div>
</div>
<table class="table">
<thead><tr><th>Severity</th><th>Host</th><th>Title</th><th>Evidence</th></tr></thead>
<tbody>${findingRows || '<tr><td colspan="4">No findings available</td></tr>'}</tbody>
</table>
</body>
</html>
`;
}

function downloadReport() {
    if (!lastScanResult) {
        showError("Es ist noch kein Scan-Ergebnis zum Export vorhanden.");
        return;
    }

    const html = buildPrintableReportHtml(lastScanResult);
    const reportWindow = window.open("", "_blank", "noopener,noreferrer");
    if (!reportWindow) {
        showError("Popup wurde blockiert. Bitte Popups für diese Seite erlauben.");
        return;
    }

    reportWindow.document.open();
    reportWindow.document.write(html);
    reportWindow.document.close();
    reportWindow.focus();
    reportWindow.print();
}

async function fetchPublicIp() {
    const endpoints = [
        "https://api64.ipify.org?format=json",
        "https://api.ipify.org?format=json",
    ];

    for (const url of endpoints) {
        try {
            const response = await fetch(url, { method: "GET" });
            if (!response.ok) {
                continue;
            }
            const data = await response.json();
            if (data.ip) {
                return data.ip;
            }
        } catch (_error) {
            // Try next endpoint.
        }
    }

    throw new Error("Public IP konnte nicht ermittelt werden.");
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
    resultOutput.innerHTML = '<p class="empty-hint">Scan läuft. Das kann je nach Profil und Port-Abdeckung dauern.</p>';

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Unbekannter Fehler");
        }

        lastScanResult = data;
        exportPdfButton.disabled = false;
        renderResult();
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

severityFilter.addEventListener("change", () => {
    if (lastScanResult) {
        renderResult();
    }
});

findingSearch.addEventListener("input", () => {
    if (lastScanResult) {
        renderResult();
    }
});

ipButton.addEventListener("click", async () => {
    clearError();
    try {
        const ip = await fetchPublicIp();
        alert(`Deine öffentliche IP: ${ip}`);
    } catch (error) {
        showError(error.message || "IP konnte nicht geladen werden.");
    }
});

exportPdfButton.addEventListener("click", downloadReport);

renderRiskSummary({});
drawRiskChart({});
