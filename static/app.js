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
const refreshHistoryButton = document.getElementById("refreshHistoryButton");
const historyOutput = document.getElementById("historyOutput");
const projectSelect = document.getElementById("projectSelect");
const scanProjectSelect = document.getElementById("scanProjectSelect");
const newProjectButton = document.getElementById("newProjectButton");
const severityFilter = document.getElementById("severityFilter");
const findingSearch = document.getElementById("findingSearch");
const apiState = document.getElementById("apiState");

const kpiTrueRisk = document.getElementById("kpiTrueRisk");
const kpiEngine = document.getElementById("kpiEngine");
const kpiPorts = document.getElementById("kpiPorts");
const kpiExposed = document.getElementById("kpiExposed");
const kpiCve = document.getElementById("kpiCve");
const kpiRiskLevel = document.getElementById("kpiRiskLevel");

const riskChart = document.getElementById("riskChart");
const surfaceChart = document.getElementById("surfaceChart");

const navButtons = Array.from(document.querySelectorAll(".nav-item"));
const tabs = Array.from(document.querySelectorAll(".tab-panel"));

let lastScanResult = null;
let activeProjectId = "default";

const ORDER = ["critical", "high", "medium", "low", "info"];
const COLORS = {
    critical: "#ff4f6f",
    high: "#ff9551",
    medium: "#efc45d",
    low: "#5cc8ff",
    info: "#8da6c3",
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

function showError(message) {
    errorBox.textContent = message;
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

function drawDonutChart(canvasEl, valuesByKey) {
    const ctx = canvasEl.getContext("2d");
    const width = canvasEl.width;
    const height = canvasEl.height;
    const centerX = 118;
    const centerY = 120;
    const radius = 76;

    ctx.clearRect(0, 0, width, height);

    const values = ORDER.map((k) => Number(valuesByKey[k] || 0));
    const total = values.reduce((a, b) => a + b, 0);

    if (total <= 0) {
        ctx.fillStyle = "#95afce";
        ctx.font = "14px Outfit";
        ctx.fillText("No data", 96, 122);
        return;
    }

    let start = -Math.PI / 2;
    ORDER.forEach((key) => {
        const value = Number(valuesByKey[key] || 0);
        if (!value) {
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
    ctx.arc(centerX, centerY, 40, 0, Math.PI * 2);
    ctx.fillStyle = "#08152a";
    ctx.fill();

    ctx.fillStyle = "#d8e8ff";
    ctx.font = "700 17px Space Grotesk";
    ctx.fillText(String(total), centerX - 10, centerY + 5);

    ctx.font = "12px Outfit";
    let y = 42;
    ORDER.forEach((key) => {
        const val = Number(valuesByKey[key] || 0);
        ctx.fillStyle = COLORS[key];
        ctx.fillRect(230, y, 10, 10);
        ctx.fillStyle = "#c7ddfb";
        ctx.fillText(`${key.toUpperCase()} ${val}`, 246, y + 9);
        y += 20;
    });
}

function drawSurfaceChart(metrics = {}) {
    const ctx = surfaceChart.getContext("2d");
    const width = surfaceChart.width;
    const height = surfaceChart.height;
    ctx.clearRect(0, 0, width, height);

    const bars = [
        { label: "Open Ports", value: Number(metrics.open_ports || 0), color: "#5cc8ff" },
        { label: "Exposed", value: Number(metrics.exposed_services || 0), color: "#ff9551" },
        { label: "CVEs", value: Number(metrics.cve_candidates || 0), color: "#ff4f6f" },
        { label: "Hosts", value: Number(metrics.hosts_scanned || 0), color: "#1ec8a3" },
    ];

    const maxValue = Math.max(1, ...bars.map((b) => b.value));
    const barWidth = 44;
    const gap = 28;
    const baseY = 198;

    bars.forEach((bar, index) => {
        const x = 60 + index * (barWidth + gap);
        const scaled = Math.max(6, (bar.value / maxValue) * 120);

        ctx.fillStyle = "rgba(98, 131, 173, 0.18)";
        ctx.fillRect(x, baseY - 122, barWidth, 122);

        ctx.fillStyle = bar.color;
        ctx.fillRect(x, baseY - scaled, barWidth, scaled);

        ctx.fillStyle = "#d8e8ff";
        ctx.font = "700 12px Space Grotesk";
        ctx.fillText(String(bar.value), x + 8, baseY - scaled - 8);

        ctx.fillStyle = "#9eb8d9";
        ctx.font = "11px Outfit";
        ctx.fillText(bar.label, x - 6, baseY + 16);
    });
}

function drawTrendChart(points = []) {
    const ctx = surfaceChart.getContext("2d");
    const width = surfaceChart.width;
    const height = surfaceChart.height;
    ctx.clearRect(0, 0, width, height);

    ctx.strokeStyle = "rgba(88, 120, 160, 0.4)";
    ctx.lineWidth = 1;
    for (let i = 0; i < 4; i += 1) {
        const y = 36 + i * 50;
        ctx.beginPath();
        ctx.moveTo(36, y);
        ctx.lineTo(width - 24, y);
        ctx.stroke();
    }

    if (!points.length) {
        ctx.fillStyle = "#9ab6d8";
        ctx.font = "13px Outfit";
        ctx.fillText("Keine Trend-Daten vorhanden", 42, 58);
        return;
    }

    const maxValue = Math.max(1, ...points.map((point) => Number(point.true_risk_score || 0)));
    const chartW = width - 70;
    const chartH = height - 70;
    const stepX = chartW / Math.max(1, points.length - 1);

    ctx.strokeStyle = "#1ec7c3";
    ctx.lineWidth = 2.2;
    ctx.beginPath();
    points.forEach((point, index) => {
        const score = Number(point.true_risk_score || 0);
        const x = 36 + index * stepX;
        const y = 28 + chartH - (score / maxValue) * chartH;
        if (index === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });
    ctx.stroke();

    points.forEach((point, index) => {
        const score = Number(point.true_risk_score || 0);
        const x = 36 + index * stepX;
        const y = 28 + chartH - (score / maxValue) * chartH;
        ctx.fillStyle = "#1ec7c3";
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fill();

        const stamp = String(point.created_at || "").slice(11, 16) || "--:--";
        ctx.fillStyle = "#8ea9ca";
        ctx.font = "10px Outfit";
        ctx.fillText(stamp, x - 12, height - 12);
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
    const lines = [
        `Target: ${meta.target || "-"}`,
        `Type: ${meta.target_type || "-"}`,
        `Profile: ${meta.profile || "-"}`,
        `Port Strategy: ${meta.port_strategy || "-"}`,
        `Engine: ${meta.engine || "-"}`,
        `Started: ${meta.started_at || "-"}`,
        `Finished: ${meta.finished_at || "-"}`,
    ];
    scanMeta.innerHTML = lines.map((line) => `<div>${esc(line)}</div>`).join("");
}

function renderKpis(data) {
    const metrics = data.metrics || {};
    kpiTrueRisk.textContent = String(data.true_risk_score || 0);
    kpiEngine.textContent = data.meta?.engine || "-";
    kpiPorts.textContent = String(metrics.open_ports || 0);
    kpiExposed.textContent = String(metrics.exposed_services || 0);
    kpiCve.textContent = String(metrics.cve_candidates || 0);
    kpiRiskLevel.textContent = String(data.meta?.risk_level || "low").toUpperCase();
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

function renderFindingsTable(items) {
    if (!items.length) {
        return '<p class="summary-banner">Keine Findings fuer den aktuellen Filter.</p>';
    }

    const rows = items
        .slice(0, 900)
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
        <div class="summary-banner">Findings gesamt: ${items.length}</div>
        <div class="table-wrap">
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Host</th>
                        <th>Title</th>
                        <th>Evidence</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

function renderCveSection(cves = []) {
    if (!cves.length) {
        return "";
    }

    const rows = cves
        .slice(0, 60)
        .map(
            (item) =>
                `<tr><td>${esc(item.cve || "-")}</td><td>${esc(item.host || "-")}</td><td>${esc(item.title || "-")}</td><td>${esc(item.evidence || "-")}</td></tr>`
        )
        .join("");

    return `
        <div class="summary-banner">Open CVE Candidates: ${cves.length}</div>
        <div class="table-wrap">
            <table class="findings-table">
                <thead><tr><th>CVE</th><th>Host</th><th>Title</th><th>Evidence</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

function renderResult() {
    if (!lastScanResult) {
        return;
    }

    const selected = filteredFindings();
    resultOutput.innerHTML = `${renderFindingsTable(selected)}${renderCveSection(lastScanResult.cve_items || [])}`;

    renderRiskSummary(lastScanResult.risk_summary || {});
    renderMeta(lastScanResult.meta || {});
    renderKpis(lastScanResult);
    drawDonutChart(riskChart, lastScanResult.risk_summary || {});
    drawSurfaceChart(lastScanResult.metrics || {});
}

function syncProjectSelects(items) {
    const options = (items || []).map((item) => `<option value="${esc(item.id)}">${esc(item.name)}</option>`).join("");
    projectSelect.innerHTML = options;
    scanProjectSelect.innerHTML = options;

    projectSelect.value = activeProjectId;
    scanProjectSelect.value = activeProjectId;
}

async function loadProjects() {
    try {
        const response = await fetch("/api/projects");
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Projects konnten nicht geladen werden.");
        }
        const items = data.items || [];
        if (!items.length) {
            return;
        }
        if (!items.some((item) => item.id === activeProjectId)) {
            activeProjectId = items[0].id;
        }
        syncProjectSelects(items);
    } catch (_error) {
        // Keep defaults if project list fails.
    }
}

async function loadProjectDashboard() {
    try {
        const response = await fetch(`/api/projects/${encodeURIComponent(activeProjectId)}/dashboard`);
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Dashboard konnte nicht geladen werden.");
        }

        const totals = data.totals || {};
        kpiTrueRisk.textContent = String(totals.avg_risk || 0);
        kpiExposed.textContent = String(totals.exposed_services || 0);
        kpiCve.textContent = String(totals.cve_count || 0);
        kpiPorts.textContent = String(totals.open_ports || 0);
        kpiEngine.textContent = "history";
        kpiRiskLevel.textContent = Object.entries(data.risk_distribution || {}).sort((a, b) => b[1] - a[1])[0]?.[0]?.toUpperCase() || "LOW";

        drawDonutChart(riskChart, { ...(data.risk_distribution || {}), info: 0 });
        drawTrendChart(data.trend || []);
        renderRiskSummary({ ...(data.risk_distribution || {}), info: 0 });

        const metaLines = [
            `Project: ${data.project?.name || "-"}`,
            `Total Scans: ${totals.scans || 0}`,
            `Total Findings: ${totals.findings || 0}`,
            `Last Scan: ${(data.recent_scans || [])[0]?.created_at || "-"}`,
        ];
        scanMeta.innerHTML = metaLines.map((line) => `<div>${esc(line)}</div>`).join("");
    } catch (_error) {
        // Dashboard still works with latest scan fallback.
    }
}

function activateTab(tabName) {
    navButtons.forEach((button) => {
        button.classList.toggle("active", button.dataset.tab === tabName);
    });

    tabs.forEach((tab) => {
        tab.classList.toggle("active", tab.id === `tab-${tabName}`);
    });
}

window.activateTab = activateTab;

async function fetchPublicIp() {
    const endpoints = ["https://api64.ipify.org?format=json", "https://api.ipify.org?format=json"];
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
            // try next endpoint
        }
    }
    throw new Error("Public IP konnte nicht ermittelt werden.");
}

async function loadHealth() {
    try {
        const response = await fetch("/api/health");
        const data = await response.json();
        apiState.textContent = data.status === "ok" ? "online" : "unknown";
    } catch (_error) {
        apiState.textContent = "offline";
    }
}

function historyItemHtml(item) {
    return `
        <article class="history-item">
            <div class="history-line">
                <strong>${esc(item.target || "-")}</strong>
                <span>${esc(item.created_at || "-")}</span>
            </div>
            <div class="history-line">
                <span>Profile: ${esc(item.profile || "-")}</span>
                <span>Risk: ${esc(String(item.risk_level || "low").toUpperCase())}</span>
                <span>True Score: ${esc(item.true_risk_score || 0)}</span>
            </div>
            <div class="history-line">
                <span>Ports: ${esc(item.open_ports || 0)}</span>
                <span>Exposed: ${esc(item.exposed_services || 0)}</span>
                <span>CVEs: ${esc(item.cve_count || 0)}</span>
            </div>
            <div class="history-actions">
                <button class="ghost-button" type="button" onclick="window.loadReportDetail('${esc(item.id)}')">Open</button>
                <button class="primary-button" type="button" onclick="window.downloadReportPdf('${esc(item.id)}')">PDF</button>
            </div>
        </article>
    `;
}

async function loadHistory() {
    historyOutput.innerHTML = '<div class="summary-banner">History wird geladen...</div>';
    try {
        const response = await fetch(`/api/reports?limit=50&project_id=${encodeURIComponent(activeProjectId)}`);
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "History konnte nicht geladen werden.");
        }

        const items = data.items || [];
        if (!items.length) {
            historyOutput.innerHTML = '<div class="summary-banner">Noch keine Reports vorhanden.</div>';
            return;
        }

        historyOutput.innerHTML = items.map(historyItemHtml).join("");
    } catch (error) {
        historyOutput.innerHTML = `<div class="summary-banner">${esc(error.message || "History Fehler")}</div>`;
    }
}

window.loadHistory = loadHistory;

window.loadReportDetail = async function loadReportDetail(reportId) {
    try {
        const response = await fetch(`/api/reports/${encodeURIComponent(reportId)}`);
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Report konnte nicht geladen werden.");
        }

        lastScanResult = data;
        exportPdfButton.disabled = false;
        renderResult();
        activateTab("scan");
        setStatus("done", "Report loaded");
    } catch (error) {
        showError(error.message || "Report laden fehlgeschlagen.");
    }
};

window.downloadReportPdf = function downloadReportPdf(reportId) {
    const id = reportId || lastScanResult?.report_id;
    if (!id) {
        showError("Kein Report fuer den PDF Export vorhanden.");
        return;
    }

    window.open(`/api/reports/${encodeURIComponent(id)}/pdf`, "_blank", "noopener,noreferrer");
};

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();

    const payload = {
        target: targetInput.value.trim(),
        profile: profileSelect.value,
        port_strategy: portStrategySelect.value,
        project_id: scanProjectSelect.value || activeProjectId,
    };

    setStatus("running", "Scanning");
    scanButton.disabled = true;
    exportPdfButton.disabled = true;
    scanButton.textContent = "Scanne...";
    resultOutput.innerHTML = '<div class="summary-banner">Scan laeuft. Bitte warten...</div>';

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
        await loadHistory();
        await loadProjectDashboard();
        activateTab("dashboard");
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
        alert(`Deine oeffentliche IP: ${ip}`);
    } catch (error) {
        showError(error.message || "IP konnte nicht geladen werden.");
    }
});

exportPdfButton.addEventListener("click", () => window.downloadReportPdf());
refreshHistoryButton.addEventListener("click", loadHistory);

projectSelect.addEventListener("change", async () => {
    activeProjectId = projectSelect.value || "default";
    scanProjectSelect.value = activeProjectId;
    await loadHistory();
    await loadProjectDashboard();
});

scanProjectSelect.addEventListener("change", () => {
    activeProjectId = scanProjectSelect.value || "default";
    projectSelect.value = activeProjectId;
});

newProjectButton.addEventListener("click", async () => {
    const name = prompt("Projektname eingeben (z.B. simi.ch)");
    if (!name || !name.trim()) {
        return;
    }
    try {
        const response = await fetch("/api/projects", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: name.trim() }),
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Projekt konnte nicht erstellt werden.");
        }

        await loadProjects();
        activeProjectId = data.id;
        projectSelect.value = data.id;
        scanProjectSelect.value = data.id;
        await loadHistory();
        await loadProjectDashboard();
    } catch (error) {
        showError(error.message || "Projektanlage fehlgeschlagen.");
    }
});

navButtons.forEach((button) => {
    button.addEventListener("click", () => {
        activateTab(button.dataset.tab);
        if (button.dataset.tab === "history") {
            loadHistory();
        }
    });
});

renderRiskSummary({});
drawDonutChart(riskChart, {});
drawSurfaceChart({});
loadHealth();
loadProjects().then(async () => {
    await loadHistory();
    await loadProjectDashboard();
});
