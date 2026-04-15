const apiState = document.getElementById("apiState");
const dbState = document.getElementById("dbState");
const engineState = document.getElementById("engineState");

const projectSelect = document.getElementById("projectSelect");
const newProjectButton = document.getElementById("newProjectButton");
const projectPdfButton = document.getElementById("projectPdfButton");

const menuItems = Array.from(document.querySelectorAll(".menu-item"));
const tabs = Array.from(document.querySelectorAll(".tab"));

const kpiAvgRisk = document.getElementById("kpiAvgRisk");
const kpiScans = document.getElementById("kpiScans");
const kpiUnique = document.getElementById("kpiUnique");
const kpiAssets = document.getElementById("kpiAssets");

const trendChart = document.getElementById("trendChart");
const riskChart = document.getElementById("riskChart");
const riskLegend = document.getElementById("riskLegend");
const topVulns = document.getElementById("topVulns");
const windowDays = document.getElementById("windowDays");

const scanForm = document.getElementById("scanForm");
const targetInput = document.getElementById("target");
const profileSelect = document.getElementById("profile");
const portStrategySelect = document.getElementById("portStrategy");
const scanButton = document.getElementById("scanButton");
const reportPdfButton = document.getElementById("reportPdfButton");
const scanError = document.getElementById("scanError");
const scanResult = document.getElementById("scanResult");

const severityFilter = document.getElementById("severityFilter");
const sinceDays = document.getElementById("sinceDays");
const sortBy = document.getElementById("sortBy");
const sortDir = document.getElementById("sortDir");
const findingSearch = document.getElementById("findingSearch");
const refreshFindingsButton = document.getElementById("refreshFindingsButton");
const findingsTable = document.getElementById("findingsTable");

const historyList = document.getElementById("historyList");
const refreshHistoryButton = document.getElementById("refreshHistoryButton");

const ORDER = ["critical", "high", "medium", "low"];
const COLORS = {
    critical: "#ff5d73",
    high: "#ffc35c",
    medium: "#67b9ff",
    low: "#4cdd88",
};

let activeProjectId = "default";
let lastReportId = null;

function esc(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function showError(message) {
    scanError.textContent = message;
    scanError.classList.remove("hidden");
}

function clearError() {
    scanError.textContent = "";
    scanError.classList.add("hidden");
}

function activateTab(tabName) {
    menuItems.forEach((button) => {
        button.classList.toggle("active", button.dataset.tab === tabName);
    });

    tabs.forEach((tab) => {
        tab.classList.toggle("active", tab.id === `tab-${tabName}`);
    });
}

menuItems.forEach((button) => {
    button.addEventListener("click", () => {
        activateTab(button.dataset.tab);
        if (button.dataset.tab === "history") {
            loadHistory();
        }
        if (button.dataset.tab === "findings") {
            loadAggregatedFindings();
        }
    });
});

function drawTrend(points) {
    const ctx = trendChart.getContext("2d");
    const width = trendChart.width;
    const height = trendChart.height;
    ctx.clearRect(0, 0, width, height);

    ctx.strokeStyle = "rgba(126, 161, 198, 0.36)";
    ctx.lineWidth = 1;
    for (let i = 0; i < 5; i += 1) {
        const y = 26 + i * 46;
        ctx.beginPath();
        ctx.moveTo(30, y);
        ctx.lineTo(width - 20, y);
        ctx.stroke();
    }

    if (!points.length) {
        ctx.fillStyle = "#9bb4cb";
        ctx.font = "13px Manrope";
        ctx.fillText("No trend data in this window.", 36, 50);
        return;
    }

    const maxValue = Math.max(1, ...points.map((item) => Number(item.true_risk_score || 0)));
    const chartW = width - 66;
    const chartH = height - 54;
    const stepX = chartW / Math.max(points.length - 1, 1);

    ctx.strokeStyle = "#39d4b5";
    ctx.lineWidth = 2.2;
    ctx.beginPath();

    points.forEach((point, index) => {
        const val = Number(point.true_risk_score || 0);
        const x = 32 + stepX * index;
        const y = 20 + chartH - (val / maxValue) * chartH;
        if (index === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });
    ctx.stroke();

    points.forEach((point, index) => {
        const val = Number(point.true_risk_score || 0);
        const x = 32 + stepX * index;
        const y = 20 + chartH - (val / maxValue) * chartH;
        ctx.beginPath();
        ctx.fillStyle = "#67b9ff";
        ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fill();

        if (index % Math.ceil(points.length / 6) === 0) {
            const stamp = String(point.created_at || "").slice(5, 10);
            ctx.fillStyle = "#8fa9c3";
            ctx.font = "10px Manrope";
            ctx.fillText(stamp, x - 12, height - 8);
        }
    });
}

function drawRiskBars(summary) {
    const ctx = riskChart.getContext("2d");
    const width = riskChart.width;
    const height = riskChart.height;
    ctx.clearRect(0, 0, width, height);

    const bars = ORDER.map((key) => ({ key, val: Number(summary[key] || 0), color: COLORS[key] }));
    const maxValue = Math.max(1, ...bars.map((item) => item.val));

    const barWidth = 70;
    const gap = 34;
    const baseY = 214;

    bars.forEach((bar, index) => {
        const x = 56 + index * (barWidth + gap);
        const h = Math.max(6, (bar.val / maxValue) * 150);

        ctx.fillStyle = "rgba(133, 173, 210, 0.18)";
        ctx.fillRect(x, baseY - 150, barWidth, 150);

        ctx.fillStyle = bar.color;
        ctx.fillRect(x, baseY - h, barWidth, h);

        ctx.fillStyle = "#dce9f7";
        ctx.font = "700 12px Sora";
        ctx.fillText(String(bar.val), x + 28, baseY - h - 8);

        ctx.fillStyle = "#9bb4cb";
        ctx.font = "11px Manrope";
        ctx.fillText(bar.key.toUpperCase(), x + 13, baseY + 14);
    });

    riskLegend.innerHTML = ORDER.map((key) => `<div class="risk-item"><span>${key.toUpperCase()}</span><strong>${summary[key] || 0}</strong></div>`).join("");
}

function renderTopVulns(items) {
    if (!items.length) {
        topVulns.innerHTML = '<div class="list-item"><div class="list-line">No data available.</div></div>';
        return;
    }

    topVulns.innerHTML = items
        .slice(0, 12)
        .map((item) => {
            const sev = String(item.severity || "low").toLowerCase();
            return `
                <div class="list-item">
                    <div class="list-line">
                        <span class="badge badge-${esc(sev)}">${esc(sev)}</span>
                        <strong>Assets: ${esc(item.affected_assets || 0)}</strong>
                    </div>
                    <div class="list-line"><span>${esc(item.title || "Finding")}</span></div>
                    <div class="list-line"><span>${esc(item.cve || "-")}</span><span>${esc(item.type || "-")}</span></div>
                </div>
            `;
        })
        .join("");
}

function renderScanResult(data) {
    const rows = (data.finding_items || [])
        .map((item) => {
            const sev = String(item.severity || "low").toLowerCase();
            return `
                <tr>
                    <td><span class="badge badge-${esc(sev)}">${esc(sev)}</span></td>
                    <td class="mono">${esc(item.host || "-")}</td>
                    <td>${esc(item.title || "-")}</td>
                    <td>${esc(item.evidence || "-")}</td>
                    <td>${esc(item.type || "-")}</td>
                </tr>
            `;
        })
        .join("");

    scanResult.innerHTML = `
        <table class="table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Asset</th>
                    <th>Title</th>
                    <th>Evidence</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>${rows || '<tr><td colspan="5">No findings</td></tr>'}</tbody>
        </table>
    `;
}

function renderFindings(items) {
    const rows = (items || [])
        .map((item) => {
            const sev = String(item.severity || "low").toLowerCase();
            const assets = (item.assets || []).slice(0, 6).map((asset) => `<span>${esc(asset)}</span>`).join(", ");
            return `
                <tr>
                    <td><span class="badge badge-${esc(sev)}">${esc(sev)}</span></td>
                    <td>${esc(item.title || "-")}</td>
                    <td>${esc(item.cve || "-")}</td>
                    <td>${esc(item.asset_count || 0)}</td>
                    <td>${esc(item.occurrence_count || 0)}</td>
                    <td>${assets || "-"}</td>
                    <td>${esc(item.last_seen || "-")}</td>
                </tr>
            `;
        })
        .join("");

    findingsTable.innerHTML = `
        <table class="table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Vulnerability</th>
                    <th>CVE</th>
                    <th>Affected Assets</th>
                    <th>Occurrences</th>
                    <th>Assets (sample)</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>${rows || '<tr><td colspan="7">No matching findings.</td></tr>'}</tbody>
        </table>
    `;
}

function renderHistory(items) {
    if (!items.length) {
        historyList.innerHTML = '<div class="list-item"><div class="list-line">No reports yet.</div></div>';
        return;
    }

    historyList.innerHTML = items
        .map((item) => {
            const sev = String(item.risk_level || "low").toLowerCase();
            return `
                <div class="list-item">
                    <div class="list-line"><strong>${esc(item.target || "-")}</strong><span>${esc(item.created_at || "-")}</span></div>
                    <div class="list-line"><span>Profile: ${esc(item.profile || "-")}</span><span class="badge badge-${esc(sev)}">${esc(sev)}</span></div>
                    <div class="list-line"><span>Risk Score: ${esc(item.true_risk_score || 0)}</span><span>Findings: ${esc(item.total_findings || 0)}</span></div>
                    <div class="list-line">
                        <button class="btn ghost" type="button" onclick="window.openReport('${esc(item.id)}')">Open</button>
                        <button class="btn ghost" type="button" onclick="window.openReportPdf('${esc(item.id)}')">PDF</button>
                    </div>
                </div>
            `;
        })
        .join("");
}

async function loadHealth() {
    try {
        const response = await fetch("/api/health");
        const data = await response.json();
        apiState.textContent = data.status || "unknown";
        dbState.textContent = data.db_engine || "-";
        engineState.textContent = data.nmap_available ? "nmap" : "light";
    } catch (_error) {
        apiState.textContent = "offline";
        dbState.textContent = "-";
        engineState.textContent = "-";
    }
}

function syncProjectSelects(items) {
    const options = (items || []).map((project) => `<option value="${esc(project.id)}">${esc(project.name)}</option>`).join("");
    projectSelect.innerHTML = options;
    if (!(items || []).some((item) => item.id === activeProjectId)) {
        activeProjectId = (items || [])[0]?.id || "default";
    }
    projectSelect.value = activeProjectId;
}

async function loadProjects() {
    const response = await fetch("/api/projects");
    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || "Projects could not be loaded");
    }
    syncProjectSelects(data.items || []);
}

async function loadDashboard() {
    const days = Number(windowDays.value || 30);
    const response = await fetch(`/api/projects/${encodeURIComponent(activeProjectId)}/dashboard?window_days=${days}`);
    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || "Dashboard unavailable");
    }

    const totals = data.totals || {};
    kpiAvgRisk.textContent = String(totals.avg_risk || 0);
    kpiScans.textContent = String(totals.scans || 0);

    const uniqueCount = (data.top_vulnerabilities || []).length;
    const affectedAssets = (data.top_vulnerabilities || []).reduce((sum, item) => sum + Number(item.affected_assets || 0), 0);
    kpiUnique.textContent = String(uniqueCount);
    kpiAssets.textContent = String(affectedAssets);

    drawTrend(data.trend || []);
    drawRiskBars(data.risk_distribution || {});
    renderTopVulns(data.top_vulnerabilities || []);
}

async function loadAggregatedFindings() {
    const params = new URLSearchParams({
        severity: severityFilter.value,
        since_days: sinceDays.value,
        sort_by: sortBy.value,
        sort_dir: sortDir.value,
        search: findingSearch.value.trim(),
    });

    const response = await fetch(`/api/projects/${encodeURIComponent(activeProjectId)}/findings?${params.toString()}`);
    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || "Findings unavailable");
    }

    renderFindings(data.items || []);
}

async function loadHistory() {
    const response = await fetch(`/api/reports?limit=60&project_id=${encodeURIComponent(activeProjectId)}`);
    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || "History unavailable");
    }

    renderHistory(data.items || []);
}

window.openReport = async function openReport(reportId) {
    try {
        const response = await fetch(`/api/reports/${encodeURIComponent(reportId)}`);
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Report not found");
        }

        lastReportId = reportId;
        reportPdfButton.disabled = false;
        renderScanResult(data);
        activateTab("scanner");
    } catch (error) {
        showError(error.message || "Could not open report");
    }
};

window.openReportPdf = function openReportPdf(reportId) {
    window.open(`/api/reports/${encodeURIComponent(reportId)}/pdf`, "_blank", "noopener,noreferrer");
};

scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();

    const payload = {
        target: targetInput.value.trim(),
        profile: profileSelect.value,
        port_strategy: portStrategySelect.value,
        project_id: activeProjectId,
    };

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Scan failed");
        }

        lastReportId = data.report_id;
        reportPdfButton.disabled = false;

        renderScanResult(data);
        await Promise.all([loadDashboard(), loadAggregatedFindings(), loadHistory()]);
        activateTab("dashboard");
    } catch (error) {
        showError(error.message || "Scan failed");
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Start Scan";
    }
});

reportPdfButton.addEventListener("click", () => {
    if (!lastReportId) {
        showError("No report available for PDF export.");
        return;
    }
    window.open(`/api/reports/${encodeURIComponent(lastReportId)}/pdf`, "_blank", "noopener,noreferrer");
});

projectPdfButton.addEventListener("click", () => {
    const days = Number(windowDays.value || 30);
    window.open(
        `/api/projects/${encodeURIComponent(activeProjectId)}/pdf?window_days=${days}`,
        "_blank",
        "noopener,noreferrer"
    );
});

projectSelect.addEventListener("change", async () => {
    activeProjectId = projectSelect.value || "default";
    await Promise.all([loadDashboard(), loadAggregatedFindings(), loadHistory()]);
});

newProjectButton.addEventListener("click", async () => {
    const name = prompt("Projektname eingeben");
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
            throw new Error(data.error || "Project could not be created");
        }

        await loadProjects();
        activeProjectId = data.id;
        projectSelect.value = data.id;
        await Promise.all([loadDashboard(), loadAggregatedFindings(), loadHistory()]);
    } catch (error) {
        showError(error.message || "Project creation failed");
    }
});

windowDays.addEventListener("change", loadDashboard);
refreshFindingsButton.addEventListener("click", loadAggregatedFindings);
refreshHistoryButton.addEventListener("click", loadHistory);
severityFilter.addEventListener("change", loadAggregatedFindings);
sinceDays.addEventListener("change", loadAggregatedFindings);
sortBy.addEventListener("change", loadAggregatedFindings);
sortDir.addEventListener("change", loadAggregatedFindings);
findingSearch.addEventListener("input", () => {
    window.clearTimeout(window.__findingSearchTimer);
    window.__findingSearchTimer = window.setTimeout(loadAggregatedFindings, 260);
});

(async function bootstrap() {
    try {
        await loadHealth();
        await loadProjects();
        await Promise.all([loadDashboard(), loadAggregatedFindings(), loadHistory()]);
    } catch (error) {
        showError(error.message || "Initial load failed");
    }
})();
