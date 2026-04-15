const apiState = document.getElementById("apiState");
const dbState = document.getElementById("dbState");
const engineState = document.getElementById("engineState");

const projectSelect = document.getElementById("projectSelect");
const newProjectButton = document.getElementById("newProjectButton");
const projectCsvButton = document.getElementById("projectCsvButton");
const projectPdfButton = document.getElementById("projectPdfButton");

const menuItems = Array.from(document.querySelectorAll(".menu-item"));
const tabs = Array.from(document.querySelectorAll(".tab"));

const kpiAvgRisk = document.getElementById("kpiAvgRisk");
const kpiScans = document.getElementById("kpiScans");
const kpiUnique = document.getElementById("kpiUnique");
const kpiAssets = document.getElementById("kpiAssets");
const recentScans = document.getElementById("recentScans");
const exposureSummary = document.getElementById("exposureSummary");

const trendChart = document.getElementById("trendChart");
const riskChart = document.getElementById("riskChart");
const severityStackChart = document.getElementById("severityStackChart");
const riskLegend = document.getElementById("riskLegend");
const severityHeatmap = document.getElementById("severityHeatmap");
const topVulns = document.getElementById("topVulns");
const windowDays = document.getElementById("windowDays");

const scanForm = document.getElementById("scanForm");
const scannerTypeSelect = document.getElementById("scannerType");
const scannerModeCards = Array.from(document.querySelectorAll(".scanner-mode-card"));
const targetInput = document.getElementById("target");
const profileSelect = document.getElementById("profile");
const portStrategySelect = document.getElementById("portStrategy");
const portStrategyGroup = document.getElementById("portStrategyGroup");
const scanButton = document.getElementById("scanButton");
const intelOnlyButton = document.getElementById("intelOnlyButton");
const scanModeNote = document.getElementById("scanModeNote");
const networkHints = document.getElementById("networkHints");
const reportPdfButton = document.getElementById("reportPdfButton");
const reportCsvButton = document.getElementById("reportCsvButton");
const scanError = document.getElementById("scanError");
const scanResult = document.getElementById("scanResult");

const severityFilter = document.getElementById("severityFilter");
const sinceDays = document.getElementById("sinceDays");
const sortBy = document.getElementById("sortBy");
const sortDir = document.getElementById("sortDir");
const findingSearch = document.getElementById("findingSearch");
const refreshFindingsButton = document.getElementById("refreshFindingsButton");
const findingsCsvButton = document.getElementById("findingsCsvButton");
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
let trendChartInstance = null;
let riskChartInstance = null;
let severityStackChartInstance = null;

function scannerSettings(mode) {
    if (mode === "network") {
        return {
            profile: "network",
            portStrategy: "aggressive",
            placeholder: "192.168.1.0/24",
            note: "Network scanner expects a CIDR target and is intended for authorized local/lab networks.",
            disableProfile: true,
            hidePortStrategy: true,
            showIntelOnly: false,
        };
    }

    if (mode === "stealth_intel") {
        return {
            profile: "stealth",
            portStrategy: "standard",
            placeholder: "example.com, 8.8.8.8",
            note: "Stealth & intel uses low-noise profiling and passive metadata collection. It does not bypass monitoring or SIEM.",
            disableProfile: true,
            hidePortStrategy: true,
            showIntelOnly: true,
        };
    }

    return {
        profile: "light",
        portStrategy: "standard",
        placeholder: "example.com, 8.8.8.8, 192.168.1.0/24",
        note: "Standard scanner supports domain/IP targets with light or deep scan profiles.",
        disableProfile: false,
        hidePortStrategy: false,
        showIntelOnly: false,
    };
}

function applyScannerMode(mode) {
    const cfg = scannerSettings(mode);
    scannerTypeSelect.value = mode;
    targetInput.placeholder = cfg.placeholder;
    scanModeNote.textContent = cfg.note;

    const profileFieldGroup = document.getElementById("profileFieldGroup");
    if (profileFieldGroup) {
        profileFieldGroup.style.display = cfg.disableProfile ? "none" : "block";
    }
    if (portStrategyGroup) {
        portStrategyGroup.style.display = cfg.hidePortStrategy ? "none" : "block";
    }
    if (intelOnlyButton) {
        intelOnlyButton.classList.toggle("hidden", !cfg.showIntelOnly);
    }

    scannerModeCards.forEach((card) => {
        card.classList.toggle("active", card.dataset.mode === mode);
    });

    profileSelect.disabled = cfg.disableProfile;
    profileSelect.value = cfg.profile;
    portStrategySelect.value = cfg.portStrategy;
}

async function fetchIntelData(target) {
    if (!target) {
        throw new Error("Target is required for intel lookup");
    }

    try {
        const resp = await fetch("/api/intel", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target }),
        });
        const data = await resp.json();
        if (resp.ok) {
            return data;
        }
        throw new Error(data.error || "Intel request failed");
    } catch (err) {
        throw err;
    }
}

async function guessLocalNetworkHints() {
    const hints = ["192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"];
    const local = ["127.0.0.1", "localhost", "::1"];
    const host = (window.location.hostname || "").trim();

    if (host && !local.includes(host)) {
        if (/^192\.168\./.test(host)) {
            const parts = host.split(".");
            hints.unshift(`${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
        } else if (/^10\./.test(host)) {
            const parts = host.split(".");
            hints.unshift(`${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
        } else if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) {
            const parts = host.split(".");
            hints.unshift(`${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
        }
    }

    try {
        const response = await fetch("/api/network-hints");
        const data = await response.json();
        if (response.ok && Array.isArray(data.hints)) {
            hints.unshift(...data.hints.map((item) => String(item || "").trim()).filter(Boolean));
        }
    } catch (_error) {
        // Keep static fallback when client IP hints are unavailable.
    }

    return [...new Set(hints)].slice(0, 8);
}

async function renderNetworkHints() {
    if (!networkHints) {
        return;
    }
    const hints = await guessLocalNetworkHints();
    networkHints.innerHTML = hints
        .map((cidr) => `<button type="button" class="hint-chip" data-cidr="${esc(cidr)}">${esc(cidr)}</button>`)
        .join("");

    networkHints.querySelectorAll(".hint-chip").forEach((btn) => {
        btn.addEventListener("click", () => {
            targetInput.value = btn.dataset.cidr || "";
            scannerTypeSelect.value = "network";
            applyScannerMode("network");
        });
    });
}

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

function setChipState(element, state) {
    const chip = element?.closest?.(".chip");
    if (!chip) {
        return;
    }
    chip.classList.remove("state-live", "state-degraded", "state-offline", "state-warn");
    chip.classList.add(`state-${state}`);
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
    if (!window.Chart) {
        return;
    }

    if (trendChartInstance) {
        trendChartInstance.destroy();
    }

    const labels = points.map((item) => String(item.created_at || "").slice(0, 10));
    const risks = points.map((item) => Number(item.true_risk_score || 0));
    const findings = points.map((item) => Number(item.total_findings || 0));

    trendChartInstance = new window.Chart(trendChart, {
        type: "line",
        data: {
            labels,
            datasets: [
                {
                    label: "Risk Score",
                    data: risks,
                    borderColor: "#39d4b5",
                    backgroundColor: "rgba(57,212,181,0.2)",
                    borderWidth: 2,
                    tension: 0.3,
                    pointRadius: 2,
                    yAxisID: "y",
                },
                {
                    label: "Findings",
                    data: findings,
                    borderColor: "#67b9ff",
                    backgroundColor: "rgba(103,185,255,0.16)",
                    borderWidth: 2,
                    tension: 0.25,
                    pointRadius: 2,
                    yAxisID: "y1",
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 950,
                easing: "easeOutQuart",
            },
            plugins: {
                legend: {
                    labels: { color: "#dce9f7" },
                },
            },
            scales: {
                x: {
                    ticks: { color: "#9bb4cb", maxTicksLimit: 8 },
                    grid: { color: "rgba(126,161,198,0.2)" },
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: "#9bb4cb" },
                    grid: { color: "rgba(126,161,198,0.2)" },
                },
                y1: {
                    beginAtZero: true,
                    position: "right",
                    ticks: { color: "#9bb4cb" },
                    grid: { drawOnChartArea: false },
                },
            },
        },
    });
}

function drawRiskBars(summary) {
    if (!window.Chart) {
        return;
    }

    if (riskChartInstance) {
        riskChartInstance.destroy();
    }

    const values = ORDER.map((key) => Number(summary[key] || 0));
    riskChartInstance = new window.Chart(riskChart, {
        type: "doughnut",
        data: {
            labels: ORDER.map((key) => key.toUpperCase()),
            datasets: [
                {
                    data: values,
                    backgroundColor: ORDER.map((key) => COLORS[key]),
                    borderColor: "rgba(11,17,26,0.4)",
                    borderWidth: 2,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1250,
                easing: "easeOutExpo",
            },
            plugins: {
                legend: { display: false },
            },
            cutout: "62%",
        },
    });

    riskLegend.innerHTML = ORDER.map((key) => `<div class="risk-item"><span>${key.toUpperCase()}</span><strong>${summary[key] || 0}</strong></div>`).join("");
}

function drawSeverityStack(points) {
    if (!window.Chart || !severityStackChart) {
        return;
    }

    if (severityStackChartInstance) {
        severityStackChartInstance.destroy();
    }

    const labels = points.map((item) => String(item.created_at || "").slice(5, 10));
    const critical = points.map((item) => Number(item.critical || 0));
    const high = points.map((item) => Number(item.high || 0));
    const medium = points.map((item) => Number(item.medium || 0));
    const low = points.map((item) => Number(item.low || 0));

    severityStackChartInstance = new window.Chart(severityStackChart, {
        type: "bar",
        data: {
            labels,
            datasets: [
                { label: "Critical", data: critical, backgroundColor: "rgba(255,93,115,0.85)", stack: "sev" },
                { label: "High", data: high, backgroundColor: "rgba(255,195,92,0.85)", stack: "sev" },
                { label: "Medium", data: medium, backgroundColor: "rgba(103,185,255,0.85)", stack: "sev" },
                { label: "Low", data: low, backgroundColor: "rgba(76,221,136,0.82)", stack: "sev" },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 1100,
                easing: "easeOutQuart",
            },
            plugins: { legend: { labels: { color: "#dce9f7" } } },
            scales: {
                x: {
                    stacked: true,
                    ticks: { color: "#9bb4cb", maxTicksLimit: 10 },
                    grid: { color: "rgba(126,161,198,0.15)" },
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    ticks: { color: "#9bb4cb" },
                    grid: { color: "rgba(126,161,198,0.18)" },
                },
            },
        },
    });
}

function renderSeverityHeatmap(items) {
    if (!severityHeatmap) {
        return;
    }
    if (!items.length) {
        severityHeatmap.innerHTML = '<div class="heat-cell"><strong>No data</strong><small>Run scans to build heatmap.</small></div>';
        return;
    }

    const bands = [
        { key: "critical", label: "Critical", cls: "heat-critical" },
        { key: "high", label: "High", cls: "heat-high" },
        { key: "medium", label: "Medium", cls: "heat-medium" },
        { key: "low", label: "Low", cls: "heat-low" },
    ];

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const item of items) {
        const sev = String(item.severity || "low").toLowerCase();
        if (counts[sev] !== undefined) {
            counts[sev] += Number(item.affected_assets || 0);
        }
    }

    severityHeatmap.innerHTML = bands
        .map((band) => {
            const val = counts[band.key] || 0;
            const descriptor = val > 20 ? "Widespread" : val > 8 ? "Elevated" : val > 0 ? "Contained" : "None";
            return `<div class="heat-cell ${band.cls}"><strong>${band.label}: ${val}</strong><small>${descriptor} exposure</small></div>`;
        })
        .join("");
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

function renderRecentScans(items) {
    if (!recentScans) {
        return;
    }
    if (!items.length) {
        recentScans.innerHTML = '<div class="list-item"><div class="list-line">No scans in this window.</div></div>';
        return;
    }

    recentScans.innerHTML = items
        .slice(0, 10)
        .map((item) => {
            const sev = String(item.risk_level || "low").toLowerCase();
            return `
                <div class="list-item">
                    <div class="list-line"><strong>${esc(item.target || "-")}</strong><span>${esc(String(item.created_at || "").slice(0, 16).replace("T", " "))}</span></div>
                    <div class="list-line"><span>Profile: ${esc(item.profile || "-")}</span><span class="badge badge-${esc(sev)}">${esc(sev)}</span></div>
                    <div class="list-line"><span>Risk: ${esc(item.true_risk_score || 0)}</span><span>Findings: ${esc(item.total_findings || 0)}</span></div>
                </div>
            `;
        })
        .join("");
}

function renderExposureSummary(totals) {
    if (!exposureSummary) {
        return;
    }

    const cards = [
        { label: "Open Ports", value: totals.open_ports || 0 },
        { label: "Exposed Services", value: totals.exposed_services || 0 },
        { label: "CVE Candidates", value: totals.cve_count || 0 },
        { label: "Total Findings", value: totals.findings || 0 },
    ];
    exposureSummary.innerHTML = cards
        .map((item) => `<div class="risk-item"><span>${esc(item.label)}</span><strong>${esc(item.value)}</strong></div>`)
        .join("");
}

function renderIntelBlock(intelData) {
    if (!intelData || typeof intelData !== "object") {
        return "";
    }

    const dnsA = (intelData.dns?.A || [])
        .map((v) => String(v || "").trim())
        .filter(Boolean)
        .map((v) => esc(v))
        .join(", ") || "-";
    const dnsMx = (intelData.dns?.MX || [])
        .map((v) => String(v || "").trim())
        .filter(Boolean)
        .map((v) => esc(v))
        .join(", ") || "-";
    const sslIssuer = intelData.ssl?.issuer?.commonName || intelData.ssl?.issuer?.organizationName || "-";
    const sslValidUntil = intelData.ssl?.notAfter || "-";
    const services = Array.isArray(intelData.services) ? intelData.services : [];

    const serviceRows = services
        .slice(0, 12)
        .map(
            (svc) => `<tr><td class="mono">${esc(svc.ip || "-")}</td><td>${esc(svc.port || "-")}</td><td>${esc(svc.service || "-")}</td><td>${esc(svc.status || "-")}</td></tr>`
        )
        .join("");

    return `
        <div class="host-card">
            <div class="host-head"><strong>Passive Intel</strong><span>Target: ${esc(intelData.target || "-")}</span></div>
            <div class="scan-summary-grid">
                <div class="scan-summary-item"><span>DNS A</span><strong>${dnsA}</strong></div>
                <div class="scan-summary-item"><span>DNS MX</span><strong>${dnsMx}</strong></div>
                <div class="scan-summary-item"><span>SSL Issuer</span><strong>${esc(sslIssuer)}</strong></div>
                <div class="scan-summary-item"><span>SSL Valid Until</span><strong>${esc(sslValidUntil)}</strong></div>
            </div>
            <div class="mini-head">Observed Services</div>
            <table class="table compact-table">
                <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Status</th></tr></thead>
                <tbody>${serviceRows || '<tr><td colspan="4">No passive service observations.</td></tr>'}</tbody>
            </table>
        </div>
    `;
}

function renderScanResult(data) {
    const metrics = data.metrics || {};
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

    const hostRows = (data.hosts || [])
        .map((host) => {
            const openPorts = (host.ports || []).filter((entry) => String(entry.state || "").toLowerCase() === "open");
            const portRows = openPorts
                .map(
                    (entry) => `
                        <tr>
                            <td>${esc(entry.port)}</td>
                            <td>${esc(entry.protocol || "-")}</td>
                            <td>${esc(entry.name || "-")}</td>
                            <td>${esc(entry.product || "-")}</td>
                            <td>${esc(entry.version || "-")}</td>
                            <td>${esc(entry.banner || "-")}</td>
                        </tr>
                    `
                )
                .join("");

            const hostnames = Array.isArray(host.hostnames) ? host.hostnames.filter(Boolean).join(", ") : "";
            return `
                <div class="host-card">
                    <div class="host-head">
                        <strong>${esc(host.host || "-")}</strong>
                        <span>${esc(host.state || "unknown")} | Open ports: ${openPorts.length}</span>
                    </div>
                    <div class="list-line"><span>Hostnames: ${esc(hostnames || "-")}</span><span>Reverse DNS: ${esc(host.reverse_dns || "-")}</span></div>
                    <table class="table compact-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Proto</th>
                                <th>Service</th>
                                <th>Product</th>
                                <th>Version</th>
                                <th>Banner</th>
                            </tr>
                        </thead>
                        <tbody>${portRows || '<tr><td colspan="6">No open ports on this host.</td></tr>'}</tbody>
                    </table>
                </div>
            `;
        })
        .join("");

    const intelBlock = renderIntelBlock(data.intel || null);

    scanResult.innerHTML = `
        <div class="scan-summary-grid">
            <div class="scan-summary-item"><span>Hosts Scanned</span><strong>${esc(metrics.hosts_scanned || 0)}</strong></div>
            <div class="scan-summary-item"><span>Open Ports</span><strong>${esc(metrics.open_ports || 0)}</strong></div>
            <div class="scan-summary-item"><span>CVE Candidates</span><strong>${esc(metrics.cve_candidates || 0)}</strong></div>
            <div class="scan-summary-item"><span>Risk Score</span><strong>${esc(data.true_risk_score || 0)}</strong></div>
        </div>
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
        <div class="host-results-grid">
            ${intelBlock}
            ${hostRows || '<div class="list-item"><div class="list-line">No host details captured.</div></div>'}
        </div>
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
                    <td>${esc(item.type || "-")}</td>
                    <td>${esc(item.cve || "-")}</td>
                    <td>${esc(item.asset_count || 0)}</td>
                    <td>${esc(item.occurrence_count || 0)}</td>
                    <td>${esc(item.evidence || "-")}</td>
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
                    <th>Type</th>
                    <th>CVE</th>
                    <th>Affected Assets</th>
                    <th>Occurrences</th>
                    <th>Evidence</th>
                    <th>Assets (sample)</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>${rows || '<tr><td colspan="9">No matching findings.</td></tr>'}</tbody>
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
                        <button class="btn ghost" type="button" onclick="window.openReportCsv('${esc(item.id)}')">CSV</button>
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
        const ENGINE_LABELS = { mongodb: "MongoDB", postgres: "Postgres", sqlite: "SQLite" };
        dbState.textContent = data.db_ready
            ? `${ENGINE_LABELS[data.db_engine] || data.db_engine} · online`
            : "offline";
        apiState.textContent = data.db_ready ? "live" : "degraded";
        engineState.textContent = data.nmap_available ? "nmap" : "lightweight";
        setChipState(dbState, data.db_ready ? "live" : "offline");
        setChipState(apiState, data.db_ready ? "live" : "degraded");
        setChipState(engineState, data.nmap_available ? "warn" : "live");
    } catch (_error) {
        dbState.textContent = "offline";
        apiState.textContent = "offline";
        engineState.textContent = "–";
        setChipState(dbState, "offline");
        setChipState(apiState, "offline");
        setChipState(engineState, "offline");
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
    drawSeverityStack(data.severity_timeline || []);
    renderSeverityHeatmap(data.top_vulnerabilities || []);
    renderTopVulns(data.top_vulnerabilities || []);
    renderRecentScans(data.recent_scans || []);
    renderExposureSummary(data.totals || {});
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
        reportCsvButton.disabled = false;
        renderScanResult(data);
        activateTab("scanner");
    } catch (error) {
        showError(error.message || "Could not open report");
    }
};

window.openReportPdf = function openReportPdf(reportId) {
    window.open(`/api/reports/${encodeURIComponent(reportId)}/pdf`, "_blank", "noopener,noreferrer");
};

window.openReportCsv = function openReportCsv(reportId) {
    window.open(`/api/reports/${encodeURIComponent(reportId)}/csv`, "_blank", "noopener,noreferrer");
};

scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();

    const scannerMode = scannerTypeSelect.value || "standard";
    const selectedProfile = scannerMode === "standard" ? profileSelect.value : scannerSettings(scannerMode).profile;

    const payload = {
        target: targetInput.value.trim(),
        profile: selectedProfile,
        port_strategy: portStrategySelect.value,
        project_id: activeProjectId,
    };
    const targetForIntel = payload.target;

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

        if (scannerMode === "stealth_intel" && !data.intel) {
            try {
                data.intel = await fetchIntelData(targetForIntel);
            } catch (_intelError) {
                // Keep scan results even if passive intel is unavailable.
            }
        }

        lastReportId = data.report_id;
        reportPdfButton.disabled = false;
        reportCsvButton.disabled = false;

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

reportCsvButton.addEventListener("click", () => {
    if (!lastReportId) {
        showError("No report available for CSV export.");
        return;
    }
    window.open(`/api/reports/${encodeURIComponent(lastReportId)}/csv`, "_blank", "noopener,noreferrer");
});

projectPdfButton.addEventListener("click", () => {
    const days = Number(windowDays.value || 30);
    window.open(
        `/api/projects/${encodeURIComponent(activeProjectId)}/pdf?window_days=${days}`,
        "_blank",
        "noopener,noreferrer"
    );
});

projectCsvButton.addEventListener("click", () => {
    const days = Number(windowDays.value || 30);
    window.open(
        `/api/projects/${encodeURIComponent(activeProjectId)}/dashboard.csv?window_days=${days}`,
        "_blank",
        "noopener,noreferrer"
    );
});

findingsCsvButton.addEventListener("click", () => {
    const params = new URLSearchParams({
        severity: severityFilter.value,
        since_days: sinceDays.value,
        sort_by: sortBy.value,
        sort_dir: sortDir.value,
        search: findingSearch.value.trim(),
    });
    window.open(
        `/api/projects/${encodeURIComponent(activeProjectId)}/findings.csv?${params.toString()}`,
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

scannerTypeSelect.addEventListener("change", () => {
    applyScannerMode(scannerTypeSelect.value || "standard");
});

scannerModeCards.forEach((card) => {
    card.addEventListener("click", () => {
        applyScannerMode(card.dataset.mode || "standard");
    });
});

intelOnlyButton.addEventListener("click", async () => {
    clearError();
    const target = targetInput.value.trim();
    if (!target) {
        showError("Please provide a target before running intel-only mode.");
        return;
    }

    intelOnlyButton.disabled = true;
    intelOnlyButton.textContent = "Loading...";
    try {
        const intel = await fetchIntelData(target);
        renderScanResult({
            metrics: { hosts_scanned: 0, open_ports: 0, cve_candidates: 0 },
            true_risk_score: 0,
            finding_items: [],
            hosts: [],
            intel,
        });
        activateTab("scanner");
    } catch (error) {
        showError(error.message || "Intel-only request failed");
    } finally {
        intelOnlyButton.disabled = false;
        intelOnlyButton.textContent = "Intel Only";
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
        applyScannerMode(scannerTypeSelect.value || "standard");
        await renderNetworkHints();
        await loadHealth();
        await loadProjects();
        await Promise.all([loadDashboard(), loadAggregatedFindings(), loadHistory()]);
    } catch (error) {
        showError(error.message || "Initial load failed");
    }
})();
