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
const kpiEngine = document.getElementById("kpiEngine");
const kpiPorts = document.getElementById("kpiPorts");
const kpiFindings = document.getElementById("kpiFindings");

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

function renderRiskSummary(summary = {}) {
    const order = ["critical", "high", "medium", "low", "info"];
    riskSummary.innerHTML = "";

    order.forEach((key) => {
        const value = summary[key] || 0;
        const row = document.createElement("div");
        row.className = "risk-item";
        row.innerHTML = `<span>${key.toUpperCase()}</span><strong>${value}</strong>`;
        riskSummary.appendChild(row);
    });
}

function renderMeta(meta = {}) {
    scanMeta.innerHTML = "";
    const lines = [
        `Target: ${meta.target || "-"}`,
        `Type: ${meta.target_type || "-"}`,
        `Profile: ${meta.profile || "-"}`,
        `Coverage: ${meta.port_strategy || "-"}`,
        `Engine: ${meta.engine || "-"}`,
        `Started: ${meta.started_at || "-"}`,
        `Finished: ${meta.finished_at || "-"}`,
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

    kpiEngine.textContent = data.meta?.engine || "-";
    kpiPorts.textContent = String(openPortCount);
    kpiFindings.textContent = String(data.total_findings || 0);
}

function formatHost(host) {
    const lines = [];
    lines.push(`Host: ${host.host} (${host.state})`);

    if (host.hostnames && host.hostnames.length) {
        lines.push(`Hostnames: ${host.hostnames.join(", ")}`);
    }
    if (host.reverse_dns) {
        lines.push(`Reverse DNS: ${host.reverse_dns}`);
    }

    const openPorts = (host.ports || []).filter((p) => p.state === "open");
    lines.push(`Open Ports: ${openPorts.length}`);
    openPorts.forEach((p) => {
        const svc = [p.name, p.product, p.version].filter(Boolean).join(" ");
        lines.push(`  - ${p.protocol}/${p.port}: ${svc || "service unknown"}`);
        if (p.banner) {
            lines.push(`    banner: ${p.banner}`);
        }
    });

    if (host.web_evidence && host.web_evidence.length) {
        lines.push("Web Evidence:");
        host.web_evidence.forEach((web) => {
            lines.push(`  - Port ${web.port}: ${web.url} [${web.status}]`);
            if (web.title) {
                lines.push(`    title: ${web.title}`);
            }
            if (web.login_pages && web.login_pages.length) {
                lines.push(`    login pages: ${web.login_pages.length}`);
            }
        });
    }

    if (host.findings && host.findings.length) {
        lines.push("Findings:");
        host.findings.slice(0, 30).forEach((finding) => {
            lines.push(
                `  - [${finding.severity.toUpperCase()}] ${finding.title}: ${finding.evidence}`
            );
        });
    }

    lines.push("-");
    return lines.join("\n");
}

function renderResult(data) {
    const blocks = [];
    blocks.push(`Scanner: ${data.meta?.scanner || "vScanner"}`);
    blocks.push(`Nmap Command: ${data.nmap?.command || "-"}`);
    blocks.push(`Total Findings: ${data.total_findings || 0}`);
    blocks.push("");

    if (!data.hosts || data.hosts.length === 0) {
        blocks.push("Keine Hosts erkannt. pruefe Ziel und Berechtigung.");
    } else {
        data.hosts.forEach((host) => blocks.push(formatHost(host)));
    }

    resultOutput.textContent = blocks.join("\n");
    renderRiskSummary(data.risk_summary || {});
    renderMeta(data.meta || {});
    renderKpis(data);
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
    scanButton.textContent = "Running...";
    resultOutput.textContent = "Scan running. This may take some time depending on profile and coverage.";

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

        renderResult(data);
        setStatus("done", "Done");
    } catch (error) {
        showError(error.message || "Scan fehlgeschlagen.");
        setStatus("idle", "Error");
        resultOutput.textContent = "";
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Scan ausfuehren";
    }
});

ipButton.addEventListener("click", async () => {
    clearError();
    try {
        const response = await fetch("/api/client-ip");
        const data = await response.json();
        alert(`Detected IP: ${data.ip || "unknown"}`);
    } catch (error) {
        showError("IP could not be loaded.");
    }
});

renderRiskSummary({});
renderKpis({});
