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
const topAssets = document.getElementById("topAssets");
const serviceInventory = document.getElementById("serviceInventory");

const trendChart = document.getElementById("trendChart");
const riskChart = document.getElementById("riskChart");
const severityStackChart = document.getElementById("severityStackChart");
const riskLegend = document.getElementById("riskLegend");
const severityHeatmap = document.getElementById("severityHeatmap");
const topVulns = document.getElementById("topVulns");
const windowDays = document.getElementById("windowDays");

const scanForm = document.getElementById("scanForm");
const scannerTypeSelect = document.getElementById("scannerType");
const scannerModeCards = Array.from(document.querySelectorAll(".scanner-mode-card[data-mode]"));
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
const languageSelect = document.getElementById("languageSelect");
const modeSelect = document.getElementById("modeSelect");
const themeSelect = document.getElementById("themeSelect");

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
const historyCache = new Map();

const I18N = {
    de: {
        documentTitle: "vScanner | Adaptive Sicherheitsplattform",
        brandSubtitle: "Adaptive Schwachstellen-Plattform",
        dashboard: "Dashboard",
        scanner: "Scanner",
        findings: "Befunde",
        history: "Verlauf",
        settings: "Einstellungen",
        workspaceEyebrow: "Sicherheits-Arbeitsbereich",
        workspaceTitle: "Schwachstellen-Intelligenz",
        workspaceSubtitle: "Übersichtliches Dashboard, adaptive Scan-Profile und deduplizierte Asset-Befunde.",
        modeDark: "Dunkel",
        modeBright: "Hell",
        window: "Zeitraum",
        runScan: "Neuer Scan",
        target: "Ziel",
        scanProfile: "Scan-Profil",
        portStrategy: "Port-Strategie",
        suggestedNetworks: "Empfohlene Netzwerke:",
        latestFindings: "Letzte Scan-Befunde",
        aggregatedFindings: "Aggregierte Befunde",
        scanHistory: "Scan-Verlauf",
        workspacePreferences: "Arbeitsbereich-Einstellungen",
        language: "Sprache",
        mode: "Modus",
        theme: "Design",
        preferencesNote: "Einstellungen werden im Browser gespeichert und sofort im gesamten Arbeitsbereich angewendet.",
        riskScanner: "Risiko-Scanner",
        riskScannerDesc: "Standard-Scanner für Host/Domain-Audits mit leichten und tiefen Profilen.",
        networkScanner: "Netzwerk-Erkundung",
        networkScannerDesc: "Erkennung und Service-Mapping für autorisierte lokale/Lab-CIDR-Bereiche.",
        stealthScanner: "Stealth & Intel",
        stealthScannerDesc: "Rauscharmer Scan mit passiver Metadaten-Anreicherung, kein Ausweichverhalten.",
        standardModeNote: "Standardscanner unterstützt Domain/IP-Ziele mit leichten oder tiefen Scan-Profilen.",
        networkModeNote: "Netzwerkscanner erwartet ein CIDR-Ziel für autorisierte lokale/Lab-Netzwerke.",
        stealthModeNote: "Stealth & Intel verwendet rauscharmes Profiling und passive Metadatensammlung. Es umgeht keine Überwachung oder SIEM.",
        operationalNotes: "Betriebshinweise",
        scannerReference: "Scanner-Referenz",
        refresh: "Aktualisieren",
        noData: "Keine Daten",
        noScansWindow: "Keine Scans in diesem Zeitraum.",
        noAssetInventory: "Noch kein Asset-Inventar.",
        noServiceInventory: "Noch kein Service-Inventar.",
        assets: "Assets",
        profile: "Profil",
        risk: "Risiko",
        findingsLabel: "Befunde",
        openPorts: "Offene Ports",
        exposedServices: "Exponierte Dienste",
        cveCandidates: "CVE-Kandidaten",
        totalFindings: "Gesamtbefunde",
        observedServices: "Beobachtete Dienste",
        passiveIntel: "Passive Intel",
        riskScore: "Risikowert",
        hostsScanned: "Gescannte Hosts",
        severity: "Schweregrad",
        asset: "Asset",
        title: "Titel",
        evidence: "Nachweis",
        type: "Typ",
        service: "Dienst",
        product: "Produkt",
        version: "Version",
        vulnerability: "Schwachstelle",
        affectedAssets: "Betroffene Assets",
        occurrences: "Vorkommen",
        assetsSample: "Assets (Auswahl)",
        lastSeen: "Zuletzt gesehen",
        noReportsYet: "Noch keine Berichte.",
        severityAll: "Alle",
        severityCritical: "Kritisch",
        severityHigh: "Hoch",
        severityMedium: "Mittel",
        severityLow: "Niedrig",
        severityInfo: "Info",
        profileLight: "Leichter Scan",
        profileDeep: "Tiefer Scan",
        profileStealth: "Stealth-Scan (geräuscharm)",
        profileNetwork: "Netzwerk-Erkundung",
        strategyStandard: "Standard",
        strategyAggressive: "Aggressiv",
        sortBy: "Sortieren nach",
        direction: "Richtung",
        since: "Seit",
        search: "Suche",
        asc: "Aufsteigend",
        desc: "Absteigend",
        newProject: "Neues Projekt",
        projectCsv: "Projekt CSV",
        projectPdf: "Projekt PDF",
        reportCsv: "Bericht CSV",
        reportPdf: "Bericht PDF",
        findingsCsv: "Befunde CSV",
        startScan: "Scan starten",
        intelOnly: "Nur Intel",
        scanning: "Scannt...",
        loading: "Lädt...",
        riskDistributionTitle: "Risikoverteilung",
        topVulnerabilitiesTitle: "Top-Schwachstellen",
        severityTimelineTitle: "Schweregrad-Zeitlinie (Executive)",
        severityHeatmapTitle: "Schweregrad-Heatmap",
        recentScansTitle: "Letzte Scans",
        exposureSnapshotTitle: "Exposure-Snapshot",
        topAssetsTitle: "Top exponierte Assets",
        serviceInventoryTitle: "Service-Inventar",
        themeOcean: "Ozean",
        themeEmerald: "Smaragd",
        themeVoid: "Void",
        themeCrimson: "Karmesin",
        themeDawn: "Morgenröte",
        themeMint: "Minze",
        themeIvory: "Elfenbein",
        themeSlate: "Schiefer",
    },
    en: {
        documentTitle: "vScanner | Adaptive Security Platform",
        brandSubtitle: "Adaptive Vulnerability Platform",
        dashboard: "Dashboard",
        scanner: "Scanner",
        findings: "Findings",
        history: "History",
        settings: "Settings",
        workspaceEyebrow: "Security Workspace",
        workspaceTitle: "Vulnerability Intelligence",
        workspaceSubtitle: "Clean dashboard, adaptive scan profiles, deduplicated asset-aware findings.",
        modeDark: "Dark",
        modeBright: "Bright",
        window: "Window",
        runScan: "Run New Scan",
        target: "Target",
        scanProfile: "Scan Profile",
        portStrategy: "Port Strategy",
        suggestedNetworks: "Suggested networks:",
        latestFindings: "Latest Scan Findings",
        aggregatedFindings: "Aggregated Findings",
        scanHistory: "Scan History",
        workspacePreferences: "Workspace Preferences",
        language: "Language",
        mode: "Mode",
        theme: "Theme",
        preferencesNote: "Preferences are stored in the browser and applied instantly across the workspace.",
        riskScanner: "Risk Scanner",
        riskScannerDesc: "Normal scanner for host/domain audits with light and deep profiles.",
        networkScanner: "Network Discovery",
        networkScannerDesc: "Discovery and service mapping for authorized local/lab CIDR ranges.",
        stealthScanner: "Stealth & Intel",
        stealthScannerDesc: "Low-noise scan plus passive metadata enrichment, no evasion behavior.",
        standardModeNote: "Standard scanner supports domain/IP targets with light or deep scan profiles.",
        networkModeNote: "Network scanner expects a CIDR target and is intended for authorized local/lab networks.",
        stealthModeNote: "Stealth & intel uses low-noise profiling and passive metadata collection. It does not bypass monitoring or SIEM.",
        operationalNotes: "Operational Notes",
        scannerReference: "Scanner Reference",
        refresh: "Refresh",
        noData: "No data",
        noScansWindow: "No scans in this window.",
        noAssetInventory: "No asset inventory yet.",
        noServiceInventory: "No service inventory yet.",
        assets: "Assets",
        profile: "Profile",
        risk: "Risk",
        findingsLabel: "Findings",
        openPorts: "Open Ports",
        exposedServices: "Exposed Services",
        cveCandidates: "CVE Candidates",
        totalFindings: "Total Findings",
        observedServices: "Observed Services",
        passiveIntel: "Passive Intel",
        riskScore: "Risk Score",
        hostsScanned: "Hosts Scanned",
        severity: "Severity",
        asset: "Asset",
        title: "Title",
        evidence: "Evidence",
        type: "Type",
        service: "Service",
        product: "Product",
        version: "Version",
        vulnerability: "Vulnerability",
        affectedAssets: "Affected Assets",
        occurrences: "Occurrences",
        assetsSample: "Assets (sample)",
        lastSeen: "Last Seen",
        noReportsYet: "No reports yet.",
        severityAll: "All",
        severityCritical: "Critical",
        severityHigh: "High",
        severityMedium: "Medium",
        severityLow: "Low",
        severityInfo: "Info",
        profileLight: "Light Scan",
        profileDeep: "Deep Scan",
        profileStealth: "Stealth Scan (Low Noise)",
        profileNetwork: "Network Discovery",
        strategyStandard: "Standard",
        strategyAggressive: "Aggressive",
        sortBy: "Sort By",
        direction: "Direction",
        since: "Since",
        search: "Search",
        asc: "Asc",
        desc: "Desc",
        newProject: "New Project",
        projectCsv: "Project CSV",
        projectPdf: "Project PDF",
        reportCsv: "Report CSV",
        reportPdf: "Report PDF",
        findingsCsv: "Findings CSV",
        startScan: "Start Scan",
        intelOnly: "Intel Only",
        scanning: "Scanning...",
        loading: "Loading...",
        riskDistributionTitle: "Risk Distribution",
        topVulnerabilitiesTitle: "Top Vulnerabilities",
        severityTimelineTitle: "Severity Timeline (Executive)",
        severityHeatmapTitle: "Severity Heatmap",
        recentScansTitle: "Recent Scans",
        exposureSnapshotTitle: "Exposure Snapshot",
        topAssetsTitle: "Top Exposed Assets",
        serviceInventoryTitle: "Service Inventory",
        themeOcean: "Ocean",
        themeEmerald: "Emerald",
        themeVoid: "Void",
        themeCrimson: "Crimson",
        themeDawn: "Dawn",
        themeMint: "Mint",
        themeIvory: "Ivory",
        themeSlate: "Slate",
    },
    es: {
        documentTitle: "vScanner | Plataforma de Seguridad Adaptativa",
        brandSubtitle: "Plataforma Adaptativa de Vulnerabilidades",
        dashboard: "Panel",
        scanner: "Escáner",
        findings: "Hallazgos",
        history: "Historial",
        settings: "Ajustes",
        workspaceEyebrow: "Espacio de Seguridad",
        workspaceTitle: "Inteligencia de Vulnerabilidades",
        workspaceSubtitle: "Panel limpio, perfiles adaptativos y hallazgos deduplicados por activo.",
        modeDark: "Oscuro",
        modeBright: "Claro",
        refresh: "Actualizar",
        startScan: "Iniciar Escaneo",
        intelOnly: "Solo Intel",
        scanning: "Escaneando...",
        loading: "Cargando...",
        riskDistributionTitle: "Distribución de Riesgos",
        topVulnerabilitiesTitle: "Principales Vulnerabilidades",
        severityTimelineTitle: "Línea de Tiempo de Gravedad",
        severityHeatmapTitle: "Mapa de Calor de Gravedad",
        recentScansTitle: "Escaneos Recientes",
        exposureSnapshotTitle: "Instantánea de Exposición",
        topAssetsTitle: "Activos más Expuestos",
        serviceInventoryTitle: "Inventario de Servicios",
        themeOcean: "Océano",
        themeEmerald: "Esmeralda",
        themeVoid: "Void",
        themeCrimson: "Carmesí",
        themeDawn: "Aurora",
        themeMint: "Menta",
        themeIvory: "Marfil",
        themeSlate: "Pizarra",
    },
    zh: {
        documentTitle: "vScanner | 自适应安全平台",
        brandSubtitle: "自适应漏洞平台",
        dashboard: "仪表盘",
        scanner: "扫描器",
        findings: "发现",
        history: "历史",
        settings: "设置",
        workspaceEyebrow: "安全工作区",
        workspaceTitle: "漏洞情报",
        workspaceSubtitle: "清晰面板，自适应扫描配置，按资产去重发现。",
        modeDark: "深色",
        modeBright: "明亮",
        refresh: "刷新",
        startScan: "开始扫描",
        intelOnly: "仅情报",
        scanning: "扫描中...",
        loading: "加载中...",
        riskDistributionTitle: "风险分布",
        topVulnerabilitiesTitle: "主要漏洞",
        severityTimelineTitle: "严重性时间线",
        severityHeatmapTitle: "严重性热图",
        recentScansTitle: "最近扫描",
        exposureSnapshotTitle: "暴露快照",
        topAssetsTitle: "最高暴露资产",
        serviceInventoryTitle: "服务清单",
        themeOcean: "海洋",
        themeEmerald: "翡翠",
        themeVoid: "虚空",
        themeCrimson: "深红",
        themeDawn: "黎明",
        themeMint: "薄荷",
        themeIvory: "象牙",
        themeSlate: "板岩",
    },
    ja: {
        documentTitle: "vScanner | 適応型セキュリティプラットフォーム",
        brandSubtitle: "適応型脆弱性プラットフォーム",
        dashboard: "ダッシュボード",
        scanner: "スキャナー",
        findings: "検出結果",
        history: "履歴",
        settings: "設定",
        workspaceEyebrow: "セキュリティワークスペース",
        workspaceTitle: "脆弱性インテリジェンス",
        workspaceSubtitle: "見やすいダッシュボード、適応スキャン、重複排除された資産別検出。",
        modeDark: "ダーク",
        modeBright: "ライト",
        refresh: "更新",
        startScan: "スキャン開始",
        intelOnly: "インテルのみ",
        scanning: "スキャン中...",
        loading: "読み込み中...",
        riskDistributionTitle: "リスク分布",
        topVulnerabilitiesTitle: "主要脆弱性",
        severityTimelineTitle: "重大度タイムライン",
        severityHeatmapTitle: "重大度ヒートマップ",
        recentScansTitle: "最近のスキャン",
        exposureSnapshotTitle: "露出スナップショット",
        topAssetsTitle: "最も露出されたアセット",
        serviceInventoryTitle: "サービスインベントリ",
        themeOcean: "オーシャン",
        themeEmerald: "エメラルド",
        themeVoid: "ヴォイド",
        themeCrimson: "クリムゾン",
        themeDawn: "ドーン",
        themeMint: "ミント",
        themeIvory: "アイボリー",
        themeSlate: "スレート",
    },
    ru: {
        documentTitle: "vScanner | Адаптивная платформа безопасности",
        brandSubtitle: "Адаптивная платформа уязвимостей",
        dashboard: "Панель",
        scanner: "Сканер",
        findings: "Находки",
        history: "История",
        settings: "Настройки",
        workspaceEyebrow: "Пространство безопасности",
        workspaceTitle: "Аналитика уязвимостей",
        workspaceSubtitle: "Чистая панель, адаптивные профили сканирования и дедупликация находок по активам.",
        modeDark: "Темный",
        modeBright: "Светлый",
        refresh: "Обновить",
        startScan: "Запустить скан",
        intelOnly: "Только Intel",
        scanning: "Сканирование...",
        loading: "Загрузка...",
        riskDistributionTitle: "Распределение рисков",
        topVulnerabilitiesTitle: "Главные уязвимости",
        severityTimelineTitle: "Хронология серьёзности",
        severityHeatmapTitle: "Тепловая карта серьёзности",
        recentScansTitle: "Недавние сканирования",
        exposureSnapshotTitle: "Снимок уязвимостей",
        topAssetsTitle: "Наиболее уязвимые активы",
        serviceInventoryTitle: "Инвентарь сервисов",
        themeOcean: "Океан",
        themeEmerald: "Изумруд",
        themeVoid: "Войд",
        themeCrimson: "Карминный",
        themeDawn: "Рассвет",
        themeMint: "Мята",
        themeIvory: "Слоновая кость",
        themeSlate: "Сланец",
    },
};

const THEMES_BY_MODE = {
    dark: ["ocean", "emerald", "void", "crimson"],
    bright: ["dawn", "mint", "ivory", "slate"],
};

function t(key) {
    const lang = localStorage.getItem("vscanner.language") || "en";
    const base = I18N[lang] || I18N.en;
    return base[key] || I18N.en[key] || I18N.de[key] || key;
}

function populateThemeOptions(mode, selectedTheme) {
    const themes = THEMES_BY_MODE[mode] || THEMES_BY_MODE.dark;
    themeSelect.innerHTML = themes
        .map((theme) => `<option value="${esc(theme)}">${esc(t(`theme${theme.charAt(0).toUpperCase()}${theme.slice(1)}`))}</option>`)
        .join("");
    themeSelect.value = themes.includes(selectedTheme) ? selectedTheme : themes[0];
}

function scannerSettings(mode) {
    if (mode === "network") {
        return {
            profile: "network",
            portStrategy: "aggressive",
            placeholder: "192.168.1.0/24",
            note: t("networkModeNote"),
            disableProfile: true,
            hidePortStrategy: true,
            showIntelOnly: false,
            showNetworkHints: true,
        };
    }

    if (mode === "stealth_intel") {
        return {
            profile: "stealth",
            portStrategy: "standard",
            placeholder: "example.com, 8.8.8.8",
            note: t("stealthModeNote"),
            disableProfile: true,
            hidePortStrategy: true,
            showIntelOnly: true,
            showNetworkHints: false,
        };
    }

    return {
        profile: "light",
        portStrategy: "standard",
        placeholder: "example.com, 8.8.8.8, 192.168.1.0/24",
        note: t("standardModeNote"),
        disableProfile: false,
        hidePortStrategy: false,
        showIntelOnly: false,
        showNetworkHints: false,
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
    document.querySelector(".network-suggestions")?.classList.toggle("hidden", !cfg.showNetworkHints);
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
        severityHeatmap.innerHTML = `<div class="heat-cell"><strong>${esc(t("noData"))}</strong><small>${esc(t("noScansWindow"))}</small></div>`;
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
        topVulns.innerHTML = `<div class="list-item"><div class="list-line">${esc(t("noData"))}</div></div>`;
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
                        <strong>${esc(t("assets"))}: ${esc(item.affected_assets || 0)}</strong>
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
        recentScans.innerHTML = `<div class="list-item"><div class="list-line">${esc(t("noScansWindow"))}</div></div>`;
        return;
    }

    recentScans.innerHTML = items
        .slice(0, 10)
        .map((item) => {
            const sev = String(item.risk_level || "low").toLowerCase();
            return `
                <div class="list-item">
                    <div class="list-line"><strong>${esc(item.target || "-")}</strong><span>${esc(String(item.created_at || "").slice(0, 16).replace("T", " "))}</span></div>
                    <div class="list-line"><span>${esc(t("profile"))}: ${esc(item.profile || "-")}</span><span class="badge badge-${esc(sev)}">${esc(sev)}</span></div>
                    <div class="list-line"><span>${esc(t("risk"))}: ${esc(item.true_risk_score || 0)}</span><span>${esc(t("findingsLabel"))}: ${esc(item.total_findings || 0)}</span></div>
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
        { label: t("openPorts"), value: totals.open_ports || 0 },
        { label: t("exposedServices"), value: totals.exposed_services || 0 },
        { label: t("cveCandidates"), value: totals.cve_count || 0 },
        { label: t("totalFindings"), value: totals.findings || 0 },
    ];
    exposureSummary.innerHTML = cards
        .map((item) => `<div class="risk-item"><span>${esc(item.label)}</span><strong>${esc(item.value)}</strong></div>`)
        .join("");
}

function renderTopAssets(items) {
    if (!topAssets) {
        return;
    }
    if (!items.length) {
        topAssets.innerHTML = `<div class="list-item"><div class="list-line">${esc(t("noAssetInventory"))}</div></div>`;
        return;
    }

    topAssets.innerHTML = items
        .slice(0, 12)
        .map(
            (item) => `
                <div class="list-item">
                    <div class="list-line"><strong>${esc(item.host || "-")}</strong><span>${esc(item.last_seen || "-")}</span></div>
                    <div class="list-line"><span>${esc(t("openPorts"))}: ${esc(item.open_ports || 0)}</span><span>${esc(t("findingsLabel"))}: ${esc(item.findings || 0)}</span></div>
                    <div class="list-line"><span>${esc(t("risk"))}: ${esc(item.risk_score || 0)}</span><span>${esc((item.profiles || []).join(", ") || "-")}</span></div>
                </div>
            `
        )
        .join("");
}

function renderServiceInventory(items) {
    if (!serviceInventory) {
        return;
    }
    if (!items.length) {
        serviceInventory.innerHTML = `<div class="list-item"><div class="list-line">${esc(t("noServiceInventory"))}</div></div>`;
        return;
    }

    serviceInventory.innerHTML = items
        .slice(0, 12)
        .map(
            (item) => `
                <div class="list-item">
                    <div class="list-line"><strong>${esc(item.service || "unknown")}</strong><span>${esc(t("assets"))}: ${esc(item.asset_count || 0)}</span></div>
                    <div class="list-line"><span>Observations: ${esc(item.count || 0)}</span><span>Ports: ${esc((item.ports || []).slice(0, 5).join(", ") || "-")}</span></div>
                </div>
            `
        )
        .join("");
}

function applyTheme(theme) {
    const mode = localStorage.getItem("vscanner.mode") || "dark";
    const themes = THEMES_BY_MODE[mode] || THEMES_BY_MODE.dark;
    const safeTheme = themes.includes(theme) ? theme : themes[0];
    document.body.dataset.theme = safeTheme;
    localStorage.setItem("vscanner.theme", safeTheme);
    themeSelect.value = safeTheme;
}

function applyLanguage(lang) {
    const safeLang = I18N[lang] ? lang : "en";
    const text = I18N[safeLang] || I18N.en;
    document.documentElement.lang = safeLang;
    localStorage.setItem("vscanner.language", safeLang);
    document.title = text.documentTitle || I18N.en.documentTitle;

    const mode = localStorage.getItem("vscanner.mode") || "dark";
    const currentTheme = localStorage.getItem("vscanner.theme") || (THEMES_BY_MODE[mode] || THEMES_BY_MODE.dark)[0];

    const setText = (id, value) => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = value;
        }
    };

    setText("brandSubtitle", text.brandSubtitle || I18N.en.brandSubtitle);
    setText("workspaceEyebrow", text.workspaceEyebrow || I18N.en.workspaceEyebrow);
    setText("workspaceTitle", text.workspaceTitle || I18N.en.workspaceTitle);
    setText("workspaceSubtitle", text.workspaceSubtitle || I18N.en.workspaceSubtitle);
    setText("riskDistributionTitle", t("riskDistributionTitle"));
    setText("topVulnerabilitiesTitle", t("topVulnerabilitiesTitle"));
    setText("severityTimelineTitle", t("severityTimelineTitle"));
    setText("severityHeatmapTitle", t("severityHeatmapTitle"));
    setText("recentScansTitle", t("recentScansTitle"));
    setText("exposureSnapshotTitle", t("exposureSnapshotTitle"));
    setText("topAssetsTitle", t("topAssetsTitle"));
    setText("serviceInventoryTitle", t("serviceInventoryTitle"));
    setText("runNewScanTitle", text.runScan || I18N.en.runScan);
    setText("modeRiskTitle", text.riskScanner || I18N.en.riskScanner);
    setText("modeRiskDesc", text.riskScannerDesc || I18N.en.riskScannerDesc);
    setText("modeNetworkTitle", text.networkScanner || I18N.en.networkScanner);
    setText("modeNetworkDesc", text.networkScannerDesc || I18N.en.networkScannerDesc);
    setText("modeStealthTitle", text.stealthScanner || I18N.en.stealthScanner);
    setText("modeStealthDesc", text.stealthScannerDesc || I18N.en.stealthScannerDesc);
    setText("suggestedNetworksLabel", text.suggestedNetworks || I18N.en.suggestedNetworks);
    setText("latestScanFindingsTitle", text.latestFindings || I18N.en.latestFindings);
    setText("aggregatedFindingsTitle", text.aggregatedFindings || I18N.en.aggregatedFindings);
    setText("scanHistoryTitle", text.scanHistory || I18N.en.scanHistory);
    setText("workspacePreferencesTitle", text.workspacePreferences || I18N.en.workspacePreferences);
    setText("preferencesNote", text.preferencesNote || I18N.en.preferencesNote);
    setText("operationalNotesTitle", text.operationalNotes || I18N.en.operationalNotes);
    setText("scannerReferenceTitle", text.scannerReference || I18N.en.scannerReference);

    document.querySelector('label[for="target"]').textContent = text.target || I18N.en.target;
    document.querySelector('label[for="profile"]').textContent = text.scanProfile || I18N.en.scanProfile;
    document.querySelector('label[for="portStrategy"]').textContent = text.portStrategy || I18N.en.portStrategy;
    document.querySelector('label[for="languageSelect"]').textContent = text.language || I18N.en.language;
    document.querySelector('label[for="modeSelect"]').textContent = text.mode || I18N.en.mode;
    document.querySelector('label[for="themeSelect"]').textContent = text.theme || I18N.en.theme;
    document.querySelector('label[for="windowDays"]').textContent = text.window || I18N.en.window;
    document.querySelector('label[for="severityFilter"]').textContent = text.severity || I18N.en.severity;
    document.querySelector('label[for="sinceDays"]').textContent = text.since || I18N.en.since;
    document.querySelector('label[for="sortBy"]').textContent = text.sortBy || I18N.en.sortBy;
    document.querySelector('label[for="sortDir"]').textContent = text.direction || I18N.en.direction;
    document.querySelector('label[for="findingSearch"]').textContent = text.search || I18N.en.search;

    const profileOptions = profileSelect?.options;
    if (profileOptions && profileOptions.length >= 4) {
        profileOptions[0].textContent = text.profileLight || I18N.en.profileLight;
        profileOptions[1].textContent = text.profileDeep || I18N.en.profileDeep;
        profileOptions[2].textContent = text.profileStealth || I18N.en.profileStealth;
        profileOptions[3].textContent = text.profileNetwork || I18N.en.profileNetwork;
    }

    const strategyOptions = portStrategySelect?.options;
    if (strategyOptions && strategyOptions.length >= 2) {
        strategyOptions[0].textContent = text.strategyStandard || I18N.en.strategyStandard;
        strategyOptions[1].textContent = text.strategyAggressive || I18N.en.strategyAggressive;
    }

    const severityOptions = severityFilter?.options;
    if (severityOptions && severityOptions.length >= 6) {
        severityOptions[0].textContent = text.severityAll || I18N.en.severityAll;
        severityOptions[1].textContent = text.severityCritical || I18N.en.severityCritical;
        severityOptions[2].textContent = text.severityHigh || I18N.en.severityHigh;
        severityOptions[3].textContent = text.severityMedium || I18N.en.severityMedium;
        severityOptions[4].textContent = text.severityLow || I18N.en.severityLow;
        severityOptions[5].textContent = text.severityInfo || I18N.en.severityInfo;
    }

    const dirOptions = sortDir?.options;
    if (dirOptions && dirOptions.length >= 2) {
        dirOptions[0].textContent = text.desc || I18N.en.desc;
        dirOptions[1].textContent = text.asc || I18N.en.asc;
    }

    modeSelect.options[0].textContent = text.modeDark || I18N.en.modeDark;
    modeSelect.options[1].textContent = text.modeBright || I18N.en.modeBright;

    populateThemeOptions(mode, currentTheme);

    document.querySelector('.menu-item[data-tab="dashboard"]').textContent = text.dashboard;
    document.querySelector('.menu-item[data-tab="scanner"]').textContent = text.scanner;
    document.querySelector('.menu-item[data-tab="findings"]').textContent = text.findings;
    document.querySelector('.menu-item[data-tab="history"]').textContent = text.history;
    document.querySelector('.menu-item[data-tab="settings"]').textContent = text.settings;
    newProjectButton.textContent = text.newProject;
    projectCsvButton.textContent = text.projectCsv;
    projectPdfButton.textContent = text.projectPdf;
    reportCsvButton.textContent = text.reportCsv;
    reportPdfButton.textContent = text.reportPdf;
    findingsCsvButton.textContent = text.findingsCsv;
    refreshFindingsButton.textContent = text.refresh;
    refreshHistoryButton.textContent = text.refresh;
    if (!scanButton.disabled) {
        scanButton.textContent = text.startScan;
    }
    if (!intelOnlyButton.disabled) {
        intelOnlyButton.textContent = text.intelOnly;
    }

    applyScannerMode(scannerTypeSelect.value || "standard");
}

function applyMode(mode) {
    const safeMode = mode === "bright" ? "bright" : "dark";
    localStorage.setItem("vscanner.mode", safeMode);
    document.body.dataset.mode = safeMode;

    const previousTheme = localStorage.getItem("vscanner.theme") || "";
    populateThemeOptions(safeMode, previousTheme);
    applyTheme(themeSelect.value);
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
            <div class="host-head"><strong>${esc(t("passiveIntel"))}</strong><span>${esc(t("target"))}: ${esc(intelData.target || "-")}</span></div>
            <div class="scan-summary-grid">
                <div class="scan-summary-item"><span>DNS A</span><strong>${dnsA}</strong></div>
                <div class="scan-summary-item"><span>DNS MX</span><strong>${dnsMx}</strong></div>
                <div class="scan-summary-item"><span>SSL Issuer</span><strong>${esc(sslIssuer)}</strong></div>
                <div class="scan-summary-item"><span>SSL Valid Until</span><strong>${esc(sslValidUntil)}</strong></div>
            </div>
            <div class="mini-head">${esc(t("observedServices"))}</div>
            <table class="table compact-table">
                <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Status</th></tr></thead>
                <tbody>${serviceRows || '<tr><td colspan="4">No passive service observations.</td></tr>'}</tbody>
            </table>
        </div>
    `;
}

function buildScanResultMarkup(data) {
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
                                <th>${esc(t("service"))}</th>
                                <th>${esc(t("product"))}</th>
                                <th>${esc(t("version"))}</th>
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

    return `
        <div class="scan-summary-grid">
            <div class="scan-summary-item"><span>${esc(t("hostsScanned"))}</span><strong>${esc(metrics.hosts_scanned || 0)}</strong></div>
            <div class="scan-summary-item"><span>${esc(t("openPorts"))}</span><strong>${esc(metrics.open_ports || 0)}</strong></div>
            <div class="scan-summary-item"><span>${esc(t("cveCandidates"))}</span><strong>${esc(metrics.cve_candidates || 0)}</strong></div>
            <div class="scan-summary-item"><span>${esc(t("riskScore"))}</span><strong>${esc(data.true_risk_score || 0)}</strong></div>
        </div>
        <table class="table">
            <thead>
                <tr>
                    <th>${esc(t("severity"))}</th>
                    <th>${esc(t("asset"))}</th>
                    <th>${esc(t("title"))}</th>
                    <th>${esc(t("evidence"))}</th>
                    <th>${esc(t("type"))}</th>
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

function renderScanResult(data) {
    scanResult.innerHTML = buildScanResultMarkup(data);
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
                    <th>${esc(t("severity"))}</th>
                    <th>${esc(t("vulnerability"))}</th>
                    <th>${esc(t("type"))}</th>
                    <th>CVE</th>
                    <th>${esc(t("affectedAssets"))}</th>
                    <th>${esc(t("occurrences"))}</th>
                    <th>${esc(t("evidence"))}</th>
                    <th>${esc(t("assetsSample"))}</th>
                    <th>${esc(t("lastSeen"))}</th>
                </tr>
            </thead>
            <tbody>${rows || '<tr><td colspan="9">No matching findings.</td></tr>'}</tbody>
        </table>
    `;
}

function renderHistory(items) {
    if (!items.length) {
        historyList.innerHTML = `<div class="list-item"><div class="list-line">${esc(t("noReportsYet"))}</div></div>`;
        return;
    }

    historyList.innerHTML = items
        .map((item) => {
            const sev = String(item.risk_level || "low").toLowerCase();
            return `
                <div class="history-card" data-report-id="${esc(item.id)}">
                    <button class="history-toggle" type="button" data-report-toggle="${esc(item.id)}">
                        <div class="history-meta"><strong>${esc(item.target || "-")}</strong><span>${esc(item.created_at || "-")}</span></div>
                        <div class="history-meta"><span>${esc(t("profile"))}: ${esc(item.profile || "-")}</span><span class="badge badge-${esc(sev)}">${esc(sev)}</span></div>
                        <div class="history-meta"><span>${esc(t("riskScore"))}: ${esc(item.true_risk_score || 0)}</span><span>${esc(t("findingsLabel"))}: ${esc(item.total_findings || 0)}</span></div>
                    </button>
                    <div class="history-body">
                        <div class="history-body-inner">
                            <div class="history-actions">
                                <button class="btn ghost" type="button" data-open-report="${esc(item.id)}">Open</button>
                                <button class="btn ghost" type="button" data-open-report-csv="${esc(item.id)}">CSV</button>
                                <button class="btn ghost" type="button" data-open-report-pdf="${esc(item.id)}">PDF</button>
                            </div>
                            <div class="history-loading hidden" data-report-loading="${esc(item.id)}">Loading report details...</div>
                            <div data-report-content="${esc(item.id)}"></div>
                        </div>
                    </div>
                </div>
            `;
        })
        .join("");
}

async function expandHistoryReport(reportId) {
    const card = historyList.querySelector(`[data-report-id="${CSS.escape(reportId)}"]`);
    if (!card) {
        return;
    }

    const loading = historyList.querySelector(`[data-report-loading="${CSS.escape(reportId)}"]`);
    const content = historyList.querySelector(`[data-report-content="${CSS.escape(reportId)}"]`);
    const expanded = card.classList.toggle("expanded");
    if (!expanded) {
        return;
    }

    if (historyCache.has(reportId)) {
        content.innerHTML = buildScanResultMarkup(historyCache.get(reportId));
        return;
    }

    loading?.classList.remove("hidden");
    try {
        const response = await fetch(`/api/reports/${encodeURIComponent(reportId)}`);
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Report not found");
        }
        historyCache.set(reportId, data);
        content.innerHTML = buildScanResultMarkup(data);
    } catch (error) {
        content.innerHTML = `<div class="error">${esc(error.message || "Could not load report details")}</div>`;
    } finally {
        loading?.classList.add("hidden");
    }
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
    renderTopAssets(data.top_assets || []);
    renderServiceInventory(data.service_inventory || []);
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

historyList.addEventListener("click", async (event) => {
    const toggle = event.target.closest("[data-report-toggle]");
    if (toggle) {
        await expandHistoryReport(toggle.dataset.reportToggle || "");
        return;
    }

    const openButton = event.target.closest("[data-open-report]");
    if (openButton) {
        await window.openReport(openButton.dataset.openReport || "");
        return;
    }

    const csvButton = event.target.closest("[data-open-report-csv]");
    if (csvButton) {
        window.openReportCsv(csvButton.dataset.openReportCsv || "");
        return;
    }

    const pdfButton = event.target.closest("[data-open-report-pdf]");
    if (pdfButton) {
        window.openReportPdf(pdfButton.dataset.openReportPdf || "");
    }
});

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
    scanButton.textContent = t("scanning");

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
        const activeLanguage = localStorage.getItem("vscanner.language") || "de";
        scanButton.textContent = (I18N[activeLanguage] || I18N.de).startScan;
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
    intelOnlyButton.textContent = t("loading");
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
        const activeLanguage = localStorage.getItem("vscanner.language") || "de";
        intelOnlyButton.textContent = (I18N[activeLanguage] || I18N.de).intelOnly;
    }
});

windowDays.addEventListener("change", loadDashboard);
refreshFindingsButton.addEventListener("click", loadAggregatedFindings);
refreshHistoryButton.addEventListener("click", loadHistory);
severityFilter.addEventListener("change", loadAggregatedFindings);
sinceDays.addEventListener("change", loadAggregatedFindings);
sortBy.addEventListener("change", loadAggregatedFindings);
sortDir.addEventListener("change", loadAggregatedFindings);
languageSelect.addEventListener("change", () => applyLanguage(languageSelect.value));
modeSelect.addEventListener("change", () => applyMode(modeSelect.value));
themeSelect.addEventListener("change", () => applyTheme(themeSelect.value));
findingSearch.addEventListener("input", () => {
    window.clearTimeout(window.__findingSearchTimer);
    window.__findingSearchTimer = window.setTimeout(loadAggregatedFindings, 260);
});

(async function bootstrap() {
    try {
        const savedMode = localStorage.getItem("vscanner.mode") || "dark";
        const savedTheme = localStorage.getItem("vscanner.theme") || "ocean";
        const savedLanguage = localStorage.getItem("vscanner.language") || "en";
        modeSelect.value = savedMode;
        themeSelect.value = savedTheme;
        languageSelect.value = savedLanguage;
        applyMode(savedMode);
        applyTheme(savedTheme);
        applyLanguage(savedLanguage);
        applyScannerMode(scannerTypeSelect.value || "standard");
        await renderNetworkHints();
        await loadHealth();
        await loadProjects();
        await Promise.all([loadDashboard(), loadAggregatedFindings(), loadHistory()]);
    } catch (error) {
        showError(error.message || "Initial load failed");
    }
})();
