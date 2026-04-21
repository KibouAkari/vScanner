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
const severityMiniChart = document.getElementById("severityMiniChart");
const severityMiniWrap = document.getElementById("severityMiniWrap");
const severityTimelinePanel = document.getElementById("severityTimelinePanel");
const severityTimelineMode = document.getElementById("severityTimelineMode");
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
const findingDetail = document.getElementById("findingDetail");
const assetsInventory = document.getElementById("assetsInventory");
const assetsSummary = document.getElementById("assetsSummary");
const refreshAssetsButton = document.getElementById("refreshAssetsButton");
const assetForm = document.getElementById("assetForm");
const assetValueInput = document.getElementById("assetValueInput");
const assetTagsInput = document.getElementById("assetTagsInput");
const assetCriticalitySelect = document.getElementById("assetCriticalitySelect");
const assetTagFilter = document.getElementById("assetTagFilter");

const historyList = document.getElementById("historyList");
const refreshHistoryButton = document.getElementById("refreshHistoryButton");
const languageSelect = document.getElementById("languageSelect");
const modeSelect = document.getElementById("modeSelect");
const themeSelect = document.getElementById("themeSelect");
const sidebarToggle = document.getElementById("sidebarToggle");
const appShell = document.querySelector(".app-shell");
const resetProjectButton = document.getElementById("resetProjectButton");
const deleteProjectButton = document.getElementById("deleteProjectButton");

const confirmModal = document.getElementById("confirmModal");
const confirmModalTitle = document.getElementById("confirmModalTitle");
const confirmModalMessage = document.getElementById("confirmModalMessage");
const confirmModalPhraseLabel = document.getElementById("confirmModalPhraseLabel");
const confirmPhraseInput = document.getElementById("confirmPhraseInput");
const confirmModalCancel = document.getElementById("confirmModalCancel");
const confirmModalOk = document.getElementById("confirmModalOk");
const authSummary = document.getElementById("authSummary");
const authSummaryText = document.getElementById("authSummaryText");
const authLogoutButton = document.getElementById("authLogoutButton");
const authModal = document.getElementById("authModal");
const authModalMessage = document.getElementById("authModalMessage");
const authForm = document.getElementById("authForm");
const authUsername = document.getElementById("authUsername");
const authPassword = document.getElementById("authPassword");
const authError = document.getElementById("authError");
const authSubmitButton = document.getElementById("authSubmitButton");

const ORDER = ["critical", "high", "medium", "low"];
const COLORS = {
    critical: "#ff5d73",
    high: "#ffc35c",
    medium: "#67b9ff",
    low: "#4cdd88",
};

let activeProjectId = "default";
let lastReportId = null;
let lastScannerScope = "standard";
let trendChartInstance = null;
let riskChartInstance = null;
let severityStackChartInstance = null;
let severityMiniChartInstance = null;
let severityTimelinePoints = [];
const historyCache = new Map();
let dashboardAbortController = null;
let dashboardRequestSeq = 0;
const CHART_ANIMATION_MS = 320;
let selectedFindingKey = "";
let activeScanJobId = "";
let activeScanStatusController = null;
let workspaceInitialized = false;

const authState = {
    required: false,
    authenticated: false,
    user: null,
    projects: [],
    defaultProjectId: "default",
};

const nativeFetch = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
    const response = await nativeFetch(input, { ...init, credentials: init?.credentials || "same-origin" });
    const requestUrl = typeof input === "string" ? input : String(input?.url || "");
    if (response.status === 401 && !requestUrl.startsWith("/api/auth/")) {
        showAuthDialog("Your session is required or has expired. Sign in to continue.");
    }
    return response;
};

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
        v2Scanner: "Adaptiver V2-Scanner",
        v2ScannerDesc: "Asynchrone Scan-Engine mit Plugin-Checks und tieferem Protokoll-Fingerprinting.",
        standardModeNote: "Standardscanner unterstützt Domain/IP-Ziele mit leichten oder tiefen Scan-Profilen.",
        networkModeNote: "Netzwerkscanner erwartet ein CIDR-Ziel für autorisierte lokale/Lab-Netzwerke.",
        stealthModeNote: "Stealth & Intel verwendet rauscharmes Profiling und passive Metadatensammlung. Es umgeht keine Überwachung oder SIEM.",
        v2ModeNote: "Der Adaptive V2 Scanner nutzt asynchrone Probes und Plugin-Checks für tiefere Service-Intelligenz.",
        operationalNotes: "Betriebshinweise",
        scannerReference: "Scanner-Referenz",
        kpiAvgRiskLabel: "Risiko-Score",
        kpiAvgRiskHint: "Gewichteter Ist-Zustand",
        kpiScansLabel: "Gesamt-Scans",
        kpiScansHint: "Gespeicherte Reports",
        kpiUniqueLabel: "Aktive Schwachstellen",
        kpiUniqueHint: "Deduplicierter aktueller Zustand",
        kpiAssetsLabel: "Betroffene Assets",
        kpiAssetsHint: "Betroffene Assets im Inventar",
        netResultTitle: "Netzwerk-Scan-Ergebnisse",
        stealthResultTitle: "Stealth-Scan-Ergebnisse",
        scanNetworkButton: "Netzwerk scannen",
        runStealthButton: "Stealth-Scan starten",
        toggleMenu: "Menü",
        hostCsv: "Host CSV",
        hostPdf: "Host PDF",
        deleteScan: "Scan löschen",
        resetProject: "Aktuelles Projekt zurücksetzen",
        deleteProject: "Aktuelles Projekt löschen",
        confirmAction: "Aktion bestätigen",
        confirmCancel: "Abbrechen",
        confirmProceed: "Bestätigen",
        confirmPhraseLabel: "Bestätigungsphrase eingeben",
        resetProjectConfirm: "Dadurch werden alle Scans und Befunde im aktuellen Projekt entfernt.",
        deleteProjectConfirm: "Dadurch wird das Projekt mit allen Scans und Befunden dauerhaft gelöscht.",
        deleteScanConfirm: "Dadurch wird dieser einzelne Scan dauerhaft gelöscht.",
        requiredPhrase: "Erforderliche Phrase",
        noteDedup: "Befunde werden pro Projekt, Asset und Schwachstellen-Schlüssel dedupliziert.",
        noteMetrics: "Dashboard-Metriken trennen eindeutige Host-Port-Expositionen von wiederholten Scans.",
        noteNetworkHint: "Netzwerkvorschläge werden nur angezeigt, wo CIDR-Scanning sinnvoll ist.",
        noteStealth: "Stealth bleibt Low-Noise und versucht kein Monitoring-Bypass.",
        notePg: "Für Vercel Postgres: DATABASE_URL setzen und psycopg in requirements installieren.",
        noteMongo: "Für MongoDB Atlas auf Vercel: MONGODB_URI und optional MONGODB_DB_NAME setzen.",
        refRiskDesc: "Für einzelne Hosts und Domains mit breiter Port-, Versions- und HTTP-Sicherheitsabdeckung.",
        refNetworkDesc: "Für autorisierte private Netzwerke zur Host-/Service-Erkennung pro Subnetz (Network-Tab).",
        refStealthDesc: "Rauscharmes Profiling und passive Metadatensammlung (Stealth-Tab).",
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
        severityTimelineModeLabel: "Ansicht",
        severityTimelineModePercent: "100% gestapelt",
        severityTimelineModeAbsoluteMini: "Absolut + Minimap",
        severityHeatmapTitle: "Schweregrad-Heatmap",
        recentScansTitle: "Letzte Scans",
        exposureSnapshotTitle: "Exposure-Snapshot",
        topAssetsTitle: "Top exponierte Assets",
        serviceInventoryTitle: "Service-Inventar",
        portIntelTitle: "Port-Intelligenz",
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
        v2Scanner: "Adaptive V2 Scanner",
        v2ScannerDesc: "Async scanner engine with plugin-based checks and deeper protocol fingerprinting.",
        standardModeNote: "Standard scanner supports domain/IP targets with light or deep scan profiles.",
        networkModeNote: "Network scanner expects a CIDR target and is intended for authorized local/lab networks.",
        stealthModeNote: "Stealth & intel uses low-noise profiling and passive metadata collection. It does not bypass monitoring or SIEM.",
        v2ModeNote: "Adaptive V2 scanner uses async probing and plugin checks. Use for deeper service intelligence.",
        operationalNotes: "Operational Notes",
        scannerReference: "Scanner Reference",
        kpiAvgRiskLabel: "Risk Score",
        kpiAvgRiskHint: "Weighted current state",
        kpiScansLabel: "Total Scans",
        kpiScansHint: "Reports saved",
        kpiUniqueLabel: "Active Vulnerabilities",
        kpiUniqueHint: "Deduplicated current state",
        kpiAssetsLabel: "Affected Assets",
        kpiAssetsHint: "Impacted asset inventory",
        netResultTitle: "Network Scan Results",
        stealthResultTitle: "Stealth Scan Results",
        scanNetworkButton: "Scan Network",
        runStealthButton: "Run Stealth Scan",
        toggleMenu: "Menu",
        hostCsv: "Host CSV",
        hostPdf: "Host PDF",
        deleteScan: "Delete Scan",
        resetProject: "Reset Current Project",
        deleteProject: "Delete Current Project",
        confirmAction: "Confirm Action",
        confirmCancel: "Cancel",
        confirmProceed: "Confirm",
        confirmPhraseLabel: "Type confirmation phrase",
        resetProjectConfirm: "This will remove all scans and findings in the current project.",
        deleteProjectConfirm: "This will permanently delete the project including all scans and findings.",
        deleteScanConfirm: "This will permanently delete this scan.",
        requiredPhrase: "Required phrase",
        noteDedup: "Findings are deduplicated per project, asset and vulnerability key.",
        noteMetrics: "Dashboard metrics separate unique host-port exposures from repeated scans.",
        noteNetworkHint: "Network suggestions are shown only where CIDR scanning is meaningful.",
        noteStealth: "Stealth mode remains low-noise only and does not attempt monitoring bypass.",
        notePg: "For Vercel Postgres set DATABASE_URL and install psycopg in requirements.",
        noteMongo: "For MongoDB Atlas on Vercel set MONGODB_URI and optional MONGODB_DB_NAME.",
        refRiskDesc: "Use for single hosts and domains when you want broad port, version and HTTP security coverage.",
        refNetworkDesc: "Use on authorized private networks to enumerate hosts, services and exposed surface by subnet. Access via the Network tab.",
        refStealthDesc: "Low-noise profiling and passive metadata collection. Access via the Stealth tab.",
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
        severityTimelineModeLabel: "View",
        severityTimelineModePercent: "100% Stacked",
        severityTimelineModeAbsoluteMini: "Absolute + Minimap",
        severityHeatmapTitle: "Severity Heatmap",
        recentScansTitle: "Recent Scans",
        exposureSnapshotTitle: "Exposure Snapshot",
        topAssetsTitle: "Top Exposed Assets",
        serviceInventoryTitle: "Service Inventory",
        portIntelTitle: "Port Intelligence",
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

function showAuthError(message) {
    if (!authError) {
        return;
    }
    authError.textContent = String(message || "Authentication failed.");
    authError.classList.remove("hidden");
}

function clearAuthError() {
    if (!authError) {
        return;
    }
    authError.textContent = "";
    authError.classList.add("hidden");
}

function setAuthUi(data = {}) {
    authState.required = !!data.required;
    authState.authenticated = !!data.authenticated;
    authState.user = data.user && typeof data.user === "object" ? data.user : null;
    authState.projects = Array.isArray(data.projects) ? data.projects : [];
    authState.defaultProjectId = String(data.default_project_id || "default");

    if (authSummary) {
        authSummary.classList.toggle("hidden", !authState.required || !authState.authenticated);
    }
    if (authSummaryText) {
        const username = String(authState.user?.username || "user");
        const role = String(authState.user?.role || "viewer");
        authSummaryText.textContent = authState.required && authState.authenticated
            ? `${username} · ${role}`
            : "Protected deployment";
    }

    const isAdmin = !!authState.user?.admin;
    if (newProjectButton) {
        newProjectButton.disabled = authState.required && authState.authenticated && !isAdmin;
    }
    if (resetProjectButton) {
        resetProjectButton.disabled = authState.required && authState.authenticated && !isAdmin;
    }
    if (deleteProjectButton) {
        deleteProjectButton.disabled = authState.required && authState.authenticated && !isAdmin;
    }

    if (authState.required && !authState.authenticated) {
        activeProjectId = "";
    } else if (authState.projects.length) {
        const visibleIds = authState.projects.map((item) => String(item.id || "")).filter(Boolean);
        if (!visibleIds.includes(activeProjectId)) {
            activeProjectId = visibleIds[0] || authState.defaultProjectId || "default";
        }
    }
}

function showAuthDialog(message = "") {
    if (!authModal) {
        return;
    }
    if (authModalMessage) {
        authModalMessage.textContent = String(message || "Authenticate to access project data and scan actions.");
    }
    clearAuthError();
    authModal.classList.remove("hidden");
    authModal.setAttribute("aria-hidden", "false");
    window.setTimeout(() => authUsername?.focus(), 0);
}

function hideAuthDialog() {
    if (!authModal) {
        return;
    }
    authModal.classList.add("hidden");
    authModal.setAttribute("aria-hidden", "true");
    clearAuthError();
    if (authPassword) {
        authPassword.value = "";
    }
}

async function loadSessionState() {
    const response = await nativeFetch("/api/auth/session", { credentials: "same-origin" });
    const data = await response.json();
    if (!response.ok) {
        throw new Error(data?.error || "Session state unavailable");
    }
    setAuthUi(data || {});
    return data || {};
}

async function ensureAuthenticatedSession() {
    const state = await loadSessionState();
    if (state.required && !state.authenticated) {
        showAuthDialog("Sign in to continue.");
        return false;
    }
    hideAuthDialog();
    return true;
}

async function submitLogin(username, password) {
    const { response, data } = await fetchJsonWithTimeout(
        "/api/auth/login",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        },
        20000,
    );
    if (!response.ok) {
        throw new Error(data?.error || "Authentication failed.");
    }
    setAuthUi(data || {});
    hideAuthDialog();
    await initializeWorkspace(true);
}

async function fetchJsonWithTimeout(url, options = {}, timeoutMs = 180000) {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        let data = null;
        try {
            data = await response.json();
        } catch (_) {
            data = null;
        }
        return { response, data };
    } catch (error) {
        if (error?.name === "AbortError") {
            throw new Error("Request timed out. Try Light/Standard profile or a smaller target.");
        }
        throw new Error("Failed to fetch. Please verify backend connection and retry.");
    } finally {
        window.clearTimeout(timeoutId);
    }
}

function openConfirmDialog({ title, message, phrase }) {
    return new Promise((resolve) => {
        if (!confirmModal || !confirmPhraseInput || !confirmModalOk || !confirmModalCancel) {
            resolve(false);
            return;
        }

        const lastFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;

        const safePhrase = String(phrase || "").trim();
        confirmModalTitle.textContent = title || t("confirmAction");
        confirmModalMessage.textContent = message || "";
        confirmModalPhraseLabel.textContent = `${t("confirmPhraseLabel")}: ${t("requiredPhrase")} \"${safePhrase}\"`;
        confirmPhraseInput.value = "";
        confirmModalOk.disabled = true;
        confirmModalCancel.textContent = t("confirmCancel");
        confirmModalOk.textContent = t("confirmProceed");

        const close = (accepted) => {
            const focusedInsideModal = confirmModal.contains(document.activeElement);
            if (focusedInsideModal && document.activeElement instanceof HTMLElement) {
                document.activeElement.blur();
            }
            confirmModal.classList.add("hidden");
            confirmModal.setAttribute("aria-hidden", "true");
            confirmPhraseInput.removeEventListener("input", onInput);
            confirmModalCancel.removeEventListener("click", onCancel);
            confirmModalOk.removeEventListener("click", onOk);
            if (lastFocused && document.contains(lastFocused)) {
                window.setTimeout(() => lastFocused.focus(), 0);
            }
            resolve(accepted);
        };

        const onInput = () => {
            confirmModalOk.disabled = confirmPhraseInput.value.trim() !== safePhrase;
        };
        const onCancel = () => close(false);
        const onOk = () => close(true);

        confirmPhraseInput.addEventListener("input", onInput);
        confirmModalCancel.addEventListener("click", onCancel);
        confirmModalOk.addEventListener("click", onOk);

        confirmModal.classList.remove("hidden");
        confirmModal.setAttribute("aria-hidden", "false");
        confirmPhraseInput.focus();
    });
}

function populateThemeOptions(mode, selectedTheme) {
    const themes = THEMES_BY_MODE[mode] || THEMES_BY_MODE.dark;
    themeSelect.innerHTML = themes
        .map((theme) => `<option value="${esc(theme)}">${esc(t(`theme${theme.charAt(0).toUpperCase()}${theme.slice(1)}`))}</option>`)
        .join("");
    themeSelect.value = themes.includes(selectedTheme) ? selectedTheme : themes[0];
}

function scannerSettings(mode) {
    if (mode === "advanced_v2") {
        return {
            profile: "light",
            portStrategy: "standard",
            placeholder: "example.com, 8.8.8.8",
            note: t("v2ModeNote") || "Adaptive V2 scanner uses async probing and plugin checks.",
            disableProfile: false,
            hidePortStrategy: false,
            showIntelOnly: false,
            endpoint: "/api/scan/v2",
        };
    }

    return {
        profile: "light",
        portStrategy: "standard",
        placeholder: "example.com, 8.8.8.8",
        note: t("standardModeNote"),
        disableProfile: false,
        hidePortStrategy: false,
        showIntelOnly: false,
        endpoint: "/api/scan",
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

    // Toggle scanner background pattern based on mode (orange=risk, blue=v2)
    const patternEl = document.querySelector(".scanner-hero-panel .scanner-header-pattern");
    if (patternEl) {
        patternEl.classList.remove("scanner-header-pattern-risk", "scanner-header-pattern-v2");
        patternEl.classList.add(mode === "advanced_v2" ? "scanner-header-pattern-v2" : "scanner-header-pattern-risk");
    }

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

function delayMs(ms) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function parseIsoToMs(value) {
    const ts = Date.parse(String(value || ""));
    if (Number.isFinite(ts)) {
        return ts;
    }
    return Date.now();
}

function formatElapsed(secondsRaw) {
    const total = Math.max(0, Math.floor(Number(secondsRaw || 0)));
    const mm = String(Math.floor(total / 60)).padStart(2, "0");
    const ss = String(total % 60).padStart(2, "0");
    return `${mm}:${ss}`;
}

function clamp(value, min, max) {
    return Math.min(max, Math.max(min, Number(value || 0)));
}

function prettyPhase(phaseRaw) {
    const raw = String(phaseRaw || "queued").trim().toLowerCase();
    const labels = {
        queued: "queued",
        init: "initializing",
        collect: "collecting",
        enrichment: "enrichment",
        correlation: "correlation",
        persist: "persisting",
        finalize: "finalizing",
        done: "completed",
        completed: "completed",
        failed: "failed",
        intel: "intel",
    };
    return labels[raw] || raw.replace(/_/g, " ");
}

function scanTypeLabel(variantRaw) {
    const variant = String(variantRaw || "risk").toLowerCase();
    if (variant === "v2") {
        return "Adaptive V2";
    }
    if (variant === "network") {
        return "Network";
    }
    if (variant === "stealth") {
        return "Stealth";
    }
    return "Risk";
}

function getPhaseProfile(phaseRaw) {
    const phase = String(phaseRaw || "collect").toLowerCase();
    const profile = {
        queued: { floor: 1, ceiling: 6, expectedSec: 8 },
        init: { floor: 2, ceiling: 10, expectedSec: 10 },
        collect: { floor: 10, ceiling: 58, expectedSec: 85 },
        enrichment: { floor: 48, ceiling: 78, expectedSec: 35 },
        correlation: { floor: 72, ceiling: 91, expectedSec: 24 },
        persist: { floor: 88, ceiling: 97, expectedSec: 15 },
        finalize: { floor: 95, ceiling: 99.4, expectedSec: 9 },
        done: { floor: 100, ceiling: 100, expectedSec: 0 },
        completed: { floor: 100, ceiling: 100, expectedSec: 0 },
        failed: { floor: 100, ceiling: 100, expectedSec: 0 },
        intel: { floor: 18, ceiling: 64, expectedSec: 30 },
    };
    return profile[phase] || { floor: 8, ceiling: 90, expectedSec: 48 };
}

function loadScanTimingStats() {
    try {
        const raw = localStorage.getItem("vscanner.scanTimingStats.v2");
        const parsed = raw ? JSON.parse(raw) : {};
        return parsed && typeof parsed === "object" ? parsed : {};
    } catch (_) {
        return {};
    }
}

function saveScanTimingStats(stats) {
    try {
        localStorage.setItem("vscanner.scanTimingStats.v2", JSON.stringify(stats || {}));
    } catch (_) {
        // ignore storage failures
    }
}

function readExpectedDurationSec(stats, mode, phase) {
    const modeData = (stats && stats[mode]) || {};
    const phases = modeData.phases || {};
    const item = phases[phase] || {};
    const avg = Number(item.avgSec || 0);
    if (avg > 0) {
        return avg;
    }
    return getPhaseProfile(phase).expectedSec;
}

function writeDurationStat(stats, mode, phase, durationSec) {
    const duration = clamp(durationSec, 0, 36000);
    if (!(duration > 0.25)) {
        return;
    }
    if (!stats[mode]) {
        stats[mode] = { phases: {}, total: { avgSec: 0, count: 0 } };
    }
    if (!stats[mode].phases) {
        stats[mode].phases = {};
    }
    const current = stats[mode].phases[phase] || { avgSec: 0, count: 0 };
    const count = Math.min(80, Number(current.count || 0) + 1);
    const prevAvg = Number(current.avgSec || 0);
    const nextAvg = prevAvg > 0 ? (prevAvg * (count - 1) + duration) / count : duration;
    stats[mode].phases[phase] = { avgSec: Number(nextAvg.toFixed(3)), count };
}

function formatEta(secondsRaw) {
    const seconds = Math.max(0, Math.floor(Number(secondsRaw || 0)));
    if (!seconds) {
        return "--:--";
    }
    const mm = String(Math.floor(seconds / 60)).padStart(2, "0");
    const ss = String(seconds % 60).padStart(2, "0");
    return `${mm}:${ss}`;
}

function createScanStatusController(container, variant = "risk", initial = {}) {
    if (!container) {
        return {
            update: () => {},
            complete: () => {},
            fail: () => {},
            dispose: () => {},
        };
    }

    const mode = ["risk", "v2", "network", "stealth"].includes(String(variant || "").toLowerCase())
        ? String(variant || "risk").toLowerCase()
        : "risk";

    const startedMs = parseIsoToMs(initial.createdAt);
    const shortJobId = String(initial.jobId || "").slice(0, 8);
    const typeLabel = scanTypeLabel(mode);
    const timingStats = loadScanTimingStats();

    let backendPhase = String(initial.phase || "queued").toLowerCase();
    let phaseStartedAtMs = Date.now();
    let phaseStartedFromProgress = clamp(initial.progress || getPhaseProfile(backendPhase).floor, 0, 100);
    let previousPhase = backendPhase;
    let pollProgress = clamp(initial.progress || 0, 0, 100);
    let shownProgress = pollProgress;
    let lastStatusAtMs = Date.now();
    let phaseClockInterval = 0;
    let elapsedClockInterval = 0;

    container.innerHTML = `
        <div class="scan-status-card scan-status-${esc(mode)}" role="status" aria-live="polite">
            <div class="scan-loader scan-loader-${esc(mode)}" aria-hidden="true">
                <div class="scan-loader-core">
                    <i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i>
                </div>
            </div>
            <div class="scan-status-body">
                <div class="scan-status-topline">
                    <strong class="scan-status-type">${esc(typeLabel)}</strong>
                    <span class="scan-status-elapsed">00:00</span>
                </div>
                <div class="scan-status-meta">
                    <span class="scan-status-phase">queued</span>
                    <span class="scan-status-eta">ETA --:--</span>
                </div>
                <div class="scan-status-message">Preparing scan pipeline...</div>
                <div class="scan-status-progress-track"><div class="scan-status-progress-fill"></div></div>
                <div class="scan-status-bottomline">
                    <span class="scan-status-progress-value">0%</span>
                    <span class="scan-status-jobref">Job ${esc(shortJobId || "pending")}</span>
                </div>
            </div>
        </div>
    `;

    const phaseEl = container.querySelector(".scan-status-phase");
    const elapsedEl = container.querySelector(".scan-status-elapsed");
    const messageEl = container.querySelector(".scan-status-message");
    const fillEl = container.querySelector(".scan-status-progress-fill");
    const valueEl = container.querySelector(".scan-status-progress-value");

    const etaEl = container.querySelector(".scan-status-eta");

    if (fillEl) {
        fillEl.style.width = "0%";
    }

    let completed = false;
    let rafId = 0;

    const estimateRemainingSeconds = () => {
        const elapsedSec = Math.max(0, (Date.now() - startedMs) / 1000);
        const currentPhase = String(backendPhase || "collect").toLowerCase();
        const phaseInfo = getPhaseProfile(currentPhase);
        const expectedCurrentSec = readExpectedDurationSec(timingStats, mode, currentPhase);
        const phaseElapsedSec = Math.max(0, (Date.now() - phaseStartedAtMs) / 1000);
        const phaseBasedRemaining = Math.max(0, expectedCurrentSec - phaseElapsedSec);

        let progressBasedRemaining = 0;
        if (shownProgress > 1) {
            progressBasedRemaining = Math.max(0, elapsedSec * ((100 - shownProgress) / shownProgress));
        }

        const remain = progressBasedRemaining > 0
            ? (phaseBasedRemaining * 0.62 + progressBasedRemaining * 0.38)
            : phaseBasedRemaining;
        const maxRemain = Math.max(20, phaseInfo.expectedSec * 4);
        return clamp(remain, 0, maxRemain);
    };

    const renderElapsed = () => {
        if (!elapsedEl || completed) {
            return;
        }
        const elapsedSeconds = Math.max(0, (Date.now() - startedMs) / 1000);
        elapsedEl.textContent = formatElapsed(elapsedSeconds);
    };

    const renderEta = () => {
        if (!etaEl) {
            return;
        }
        if (completed) {
            etaEl.textContent = "ETA 00:00";
            return;
        }
        etaEl.textContent = `ETA ${formatEta(estimateRemainingSeconds())}`;
    };

    const predictedProgress = () => {
        const phase = String(backendPhase || "collect").toLowerCase();
        const phaseInfo = getPhaseProfile(phase);
        const phaseElapsed = Math.max(0, (Date.now() - phaseStartedAtMs) / 1000);
        const expectedSec = Math.max(4, readExpectedDurationSec(timingStats, mode, phase));
        const phaseSpan = Math.max(0, phaseInfo.ceiling - phaseStartedFromProgress);
        const phaseAdvance = phaseSpan > 0 ? (phaseElapsed / expectedSec) * phaseSpan : 0;

        const timeSinceStatusSec = Math.max(0, (Date.now() - lastStatusAtMs) / 1000);
        const leadBudget = Math.min(7.5, 1.4 + (timeSinceStatusSec * 0.28));
        const baseline = phaseStartedFromProgress + phaseAdvance;
        const boundedTarget = Math.min(phaseInfo.ceiling - 0.12, pollProgress + leadBudget);
        return clamp(Math.max(pollProgress, baseline), 0, Math.max(pollProgress, boundedTarget));
    };

    const animate = () => {
        if (completed) {
            return;
        }
        const target = predictedProgress();
        const delta = target - shownProgress;
        if (Math.abs(delta) > 0.05) {
            shownProgress += delta * 0.11;
        } else {
            shownProgress = target;
        }
        const safeProgress = clamp(shownProgress, 0, 100);
        if (fillEl) {
            fillEl.style.width = `${safeProgress.toFixed(1)}%`;
        }
        if (valueEl) {
            valueEl.textContent = `${Math.round(safeProgress)}%`;
        }
        renderEta();
        rafId = window.requestAnimationFrame(animate);
    };

    renderElapsed();
    renderEta();
    elapsedClockInterval = window.setInterval(renderElapsed, 1000);
    phaseClockInterval = window.setInterval(renderEta, 1000);
    rafId = window.requestAnimationFrame(animate);

    const closePhaseWindow = (phaseName, endedAtMs) => {
        const ended = Number(endedAtMs || Date.now());
        const started = Number(phaseStartedAtMs || ended);
        const durationSec = Math.max(0, (ended - started) / 1000);
        writeDurationStat(timingStats, mode, String(phaseName || "collect").toLowerCase(), durationSec);
    };

    const flushStats = () => {
        saveScanTimingStats(timingStats);
    };

    return {
        update(job = {}) {
            if (completed) {
                return;
            }
            const nowMs = Date.now();
            const statusRaw = String(job.status || "").toLowerCase();
            const nextProgress = clamp(job.progress || 0, 0, 100);
            const phaseRaw = String(job.phase || backendPhase || "running").toLowerCase();

            if (phaseRaw !== backendPhase) {
                closePhaseWindow(previousPhase, nowMs);
                previousPhase = phaseRaw;
                backendPhase = phaseRaw;
                phaseStartedAtMs = nowMs;
                phaseStartedFromProgress = Math.max(nextProgress, clamp(shownProgress, 0, 100));
            }

            pollProgress = Math.max(pollProgress, nextProgress, getPhaseProfile(backendPhase).floor);
            lastStatusAtMs = nowMs;
            if (phaseEl) {
                phaseEl.textContent = prettyPhase(backendPhase);
            }
            if (messageEl) {
                let nextMessage = String(job.message || "Running scan...");
                if (statusRaw === "queued" && job.queue && typeof job.queue === "object") {
                    const position = Number(job.queue.position || 0);
                    const eta = Number(job.queue.estimated_start_seconds || 0);
                    const etaText = eta > 0 ? formatEta(eta) : "--:--";
                    if (position > 0) {
                        nextMessage = `Queued (position ${position}, ETA ${etaText})`;
                    }
                }
                messageEl.textContent = nextMessage;
            }
            renderEta();
        },
        complete(message = "Completed") {
            completed = true;
            closePhaseWindow(backendPhase, Date.now());
            pollProgress = 100;
            shownProgress = 100;
            if (fillEl) {
                fillEl.style.width = "100%";
            }
            if (valueEl) {
                valueEl.textContent = "100%";
            }
            if (phaseEl) {
                phaseEl.textContent = "completed";
            }
            if (messageEl) {
                messageEl.textContent = String(message || "Completed");
            }
            renderElapsed();
            renderEta();
            flushStats();
            window.cancelAnimationFrame(rafId);
            window.clearInterval(elapsedClockInterval);
            window.clearInterval(phaseClockInterval);
        },
        fail(message = "Scan failed") {
            completed = true;
            closePhaseWindow(backendPhase, Date.now());
            if (phaseEl) {
                phaseEl.textContent = "failed";
            }
            if (messageEl) {
                messageEl.textContent = String(message || "Scan failed");
            }
            container.querySelector(".scan-status-card")?.classList.add("scan-status-failed");
            renderElapsed();
            renderEta();
            flushStats();
            window.cancelAnimationFrame(rafId);
            window.clearInterval(elapsedClockInterval);
            window.clearInterval(phaseClockInterval);
        },
        dispose() {
            completed = true;
            flushStats();
            window.cancelAnimationFrame(rafId);
            window.clearInterval(elapsedClockInterval);
            window.clearInterval(phaseClockInterval);
        },
    };
}

async function runQueuedScan(payload, options = {}) {
    const useV2 = !!options.useV2;
    const uiMode = String(options.uiMode || (useV2 ? "v2" : "risk"));
    const statusContainer = options.statusContainer || scanResult;

    const { response, data } = await fetchJsonWithTimeout(
        "/api/scan/jobs",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ...payload, use_v2: !!useV2 }),
        },
        20000,
    );
    if (!response.ok) {
        throw new Error(data?.error || "Could not enqueue scan job");
    }
    const jobId = String(data?.id || "");
    if (!jobId) {
        throw new Error("Invalid scan job response");
    }

    activeScanStatusController?.dispose();
    activeScanStatusController = createScanStatusController(statusContainer, uiMode, {
        jobId,
        createdAt: data?.created_at,
        progress: 0,
    });

    activeScanJobId = jobId;
    let polls = 0;
    while (polls < 500) {
        polls += 1;
        const statusResponse = await fetchJsonWithTimeout(`/api/scan/jobs/${encodeURIComponent(jobId)}`, {}, 20000);
        if (!statusResponse.response.ok) {
            throw new Error(statusResponse.data?.error || "Scan job status unavailable");
        }
        const job = statusResponse.data || {};
        const status = String(job.status || "queued").toLowerCase();
        activeScanStatusController?.update(job);
        if (status === "completed") {
            activeScanStatusController?.complete(job.message || "Scan completed");
            return job.result || {};
        }
        if (status === "failed") {
            activeScanStatusController?.fail(job.error || job.message || "Scan job failed");
            throw new Error(job.error || job.message || "Scan job failed");
        }
        await delayMs(1400);
    }
    activeScanStatusController?.fail("Scan job timeout. Please check backend status.");
    throw new Error("Scan job timeout. Please check job status in backend.");
}

async function loadFindingDetail(findingKey) {
    const key = String(findingKey || "").trim();
    if (!findingDetail) {
        return;
    }
    if (!key) {
        findingDetail.innerHTML = `<div class="list-item"><div class="list-line">Select a finding to inspect technical context, evidence, CVEs, and remediation guidance.</div></div>`;
        return;
    }

    findingDetail.innerHTML = '<div class="list-item"><div class="list-line">Loading finding detail...</div></div>';
    const { response, data } = await fetchJsonWithTimeout(
        `/api/projects/${encodeURIComponent(activeProjectId)}/findings/${encodeURIComponent(key)}?since_days=${encodeURIComponent(sinceDays.value || "3650")}`,
        {},
        30000,
    );
    if (!response.ok) {
        throw new Error(data?.error || "Could not load finding detail");
    }

    const assets = Array.isArray(data.assets) ? data.assets : [];
    const ports = Array.isArray(data.ports) ? data.ports : [];
    const cves = Array.isArray(data.related_cves) ? data.related_cves : [];
    const instances = Array.isArray(data.instances) ? data.instances : [];
    const remediation = data.remediation || {};
    const actions = Array.isArray(remediation.recommended_actions) ? remediation.recommended_actions : [];

    const instanceRows = instances
        .slice(0, 60)
        .map((item) => `
            <tr>
                <td>${esc(item.asset || item.host || "-")}</td>
                <td>${esc(item.port || "-")}</td>
                <td>${esc(item.service || "unknown")}</td>
                <td>${esc(item.status || "active")}</td>
                <td>${esc(item.last_seen || "-")}</td>
                <td>${esc(item.evidence || "-")}</td>
            </tr>
        `)
        .join("");

    findingDetail.innerHTML = `
        <div class="finding-detail-grid">
            <div class="finding-detail-kpis">
                <div class="finding-detail-kpi"><span>Severity</span><strong>${esc(data.severity || "low")}</strong></div>
                <div class="finding-detail-kpi"><span>Risk</span><strong>${esc(data.risk_score || 0)}</strong></div>
                <div class="finding-detail-kpi"><span>Assets</span><strong>${esc(data.asset_count || 0)}</strong></div>
                <div class="finding-detail-kpi"><span>Occurrences</span><strong>${esc(data.occurrence_count || 0)}</strong></div>
            </div>
            <div class="list-item">
                <div class="list-line"><strong>${esc(data.title || "Finding")}</strong><span>${esc(data.type || "-")}</span></div>
                <div class="finding-section-title">Related CVEs</div>
                <div class="finding-chip-row">${(cves.length ? cves : ["-"]).map((v) => `<span class="finding-chip">${esc(v)}</span>`).join("")}</div>
                <div class="finding-section-title">Affected Assets</div>
                <div class="finding-chip-row">${(assets.length ? assets : ["-"]).map((v) => `<span class="finding-chip">${esc(v)}</span>`).join("")}</div>
                <div class="finding-section-title">Observed Ports</div>
                <div class="finding-chip-row">${(ports.length ? ports : ["-"]).map((v) => `<span class="finding-chip">${esc(v)}</span>`).join("")}</div>
                <div class="finding-section-title">Primary Evidence</div>
                <div class="finding-evidence">${esc(data.evidence || "-")}</div>
                <div class="finding-section-title">Remediation</div>
                <div class="list-line"><span>${esc(remediation.summary || "-")}</span></div>
                <div class="list-line"><span>Priority: ${esc(remediation.priority || "scheduled")}</span><span>Effort: ${esc(remediation.effort || "medium")}</span></div>
                <div class="finding-chip-row">${actions.map((a) => `<span class="finding-chip">${esc(a)}</span>`).join("")}</div>
            </div>
            <div>
                <div class="finding-section-title">Technical Instances</div>
                <div class="finding-instance-table">
                    <table class="table compact-table">
                        <thead>
                            <tr><th>Asset</th><th>Port</th><th>Service</th><th>Status</th><th>Last Seen</th><th>Evidence</th></tr>
                        </thead>
                        <tbody>${instanceRows || '<tr><td colspan="6">No instance data available.</td></tr>'}</tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

function activateTab(tabName) {
    menuItems.forEach((button) => {
        button.classList.toggle("active", button.dataset.tab === tabName);
    });

    tabs.forEach((tab) => {
        tab.classList.toggle("active", tab.id === `tab-${tabName}`);
        if (tab.id === `tab-${tabName}`) {
            tab.classList.remove("tab-transition-in");
            // Restart animation for each tab activation.
            void tab.offsetWidth;
            tab.classList.add("tab-transition-in");
        }
    });

    const targetPath = tabToPath(tabName);
    if (window.location.pathname !== targetPath) {
        window.history.pushState({ tab: tabName }, "", targetPath);
    }
}

function tabToPath(tabName) {
    const map = {
        dashboard: "/dashboard",
        scanner: "/scanner",
        network: "/network",
        stealth: "/stealth",
        findings: "/findings",
        assets: "/assets",
        history: "/history",
        settings: "/settings",
    };
    return map[tabName] || "/dashboard";
}

function pathToTab(pathname) {
    const map = {
        "/": "dashboard",
        "/dashboard": "dashboard",
        "/scanner": "scanner",
        "/network": "network",
        "/stealth": "stealth",
        "/findings": "findings",
        "/assets": "assets",
        "/history": "history",
        "/settings": "settings",
    };
    return map[pathname] || "dashboard";
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

window.addEventListener("popstate", () => {
    const tab = pathToTab(window.location.pathname);
    menuItems.forEach((button) => {
        button.classList.toggle("active", button.dataset.tab === tab);
    });
    tabs.forEach((tabEl) => {
        tabEl.classList.toggle("active", tabEl.id === `tab-${tab}`);
    });
    if (tab === "history") {
        loadHistory();
    }
    if (tab === "findings") {
        loadAggregatedFindings();
    }
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
                duration: CHART_ANIMATION_MS,
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

    const values = ORDER.map((key) => Number(summary[key]));
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
                duration: CHART_ANIMATION_MS + 80,
                easing: "easeOutExpo",
            },
            plugins: {
                legend: { display: false },
            },
            cutout: "62%",
        },
    });

    riskLegend.innerHTML = ORDER.map((key) => `<div class="risk-item"><span>${key.toUpperCase()}</span><strong>${summary[key]}</strong></div>`).join("");
}

function drawSeverityStack(points) {
    if (!window.Chart || !severityStackChart) {
        return;
    }

    const mode = severityTimelineMode?.value === "absolute_minimap" ? "absolute_minimap" : "percent_stacked";
    localStorage.setItem("vscanner.severityTimelineMode", mode);

    if (severityStackChartInstance) {
        severityStackChartInstance.destroy();
    }
    if (severityMiniChartInstance) {
        severityMiniChartInstance.destroy();
    }

    const safePoints = Array.isArray(points) && points.length
        ? points
        : [{ created_at: "", critical: 0, high: 0, medium: 0, low: 0 }];

    const labels = safePoints.map((item) => String(item.created_at || "").slice(5, 10) || "-");
    const criticalAbs = safePoints.map((item) => Number(item.critical || 0));
    const highAbs = safePoints.map((item) => Number(item.high || 0));
    const mediumAbs = safePoints.map((item) => Number(item.medium || 0));
    const lowAbs = safePoints.map((item) => Number(item.low || 0));
    const totals = safePoints.map((_, idx) => criticalAbs[idx] + highAbs[idx] + mediumAbs[idx] + lowAbs[idx]);

    if (mode === "absolute_minimap") {
        severityTimelinePanel?.classList.add("minimap-enabled");
        if (severityMiniWrap) {
            severityMiniWrap.style.display = "block";
        }

        severityStackChartInstance = new window.Chart(severityStackChart, {
            type: "line",
            data: {
                labels,
                datasets: [
                    {
                        label: "Critical",
                        data: criticalAbs,
                        borderColor: "rgba(255,93,115,0.95)",
                        backgroundColor: "rgba(255,93,115,0.16)",
                        fill: false,
                        tension: 0.3,
                        pointRadius: 0,
                        borderWidth: 2,
                    },
                    {
                        label: "High",
                        data: highAbs,
                        borderColor: "rgba(255,195,92,0.95)",
                        backgroundColor: "rgba(255,195,92,0.16)",
                        fill: false,
                        tension: 0.3,
                        pointRadius: 0,
                        borderWidth: 2,
                    },
                    {
                        label: "Medium",
                        data: mediumAbs,
                        borderColor: "rgba(103,185,255,0.95)",
                        backgroundColor: "rgba(103,185,255,0.16)",
                        fill: false,
                        tension: 0.3,
                        pointRadius: 0,
                        borderWidth: 2,
                    },
                    {
                        label: "Low",
                        data: lowAbs,
                        borderColor: "rgba(76,221,136,0.95)",
                        backgroundColor: "rgba(76,221,136,0.16)",
                        fill: false,
                        tension: 0.3,
                        pointRadius: 0,
                        borderWidth: 2,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: CHART_ANIMATION_MS,
                    easing: "easeOutQuart",
                },
                interaction: {
                    mode: "index",
                    intersect: false,
                },
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: "#dce9f7",
                            usePointStyle: true,
                            boxWidth: 10,
                            boxHeight: 10,
                            padding: 14,
                        },
                    },
                },
                scales: {
                    x: {
                        ticks: { color: "#9bb4cb", maxTicksLimit: 10 },
                        grid: { color: "rgba(126,161,198,0.1)" },
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: "#9bb4cb" },
                        grid: { color: "rgba(126,161,198,0.14)" },
                    },
                },
            },
        });

        if (severityMiniChart) {
            severityMiniChartInstance = new window.Chart(severityMiniChart, {
                type: "line",
                data: {
                    labels,
                    datasets: [
                        {
                            label: "Total",
                            data: totals,
                            borderColor: "rgba(103,185,255,0.95)",
                            backgroundColor: "rgba(103,185,255,0.22)",
                            fill: true,
                            tension: 0.35,
                            pointRadius: 0,
                            borderWidth: 1.6,
                        },
                    ],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: {
                        duration: CHART_ANIMATION_MS,
                        easing: "easeOutQuad",
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: { enabled: false },
                    },
                    scales: {
                        x: { display: false, grid: { display: false } },
                        y: { display: false, grid: { display: false }, beginAtZero: true },
                    },
                },
            });
        }
        return;
    }

    severityTimelinePanel?.classList.remove("minimap-enabled");
    if (severityMiniWrap) {
        severityMiniWrap.style.display = "none";
    }

    const pct = safePoints.map((_, idx) => {
        const total = totals[idx] || 0;
        if (!total) {
            return { critical: 0, high: 0, medium: 0, low: 0 };
        }
        return {
            critical: (criticalAbs[idx] / total) * 100,
            high: (highAbs[idx] / total) * 100,
            medium: (mediumAbs[idx] / total) * 100,
            low: (lowAbs[idx] / total) * 100,
        };
    });

    severityStackChartInstance = new window.Chart(severityStackChart, {
        type: "line",
        data: {
            labels,
            datasets: [
                {
                    label: "Critical",
                    data: pct.map((item) => Number(item.critical.toFixed(2))),
                    absoluteData: criticalAbs,
                    borderColor: "rgba(255,93,115,0.95)",
                    backgroundColor: "rgba(255,93,115,0.28)",
                    fill: true,
                    stack: "sev",
                    tension: 0.35,
                    pointRadius: 0,
                    borderWidth: 1.8,
                },
                {
                    label: "High",
                    data: pct.map((item) => Number(item.high.toFixed(2))),
                    absoluteData: highAbs,
                    borderColor: "rgba(255,195,92,0.95)",
                    backgroundColor: "rgba(255,195,92,0.28)",
                    fill: true,
                    stack: "sev",
                    tension: 0.35,
                    pointRadius: 0,
                    borderWidth: 1.8,
                },
                {
                    label: "Medium",
                    data: pct.map((item) => Number(item.medium.toFixed(2))),
                    absoluteData: mediumAbs,
                    borderColor: "rgba(103,185,255,0.95)",
                    backgroundColor: "rgba(103,185,255,0.25)",
                    fill: true,
                    stack: "sev",
                    tension: 0.35,
                    pointRadius: 0,
                    borderWidth: 1.8,
                },
                {
                    label: "Low",
                    data: pct.map((item) => Number(item.low.toFixed(2))),
                    absoluteData: lowAbs,
                    borderColor: "rgba(76,221,136,0.95)",
                    backgroundColor: "rgba(76,221,136,0.25)",
                    fill: true,
                    stack: "sev",
                    tension: 0.35,
                    pointRadius: 0,
                    borderWidth: 1.8,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: CHART_ANIMATION_MS + 40,
                easing: "easeOutQuart",
            },
            interaction: {
                mode: "index",
                intersect: false,
            },
            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#dce9f7",
                        usePointStyle: true,
                        boxWidth: 10,
                        boxHeight: 10,
                        padding: 14,
                    },
                },
                tooltip: {
                    backgroundColor: "rgba(8, 16, 27, 0.95)",
                    borderColor: "rgba(133, 173, 210, 0.3)",
                    borderWidth: 1,
                    titleColor: "#e7f2ff",
                    bodyColor: "#d3e5f8",
                    callbacks: {
                        label(context) {
                            const pctValue = Number(context.parsed.y || 0).toFixed(1);
                            const absValue = context.dataset.absoluteData?.[context.dataIndex] || 0;
                            return `${context.dataset.label}: ${pctValue}% (${absValue})`;
                        },
                    },
                },
            },
            scales: {
                x: {
                    stacked: true,
                    ticks: { color: "#9bb4cb", maxTicksLimit: 10 },
                    grid: { color: "rgba(126,161,198,0.1)" },
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    max: 100,
                    ticks: { color: "#9bb4cb" },
                    grid: { color: "rgba(126,161,198,0.14)" },
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
            counts[sev] += Number(item.affected_assets);
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
            const title = String(item.title || "");
            const cve = String(item.cve || "");
            return `
                <div class="list-item" data-top-vuln="1" data-title="${esc(title)}" data-cve="${esc(cve)}">
                    <div class="list-line">
                        <span class="badge badge-${esc(sev)}">${esc(sev)}</span>
                        <strong>${esc(t("assets"))}: ${esc(item.affected_assets)}</strong>
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
        { label: t("openPorts"), value: totals.open_ports },
        { label: t("exposedServices"), value: totals.exposed_services },
        { label: t("cveCandidates"), value: totals.cve_count },
        { label: t("totalFindings"), value: totals.active_vulnerabilities },
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
                <div class="list-item" data-top-asset="1" data-asset="${esc(item.host || "")}">
                    <div class="list-line"><strong>${esc(item.host || "-")}</strong><span>${esc(item.last_seen || "-")}</span></div>
                    <div class="list-line"><span>${esc(t("openPorts"))}: ${esc(item.open_ports)}</span><span>${esc(t("findingsLabel"))}: ${esc(item.findings)}</span></div>
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
        .map(
            (item) => `
                <div class="list-item" data-service-item="1" data-service="${esc(item.service || "unknown")}">
                    <div class="list-line"><strong>${esc(item.service || "unknown")}</strong><span>${esc(t("assets"))}: ${esc(item.asset_count || 0)}</span></div>
                    <div class="list-line"><span>Observations: ${esc(item.count || 0)}</span><span>Ports: ${esc((item.ports || []).join(", ") || "-")}</span></div>
                </div>
            `
        )
        .join("");
}

function renderPortIntelligence(inventoryItems) {
    const el = document.getElementById("portIntelList");
    if (!el) return;
    // Build a flat port→service→count mapping from service_inventory
    const portMap = new Map();
    (inventoryItems || []).forEach((item) => {
        (item.ports || []).forEach((p) => {
            const key = String(p);
            if (!portMap.has(key)) portMap.set(key, { service: item.service || "unknown", count: 0 });
            portMap.get(key).count += item.count || 1;
        });
    });
    const sorted = [...portMap.entries()].sort((a, b) => b[1].count - a[1].count);
    if (!sorted.length) {
        el.innerHTML = `<div class="port-intel-item port-intel-empty"><span class="port-intel-service">No port data yet - run a scan to populate.</span></div>`;
        return;
    }
    const maxCount = sorted[0][1].count || 1;
    el.innerHTML = sorted.map(([port, info]) => {
        const svc = info.service.length > 22 ? info.service.slice(0, 20) + "…" : info.service;
        return `<div class="port-intel-item" data-port-intel="1" data-port="${esc(port)}" data-service="${esc(info.service || "unknown")}">
            <span class="port-intel-port">${esc(port)}</span>
            <span class="port-intel-service">${esc(svc)}</span>
            <div class="port-intel-bar-wrap"><progress class="port-intel-bar" max="${maxCount}" value="${Math.max(0, Number(info.count) || 0)}"></progress></div>
            <span class="port-intel-count">${esc(info.count)}</span>
        </div>`;
    }).join("");
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
    setText("severityTimelineModeLabel", text.severityTimelineModeLabel || I18N.en.severityTimelineModeLabel || "View");
    setText("severityHeatmapTitle", t("severityHeatmapTitle"));
    setText("recentScansTitle", t("recentScansTitle"));
    setText("exposureSnapshotTitle", t("exposureSnapshotTitle"));
    setText("topAssetsTitle", t("topAssetsTitle"));
    setText("serviceInventoryTitle", t("serviceInventoryTitle"));
    setText("portIntelTitle", t("portIntelTitle") || "Port Intelligence");
    setText("assetsInventoryTitle", text.assets || I18N.en.assets || "Assets");
    setText("assetsAddTitle", text.newProject || "Add Asset");
    setText("runNewScanTitle", text.runScan || I18N.en.runScan);
    setText("modeRiskTitle", text.riskScanner || I18N.en.riskScanner);
    setText("modeRiskDesc", text.riskScannerDesc || I18N.en.riskScannerDesc);
    setText("modeNetworkTitle", text.networkScanner || I18N.en.networkScanner);
    setText("modeNetworkDesc", text.networkScannerDesc || I18N.en.networkScannerDesc);
    setText("modeStealthTitle", text.stealthScanner || I18N.en.stealthScanner);
    setText("modeStealthDesc", text.stealthScannerDesc || I18N.en.stealthScannerDesc);
    setText("modeV2Title", text.v2Scanner || I18N.en.v2Scanner || "Adaptive V2 Scanner");
    setText("modeV2Desc", text.v2ScannerDesc || I18N.en.v2ScannerDesc || "Async scanner engine with plugin-based checks and deeper protocol fingerprinting.");
    setText("netSuggestedLabel", text.suggestedNetworks || I18N.en.suggestedNetworks);
    setText("latestScanFindingsTitle", text.latestFindings || I18N.en.latestFindings);
    setText("aggregatedFindingsTitle", text.aggregatedFindings || I18N.en.aggregatedFindings);
    setText("scanHistoryTitle", text.scanHistory || I18N.en.scanHistory);
    setText("workspacePreferencesTitle", text.workspacePreferences || I18N.en.workspacePreferences);
    setText("preferencesNote", text.preferencesNote || I18N.en.preferencesNote);
    setText("operationalNotesTitle", text.operationalNotes || I18N.en.operationalNotes);
    setText("scannerReferenceTitle", text.scannerReference || I18N.en.scannerReference);
    setText("kpiAvgRiskLabel", text.kpiAvgRiskLabel || I18N.en.kpiAvgRiskLabel);
    setText("kpiAvgRiskHint", text.kpiAvgRiskHint || I18N.en.kpiAvgRiskHint);
    setText("kpiScansLabel", text.kpiScansLabel || I18N.en.kpiScansLabel);
    setText("kpiScansHint", text.kpiScansHint || I18N.en.kpiScansHint);
    setText("kpiUniqueLabel", text.kpiUniqueLabel || I18N.en.kpiUniqueLabel);
    setText("kpiUniqueHint", text.kpiUniqueHint || I18N.en.kpiUniqueHint);
    setText("kpiAssetsLabel", text.kpiAssetsLabel || I18N.en.kpiAssetsLabel);
    setText("kpiAssetsHint", text.kpiAssetsHint || I18N.en.kpiAssetsHint);
    setText("netScanTitle", text.networkScanner || I18N.en.networkScanner);
    setText("netResultTitle", text.netResultTitle || I18N.en.netResultTitle);
    setText("stealthScanTitle", text.stealthScanner || I18N.en.stealthScanner);
    setText("stealthResultTitle", text.stealthResultTitle || I18N.en.stealthResultTitle);
    setText("noteDedup", text.noteDedup || I18N.en.noteDedup);
    setText("noteMetrics", text.noteMetrics || I18N.en.noteMetrics);
    setText("noteNetworkHint", text.noteNetworkHint || I18N.en.noteNetworkHint);
    setText("noteStealth", text.noteStealth || I18N.en.noteStealth);
    setText("notePg", text.notePg || I18N.en.notePg);
    setText("noteMongo", text.noteMongo || I18N.en.noteMongo);
    setText("refRiskTitle", text.riskScanner || I18N.en.riskScanner);
    setText("refNetworkTitle", text.networkScanner || I18N.en.networkScanner);
    setText("refStealthTitle", text.stealthScanner || I18N.en.stealthScanner);
    setText("refRiskDesc", text.refRiskDesc || I18N.en.refRiskDesc);
    setText("refNetworkDesc", text.refNetworkDesc || I18N.en.refNetworkDesc);
    setText("refStealthDesc", text.refStealthDesc || I18N.en.refStealthDesc);

    const setLabel = (selector, value) => {
        const label = document.querySelector(selector);
        if (label) {
            label.textContent = value;
        }
    };

    setLabel('label[for="target"]', text.target || I18N.en.target);
    setLabel('label[for="profile"]', text.scanProfile || I18N.en.scanProfile);
    setLabel('label[for="portStrategy"]', text.portStrategy || I18N.en.portStrategy);
    setLabel('label[for="languageSelect"]', text.language || I18N.en.language);
    setLabel('label[for="modeSelect"]', text.mode || I18N.en.mode);
    setLabel('label[for="themeSelect"]', text.theme || I18N.en.theme);
    setLabel('label[for="windowDays"]', text.window || I18N.en.window);
    setLabel('label[for="severityFilter"]', text.severity || I18N.en.severity);
    setLabel('label[for="sinceDays"]', text.since || I18N.en.since);
    setLabel('label[for="sortBy"]', text.sortBy || I18N.en.sortBy);
    setLabel('label[for="sortDir"]', text.direction || I18N.en.direction);
    setLabel('label[for="findingSearch"]', text.search || I18N.en.search);

    const profileOptions = profileSelect?.options;
    if (profileOptions && profileOptions.length >= 2) {
        profileOptions[0].textContent = text.profileLight || I18N.en.profileLight;
        profileOptions[1].textContent = text.profileDeep || I18N.en.profileDeep;
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

    const severityTimelineModeOptions = severityTimelineMode?.options;
    if (severityTimelineModeOptions && severityTimelineModeOptions.length >= 2) {
        severityTimelineModeOptions[0].textContent = text.severityTimelineModePercent || I18N.en.severityTimelineModePercent || "100% Stacked";
        severityTimelineModeOptions[1].textContent = text.severityTimelineModeAbsoluteMini || I18N.en.severityTimelineModeAbsoluteMini || "Absolute + Minimap";
    }

    modeSelect.options[0].textContent = text.modeDark || I18N.en.modeDark;
    modeSelect.options[1].textContent = text.modeBright || I18N.en.modeBright;

    populateThemeOptions(mode, currentTheme);

    const navText = {
        dashboard: text.dashboard,
        scanner: text.scanner,
        network: text.networkTab || "Network",
        stealth: text.stealthTab || "Stealth",
        findings: text.findings,
        assets: text.assets,
        history: text.history,
        settings: text.settings,
    };
    Object.entries(navText).forEach(([tab, label]) => {
        const navLabel = document.querySelector(`.menu-item[data-tab="${tab}"] .menu-label`);
        if (navLabel) {
            navLabel.textContent = label;
        }
    });
    newProjectButton.textContent = text.newProject;
    projectCsvButton.textContent = text.projectCsv;
    projectPdfButton.textContent = text.projectPdf;
    reportCsvButton.textContent = text.reportCsv;
    reportPdfButton.textContent = text.reportPdf;
    if (resetProjectButton) {
        resetProjectButton.textContent = text.resetProject || I18N.en.resetProject || "Reset Current Project";
    }
    if (deleteProjectButton) {
        deleteProjectButton.textContent = text.deleteProject || I18N.en.deleteProject || "Delete Current Project";
    }
    if (confirmModalCancel) {
        confirmModalCancel.textContent = text.confirmCancel || I18N.en.confirmCancel || "Cancel";
    }
    if (confirmModalOk) {
        confirmModalOk.textContent = text.confirmProceed || I18N.en.confirmProceed || "Confirm";
    }
    findingsCsvButton.textContent = text.findingsCsv;
    refreshFindingsButton.textContent = text.refresh;
    refreshHistoryButton.textContent = text.refresh;
    if (netScanButton && !netScanButton.disabled) {
        netScanButton.textContent = text.scanNetworkButton || I18N.en.scanNetworkButton || "Scan Network";
    }
    if (stealthScanButton && !stealthScanButton.disabled) {
        stealthScanButton.textContent = text.runStealthButton || I18N.en.runStealthButton || "Run Stealth Scan";
    }
    if (scanButton && !scanButton.disabled) {
        scanButton.textContent = text.startScan;
    }
    if (intelOnlyButton && !intelOnlyButton.disabled) {
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

function applySidebarState(collapsed) {
    if (!appShell) return;
    appShell.classList.toggle("sidebar-collapsed", !!collapsed);
    localStorage.setItem("vscanner.sidebarCollapsed", collapsed ? "1" : "0");
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
    const hostOpenPortsObserved = (data.hosts || []).reduce((acc, host) => {
        const openPorts = (host.ports || []).filter((entry) => String(entry.state || "").toLowerCase() === "open");
        return acc + openPorts.length;
    }, 0);
    const openPortsDisplay = hostOpenPortsObserved > 0 ? hostOpenPortsObserved : (metrics.open_ports || 0);
    const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const rows = [...(data.finding_items || [])]
        .sort((a, b) => {
            const aRank = severityRank[String(a?.severity || "low").toLowerCase()] || 0;
            const bRank = severityRank[String(b?.severity || "low").toLowerCase()] || 0;
            if (aRank !== bRank) {
                return bRank - aRank;
            }
            return String(a?.title || "").localeCompare(String(b?.title || ""));
        })
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
            const openPorts = [...(host.ports || [])]
                .filter((entry) => String(entry.state || "").toLowerCase() === "open")
                .sort((a, b) => Number(a.port || 0) - Number(b.port || 0));
            const portRows = openPorts
                .map(
                    (entry) => {
                        const metadata = entry.metadata && typeof entry.metadata === "object" ? entry.metadata : {};
                        const detailParts = [
                            metadata.http_app || "",
                            metadata.title ? `title: ${metadata.title}` : "",
                            metadata.http_status || "",
                            metadata.http_server || "",
                            metadata.http_powered_by || "",
                        ].filter(Boolean);
                        const detail = detailParts.join(" | ") || "-";
                        const banner = String(entry.banner || "-").replace(/\s+/g, " ").slice(0, 220);
                        return `
                        <tr>
                            <td>${esc(entry.port)}</td>
                            <td>${esc(entry.protocol || "-")}</td>
                            <td>${esc(entry.name || "-")}</td>
                            <td>${esc(entry.product || "-")}</td>
                            <td>${esc(entry.version || "-")}</td>
                            <td>${esc(detail)}</td>
                            <td>${esc(banner || "-")}</td>
                        </tr>
                    `;
                    }
                )
                .join("");

            const hostnames = Array.isArray(host.hostnames) ? host.hostnames.filter(Boolean).join(", ") : "";
            const hostId = String(host.host || "-");
            const reportId = String(data.report_id || "");
            return `
                <div class="host-card">
                    <div class="host-head">
                        <strong>${esc(host.host || "-")}</strong>
                        <span>${esc(host.state || "unknown")} | Open ports: ${openPorts.length}</span>
                    </div>
                    <div class="list-line"><span>Hostnames: ${esc(hostnames || "-")}</span><span>Reverse DNS: ${esc(host.reverse_dns || "-")}</span></div>
                    ${reportId ? `<div class="host-actions"><button class="btn ghost" type="button" data-host-report-csv="${esc(reportId)}" data-host-name="${esc(hostId)}">${esc(t("hostCsv"))}</button><button class="btn ghost" type="button" data-host-report-pdf="${esc(reportId)}" data-host-name="${esc(hostId)}">${esc(t("hostPdf"))}</button></div>` : ""}
                    <table class="table compact-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Proto</th>
                                <th>${esc(t("service"))}</th>
                                <th>${esc(t("product"))}</th>
                                <th>${esc(t("version"))}</th>
                                <th>Details</th>
                                <th>Banner</th>
                            </tr>
                        </thead>
                        <tbody>${portRows || '<tr><td colspan="7">No open ports on this host.</td></tr>'}</tbody>
                    </table>
                </div>
            `;
        })
        .join("");

    const intelBlock = renderIntelBlock(data.intel || null);

    return `
        <div class="scan-summary-grid">
            <div class="scan-summary-item"><span>${esc(t("hostsScanned"))}</span><strong>${esc(metrics.hosts_scanned || 0)}</strong></div>
            <div class="scan-summary-item"><span>${esc(t("openPorts"))}</span><strong>${esc(openPortsDisplay)}</strong></div>
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
            const conf = String(item.confidence || "medium").toLowerCase();
            const crit = String(item.asset_criticality || "normal").toLowerCase();
            const findingKey = String(item.dedup_key || item.vuln_key || "");
            const selectedClass = selectedFindingKey && findingKey === selectedFindingKey ? "is-selected" : "";
            return `
                <tr class="finding-row ${selectedClass}" data-finding-key="${esc(findingKey)}">
                    <td><span class="badge badge-${esc(sev)}">${esc(sev)}</span></td>
                    <td>${esc(item.title || "-")}</td>
                    <td>${esc(item.type || "-")}</td>
                    <td>${esc(item.cve || "-")}</td>
                    <td>${esc(item.asset_count || 0)}</td>
                    <td>${esc(item.occurrence_count || 0)}</td>
                    <td><span class="conf-badge conf-${esc(conf)}">${esc(conf)}</span></td>
                    <td><span class="crit-badge crit-${esc(crit)}">${esc(crit)}</span></td>
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
                    <th>Confidence</th>
                    <th>Criticality</th>
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
                                <button class="btn ghost" type="button" data-delete-report="${esc(item.id)}">${esc(t("deleteScan"))}</button>
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

function renderAssetsSummary(items, totals) {
    if (!assetsSummary) {
        return;
    }
    const highCriticality = (items || []).filter((item) => String(item.criticality || "medium") === "high").length;
    assetsSummary.innerHTML = [
        `<span>Assets <strong>${esc((items || []).length)}</strong></span>`,
        `<span>Critical assets <strong>${esc(totals.critical_assets ?? highCriticality)}</strong></span>`,
        `<span>Affected assets <strong>${esc(totals.affected_assets)}</strong></span>`,
    ].join("");
}

function renderAssets(items) {
    if (!assetsInventory) {
        return;
    }
    if (!items.length) {
        assetsInventory.innerHTML = `<div class="list-item"><div class="list-line">${esc(t("noAssetInventory") || "No assets yet")}</div></div>`;
        return;
    }

    assetsInventory.innerHTML = items
        .map((item) => {
            const tags = (item.tags || []).map((tag) => `<span class="chip">${esc(tag)}</span>`).join(" ");
            const criticality = String(item.criticality || "medium").toLowerCase();
            return `
                <div class="list-item">
                    <div class="list-line"><strong>${esc(item.value || "-")}</strong><span class="crit-badge crit-${esc(criticality)}">${esc(criticality)}</span></div>
                    <div class="list-line"><span>${tags || "-"}</span><span>${esc(item.created_at || "-")}</span></div>
                </div>
            `;
        })
        .join("");
}

async function loadAssets() {
    const params = new URLSearchParams();
    const rawTags = String(assetTagFilter?.value || "").trim();
    if (rawTags) {
        params.set("tags", rawTags);
    }
    const qs = params.toString();
    const response = await fetch(`/api/projects/${encodeURIComponent(activeProjectId)}/assets${qs ? `?${qs}` : ""}`);
    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || "Assets unavailable");
    }
    renderAssets(data.items || []);
    return data.items || [];
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
    projectSelect.disabled = !(items || []).length;
    if (!(items || []).some((item) => item.id === activeProjectId)) {
        activeProjectId = (items || [])[0]?.id || authState.defaultProjectId || "default";
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
    return data.items || [];
}

async function loadDashboard() {
    const days = Number(windowDays.value || 30);
    const projectId = activeProjectId || "default";
    const requestSeq = ++dashboardRequestSeq;
    if (dashboardAbortController) {
        dashboardAbortController.abort();
    }
    dashboardAbortController = new AbortController();
    const endpoint = `/api/dashboard?project_id=${encodeURIComponent(projectId)}&window_days=${days}&lite=1`;
    let response;
    let data;
    try {
        response = await fetch(endpoint, { signal: dashboardAbortController.signal });
        data = await response.json();
    } catch (error) {
        if (error && error.name === "AbortError") {
            return;
        }
        throw error;
    }
    if (requestSeq !== dashboardRequestSeq) {
        return;
    }
    if (!response.ok) {
        throw new Error(data.error || "Dashboard unavailable");
    }

    const dashboardData = { ...(data.totals || {}), ...data };
    kpiAvgRisk.textContent = String(dashboardData.risk_score);
    kpiScans.textContent = String(dashboardData.scans);
    kpiUnique.textContent = String(dashboardData.active_vulnerabilities);
    kpiAssets.textContent = String(dashboardData.affected_assets);

    drawTrend(data.trend || []);
    drawRiskBars(data.risk_distribution);
    severityTimelinePoints = data.severity_timeline || [];
    drawSeverityStack(severityTimelinePoints);
    renderSeverityHeatmap(data.top_vulnerabilities || []);
    renderTopVulns(data.top_vulnerabilities || []);
    renderRecentScans(data.recent_scans || []);
    renderExposureSummary(dashboardData);
    renderTopAssets(data.top_assets || []);
    renderServiceInventory(data.service_inventory || []);
    renderPortIntelligence(data.service_inventory || []);
    renderAssetsSummary(data.assets || [], dashboardData);
}

async function refreshWorkspaceViews(priority = "dashboard") {
    if (priority === "dashboard") {
        await loadDashboard();
        void Promise.allSettled([loadAggregatedFindings(), loadHistory(), loadAssets()]);
        return;
    }
    await Promise.all([loadDashboard(), loadAggregatedFindings(), loadHistory(), loadAssets()]);
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

    const items = data.items || [];
    renderFindings(items);
    if (!items.length) {
        selectedFindingKey = "";
        await loadFindingDetail("");
        return;
    }
    const hasCurrentSelection = items.some((item) => String(item.dedup_key || item.vuln_key || "") === selectedFindingKey);
    if (!hasCurrentSelection) {
        selectedFindingKey = String(items[0].dedup_key || items[0].vuln_key || "");
    }
    if (selectedFindingKey) {
        await loadFindingDetail(selectedFindingKey);
    }
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

window.openHostReportCsv = function openHostReportCsv(reportId, host) {
    window.open(`/api/reports/${encodeURIComponent(reportId)}/hosts/${encodeURIComponent(host)}/csv`, "_blank", "noopener,noreferrer");
};

window.openHostReportPdf = function openHostReportPdf(reportId, host) {
    window.open(`/api/reports/${encodeURIComponent(reportId)}/hosts/${encodeURIComponent(host)}/pdf`, "_blank", "noopener,noreferrer");
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
        return;
    }

    const deleteButton = event.target.closest("[data-delete-report]");
    if (deleteButton) {
        const reportId = deleteButton.dataset.deleteReport || "";
        const accepted = await openConfirmDialog({
            title: t("confirmAction"),
            message: t("deleteScanConfirm"),
            phrase: "DELETE SCAN",
        });
        if (!accepted) {
            return;
        }

        try {
            const { response, data } = await fetchJsonWithTimeout(`/api/reports/${encodeURIComponent(reportId)}`, { method: "DELETE" }, 30000);
            if (!response.ok) {
                throw new Error(data?.error || "Could not delete scan.");
            }
            historyCache.delete(reportId);
            await Promise.all([loadDashboard(), loadAggregatedFindings(), loadHistory(), loadAssets()]);
        } catch (error) {
            showError(error.message || "Could not delete scan.");
        }
    }
});

authForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearAuthError();
    const username = String(authUsername?.value || "").trim();
    const password = String(authPassword?.value || "");
    if (!username || !password) {
        showAuthError("Username and password are required.");
        return;
    }
    if (authSubmitButton) {
        authSubmitButton.disabled = true;
    }
    try {
        await submitLogin(username, password);
    } catch (error) {
        showAuthError(error.message || "Authentication failed.");
    } finally {
        if (authSubmitButton) {
            authSubmitButton.disabled = false;
        }
    }
});

authLogoutButton?.addEventListener("click", async () => {
    try {
        await fetchJsonWithTimeout("/api/auth/logout", { method: "POST" }, 10000);
    } catch (_) {
        // Keep client-side session UX consistent even if logout request fails during a reload.
    }
    workspaceInitialized = false;
    setAuthUi({ required: authState.required, authenticated: false, user: null, projects: [] });
    showAuthDialog("You have been signed out.");
});

scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();

    const scannerMode = scannerTypeSelect.value || "standard";
    const exportScope = scannerMode === "v2" ? "v2" : "standard";
    const modeCfg = scannerSettings(scannerMode);
    const selectedProfile = modeCfg.disableProfile ? modeCfg.profile : profileSelect.value;
    const endpoint = modeCfg.endpoint || "/api/scan";

    const payload = {
        target: targetInput.value.trim(),
        profile: selectedProfile,
        port_strategy: portStrategySelect.value,
        project_id: activeProjectId,
    };
    const targetForIntel = payload.target;

    scanButton.disabled = true;
    scanButton.classList.add("scanning");
    scanButton.textContent = t("scanning");

    try {
        const useV2 = endpoint.includes("/api/scan/v2") || scannerMode === "advanced_v2";
        const data = await runQueuedScan(payload, {
            useV2,
            uiMode: useV2 ? "v2" : "risk",
            statusContainer: scanResult,
        });

        lastReportId = data.report_id || null;
        lastScannerScope = exportScope;
        reportPdfButton.disabled = false;
        reportCsvButton.disabled = false;

        if (data.persisted === false) {
            const persistMsg = data.persist_error ? `Save warning: ${data.persist_error}` : (data.warning || "Scan was completed but persistence reported an error.");
            showError(persistMsg);
        }

    renderScanResult(data);
    saveLastScan(exportScope, data);
        await refreshWorkspaceViews("all");
        activateTab("dashboard");
    } catch (error) {
        showError(error.message || "Scan failed");
        if (scanResult) {
            scanResult.innerHTML = "";
        }
    } finally {
        scanButton.disabled = false;
        scanButton.classList.remove("scanning");
        if (activeScanJobId) {
            activeScanJobId = "";
        }
        const activeLanguage = localStorage.getItem("vscanner.language") || "de";
        scanButton.textContent = (I18N[activeLanguage] || I18N.de).startScan;
    }
});

reportPdfButton.addEventListener("click", () => {
    if (!lastReportId) {
        window.open(
            `/api/reports/latest/${encodeURIComponent(lastScannerScope)}/pdf?project_id=${encodeURIComponent(activeProjectId)}`,
            "_blank",
            "noopener,noreferrer"
        );
    } else {
        window.open(`/api/reports/${encodeURIComponent(lastReportId)}/pdf`, "_blank", "noopener,noreferrer");
    }
});

reportCsvButton.addEventListener("click", () => {
    if (!lastReportId) {
        window.open(
            `/api/reports/latest/${encodeURIComponent(lastScannerScope)}/csv?project_id=${encodeURIComponent(activeProjectId)}`,
            "_blank",
            "noopener,noreferrer"
        );
    } else {
        window.open(`/api/reports/${encodeURIComponent(lastReportId)}/csv`, "_blank", "noopener,noreferrer");
    }
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

sidebarToggle?.addEventListener("click", () => {
    const isCollapsed = appShell?.classList.contains("sidebar-collapsed");
    applySidebarState(!isCollapsed);
});

const hostDownloadHandler = (event) => {
    const csvButton = event.target.closest("[data-host-report-csv]");
    if (csvButton) {
        window.openHostReportCsv(csvButton.dataset.hostReportCsv || "", csvButton.dataset.hostName || "");
        return;
    }
    const pdfButton = event.target.closest("[data-host-report-pdf]");
    if (pdfButton) {
        window.openHostReportPdf(pdfButton.dataset.hostReportPdf || "", pdfButton.dataset.hostName || "");
    }
};
scanResult?.addEventListener("click", hostDownloadHandler);

resetProjectButton?.addEventListener("click", async () => {
    const project = (projectSelect.options[projectSelect.selectedIndex]?.textContent || "Current Project").trim();
    const phrase = `RESET ${project}`;
    const accepted = await openConfirmDialog({
        title: t("resetProject"),
        message: t("resetProjectConfirm"),
        phrase,
    });
    if (!accepted) return;

    try {
        const { response, data } = await fetchJsonWithTimeout(`/api/projects/${encodeURIComponent(activeProjectId)}/reset`, { method: "POST" }, 40000);
        if (!response.ok) {
            throw new Error(data?.error || "Project reset failed.");
        }
        lastReportId = null;
        reportPdfButton.disabled = true;
        reportCsvButton.disabled = true;
        scanResult.innerHTML = "";
        await Promise.all([loadProjects(), loadDashboard(), loadAggregatedFindings(), loadHistory(), loadAssets()]);
    } catch (error) {
        showError(error.message || "Project reset failed.");
    }
});

deleteProjectButton?.addEventListener("click", async () => {
    const project = (projectSelect.options[projectSelect.selectedIndex]?.textContent || "Current Project").trim();
    const phrase = `DELETE ${project}`;
    const accepted = await openConfirmDialog({
        title: t("deleteProject"),
        message: t("deleteProjectConfirm"),
        phrase,
    });
    if (!accepted) return;

    try {
        const { response, data } = await fetchJsonWithTimeout(`/api/projects/${encodeURIComponent(activeProjectId)}`, { method: "DELETE" }, 40000);
        if (!response.ok) {
            throw new Error(data?.error || "Project deletion failed.");
        }
        activeProjectId = data?.fallback_project_id || "default";
        await Promise.all([loadProjects(), loadDashboard(), loadAggregatedFindings(), loadHistory(), loadAssets()]);
    } catch (error) {
        showError(error.message || "Project deletion failed.");
    }
});

projectSelect.addEventListener("change", async () => {
    activeProjectId = projectSelect.value || "default";
    await refreshWorkspaceViews("dashboard");
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
        await refreshWorkspaceViews("dashboard");
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

intelOnlyButton?.addEventListener("click", async () => {
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
refreshAssetsButton?.addEventListener("click", loadAssets);
severityFilter.addEventListener("change", loadAggregatedFindings);
sinceDays.addEventListener("change", loadAggregatedFindings);
sortBy.addEventListener("change", loadAggregatedFindings);
sortDir.addEventListener("change", loadAggregatedFindings);
languageSelect.addEventListener("change", () => applyLanguage(languageSelect.value));
modeSelect.addEventListener("change", () => applyMode(modeSelect.value));
themeSelect.addEventListener("change", () => applyTheme(themeSelect.value));
severityTimelineMode?.addEventListener("change", () => drawSeverityStack(severityTimelinePoints));
findingSearch.addEventListener("input", () => {
    window.clearTimeout(window.__findingSearchTimer);
    window.__findingSearchTimer = window.setTimeout(loadAggregatedFindings, 260);
});
findingsTable?.addEventListener("click", async (event) => {
    const row = event.target.closest("tr[data-finding-key]");
    if (!row) {
        return;
    }
    const key = String(row.dataset.findingKey || "");
    if (!key) {
        return;
    }
    selectedFindingKey = key;
    try {
        await loadFindingDetail(key);
        findingsTable.querySelectorAll("tr.finding-row").forEach((entry) => {
            entry.classList.toggle("is-selected", entry.dataset.findingKey === key);
        });
    } catch (error) {
        showError(error.message || "Could not load finding detail");
    }
});
topVulns?.addEventListener("click", async (event) => {
    const card = event.target.closest("[data-top-vuln]");
    if (!card) {
        return;
    }
    const title = String(card.dataset.title || "").trim();
    const cve = String(card.dataset.cve || "").trim();
    if (findingSearch) {
        findingSearch.value = cve && cve !== "-" ? cve : title;
    }
    activateTab("findings");
    try {
        await loadAggregatedFindings();
    } catch (error) {
        showError(error.message || "Could not load findings from vulnerability selection");
    }
});
topAssets?.addEventListener("click", async (event) => {
    const card = event.target.closest("[data-top-asset]");
    if (!card) {
        return;
    }
    const assetValue = String(card.dataset.asset || "").trim();
    if (findingSearch) {
        findingSearch.value = assetValue;
    }
    activateTab("findings");
    try {
        await loadAggregatedFindings();
    } catch (error) {
        showError(error.message || "Could not filter findings by asset");
    }
});
serviceInventory?.addEventListener("click", async (event) => {
    const card = event.target.closest("[data-service-item]");
    if (!card) {
        return;
    }
    const serviceName = String(card.dataset.service || "").trim();
    if (findingSearch) {
        findingSearch.value = serviceName;
    }
    activateTab("findings");
    try {
        await loadAggregatedFindings();
    } catch (error) {
        showError(error.message || "Could not filter findings by service");
    }
});
document.getElementById("portIntelList")?.addEventListener("click", async (event) => {
    const card = event.target.closest("[data-port-intel]");
    if (!card) {
        return;
    }
    const port = String(card.dataset.port || "").trim();
    const service = String(card.dataset.service || "").trim();
    if (findingSearch) {
        findingSearch.value = service && service !== "unknown" ? `${service} ${port}` : `port ${port}`;
    }
    activateTab("findings");
    try {
        await loadAggregatedFindings();
    } catch (error) {
        showError(error.message || "Could not filter findings by port");
    }
});
assetTagFilter?.addEventListener("input", () => {
    window.clearTimeout(window.__assetFilterTimer);
    window.__assetFilterTimer = window.setTimeout(loadAssets, 260);
});

assetForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const value = String(assetValueInput?.value || "").trim();
    if (!value) {
        showError("Asset value is required");
        return;
    }
    const tags = String(assetTagsInput?.value || "")
        .split(",")
        .map((tag) => tag.trim().toLowerCase())
        .filter(Boolean);
    try {
        const { response, data } = await fetchJsonWithTimeout(`/api/projects/${encodeURIComponent(activeProjectId)}/assets`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                value,
                tags,
                criticality: assetCriticalitySelect?.value || "medium",
            }),
        }, 20000);
        if (!response.ok) {
            throw new Error(data?.error || "Asset creation failed");
        }
        assetForm.reset();
        await loadAssets();
    } catch (error) {
        showError(error.message || "Asset creation failed");
    }
});

// ─── Network Scanner ───────────────────────────────────────────────────────
const netScanForm = document.getElementById("netScanForm");
const netScanButton = document.getElementById("netScanButton");
const netScanError = document.getElementById("netScanError");
const netScanResult = document.getElementById("netScanResult");
const netReportPdfButton = document.getElementById("netReportPdfButton");
const netReportCsvButton = document.getElementById("netReportCsvButton");
const netHints = document.getElementById("netHints");
let lastNetReportId = null;

async function renderNetworkPageHints() {
    if (!netHints) return;
    const hints = await guessLocalNetworkHints();
    netHints.innerHTML = hints
        .map((cidr) => `<button type="button" class="hint-chip hint-chip-net" data-cidr="${esc(cidr)}">${esc(cidr)}</button>`)
        .join("");
    netHints.querySelectorAll(".hint-chip-net").forEach((btn) => {
        btn.addEventListener("click", () => {
            const netTarget = document.getElementById("netTarget");
            if (netTarget) netTarget.value = btn.dataset.cidr || "";
        });
    });
}

function updateNetStats(data) {
    const hosts = data.metrics?.hosts_scanned ?? (data.hosts?.length ?? "—");
    const ports = data.metrics?.open_ports ?? "—";
    const services = data.hosts ? data.hosts.reduce((a, h) => a + (h.services?.length || 0), 0) : "—";
    const risk = data.true_risk_score ?? "—";
    const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    el("netStatHosts", hosts);
    el("netStatPorts", ports);
    el("netStatServices", services);
    el("netStatRisk", typeof risk === "number" ? risk.toFixed(1) : risk);
}

netScanForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    netScanError?.classList.add("hidden");
    const cidr = document.getElementById("netTarget")?.value?.trim() || "";
    const depth = document.getElementById("netPortStrategy")?.value || "standard";
    if (!cidr) { netScanError.textContent = "CIDR target required."; netScanError.classList.remove("hidden"); return; }

    netScanButton.disabled = true;
    netScanButton.textContent = "Scanning…";

    try {
        const data = await runQueuedScan(
            { target: cidr, profile: "network", port_strategy: depth, project_id: activeProjectId },
            { useV2: false, uiMode: "network", statusContainer: netScanResult }
        );
        lastNetReportId = data.report_id;
        if (netReportPdfButton) netReportPdfButton.disabled = false;
        if (netReportCsvButton) netReportCsvButton.disabled = false;
        if (netScanResult) netScanResult.innerHTML = buildScanResultMarkup(data);
        updateNetStats(data);
        saveLastScan("network", data);
        await refreshWorkspaceViews("all");
    } catch (err) {
        if (netScanError) { netScanError.textContent = err.message || "Network scan failed"; netScanError.classList.remove("hidden"); }
        if (netScanResult) netScanResult.innerHTML = "";
    } finally {
        netScanButton.disabled = false;
        netScanButton.textContent = "Scan Network";
    }
});

netReportPdfButton?.addEventListener("click", () => {
    if (lastNetReportId) {
        window.open(`/api/reports/${encodeURIComponent(lastNetReportId)}/pdf`, "_blank", "noopener,noreferrer");
        return;
    }
    window.open(
        `/api/reports/latest/network/pdf?project_id=${encodeURIComponent(activeProjectId)}`,
        "_blank",
        "noopener,noreferrer"
    );
});
netReportCsvButton?.addEventListener("click", () => {
    if (lastNetReportId) {
        window.open(`/api/reports/${encodeURIComponent(lastNetReportId)}/csv`, "_blank", "noopener,noreferrer");
        return;
    }
    window.open(
        `/api/reports/latest/network/csv?project_id=${encodeURIComponent(activeProjectId)}`,
        "_blank",
        "noopener,noreferrer"
    );
});

// ─── Stealth Scanner ───────────────────────────────────────────────────────
const stealthScanForm = document.getElementById("stealthScanForm");
const stealthScanButton = document.getElementById("stealthScanButton");
const stealthIntelButton = document.getElementById("stealthIntelButton");
const stealthScanError = document.getElementById("stealthScanError");
const stealthScanResult = document.getElementById("stealthScanResult");
const stealthReportPdfButton = document.getElementById("stealthReportPdfButton");
const stealthReportCsvButton = document.getElementById("stealthReportCsvButton");
let lastStealthReportId = null;

netScanResult?.addEventListener("click", hostDownloadHandler);
stealthScanResult?.addEventListener("click", hostDownloadHandler);

document.querySelectorAll(".ss-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
        document.querySelectorAll(".ss-pill").forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        const modeInput = document.getElementById("stealthModeInput");
        if (modeInput) modeInput.value = pill.dataset.stealthMode || "stealth";
    });
});

async function runStealthScan(intelOnly = false) {
    stealthScanError?.classList.add("hidden");
    const tgt = document.getElementById("stealthTarget")?.value?.trim() || "";
    const mode = document.getElementById("stealthModeInput")?.value || "stealth";
    const port_strategy = document.getElementById("stealthPortStrategy")?.value || "standard";
    if (!tgt) { stealthScanError.textContent = "Target required."; stealthScanError.classList.remove("hidden"); return; }

    stealthScanButton.disabled = true;
    stealthIntelButton.disabled = true;
    stealthScanButton.textContent = "Probing…";
    if (intelOnly && stealthScanResult) {
        activeScanStatusController?.dispose();
        activeScanStatusController = createScanStatusController(stealthScanResult, "stealth", {
            jobId: "intel",
            createdAt: new Date().toISOString(),
            progress: 10,
        });
        activeScanStatusController.update({ phase: "intel", progress: 22, message: "Collecting passive intelligence..." });
    }

    try {
        if (intelOnly) {
            const intel = await fetchIntelData(tgt);
            const mockData = { metrics: { hosts_scanned: 0, open_ports: 0, cve_candidates: 0 }, true_risk_score: 0, finding_items: [], hosts: [], intel };
            activeScanStatusController?.complete("Intel collection completed");
            if (stealthScanResult) stealthScanResult.innerHTML = buildScanResultMarkup(mockData);
        } else {
            const data = await runQueuedScan(
                { target: tgt, profile: mode, port_strategy, project_id: activeProjectId },
                { useV2: false, uiMode: "stealth", statusContainer: stealthScanResult }
            );
            lastStealthReportId = data.report_id;
            if (stealthReportPdfButton) stealthReportPdfButton.disabled = false;
            if (stealthReportCsvButton) stealthReportCsvButton.disabled = false;
            if (stealthScanResult) stealthScanResult.innerHTML = buildScanResultMarkup(data);
            saveLastScan("stealth", data);
            await refreshWorkspaceViews("all");
        }
    } catch (err) {
        if (stealthScanError) { stealthScanError.textContent = err.message || "Stealth scan failed"; stealthScanError.classList.remove("hidden"); }
        if (stealthScanResult) stealthScanResult.innerHTML = "";
        activeScanStatusController?.fail(err.message || "Stealth scan failed");
    } finally {
        stealthScanButton.disabled = false;
        stealthIntelButton.disabled = false;
        stealthScanButton.textContent = "Run Stealth Scan";
    }
}

stealthScanForm?.addEventListener("submit", (e) => { e.preventDefault(); runStealthScan(false); });
stealthIntelButton?.addEventListener("click", () => runStealthScan(true));
stealthReportPdfButton?.addEventListener("click", () => {
    if (lastStealthReportId) {
        window.open(`/api/reports/${encodeURIComponent(lastStealthReportId)}/pdf`, "_blank", "noopener,noreferrer");
        return;
    }
    window.open(
        `/api/reports/latest/stealth/pdf?project_id=${encodeURIComponent(activeProjectId)}`,
        "_blank",
        "noopener,noreferrer"
    );
});
stealthReportCsvButton?.addEventListener("click", () => {
    if (lastStealthReportId) {
        window.open(`/api/reports/${encodeURIComponent(lastStealthReportId)}/csv`, "_blank", "noopener,noreferrer");
        return;
    }
    window.open(
        `/api/reports/latest/stealth/csv?project_id=${encodeURIComponent(activeProjectId)}`,
        "_blank",
        "noopener,noreferrer"
    );
});

// ─── 24h Last Scan Persistence ─────────────────────────────────────────────
const _LAST_SCAN_KEY = "vscanner.lastScan";
const _24H = 86_400_000;

function saveLastScan(scope, data) {
    try {
        const payload = { scope, data, ts: Date.now() };
        localStorage.setItem(_LAST_SCAN_KEY, JSON.stringify(payload));
    } catch (_) {}
}

function restoreLastScan() {
    try {
        const raw = localStorage.getItem(_LAST_SCAN_KEY);
        if (!raw) return;
        const { scope, data, ts } = JSON.parse(raw);
        if (!data || Date.now() - ts > _24H) return;
        if (scope === "network" && netScanResult) {
            netScanResult.innerHTML = buildScanResultMarkup(data);
            updateNetStats(data);
            if (netReportPdfButton && data.report_id) { netReportPdfButton.disabled = false; lastNetReportId = data.report_id; }
            if (netReportCsvButton && data.report_id) { netReportCsvButton.disabled = false; }
        } else if (scope === "stealth" && stealthScanResult) {
            stealthScanResult.innerHTML = buildScanResultMarkup(data);
            if (stealthReportPdfButton && data.report_id) { stealthReportPdfButton.disabled = false; lastStealthReportId = data.report_id; }
            if (stealthReportCsvButton && data.report_id) { stealthReportCsvButton.disabled = false; }
        } else if ((scope === "standard" || scope === "v2") && scanResult) {
            renderScanResult(data);
            lastScannerScope = scope;
            if (reportPdfButton && data.report_id) { reportPdfButton.disabled = false; lastReportId = data.report_id; }
            if (reportCsvButton && data.report_id) { reportCsvButton.disabled = false; }
        }
    } catch (_) {}
}

async function initializeWorkspace(forceRefresh = false) {
    if (workspaceInitialized && !forceRefresh) {
        return;
    }
    restoreLastScan();
    await loadHealth();
    const projects = await loadProjects();
    if (!projects.length) {
        workspaceInitialized = true;
        showError("No projects are assigned to this account.");
        return;
    }
    await Promise.all([loadDashboard(), loadAggregatedFindings(), loadHistory(), loadAssets()]);
    workspaceInitialized = true;
}

(async function bootstrap() {
    try {
        const savedMode = localStorage.getItem("vscanner.mode") || "dark";
        const savedTheme = localStorage.getItem("vscanner.theme") || "ocean";
        const savedLanguage = localStorage.getItem("vscanner.language") || "en";
        const savedTimelineMode = localStorage.getItem("vscanner.severityTimelineMode") || "percent_stacked";
        const savedSidebarCollapsed = localStorage.getItem("vscanner.sidebarCollapsed") === "1";
        modeSelect.value = savedMode;
        themeSelect.value = savedTheme;
        languageSelect.value = savedLanguage;
        if (severityTimelineMode) {
            severityTimelineMode.value = savedTimelineMode === "absolute_minimap" ? "absolute_minimap" : "percent_stacked";
        }
        applyMode(savedMode);
        applyTheme(savedTheme);
        applyLanguage(savedLanguage);
        applySidebarState(savedSidebarCollapsed);
        applyScannerMode(scannerTypeSelect.value || "standard");
        activateTab(pathToTab(window.location.pathname));
        await renderNetworkHints();
        await renderNetworkPageHints();
        const ready = await ensureAuthenticatedSession();
        if (ready) {
            await initializeWorkspace();
        }
    } catch (error) {
        showError(error.message || "Initial load failed");
    }
    const cursorGlow = document.getElementById("cursor-glow");
    if (cursorGlow) {
        document.addEventListener("mousemove", (e) => {
            cursorGlow.style.left = `${e.clientX}px`;
            cursorGlow.style.top = `${e.clientY}px`;
            cursorGlow.style.opacity = "1";
        });
        document.addEventListener("mouseleave", () => {
            cursorGlow.style.opacity = "0";
        });
    }
})();
