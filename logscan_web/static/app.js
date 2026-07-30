const form = document.querySelector("#upload-form");
const input = document.querySelector("#log-file");
const dropZone = document.querySelector("#drop-zone");
const filePill = document.querySelector("#file-pill");
const status = document.querySelector("#form-status");
const scanButton = document.querySelector("#scan-button");
const results = document.querySelector("#results");
const summaryGrid = document.querySelector("#summary-grid");
const sectionNav = document.querySelector("#section-nav");
const sectionContent = document.querySelector("#section-content");
const logViewer = document.querySelector("#log-viewer");
const logCode = document.querySelector("#log-code");
const lineJump = document.querySelector("#line-jump");
const sectionJump = document.querySelector("#section-jump");
const viewerPosition = document.querySelector("#viewer-position");
let currentFile = null;
let currentScanId = null;
let deleteToken = null;
let currentLogLines = null;
let currentLogSections = [];
let highlightedRange = { start: 1, end: 1 };
let viewerFirstLine = 1;
let viewerLastLine = 1;
let loadingViewerChunk = false;
const VIEWER_CHUNK_SIZE = 1000;

const groups = [
  { key: "critical", label: "Critical issues", description: "Items most likely to prevent a successful or secure run." },
  { key: "warning", label: "Warnings", description: "Potential problems worth reviewing before your next run." },
  { key: "advice", label: "Advice", description: "Configuration and performance improvements." },
];

function selectedFile(file) {
  input.files = file ? makeFileList(file) : input.files;
  const chosen = file || input.files[0];
  currentFile = chosen || null;
  currentLogLines = null;
  currentLogSections = [];
  scanButton.disabled = !chosen;
  filePill.textContent = chosen ? `${chosen.name} · ${formatBytes(chosen.size)}` : "LOG, TXT or YML · up to 100 MB";
  status.textContent = chosen ? "File selected" : "Ready to scan";
  status.classList.remove("error");
}

function makeFileList(file) {
  const transfer = new DataTransfer();
  transfer.items.add(file);
  return transfer.files;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function linkLabel(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    if (host.endsWith("kometa.wiki")) return "Kometa documentation";
    if (host.endsWith("plex.tv")) return "Plex documentation";
    if (host.endsWith("github.com")) return "GitHub reference";
    return host;
  } catch {
    return "View documentation";
  }
}

function appendInlineFormatting(container, text) {
  const tokenPattern = /(\*\*.+?\*\*|`[^`]+`|\[?https?:\/\/[^\s\]]+\]?)/g;
  let cursor = 0;
  for (const match of text.matchAll(tokenPattern)) {
    container.append(document.createTextNode(text.slice(cursor, match.index)));
    const token = match[0];
    if (token.startsWith("**") && token.endsWith("**")) {
      const strong = document.createElement("strong");
      strong.textContent = token.slice(2, -2);
      container.append(strong);
    } else if (token.startsWith("`") && token.endsWith("`")) {
      const code = document.createElement("code");
      code.textContent = token.slice(1, -1);
      container.append(code);
    } else {
      const url = token.replace(/^\[/, "").replace(/\]$/, "");
      const link = document.createElement("a");
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = linkLabel(url);
      container.append(link);
    }
    cursor = match.index + token.length;
  }
  container.append(document.createTextNode(text.slice(cursor)));
}

function appendRecommendationMeta(container, text) {
  const marker = /^(.*?Line number\(s\):\s*)(.*)$/i.exec(text);
  if (!marker) {
    appendInlineFormatting(container, text);
    return;
  }
  appendInlineFormatting(container, marker[1]);
  const references = marker[2];
  const rangePattern = /\d+(?:-\d+)?/g;
  let cursor = 0;
  for (const match of references.matchAll(rangePattern)) {
    container.append(document.createTextNode(references.slice(cursor, match.index)));
    const [startText, endText] = match[0].split("-");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "line-link";
    button.textContent = match[0];
    button.title = `View log at line ${match[0]}`;
    button.addEventListener("click", () => openLogViewer(Number(startText), Number(endText || startText)));
    container.append(button);
    cursor = match.index + match[0].length;
  }
  container.append(document.createTextNode(references.slice(cursor)));
}

function recommendationBody(message) {
  const body = document.createElement("div");
  body.className = "recommendation-body";
  const lines = message.split("\n").slice(1);
  lines.forEach((line) => {
    const row = document.createElement("div");
    if (/^\s*\d+\s+line\(s\)/i.test(line)) row.className = "recommendation-meta";
    if (!line.trim()) row.classList.add("spacer");
    if (row.classList.contains("recommendation-meta")) appendRecommendationMeta(row, line);
    else appendInlineFormatting(row, line);
    body.append(row);
  });
  return body;
}

async function loadLogLines() {
  if (!currentFile && !currentScanId) throw new Error("Select and scan a log before opening the viewer.");
  if (!currentLogLines) {
    const response = currentFile
      ? null
      : await fetch(`/api/scans/${encodeURIComponent(currentScanId)}/log`);
    if (response && !response.ok) throw new Error("The stored log could not be loaded.");
    const text = currentFile ? await currentFile.text() : await response.text();
    currentLogLines = text.split(/\r?\n/);
    currentLogSections = findLogSections(currentLogLines);
    populateSectionJump();
  }
  return currentLogLines;
}

function isSectionDivider(line) {
  return /\|={10,}\|\s*$/.test(line);
}

function sectionTitle(line) {
  const match = /\|\s*([^|=][^|]*?)\s*\|\s*$/.exec(line);
  return match ? match[1].trim() : null;
}

function findLogSections(lines) {
  const sections = [];
  for (let index = 1; index < lines.length - 1; index += 1) {
    if (!isSectionDivider(lines[index - 1]) || !isSectionDivider(lines[index + 1])) continue;
    const title = sectionTitle(lines[index]);
    if (title) sections.push({ title, line: index + 1 });
  }
  return sections;
}

function populateSectionJump() {
  sectionJump.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = currentLogSections.length ? "Select a section" : "No sections found";
  sectionJump.append(placeholder);
  currentLogSections.forEach((section) => {
    const option = document.createElement("option");
    option.value = section.line;
    option.textContent = `${section.title} — line ${section.line.toLocaleString()}`;
    sectionJump.append(option);
  });
  sectionJump.disabled = currentLogSections.length === 0;
}

function createLogRows(first, last) {
  const fragment = document.createDocumentFragment();
  for (let lineNumber = first; lineNumber <= last; lineNumber += 1) {
    const row = document.createElement("div");
    row.className = "log-line";
    row.dataset.line = lineNumber;
    if (lineNumber >= highlightedRange.start && lineNumber <= highlightedRange.end) row.classList.add("highlighted");
    const number = document.createElement("span");
    number.className = "line-number";
    number.textContent = lineNumber;
    const content = document.createElement("span");
    content.textContent = currentLogLines[lineNumber - 1] || " ";
    row.append(number, content);
    fragment.append(row);
  }
  return fragment;
}

function updateViewerPosition() {
  viewerPosition.textContent = `Lines ${viewerFirstLine.toLocaleString()}–${viewerLastLine.toLocaleString()} of ${currentLogLines.length.toLocaleString()}`;
}

function renderLogWindow(targetStart, targetEnd = targetStart) {
  const total = currentLogLines.length;
  const startTarget = Math.max(1, Math.min(total, Number(targetStart) || 1));
  const endTarget = Math.max(startTarget, Math.min(total, Number(targetEnd) || startTarget));
  highlightedRange = { start: startTarget, end: endTarget };
  viewerFirstLine = Math.max(1, startTarget - Math.floor(VIEWER_CHUNK_SIZE / 2));
  viewerLastLine = Math.min(
    total,
    Math.max(viewerFirstLine + VIEWER_CHUNK_SIZE - 1, endTarget + Math.floor(VIEWER_CHUNK_SIZE / 2)),
  );
  if (viewerLastLine === total) viewerFirstLine = Math.max(1, viewerLastLine - VIEWER_CHUNK_SIZE + 1);
  const fragment = createLogRows(viewerFirstLine, viewerLastLine);
  logCode.replaceChildren(fragment);
  lineJump.max = total;
  lineJump.value = startTarget;
  updateViewerPosition();
  requestAnimationFrame(() => {
    logCode.querySelector(`[data-line="${startTarget}"]`)?.scrollIntoView({ block: "center" });
  });
}

function loadAdjacentLogChunk(direction) {
  if (loadingViewerChunk || !currentLogLines) return;
  const total = currentLogLines.length;
  if (direction === "next" && viewerLastLine >= total) return;
  if (direction === "previous" && viewerFirstLine <= 1) return;
  loadingViewerChunk = true;

  if (direction === "next") {
    const first = viewerLastLine + 1;
    const last = Math.min(total, first + VIEWER_CHUNK_SIZE - 1);
    logCode.append(createLogRows(first, last));
    viewerLastLine = last;
  } else {
    const previousHeight = logCode.scrollHeight;
    const last = viewerFirstLine - 1;
    const first = Math.max(1, last - VIEWER_CHUNK_SIZE + 1);
    logCode.prepend(createLogRows(first, last));
    viewerFirstLine = first;
    logCode.scrollTop += logCode.scrollHeight - previousHeight;
  }
  updateViewerPosition();
  requestAnimationFrame(() => { loadingViewerChunk = false; });
}

async function openLogViewer(targetStart = 1, targetEnd = targetStart) {
  try {
    await loadLogLines();
    document.querySelector("#viewer-filename").textContent =
      currentFile?.name || document.querySelector("#results-title").textContent;
    if (!logViewer.open) logViewer.showModal();
    renderLogWindow(targetStart, targetEnd);
  } catch (error) {
    status.textContent = error.message;
    status.classList.add("error");
  }
}

function showGroup(group, recommendations) {
  document.querySelectorAll(".nav-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.group === group.key);
  });
  sectionContent.replaceChildren();
  const header = document.createElement("div");
  header.className = "section-header";
  const title = document.createElement("h3");
  title.textContent = group.label;
  const copy = document.createElement("p");
  copy.textContent = group.description;
  header.append(title, copy);
  sectionContent.append(header);

  const matches = recommendations
    .filter((item) => item.severity === group.key)
    .sort((left, right) => {
      if (group.key !== "warning") return 0;
      return Number(left.title === "Kometa warnings detected")
        - Number(right.title === "Kometa warnings detected");
    });
  if (!matches.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = `No ${group.label.toLowerCase()} were found.`;
    sectionContent.append(empty);
    return;
  }
  const list = document.createElement("div");
  list.className = "recommendation-list";
  matches.forEach((item, index) => {
    const details = document.createElement("details");
    details.className = `recommendation ${item.severity}`;
    details.open = true;
    const summary = document.createElement("summary");
    const dot = document.createElement("span");
    dot.className = "severity-dot";
    const titleText = document.createElement("span");
    titleText.textContent = item.title;
    const chevron = document.createElement("span");
    chevron.className = "chevron";
    chevron.textContent = "›";
    summary.append(dot, titleText, chevron);
    details.append(summary, recommendationBody(item.message));
    list.append(details);
  });
  sectionContent.append(list);
}

function summaryCard(label, value, small = false) {
  const card = document.createElement("div");
  card.className = "summary-card";
  const name = document.createElement("div");
  name.className = "summary-label";
  name.textContent = label;
  const content = document.createElement("div");
  content.className = `summary-value${small ? " small" : ""}`;
  content.textContent = value;
  card.append(name, content);
  return card;
}

function renderResults(data) {
  const { metadata, recommendations } = data;
  document.querySelector("#results-title").textContent = data.filename;
  summaryGrid.replaceChildren(
    summaryCard("Log details", `${metadata.line_count.toLocaleString()} lines · ${formatBytes(metadata.size_bytes)}${metadata.kometa_version ? `\nKometa ${metadata.kometa_version}` : ""}`, true),
    summaryCard("Critical", metadata.counts.critical),
    summaryCard("Warnings", metadata.counts.warning),
    summaryCard("Advice", metadata.counts.advice),
  );

  sectionNav.replaceChildren();
  groups.forEach((group) => {
    const count = recommendations.filter((item) => item.severity === group.key).length;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "nav-button";
    button.dataset.group = group.key;
    const label = document.createElement("span");
    label.textContent = group.label;
    const badge = document.createElement("span");
    badge.className = "nav-count";
    badge.textContent = count;
    button.append(label, badge);
    button.addEventListener("click", () => showGroup(group, recommendations));
    sectionNav.append(button);
  });
  showGroup(groups.find((group) => metadata.counts[group.key] > 0) || groups[0], recommendations);
  results.hidden = false;
  currentScanId = data.id || currentScanId;
  document.querySelector("#delete-scan").hidden = !deleteToken;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

input.addEventListener("change", () => selectedFile());
["dragenter", "dragover"].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
  event.preventDefault();
  dropZone.classList.add("dragover");
}));
["dragleave", "drop"].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
  event.preventDefault();
  dropZone.classList.remove("dragover");
}));
dropZone.addEventListener("drop", (event) => {
  const file = event.dataTransfer.files[0];
  if (file) selectedFile(file);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = input.files[0];
  if (!file) return;
  dropZone.classList.add("loading");
  scanButton.disabled = true;
  status.textContent = "Scanning your log…";
  status.classList.remove("error");
  const body = new FormData();
  body.append("log", file);
  try {
    const response = await fetch("/api/scan", { method: "POST", body });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The scan could not be completed.");
    status.textContent = "Scan complete";
    currentScanId = data.id;
    deleteToken = data.delete_token;
    history.replaceState({}, "", `/scan/${encodeURIComponent(data.id)}#delete=${encodeURIComponent(deleteToken)}`);
    renderResults(data);
  } catch (error) {
    status.textContent = error.message;
    status.classList.add("error");
  } finally {
    dropZone.classList.remove("loading");
    scanButton.disabled = false;
  }
});

document.querySelector("#new-scan").addEventListener("click", () => {
  form.reset();
  results.hidden = true;
  selectedFile();
  document.querySelector("#upload-section").scrollIntoView({ behavior: "smooth", block: "center" });
});

document.querySelector("#view-log").addEventListener("click", () => openLogViewer(1));
document.querySelector("#delete-scan").addEventListener("click", async () => {
  if (!currentScanId || !deleteToken || !confirm("Permanently delete this log and its scan results?")) return;
  const response = await fetch(`/api/scans/${encodeURIComponent(currentScanId)}`, {
    method: "DELETE",
    headers: { "X-Delete-Token": deleteToken },
  });
  if (!response.ok) {
    alert("The log could not be deleted. The deletion link may be invalid.");
    return;
  }
  location.href = "/";
});
document.querySelector("#close-viewer").addEventListener("click", () => logViewer.close());
document.querySelector("#line-jump-form").addEventListener("submit", (event) => {
  event.preventDefault();
  renderLogWindow(Number(lineJump.value), Number(lineJump.value));
});
sectionJump.addEventListener("change", () => {
  if (!sectionJump.value) return;
  const targetLine = Number(sectionJump.value);
  renderLogWindow(targetLine, targetLine);
});
logViewer.addEventListener("click", (event) => {
  if (event.target === logViewer) logViewer.close();
});
logCode.addEventListener("scroll", () => {
  if (logCode.scrollTop + logCode.clientHeight >= logCode.scrollHeight - 240) {
    loadAdjacentLogChunk("next");
  } else if (logCode.scrollTop <= 120) {
    loadAdjacentLogChunk("previous");
  }
});

const initialScan = JSON.parse(document.querySelector("#initial-scan").textContent);
if (initialScan) {
  currentScanId = initialScan.id;
  const fragment = new URLSearchParams(location.hash.slice(1));
  deleteToken = fragment.get("delete");
  renderResults(initialScan);
}
