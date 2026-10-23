"use strict";

(() => {
  const $ = (selector, scope = document) => scope.querySelector(selector);
  const $$ = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));
  const state = { view: "analysis", mode: "quick", tab: "findings", job: null, report: null, jobs: [], tools: [], timer: null, pollBusy: false, uploading: false, maxSize: null, selectedId: null, query: "", utilityBusy: false, reportLoaded: false, healthBusy: false };
  const activeStatuses = new Set(["queued", "pending", "running", "processing", "cancelling"]);
  const terminalStatuses = new Set(["completed", "complete", "succeeded", "success", "failed", "error", "cancelled", "canceled", "timed_out", "timeout"]);
  const make = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };
  const readable = value => typeof value === "string" ? value : JSON.stringify(value, null, 2) ?? "—";
  const bytes = value => {
    const n = Number(value);
    if (!Number.isFinite(n)) return "Unknown size";
    if (n < 1024) return `${n} B`;
    const units = ["KiB", "MiB", "GiB"];
    let v = n / 1024, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
  };
  const label = value => String(value || "unknown").replace(/_/g, " ");
  const offset = value => value === null || value === undefined ? null : `0x${Number.isFinite(Number(value)) ? Number(value).toString(16).toUpperCase().padStart(8, "0") : value}`;
  const isActive = job => job && activeStatuses.has(job.status);

  async function api(path, options = {}) {
    const response = await fetch(path, { ...options, headers: { Accept: "application/json", ...(options.headers || {}) } });
    if (response.status === 204) return null;
    let data;
    try { data = await response.json(); } catch { throw new Error(`The server returned an unreadable response (${response.status}).`); }
    if (!response.ok) {
      const detail = data.detail || data.error || data.message;
      throw new Error(typeof detail === "string" ? detail : detail ? readable(detail) : `Request failed (${response.status}).`);
    }
    return data;
  }

  function notify(message) {
    const notice = $("#notification");
    notice.textContent = message || "";
    notice.hidden = !message;
  }

  function empty(parent, title, text) {
    const wrap = make("div", "empty-state compact");
    wrap.append(make("h4", "", title));
    if (text) wrap.append(make("p", "", text));
    parent.append(wrap);
  }

  function codeBlock(value) { return make("pre", "code-block", readable(value)); }
  function getAnalyzers() { return Array.isArray(state.report?.analyzers) ? state.report.analyzers : []; }
  function getFindings() {
    const findings = state.report?.findings;
    return Array.isArray(findings) ? findings : getAnalyzers().flatMap(analyzer => (analyzer.findings || []).map(finding => ({ analyzer: analyzer.name, ...finding })));
  }
  function matchesAnalyzer(analyzer, patterns) { return patterns.some(pattern => String(analyzer.name || "").toLowerCase().includes(pattern)); }

  async function loadHealth() {
    if (state.healthBusy || document.hidden) return;
    state.healthBusy = true;
    const el = $("#worker-state");
    try {
      const data = await api("/api/health");
      const online = data.worker?.online === true;
      el.classList.toggle("online", online);
      el.classList.toggle("offline", !online);
      $("#worker-label").textContent = online ? "Local worker online" : "Local worker offline";
      const limits = data.limits || {};
      state.maxSize = Number(limits.max_upload_bytes || limits.max_file_bytes || limits.max_file_size || limits.upload_max_bytes) || null;
      $("#file-limit").textContent = state.maxSize ? `Up to ${bytes(state.maxSize)} per file` : "Quick scan inspects evidence · Deep scan extracts and probes";
    } catch {
      el.classList.remove("online");
      el.classList.add("offline");
      $("#worker-label").textContent = "Worker connection unavailable";
      $("#file-limit").textContent = "Connect the local worker to start analysis";
    } finally { state.healthBusy = false; }
  }

  function route() {
    const next = location.hash.slice(1) || "dashboard";
    state.view = ["dashboard", "analysis", "studio", "audio", "flags", "reports", "jobs", "tools", "utilities", "crypto"].includes(next) ? next : "dashboard";
    const surface = ["studio", "audio"].includes(state.view) ? "analysis" : state.view;
    $$(".view").forEach(view => { view.hidden = view.id !== `view-${surface}`; });
    $$(".nav-link").forEach(link => {
      const selected = link.hash === `#${state.view}`;
      link.classList.toggle("active", selected);
      if (selected) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
    });
    $("#page-title").textContent = state.view[0].toUpperCase() + state.view.slice(1);
    if (state.view === "jobs") loadJobs().catch(error => notify(error.message));
    if (state.view === "tools") loadTools().catch(error => notify(error.message));
    window.dispatchEvent(new CustomEvent("stegolab:route", {detail:state.view}));
    schedulePoll();
  }

  async function upload(file) {
    if (!file || state.uploading) return;
    if (state.maxSize && file.size > state.maxSize) { notify(`This file is ${bytes(file.size)}. The upload limit is ${bytes(state.maxSize)}.`); return; }
    if (!file.size) { notify("This file is empty. Choose a file containing evidence."); return; }
    notify("");
    state.uploading = true;
    $("#choose-file").disabled = true;
    $("#upload-title").textContent = "Uploading evidence…";
    $("#upload-description").textContent = `${file.name} · ${bytes(file.size)}`;
    $("#choose-file").textContent = "Uploading…";
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("mode", state.mode);
      const data = await api("/api/jobs", { method: "POST", body: form });
      state.job = data.job || data;
      state.selectedId = state.job.id;
      state.report = null;
      state.reportLoaded = false;
      state.query = "";
      state.tab = "findings";
      renderProgress();
      renderReport();
      await loadJobs();
      await loadReport();
      schedulePoll();
      localStorage.setItem("stegolab.lastJob", state.job.id);
      return state.job;
    } catch (error) { notify(error.message); }
    finally {
      state.uploading = false;
      $("#choose-file").disabled = false;
      $("#choose-file").textContent = "Choose evidence file";
      $("#upload-title").textContent = "Drop a file to begin";
      $("#upload-description").textContent = "Images, audio, archives, documents, and binary files";
      $("#file-input").value = "";
    }
  }

  async function uploadFiles(files) {
    if (state.uploading || state.batchUploading) return;
    state.batchUploading = true;
    location.hash = "analysis";
    const batch = Array.from(files || []);
    const accepted = [], rejected = [];
    for (let i = 0; i < batch.length; i++) {
      const queue = $("#upload-queue");
      if (queue) queue.textContent = batch.length > 1 ? `Uploading ${i + 1} of ${batch.length}: ${batch[i].name}` : "";
      const job = await upload(batch[i]);
      if (job) accepted.push(job); else rejected.push(`${batch[i].name}: ${$("#notification").textContent || "Upload was rejected"}`);
    }
    state.batchUploading = false;
    const queue = $("#upload-queue");
    if (queue) queue.textContent = `${accepted.length} file${accepted.length === 1 ? "" : "s"} submitted${rejected.length ? ` · ${rejected.length} rejected` : ""}. Each accepted file has its own investigation in History.`;
    if (rejected.length) notify(rejected.join("\n"));
  }

  function renderProgress() {
    const job = state.job;
    const panel = $("#job-progress");
    panel.hidden = !job;
    if (!job) return;
    $("#progress-filename").textContent = job.filename || "Evidence analysis";
    $("#progress-stage").textContent = job.stage || label(job.status);
    const progress = Math.max(0, Math.min(100, Number(job.progress) || 0));
    const progressValue = job.status === "completed" ? 100 : progress;
    $("#progress-fill").style.width = `${progressValue}%`;
    $("#progress-bar").setAttribute("aria-valuenow", String(Math.round(progressValue)));
    $("#progress-bar").setAttribute("aria-valuetext", `${Math.round(progressValue)} percent, ${job.stage || label(job.status)}`);
    $("#progress-percent").textContent = `${Math.round(progressValue)}%`;
    $("#progress-detail").textContent = `${label(job.mode || "quick")} scan · ${label(job.status)}`;
    const cancel = $("#cancel-job");
    cancel.hidden = !isActive(job);
    cancel.disabled = job.status === "cancelling";
    cancel.textContent = job.status === "cancelling" ? "Cancelling…" : "Cancel scan";
    if (["failed", "error", "timeout", "timed_out"].includes(job.status)) {
      const message = job.error || job.errors;
      if (message) notify(readable(message));
    }
  }

  async function loadReport() {
    if (!state.job || isActive(state.job) || state.reportLoaded) return;
    const id = state.job.id;
    try {
      const report = await api(`/api/jobs/${encodeURIComponent(id)}/report`);
      if (state.selectedId !== id) return;
      state.report = report;
      state.reportLoaded = true;
      renderReport();
    } catch (error) {
      if (["completed", "complete", "succeeded", "success"].includes(state.job.status)) notify(`The report could not be loaded: ${error.message}`);
      state.reportLoaded = true;
      renderReport();
    }
  }

  async function selectJob(job) {
    notify("");
    state.selectedId = job.id;
    state.job = job;
    state.report = null;
    state.reportLoaded = false;
    state.query = "";
    state.tab = "findings";
    localStorage.setItem("stegolab.lastJob", job.id);
    location.hash = "analysis";
    renderProgress();
    renderReport();
    await refreshJob();
    schedulePoll();
  }

  async function refreshJob() {
    if (!state.job) return;
    const wasActive = isActive(state.job);
    const id = state.selectedId;
    const result = await api(`/api/jobs/${encodeURIComponent(id)}`);
    if (id !== state.selectedId) return;
    state.job = result.job || result;
    renderProgress();
    await loadReport();
    if (wasActive && !isActive(state.job)) await loadJobs();
  }

  function schedulePoll() {
    clearTimeout(state.timer);
    state.timer = null;
    if (document.hidden || (!isActive(state.job) && state.view !== "jobs")) return;
    state.timer = setTimeout(async () => {
      if (state.pollBusy) { schedulePoll(); return; }
      state.pollBusy = true;
      try {
        if (state.job && isActive(state.job)) await refreshJob();
        if (state.view === "jobs") await loadJobs();
      } catch (error) { notify(`Could not update analysis status: ${error.message}`); }
      finally { state.pollBusy = false; schedulePoll(); }
    }, state.view === "jobs" && !isActive(state.job) ? 5000 : 1200);
  }

  async function cancelJob() {
    if (!state.job || !isActive(state.job)) return;
    $("#cancel-job").disabled = true;
    try {
      const result = await api(`/api/jobs/${encodeURIComponent(state.job.id)}/cancel`, { method: "POST" });
      state.job = result.job || result;
      renderProgress();
      await loadReport();
      schedulePoll();
    } catch (error) { notify(error.message); $("#cancel-job").disabled = false; }
  }

  function renderReport() {
    const content = $("#result-content");
    content.replaceChildren();
    content.setAttribute("aria-labelledby", `tab-${state.tab}`);
    $$(".tabs button").forEach(tab => {
      const active = tab.dataset.tab === state.tab;
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    });
    const report = state.report;
    if (report && !isActive(state.job)) $("#job-progress").hidden = true;
    const summary = $("#evidence-summary");
    summary.replaceChildren();
    summary.hidden = !report?.file;
    if (report?.file) {
      const file = report.file;
      summary.append(make("div", "evidence-name", file.filename || state.job?.filename || "Evidence"));
      summary.append(make("div", "evidence-attributes", [file.format || file.type || file.mime, bytes(file.size)].filter(Boolean).join(" · ")));
      if (file.sha256) {
        const hash = make("div", "evidence-hash");
        hash.append(make("span", "", "SHA-256"), make("code", "", file.sha256));
        summary.append(hash);
      }
    }
    const evidenceStatus = $("#evidence-state");
    evidenceStatus.replaceChildren(make("span", "status-dot"), make("span", "", report ? label(state.job?.status || "completed") : state.job ? label(state.job.status) : "Awaiting evidence"));
    const count = getFindings().length;
    $("#finding-count").textContent = report ? count : "";
    const download = $("#report-download");
    download.hidden = !report;
    if (report) download.href = `/api/jobs/${encodeURIComponent(state.job.id)}/report?download=1`;
    window.dispatchEvent(new CustomEvent("stegolab:evidence"));
    if (!report) {
      empty(content, state.job ? isActive(state.job) ? "Following the evidence…" : "No report available" : "Your investigation starts here", state.job ? isActive(state.job) ? "Local analyzers are inspecting your file. Findings appear when the scan finishes." : "The scan ended without a report. Check its status above or try another file." : "Upload evidence to inspect findings, signatures, and extracted files.");
      return;
    }
    const renderers = { findings: renderFindings, metadata: renderMetadata, strings: renderStrings, hex: renderHex, artifacts: renderArtifacts, report: renderRawReport, ...(window.StegoLabLabs?.renderers || {}) };
    const rendered = renderers[state.tab]?.(content, {job:state.job,report:state.report,byteSelection:state.byteSelection});
    state.byteSelection = null;
    if (rendered?.catch) rendered.catch(error => notify(error.message));
  }

  function renderFindings(content) {
    const findings = getFindings();
    const flags = findings.filter(isFlag).length;
    const toolbar = make("div", "result-toolbar");
    const search = make("input");
    search.type = "search";
    search.placeholder = "Search findings…";
    search.setAttribute("aria-label", "Search findings");
    search.value = state.query;
    const summary = make("span", "finding-summary", `${findings.length} findings · ${flags} possible flags`);
    toolbar.append(search, summary);
    content.append(toolbar);
    const list = make("div", "findings-list");
    content.append(list);
    const drawFindings = () => {
      list.replaceChildren();
      const query = state.query.toLowerCase();
      const filtered = findings.filter(finding => readable(finding).toLowerCase().includes(query));
      if (!filtered.length) empty(list, query ? "No matching findings" : "No findings reported", query ? "Try another search term." : "Review metadata, strings, and the suggested checks below.");
      [...filtered].sort((a, b) => Number(isFlag(b)) - Number(isFlag(a))).forEach(finding => {
        const card = make("article", `finding${isFlag(finding) ? " flag" : ""}`);
        const top = make("div", "finding-header");
        top.append(make("h4", "", finding.title || label(finding.type || "Finding")));
        if (finding.confidence !== undefined && finding.confidence !== null) {
          const confidence = typeof finding.confidence === "number" ? `${Math.round(finding.confidence <= 1 ? finding.confidence * 100 : finding.confidence)}% confidence` : `${finding.confidence} confidence`;
          top.append(make("span", "finding-confidence", confidence));
        }
        card.append(top);
        const detail = finding.detail ?? finding.description ?? finding.value ?? finding.text;
        if (detail !== undefined) card.append(make("div", "finding-detail", readable(detail)));
        const footer = make("div", "finding-footer");
        if (finding.analyzer) footer.append(make("span", "", label(finding.analyzer)));
        if (finding.type) footer.append(make("span", "", label(finding.type)));
        if (finding.source) footer.append(make("span", "", `Source ${finding.source}`));
        if (finding.encoding) footer.append(make("span", "", finding.encoding));
        if (offset(finding.offset)) footer.append(make("span", "", `Offset ${offset(finding.offset)}`));
        if (finding.artifact_id) footer.append(make("span", "", `Artifact ${finding.artifact_id}`));
        if (footer.childElementCount) card.append(footer);
        list.append(card);
      });
      summary.textContent = `${query ? `${filtered.length} of ` : ""}${findings.length} findings · ${flags} possible flags`;
    };
    search.addEventListener("input", () => { state.query = search.value; drawFindings(); });
    drawFindings();
    const recommendations = state.report.recommendations || [];
    if (recommendations.length) {
      content.append(make("h4", "section-label", "Suggested next checks"));
      const items = make("ul", "recommendations");
      recommendations.forEach(item => items.append(make("li", "", typeof item === "string" ? item : item.title || item.detail || readable(item))));
      content.append(items);
    }
    if (getAnalyzers().length) {
      content.append(make("h4", "section-label", "Analyzer execution"));
      const statuses = make("div", "analyzer-statuses");
      getAnalyzers().forEach(analyzer => {
        const chip = make("span", `status-chip ${String(analyzer.status || "").replace(/[^a-z_]/g, "")}`, `${label(analyzer.name)} · ${label(analyzer.status)}`);
        chip.title = (analyzer.errors || []).map(readable).join("\n") || `${analyzer.duration_ms ?? "—"} ms`;
        statuses.append(chip);
      });
      content.append(statuses);
    }
    const errors = [...(state.report.errors || []), ...getAnalyzers().flatMap(analyzer => (analyzer.errors || []).map(error => `${analyzer.name}: ${readable(error)}`))];
    if (errors.length) {
      const details = make("details");
      details.style.marginTop = "20px";
      details.append(make("summary", "text-link", `Execution notices (${errors.length})`), codeBlock(errors));
      content.append(details);
    }
  }

  function isFlag(finding) { return /flag/i.test(String(finding.type || "")) || /flag/i.test(String(finding.title || "")); }

  function table(headers, rows, className = "") {
    const el = make("table", `data-table ${className}`);
    const head = make("thead"), tr = make("tr");
    headers.forEach(value => { const th = make("th", "", value); th.scope = "col"; tr.append(th); });
    head.append(tr);
    const body = make("tbody");
    rows.forEach(row => { const line = make("tr"); row.forEach(value => line.append(make("td", "", readable(value)))); body.append(line); });
    el.append(head, body);
    return el;
  }

  function renderMetadata(content) {
    const metadata = getAnalyzers().filter(analyzer => matchesAnalyzer(analyzer, ["metadata", "exif", "identification", "identify"]));
    content.append(make("h4", "section-label", "Evidence identity"));
    content.append(table(["Property", "Value"], Object.entries(state.report.file || {}), "metadata-table"));
    metadata.forEach(analyzer => {
      if (!analyzer.data || !Object.keys(analyzer.data).length) return;
      content.append(make("h4", "section-label", label(analyzer.name)));
      if (Array.isArray(analyzer.data)) content.append(codeBlock(analyzer.data));
      else content.append(table(["Property", "Value"], Object.entries(analyzer.data), "metadata-table"));
    });
  }

  function renderStrings(content) {
    const analyzers = getAnalyzers().filter(analyzer => matchesAnalyzer(analyzer, ["strings"]));
    const all = [];
    analyzers.forEach(analyzer => {
      const data = analyzer.data;
      const items = Array.isArray(data) ? data : data?.strings || data?.items || data?.results;
      if (Array.isArray(items)) all.push(...items);
      else if (typeof data === "string") all.push(...data.split("\n"));
      else if (data) content.append(codeBlock(data));
    });
    if (all.length) {
      const extractedCount = Math.max(all.length, ...analyzers.flatMap(analyzer => (analyzer.findings || []).map(finding => Number(finding.count) || 0)));
      if (extractedCount > all.length) content.append(make("p", "notice", `The report previews ${all.length} of ${extractedCount} extracted strings. Download the strings artifact from Artifacts to inspect the full stored output.`));
      const toolbar = make("div", "result-toolbar");
      const search = make("input"); search.type = "search"; search.placeholder = "Search readable strings…"; search.setAttribute("aria-label", "Search strings");
      const count = make("span", "finding-summary", `${all.length} strings`);
      toolbar.append(search, count); content.prepend(toolbar);
      const results = make("div"); content.append(results);
      const draw = () => {
        const query = search.value.toLowerCase();
        const filtered = all.filter(item => readable(item).toLowerCase().includes(query));
        results.replaceChildren();
        count.textContent = `${filtered.length} strings`;
        if (filtered.length > 2000) results.append(make("p", "truncation-note", "Showing the first 2,000 matches. Export the JSON report to inspect all stored strings."));
        const rows = filtered.slice(0, 2000).map(item => typeof item === "string" ? ["—", item] : [offset(item.offset) || "—", item.text ?? item.value ?? item.string ?? readable(item)]);
        if (rows.length) results.append(table(["Offset", "Readable content"], rows, "strings-table"));
        else empty(results, "No matching strings", "Try another search term.");
      };
      search.addEventListener("input", draw); draw();
    } else if (!content.childElementCount) empty(content, "No readable strings available", "The analyzer may have found none, reached a limit, or been unavailable. Review the report for execution details.");
  }

  function renderHex(content) {
    const analyzers = getAnalyzers().filter(analyzer => matchesAnalyzer(analyzer, ["binary", "hex", "signature"]));
    let found = false;
    analyzers.forEach(analyzer => {
      const data = analyzer.data;
      if (!data) return;
      const preview = data.hex || data.hexdump || data.hex_preview || data.preview;
      if (preview) {
        content.append(make("h4", "section-label", `${label(analyzer.name)} · byte preview`), codeBlock(preview));
        found = true;
      }
    });
    if (!found) {
      const signatures = getFindings().filter(finding => /signature|header|magic|appended|entropy|binary/.test(`${finding.type} ${finding.title}`.toLowerCase()));
      if (signatures.length) {
        content.append(make("p", "notice", "Signature findings below include byte offsets. Full analyzer data is available in the JSON report."));
        content.append(table(["Offset", "Finding"], signatures.map(item => [offset(item.offset) || "—", `${item.title || item.type}\n${readable(item.detail ?? item.description ?? "")}`]), "strings-table"));
      } else empty(content, "No byte preview available", "Review signature findings or the full JSON report for binary analysis details.");
    }
  }

  function renderArtifacts(content) {
    const artifacts = state.report.artifacts || getAnalyzers().flatMap(analyzer => analyzer.artifacts || []);
    if (!artifacts.length) { empty(content, "No extracted artifacts", "Deep scan can probe embedded files and perform bounded recursive extraction."); return; }
    content.append(make("p", "notice", "Extracted content is untrusted. Artifact links download files for further inspection."));
    const list = make("div", "artifact-list");
    artifacts.forEach(artifact => {
      const row = make("div", "artifact-row"), info = make("div");
      info.append(make("div", "artifact-name", artifact.name || artifact.filename || artifact.path || artifact.id));
      info.append(make("div", "artifact-info", [bytes(artifact.size), artifact.media_type || artifact.mime, artifact.source || artifact.analyzer].filter(Boolean).join(" · ")));
      row.append(info);
      if (artifact.id) {
        const link = make("a", "button secondary small", "Download");
        link.href = `/api/jobs/${encodeURIComponent(state.job.id)}/artifacts/${encodeURIComponent(artifact.id)}`;
        link.download = artifact.name || artifact.filename || "artifact";
        row.append(link);
      }
      list.append(row);
    });
    content.append(list);
  }

  function renderRawReport(content) {
    const toolbar = make("div", "report-actions");
    toolbar.append(make("p", "", "Complete structured evidence and analyzer results."));
    const copy = make("button", "button secondary small", "Copy JSON"); copy.type = "button";
    copy.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(readable(state.report)); copy.textContent = "Copied"; }
      catch { notify("Clipboard is unavailable. Use Export JSON to save the report."); }
    });
    toolbar.append(copy);
    content.append(toolbar, codeBlock(state.report));
  }

  async function loadJobs() {
    const data = await api("/api/jobs");
    state.jobs = Array.isArray(data) ? data : data.jobs || [];
    window.dispatchEvent(new CustomEvent("stegolab:jobs"));
    const count = $("#job-count"); count.textContent = state.jobs.length; count.hidden = !state.jobs.length;
    const container = $("#jobs-list"); container.replaceChildren();
    if (!state.jobs.length) { empty(container, "No investigations yet", "Upload your first evidence file from Analysis to start a local scan."); return; }
    state.jobs.forEach(job => {
      const row = make("div", "job-row"), name = make("div");
      name.append(make("span", "job-name", job.filename || job.id), make("span", "job-subtitle", `${bytes(job.size)} · ${String(job.id).slice(0, 12)}`));
      const status = make("span", `job-status ${String(job.status).replace(/[^a-z_]/g, "")}`, `${label(job.status)}${isActive(job) ? ` · ${Math.round(Number(job.progress) || 0)}%` : ""}`);
      const mode = make("span", "job-subtitle job-mode", `${label(job.mode)} scan`);
      const created = new Date(job.created_at);
      const date = make("span", "job-date", Number.isNaN(created.valueOf()) ? "" : created.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }));
      const open = make("button", "button secondary small", "Open"); open.type = "button"; open.setAttribute("aria-label", `Open analysis for ${job.filename || job.id}`);
      open.addEventListener("click", () => selectJob(job).catch(error => notify(error.message)));
      const actions = make("div", "job-actions");
      actions.append(open);
      if (terminalStatuses.has(job.status)) {
        const remove = make("button", "text-link delete-job", "Delete");
        remove.type = "button";
        remove.setAttribute("aria-label", `Delete analysis and evidence for ${job.filename || job.id}`);
        remove.addEventListener("click", async () => {
          if (!window.confirm(`Delete "${job.filename || job.id}" and its original evidence, report, and artifacts from this instance? This cannot be undone.`)) return;
          remove.disabled = true;
          try {
            await api(`/api/jobs/${encodeURIComponent(job.id)}`, { method: "DELETE" });
            if (state.selectedId === job.id) {
              state.selectedId = null; state.job = null; state.report = null; state.reportLoaded = false;
              renderProgress(); renderReport();
            }
            await loadJobs();
          } catch (error) { notify(error.message); remove.disabled = false; }
        });
        actions.append(remove);
      }
      row.append(name, status, mode, date, actions); container.append(row);
    });
  }

  async function loadTools() {
    const data = await api("/api/tools");
    state.tools = Array.isArray(data) ? data : data.tools || [];
    window.dispatchEvent(new CustomEvent("stegolab:tools"));
    const available = state.tools.filter(tool => tool.available).length;
    $("#tools-summary").textContent = `${available} available · ${state.tools.length - available} unavailable · unavailable optional tools are skipped`;
    const container = $("#tools-list"); container.replaceChildren();
    if (!state.tools.length) { empty(container, "The tool registry is empty", "Restart the worker and refresh its availability."); return; }
    state.tools.forEach(tool => {
      const row = make("article", "tool-row"), top = make("div", "tool-heading"), name = make("h3", "", tool.name);
      if (tool.version) name.append(make("span", "tool-version", tool.version));
      top.append(name, make("span", `tool-status${tool.available ? "" : " unavailable"}`, tool.available ? "Available" : "Unavailable"));
      row.append(top);
      const formats = tool.formats || tool.supported_formats;
      row.append(make("p", "tool-description", tool.description || (Array.isArray(formats) ? formats.join(" · ") : formats) || "Local analysis tool"));
      if (!tool.available && (tool.error || tool.reason)) row.append(make("p", "tool-description", tool.error || tool.reason));
      const details = make("details");
      details.append(make("summary", "", "Parameters & execution limits"));
      details.append(codeBlock({ formats: tool.formats || tool.supported_formats, parameters: tool.parameters, limits: tool.limits || tool.execution_limits, parser: tool.parser || tool.output_parser, error_handling: tool.error_handling, license:tool.license, source:tool.source, installation:tool.installation, blocked:tool.blocked }));
      row.append(details); container.append(row);
    });
  }

  async function runUtility(event) {
    event.preventDefault();
    if (state.utilityBusy) return;
    const input = $("#utility-input");
    if (!input.value) { input.focus(); return; }
    const status = $("#utility-status");
    state.utilityBusy = true; $("#run-utility").disabled = true; $("#run-utility").textContent = "Processing…";
    status.textContent = ""; status.classList.remove("error-text"); $("#copy-result").disabled = true;
    try {
      const operation = $("#utility-operation").value;
      const payload = { operation, text: input.value };
      if (operation === "xor") payload.key = $("#xor-key").value;
      const result = await api("/api/utilities", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      $("#utility-output").value = readable(result.result ?? result);
      $("#copy-result").disabled = false;
      status.textContent = "Completed locally";
    } catch (error) { status.textContent = error.message; status.classList.add("error-text"); $("#utility-output").value = ""; }
    finally { state.utilityBusy = false; $("#run-utility").disabled = false; $("#run-utility").textContent = "Run transform →"; }
  }

  $("#choose-file").addEventListener("click", () => $("#file-input").click());
  $("#file-input").multiple = true;
  $("#file-input").addEventListener("change", event => uploadFiles(event.target.files));
  const dropZone = $("#drop-zone");
  ["dragenter", "dragover"].forEach(type => dropZone.addEventListener(type, event => { event.preventDefault(); dropZone.classList.add("dragover"); }));
  ["dragleave", "drop"].forEach(type => dropZone.addEventListener(type, event => { event.preventDefault(); dropZone.classList.remove("dragover"); }));
  dropZone.addEventListener("drop", event => {
    uploadFiles(event.dataTransfer.files);
  });
  document.addEventListener("dragover", event => event.preventDefault());
  document.addEventListener("drop", event => event.preventDefault());
  $$("input[name=mode]").forEach(input => input.addEventListener("change", () => { state.mode = input.value; }));
  $$(".tabs button").forEach(tab => tab.addEventListener("click", () => { state.tab = tab.dataset.tab; renderReport(); }));
  $(".tabs").addEventListener("keydown", event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const tabs = $$(".tabs button"), index = tabs.indexOf(document.activeElement);
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].click(); tabs[next].focus();
  });
  $("#cancel-job").addEventListener("click", cancelJob);
  $("#refresh-jobs").addEventListener("click", () => loadJobs().catch(error => notify(error.message)));
  $("#refresh-tools").addEventListener("click", () => loadTools().catch(error => notify(error.message)));
  $("#utility-operation").addEventListener("change", event => { const xor = event.target.value === "xor"; $("#xor-key-field").hidden = !xor; $("#xor-key").required = xor; });
  $("#utility-form").addEventListener("submit", runUtility);
  $("#copy-result").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("#utility-output").value); $("#utility-status").textContent = "Result copied"; }
    catch { $("#utility-status").textContent = "Select the result text to copy it manually."; }
  });
  window.addEventListener("hashchange", route);
  document.addEventListener("visibilitychange", schedulePoll);
  window.StegoLab = {context:()=>({job:state.job,report:state.report,jobs:state.jobs,tools:state.tools,view:state.view,tab:state.tab}),selectJob,
    showTab:tab=>{state.tab=tab;renderReport();},openBytes:(artifact_id=null,offset=0)=>{state.byteSelection={artifact_id,offset};state.tab='forensics';renderReport();},route,notify,api,uploadFiles,loadJobs,loadTools,cancelJob};
  route();
  loadHealth();
  setInterval(loadHealth, 15000);
  loadJobs().catch(() => {});
})();
