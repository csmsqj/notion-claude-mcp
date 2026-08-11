"use strict";

const $ = (id) => document.getElementById(id);
const state = { levels: [], roots: [], settings: {}, server: {}, browsePath: "", locked: false };
let approvalPollTimer = 0;

function esc(text) {
  return String(text ?? "").replace(/[&<>"']/g, (ch) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]
  ));
}

function toast(message, kind = "") {
  const box = $("toast");
  box.textContent = message;
  box.className = "toast " + kind;
  box.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { box.hidden = true; }, kind === "err" ? 6000 : 2600);
}

// 前端出未捕获异常时不要静默失败，否则页面会停在半渲染状态难以排查。
window.addEventListener("error", (event) => {
  toast("界面脚本出错：" + (event.message || event.error), "err");
});
window.addEventListener("unhandledrejection", (event) => {
  toast("界面请求失败：" + (event.reason && event.reason.message ? event.reason.message : event.reason), "err");
});

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, Object.assign({}, options, { headers }));
  let data;
  try {
    data = await response.json();
  } catch (err) {
    throw new Error("服务端返回了非 JSON 响应（HTTP " + response.status + "）");
  }
  if (!response.ok || data.ok === false) {
    throw new Error(data.error || ("请求失败：HTTP " + response.status));
  }
  return data;
}

function levelOptions(select, current) {
  select.innerHTML = state.levels
    .map((item) => `<option value="${item.level}"${item.level === current ? " selected" : ""}>第 ${item.level} 级 · ${esc(item.label)}</option>`)
    .join("");
}

function levelBadge(level) {
  const found = state.levels.find((item) => item.level === level);
  const text = found ? `${level}级 ${found.label}` : "未授权";
  return `<span class="badge lv${level || 0}">${esc(text)}</span>`;
}

// ---------------- 标签切换 ----------------
// 记进 location.hash，刷新后仍停在同一个标签页。
function activateTab(name) {
  const tab = document.querySelector(`.tab[data-tab="${name}"]`);
  if (!tab) return;
  document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
  document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
  tab.classList.add("active");
  $("panel-" + name).classList.add("active");
  clearInterval(approvalPollTimer);
  approvalPollTimer = 0;
  if (name === "approvals") {
    loadApprovals();
    approvalPollTimer = setInterval(loadApprovals, 2000);
  }
  if (name === "audit") loadAudit();
  if (name === "trash") loadTrash();
  if (name === "browse" && !state.browsePath) loadDrives();
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    location.hash = tab.dataset.tab;
    activateTab(tab.dataset.tab);
  });
});

window.addEventListener("hashchange", () => activateTab(location.hash.slice(1)));

// ---------------- 全局状态 ----------------
async function loadState() {
  const data = await api("/api/state");
  state.levels = data.levels;
  state.roots = data.roots;
  state.settings = data.settings;
  state.locked = !!data.settings.global_lock;

  const authLabel = data.server.auth_mode || (data.server.oauth && data.server.oauth.enabled ? "OAuth 2.1" : "等待 OAuth 重启");
  $("serverLine").textContent =
    `${authLabel} · ${data.server.tool_count} 个工具` + (state.locked ? " · 已锁定" : " · 运行中");
  $("lockBtn").textContent = state.locked ? "已锁定 · 点击解锁" : "运行中 · 点击锁定";
  $("lockBtn").className = "btn " + (state.locked ? "btn-danger" : "btn-ghost");
  $("pendingPill").hidden = !data.pending_approvals;
  $("pendingCount").textContent = data.pending_approvals;

  renderLevels();
  renderRoots();
  $("denyBox").value = data.denies.join("\n");
  levelOptions($("newRootLevel"), 1);
  levelOptions($("grantLevel"), 2);
  renderSettings();
  renderConn(data.server);
  renderTools(data.tools);
}

function renderLevels() {
  $("levelLegend").innerHTML = state.levels
    .map((item) => `
      <div class="level-card lv${item.level}">
        <div class="tag">第 ${item.level} 级 · ${esc(item.label)}</div>
        <p>${esc(item.hint)}</p>
      </div>`)
    .join("");
}

function renderRoots() {
  $("rootCount").textContent = `（${state.roots.length} 条）`;
  if (!state.roots.length) {
    $("rootList").innerHTML = '<div class="empty">还没有授权任何路径。MCP 客户端现在读不到本机任何文件。</div>';
    return;
  }
  $("rootList").innerHTML = state.roots
    .map((root) => `
      <div class="root-item ${root.enabled ? "" : "off"}" data-id="${root.id}">
        <div class="path mono">${esc(root.path)}
          ${root.exists ? "" : '<span class="missing">（路径已不存在）</span>'}
          ${root.note ? `<div class="note">${esc(root.note)}</div>` : ""}
        </div>
        <select class="input" data-act="level">${
          state.levels.map((lv) => `<option value="${lv.level}"${lv.level === root.level ? " selected" : ""}>第 ${lv.level} 级 · ${esc(lv.label)}</option>`).join("")
        }</select>
        <button class="btn btn-sm" data-act="toggle">${root.enabled ? "停用" : "启用"}</button>
        <button class="btn btn-sm btn-danger" data-act="remove">移除</button>
      </div>`)
    .join("");
}

$("rootList").addEventListener("change", async (event) => {
  const select = event.target.closest('select[data-act="level"]');
  if (!select) return;
  const id = select.closest(".root-item").dataset.id;
  try {
    await api("/api/roots/update", { method: "POST", body: JSON.stringify({ id, level: Number(select.value) }) });
    toast("权限级别已更新", "ok");
    await loadState();
  } catch (err) { toast(err.message, "err"); }
});

$("rootList").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-act]");
  if (!button) return;
  const item = button.closest(".root-item");
  const id = item.dataset.id;
  const root = state.roots.find((r) => r.id === id);
  try {
    if (button.dataset.act === "toggle") {
      await api("/api/roots/update", { method: "POST", body: JSON.stringify({ id, enabled: !root.enabled }) });
      toast(root.enabled ? "已停用" : "已启用", "ok");
    } else if (button.dataset.act === "remove") {
      if (!confirm("移除后 MCP 客户端将无法访问该路径：\n" + root.path)) return;
      await api("/api/roots/remove", { method: "POST", body: JSON.stringify({ id }) });
      toast("已移除", "ok");
    }
    await loadState();
  } catch (err) { toast(err.message, "err"); }
});

$("addRootBtn").addEventListener("click", async () => {
  const path = $("newRootPath").value.trim();
  if (!path) { toast("请输入要授权的绝对路径", "err"); return; }
  try {
    await api("/api/roots/add", {
      method: "POST",
      body: JSON.stringify({
        path,
        level: Number($("newRootLevel").value),
        note: $("newRootNote").value.trim(),
      }),
    });
    $("newRootPath").value = "";
    $("newRootNote").value = "";
    toast("已添加授权路径", "ok");
    await loadState();
  } catch (err) { toast(err.message, "err"); }
});

$("pickFromBrowse").addEventListener("click", () => {
  location.hash = "browse";
  activateTab("browse");
});

// 调用本机原生选择器。弹窗会一直阻塞这个请求，所以按钮先置灰给出提示。
async function pickNative(mode, button) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = "请在弹出的窗口里选择…";
  toast("已在你的电脑上打开选择窗口，若没看到请检查任务栏", "ok");
  try {
    const data = await api("/api/pick", {
      method: "POST",
      body: JSON.stringify({ mode, initial: $("newRootPath").value.trim() }),
    });
    if (data.cancelled) { toast("已取消选择"); return; }
    $("newRootPath").value = data.path;
    $("addRootHint").textContent = "已填入：" + data.path + "。选好权限级别后点【添加】。";
    toast("已选择 " + data.path, "ok");
  } catch (err) {
    toast(err.message, "err");
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

$("pickFolderBtn").addEventListener("click", (event) => pickNative("folder", event.currentTarget));
$("pickFileBtn").addEventListener("click", (event) => pickNative("file", event.currentTarget));

$("saveDenyBtn").addEventListener("click", async () => {
  const patterns = $("denyBox").value.split("\n").map((line) => line.trim()).filter(Boolean);
  try {
    await api("/api/denies", { method: "POST", body: JSON.stringify({ patterns }) });
    toast("黑名单已保存", "ok");
  } catch (err) { toast(err.message, "err"); }
});

$("lockBtn").addEventListener("click", async () => {
  try {
    await api("/api/lock", { method: "POST", body: JSON.stringify({ locked: !state.locked }) });
    toast(state.locked ? "已解锁" : "已锁定，所有操作将被拒绝", "ok");
    await loadState();
  } catch (err) { toast(err.message, "err"); }
});

$("refreshBtn").addEventListener("click", async () => {
  try {
    await loadState();
    if (document.querySelector('.tab[data-tab="approvals"]').classList.contains("active")) await loadApprovals();
    toast("已刷新", "ok");
  } catch (err) { toast(err.message, "err"); }
});

// ---------------- 浏览与搜索 ----------------
async function loadDrives() {
  try {
    const data = await api("/api/drives");
    $("driveBar").innerHTML = data.drives
      .map((d) => `<button class="drive-chip" data-path="${esc(d.path)}">${esc(d.label)}<span>${esc(d.free_text || "")} 可用</span></button>`)
      .join("");
  } catch (err) { toast(err.message, "err"); }
}

$("driveBar").addEventListener("click", (event) => {
  const chip = event.target.closest(".drive-chip");
  if (chip) browse(chip.dataset.path);
});

async function browse(path) {
  try {
    const query = new URLSearchParams({ path, hidden: $("browseHidden").checked ? "1" : "0" });
    const data = await api("/api/browse?" + query.toString());
    state.browsePath = data.path;
    $("browsePath").value = data.path;
    $("crumb").innerHTML = `当前位置 ${esc(data.path)} ${levelBadge(data.level)}`;
    $("grantBar").hidden = false;
    $("grantPath").textContent = data.path;
    const entries = data.entries;
    if (!entries.length) {
      $("browseList").innerHTML = '<div class="empty">这个目录是空的，或所有条目都被隐藏。</div>';
      return;
    }
    $("browseList").innerHTML = entries
      .map((item) => `
        <div class="entry">
          <span class="icon">${item.is_dir ? "▣" : "▢"}</span>
          <span class="name ${item.is_dir ? "link" : ""}" ${item.is_dir ? `data-dir="${esc(item.path)}"` : ""}>${esc(item.name)}</span>
          <span class="meta">${esc(item.size_text)} · ${esc(item.mtime)}</span>
          ${item.is_dir ? "" : `<button class="btn btn-sm" data-preview="${esc(item.path)}">查看</button>`}
          <button class="btn btn-sm" data-fill="${esc(item.path)}">选为授权路径</button>
        </div>`)
      .join("");
    if (data.truncated) {
      $("browseList").innerHTML += '<div class="empty">条目过多，仅显示前一部分。</div>';
    }
  } catch (err) { toast(err.message, "err"); }
}

let previewPath = "";
let previewNextStartLine = 0;
let previewController = null;
let previewRequest = 0;

async function previewFile(path, startLine = 1) {
  if (previewController) previewController.abort();
  previewController = new AbortController();
  const request = ++previewRequest;
  previewPath = path;
  $("previewBox").hidden = false;
  $("previewPath").textContent = path;
  $("previewContent").textContent = startLine === 1
    ? "正在读取…"
    : $("previewContent").textContent + "\n正在读取…";
  try {
    const query = new URLSearchParams({ path, start_line: String(startLine), max_lines: "500" });
    const data = await api("/api/preview?" + query.toString(), { signal: previewController.signal });
    if (request !== previewRequest || path !== previewPath) return;
    $("previewPath").textContent = data.path;
    $("previewMeta").textContent = `${data.size_text} · 第 ${data.start_line}-${data.end_line} 行${data.truncated ? " · 内容较长" : ""}`;
    $("previewContent").textContent = startLine === 1
      ? data.content
      : $("previewContent").textContent.replace(/\n正在读取…$/, "") + (data.content ? "\n" + data.content : "");
    previewNextStartLine = data.next_start_line || 0;
    $("previewMore").hidden = !previewNextStartLine;
  } catch (err) {
    if (err.name === "AbortError" || request !== previewRequest) return;
    $("previewMeta").textContent = "";
    $("previewContent").textContent = err.message;
    $("previewMore").hidden = true;
  }
}

$("previewClose").addEventListener("click", () => {
  if (previewController) previewController.abort();
  previewRequest++;
  $("previewBox").hidden = true;
  previewPath = "";
  previewNextStartLine = 0;
});
$("previewMore").addEventListener("click", () => {
  if (previewPath && previewNextStartLine) previewFile(previewPath, previewNextStartLine);
});

$("browseList").addEventListener("click", (event) => {
  const preview = event.target.closest("[data-preview]");
  if (preview) { previewFile(preview.dataset.preview); return; }
  const dir = event.target.closest("[data-dir]");
  if (dir) { browse(dir.dataset.dir); return; }
  const fill = event.target.closest("[data-fill]");
  if (fill) {
    $("newRootPath").value = fill.dataset.fill;
    document.querySelector('.tab[data-tab="paths"]').click();
    $("addRootHint").textContent = "已填入路径，选好权限级别后点【添加】。";
    toast("已填入待授权路径");
  }
});

$("browseGoBtn").addEventListener("click", () => browse($("browsePath").value.trim()));
$("browsePath").addEventListener("keydown", (event) => {
  if (event.key === "Enter") browse($("browsePath").value.trim());
});
$("browseUpBtn").addEventListener("click", async () => {
  const current = state.browsePath || $("browsePath").value.trim();
  if (!current) return;
  const parts = current.replace(/[\/]+$/, "").split(/[\/]/);
  if (parts.length <= 1) { loadDrives(); return; }
  parts.pop();
  browse(parts.length === 1 ? parts[0] + "\\" : parts.join("\\"));
});
$("browseHidden").addEventListener("change", () => { if (state.browsePath) browse(state.browsePath); });

$("grantBtn").addEventListener("click", async () => {
  const path = state.browsePath;
  if (!path) return;
  try {
    await api("/api/roots/add", { method: "POST", body: JSON.stringify({ path, level: Number($("grantLevel").value) }) });
    toast("已授权：" + path, "ok");
    await loadState();
  } catch (err) { toast(err.message, "err"); }
});

async function doSearch() {
  const keyword = $("searchInput").value.trim();
  if (!keyword) { toast("请输入搜索关键字", "err"); return; }
  $("searchResult").innerHTML = '<div class="empty">正在搜索…</div>';
  try {
    const query = new URLSearchParams({
      q: keyword,
      scope: $("searchScope").value.trim(),
      hidden: $("searchHidden").checked ? "1" : "0",
    });
    const data = await api("/api/search?" + query.toString());
    if (!data.matches.length) {
      $("searchResult").innerHTML = `<div class="empty">没有命中（扫描 ${data.scanned} 个条目${data.timed_out ? "，已达时间上限" : ""}）。</div>`;
      return;
    }
    const rows = data.matches
      .map((item) => `
        <div class="entry">
          <span class="icon">${item.is_dir ? "▣" : "▢"}</span>
          <span class="name mono">${esc(item.path)}</span>
          ${levelBadge(item.level)}
          <span class="meta">${esc(item.size_text)}</span>
          ${item.is_dir ? "" : `<button class="btn btn-sm" data-preview="${esc(item.path)}">查看</button>`}
          <button class="btn btn-sm" data-fill="${esc(item.path)}">选为授权路径</button>
        </div>`)
      .join("");
    const note = `<div class="empty">命中 ${data.count} 条${data.truncated ? "（已截断）" : ""}，扫描 ${data.scanned} 个条目。</div>`;
    $("searchResult").innerHTML = note + rows;
  } catch (err) {
    $("searchResult").innerHTML = "";
    toast(err.message, "err");
  }
}

$("searchBtn").addEventListener("click", doSearch);
$("searchInput").addEventListener("keydown", (event) => { if (event.key === "Enter") doSearch(); });
$("searchResult").addEventListener("click", (event) => {
  const preview = event.target.closest("[data-preview]");
  if (preview) { previewFile(preview.dataset.preview); return; }
  const fill = event.target.closest("[data-fill]");
  if (!fill) return;
  $("newRootPath").value = fill.dataset.fill;
  document.querySelector('.tab[data-tab="paths"]').click();
  toast("已填入待授权路径");
});

// ---------------- 受控审批 ----------------
const RISK_TEXT = { low: "低风险", medium: "中风险", high: "高风险", critical: "极高风险", blocked: "已拦截" };
const OP_TEXT = { read: "读取", write: "写入", delete: "删除", exec: "执行命令" };
const STATUS_TEXT = { pending: "等待确认", approved: "已同意", denied: "已拒绝", expired: "已过期" };
const BY_TEXT = { console: "在本机控制台", desktop: "在确认窗点击" };
const APPROVAL_MODE_TEXT = {
  desktop: "· 当前：本机弹确认窗",
  console: "· 当前：只认本机控制台",
};

async function loadApprovals() {
  try {
    const [data, oauth] = await Promise.all([
      api("/api/approvals?limit=60"),
      api("/api/oauth/requests"),
    ]);
    $("approvalModeTag").textContent = APPROVAL_MODE_TEXT[state.settings.approval_mode] || "";
    renderOAuthRequests(oauth.items || []);
    if (!data.items.length) {
      $("approvalList").innerHTML = '<div class="empty">目前没有受控操作。</div>';
      return;
    }
    $("approvalList").innerHTML = data.items.map(renderApproval).join("");
  } catch (err) { toast(err.message, "err"); }
}

function renderOAuthRequests(items) {
  if (!items.length) {
    $("oauthRequestList").innerHTML = '<div class="empty">目前没有 OAuth 连接请求。</div>';
    return;
  }
  $("oauthRequestList").innerHTML = items.map((item) => {
    const pending = item.status === "pending";
    const statusText = { pending: "等待确认", approved: "已允许", denied: "已拒绝", expired: "已过期", error: "失败" }[item.status] || item.status;
    return `<div class="approval-item ${esc(item.status)}" data-oauth-id="${esc(item.id)}">
      <div class="approval-head"><span class="op">OAuth 连接</span><span class="badge lv0" title="客户端自报名称，未经网关验证">自报：${esc(item.client_name)}</span><span class="muted">${esc(statusText)}${pending ? ` · 剩余 ${item.seconds_left}s` : ""}</span></div>
      <div class="path mono">${esc(item.redirect_uri)}</div>
      <div class="reason">${esc(item.message || "")}</div>
      ${pending ? '<div class="approval-actions"><button class="btn btn-sm btn-ok" data-oauth-decide="1">允许连接</button><button class="btn btn-sm btn-danger" data-oauth-decide="0">拒绝连接</button></div>' : ""}
    </div>`;
  }).join("");
}

$("oauthRequestList").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-oauth-decide]");
  if (!button) return;
  const item = button.closest("[data-oauth-id]");
  const id = item.dataset.oauthId;
  item.querySelectorAll("button").forEach((entry) => { entry.disabled = true; });
  try {
    const result = await api("/api/oauth/decide", {
      method: "POST",
      body: JSON.stringify({ id, approve: button.dataset.oauthDecide === "1" }),
    });
    const actual = { approved: "已允许客户端连接", denied: "已拒绝客户端连接", expired: "连接请求已过期" }[result.status] || `请求状态：${result.status}`;
    toast(actual, result.status === "approved" ? "ok" : "");
    await loadApprovals();
  } catch (err) { toast(err.message, "err"); }
});

function renderApproval(item) {
  const pending = item.status === "pending";
  const decidedBy = item.decided_by ? `（${BY_TEXT[item.decided_by] || item.decided_by}）` : "";
  return `
    <div class="approval-item ${item.status}" data-id="${item.id}">
      <div class="approval-head">
        <span class="op">${esc(OP_TEXT[item.operation] || item.operation)}</span>
        <span class="risk risk-${item.risk}">${esc(RISK_TEXT[item.risk] || item.risk)}</span>
        <span class="badge lv0">${esc(item.tool)}</span>
        <span class="muted">${esc(STATUS_TEXT[item.status] || item.status)}${esc(decidedBy)}${pending ? ` · 剩余 ${item.seconds_left}s` : ""}</span>
      </div>
      <div class="path mono">${esc(item.path)}</div>
      <div class="reason">${esc(item.reason)}</div>
      ${item.preview ? `<pre>${esc(item.preview)}</pre>` : ""}
      ${item.user_reply ? `<div class="reason">你的回复：${esc(item.user_reply)}</div>` : ""}
      ${pending ? `
      <div class="approval-actions">
        <button class="btn btn-sm btn-ok" data-decide="1">批准</button>
        <button class="btn btn-sm btn-danger" data-decide="0">拒绝</button>
      </div>` : ""}
    </div>`;
}

$("approvalList").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-decide]");
  if (!button) return;
  const id = button.closest(".approval-item").dataset.id;
  const row = button.closest(".approval-item");
  row.querySelectorAll("button").forEach((entry) => { entry.disabled = true; });
  try {
    const result = await api("/api/approvals/decide", {
      method: "POST",
      body: JSON.stringify({ id, approve: button.dataset.decide === "1" }),
    });
    const actual = { approved: "已批准", denied: "已拒绝", expired: "审批已过期" }[result.item.status] || `审批状态：${result.item.status}`;
    toast(actual, result.item.status === "approved" ? "ok" : "");
    await loadApprovals();
    await loadState();
  } catch (err) { toast(err.message, "err"); }
});

// ---------------- 设置 ----------------
const SETTING_META = [
  { key: "approval_mode", label: "受控操作怎么确认", type: "select",
    options: [
      ["desktop", "在本机弹确认窗，点一下即可（推荐）"],
      ["console", "只认本机控制台的批准按钮（最严）"],
    ],
    desc: "默认弹窗：AI 一发起高风险操作，你屏幕上就跳出确认框，点【批准】或【拒绝】；也可在本机控制台裁决。" },
  { key: "approval_popup_seconds", label: "确认窗等待秒数", type: "number",
    desc: "确认窗最多显示多久。到时间没点就算未确认，操作不会执行。" },
  { key: "delete_mode", label: "删除方式", type: "select",
    options: [["trash", "先移入网关回收站（可恢复）"], ["permanent", "直接永久删除"]],
    desc: "建议保持回收站模式，误删还能找回。" },
  { key: "system_protection", label: "系统文件保护", type: "select",
    options: [["true", "开启（推荐）"], ["false", "关闭"]],
    desc: "开启后 Windows 目录、密钥、凭据类文件的破坏性操作必须走审批。" },
  { key: "safe_delete_max_bytes", label: "小文件删除上限（字节）", type: "number",
    desc: "第 3 级路径下，超过这个大小的文件不再算小文件，会被拒绝。" },
  { key: "safe_delete_max_entries", label: "小目录条目上限", type: "number",
    desc: "目录内条目超过这个数量就算大目录，第 3 级不允许删除。" },
  { key: "safe_overwrite_max_bytes", label: "安全覆盖上限（字节）", type: "number",
    desc: "覆盖超过这个大小的已有文件需要 4 级并走审批。" },
  { key: "approval_wait_seconds", label: "审批等待秒数", type: "number",
    desc: "工具调用最多阻塞等待多久。超时不代表作废，批准后重试即可执行。" },
  { key: "approval_ttl_seconds", label: "审批单有效期（秒）", type: "number",
    desc: "超过这个时间未处理的审批单自动过期。" },
  { key: "trash_retention_days", label: "回收站保留天数", type: "number",
    desc: "清理时删除早于这个天数的条目。" },
  { key: "trash_copy_max_bytes", label: "回收站单体上限（字节）", type: "number",
    desc: "超过这个大小的目标不进回收站，直接永久删除。" },
  { key: "max_read_bytes", label: "单次读取上限（字节）", type: "number",
    desc: "限制一次 read_file 返回的内容量，防止塞爆模型上下文。" },
  { key: "search_max_results", label: "搜索结果上限", type: "number", desc: "单次搜索最多返回多少条。" },
  { key: "search_timeout_seconds", label: "搜索超时（秒）", type: "number", desc: "搜索最长耗时。" },
  { key: "exec_timeout_seconds", label: "命令超时（秒）", type: "number", desc: "受控命令执行的最长运行时间。" },
];

function renderSettings() {
  $("settingsGrid").innerHTML = SETTING_META.map((meta) => {
    const value = state.settings[meta.key];
    if (meta.type === "select") {
      const current = String(value);
      const options = meta.options
        .map(([optValue, optLabel]) => `<option value="${optValue}"${optValue === current ? " selected" : ""}>${esc(optLabel)}</option>`)
        .join("");
      return `<div class="setting"><label>${esc(meta.label)}</label>
        <select class="input" data-key="${meta.key}" data-type="select">${options}</select>
        <div class="desc">${esc(meta.desc)}</div></div>`;
    }
    return `<div class="setting"><label>${esc(meta.label)}</label>
      <input class="input" type="number" data-key="${meta.key}" data-type="number" value="${esc(value)}" />
      <div class="desc">${esc(meta.desc)}</div></div>`;
  }).join("");
}

$("saveSettingsBtn").addEventListener("click", async () => {
  const payload = {};
  document.querySelectorAll("#settingsGrid [data-key]").forEach((element) => {
    const key = element.dataset.key;
    if (key === "system_protection") payload[key] = element.value === "true";
    else if (element.dataset.type === "number") payload[key] = Number(element.value);
    else payload[key] = element.value;
  });
  try {
    await api("/api/settings", { method: "POST", body: JSON.stringify(payload) });
    toast("设置已保存", "ok");
    await loadState();
  } catch (err) { toast(err.message, "err"); }
});

// ---------------- OAuth 连接信息 ----------------
function renderConn(server) {
  state.server = server;
  const oauth = server.oauth || {};
  const url = server.public_url || "";
  const oauthReady = server.auth_mode === "OAuth 2.1" || oauth.enabled === true;
  const stable = server.stable_url === true || server.tunnel_mode === "named";

  $("connUrl").textContent = url || "公网隧道尚未启动 — 请运行 START.cmd";
  $("connUrl").classList.toggle("warn", !url);
  $("oauthMode").textContent = oauthReady ? "OAuth 2.1 已启用" : "重启后启用 OAuth";
  $("oauthMode").className = "status-badge " + (oauthReady ? "" : "warn");
   $("tunnelMode").textContent = stable ? "固定链接" : "运行期固定";
  $("tunnelMode").className = "status-badge " + (stable ? "neutral" : "warn");

  if (!url) {
    $("connUrlDesc").textContent = "网关只有本地地址时，云端 AI 客户端无法连接。";
  } else if (stable) {
    $("connUrlDesc").textContent = "已使用命名 Cloudflare Tunnel。该地址在断线重连和程序重启后仍保持不变。";
  } else {
    $("connUrlDesc").textContent = "当前 Quick Tunnel 地址在网关和 Tunnel 进程不关闭期间持续有效；跨重启固定域名需运行 SETUP-STABLE-TUNNEL.cmd。";
  }

  const accessTtl = Number(oauth.access_token_ttl_seconds || 0);
  const refreshTtl = Number(oauth.refresh_token_ttl_seconds || 0);
  const accessText = accessTtl ? Math.round(accessTtl / 60) + " 分钟" : "等待重启";
  const refreshText = refreshTtl ? Math.round(refreshTtl / 86400) + " 天（每次使用自动轮换）" : "等待重启";
  $("connInfo").innerHTML = `
    <div><b>认证方式</b><span>${oauthReady ? "OAuth 2.1 · Authorization Code + PKCE S256" : "当前进程仍是旧版本，请重启网关"}</span></div>
    <div><b>本地 MCP</b><span class="mono">${esc(server.local_url || "")}</span></div>
    <div><b>访问令牌</b><span>${esc(accessText)}</span></div>
    <div><b>刷新令牌</b><span>${esc(refreshText)}</span></div>
    <div><b>动态注册</b><span>${oauth.dynamic_client_registration ? "已启用" : "等待重启"}</span></div>
    <div><b>控制台</b><span class="mono">http://127.0.0.1:${esc(server.console_port)}/（仅本机可访问）</span></div>
    <div><b>网关版本</b><span>${esc(server.version)} · ${esc(server.tool_count)} 个工具</span></div>`;
}

async function copyText(text, label) {
  if (!text) { toast("没有可复制的内容", "err"); return; }
  try {
    await navigator.clipboard.writeText(text);
    toast(label + "已复制到剪贴板", "ok");
    return;
  } catch (err) {
    // 本地 HTTP 页面可能无法使用 Clipboard API，退回兼容方式。
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
  document.body.removeChild(area);
  toast(ok ? label + "已复制到剪贴板" : "复制失败，请手动选中复制", ok ? "ok" : "err");
}

$("connCard").addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  if (button.dataset.copy === "url") copyText((state.server || {}).public_url, "MCP 地址");
});

function renderTools(list) {
  $("toolCount").textContent = `（${list.length} 个）`;
  $("toolList").innerHTML = list
    .map((item) => `<div class="tool-item"><b>${esc(item.title)}</b> <span class="muted mono">${esc(item.name)}</span><p>${esc(item.description)}</p></div>`)
    .join("");
}

// ---------------- 操作记录 / 回收站 ----------------
const AUDIT_TEXT = {
  read: "读取", list: "列目录", write: "写入", mkdir: "建目录", move: "移动", copy: "复制",
  delete: "删除", exec: "执行命令", denied: "被拒绝", search_files: "搜文件名", search_content: "搜内容",
  approval_requested: "发起审批", approval_approved: "审批通过", approval_denied: "审批拒绝",
  approval_pending: "等待确认", approval_expired: "审批过期", approval_reused: "复用批准",
  approval_already_used: "凭证已用过", approval_recently_denied: "刚拒绝过已拦下",
  popup_approve: "弹窗批准", popup_deny: "弹窗拒绝", popup_timeout: "弹窗超时未点",
  popup_unavailable: "弹窗不可用",
  confirm_approved: "对话中同意", confirm_denied: "对话中拒绝", confirm_rejected_by_mode: "对话确认被策略禁止",
  pick_selected: "本机选择路径", pick_cancelled: "取消选择",
  root_added: "新增授权", root_updated: "修改授权", root_removed: "移除授权",
  denies_updated: "更新黑名单", settings_updated: "修改设置", global_lock: "全局开关",
  trash_purged: "清理回收站", gateway_started: "网关启动", gateway_stopped: "网关停止",
};

async function loadAudit() {
  try {
    const data = await api("/api/audit?limit=300");
    if (!data.items.length) {
      $("auditList").innerHTML = '<div class="empty">暂无记录。</div>';
      return;
    }
    $("auditList").innerHTML = data.items.map((item) => {
      const skip = new Set(["ts", "epoch", "action"]);
      const detail = Object.keys(item)
        .filter((key) => !skip.has(key))
        .map((key) => `${key}=${typeof item[key] === "object" ? JSON.stringify(item[key]) : item[key]}`)
        .join("  ");
      return `<div class="audit-row">
        <span class="ts mono">${esc(item.ts)}</span>
        <span class="act act-${esc(item.action)}">${esc(AUDIT_TEXT[item.action] || item.action)}</span>
        <span class="det mono">${esc(detail)}</span>
      </div>`;
    }).join("");
  } catch (err) { toast(err.message, "err"); }
}

async function loadTrash() {
  try {
    const data = await api("/api/trash?limit=200");
    if (!data.items.length) {
      $("trashList").innerHTML = '<div class="empty">回收站是空的。</div>';
      return;
    }
    $("trashList").innerHTML = data.items.map((item) => `
      <div class="entry">
        <span class="icon">${item.is_dir ? "▣" : "▢"}</span>
        <span class="name mono">${esc(item.name)}</span>
        <span class="meta">${esc(item.size_text)} · ${esc(item.mtime)} · ${esc(item.holder)}</span>
      </div>`).join("");
  } catch (err) { toast(err.message, "err"); }
}

$("purgeTrashBtn").addEventListener("click", async () => {
  try {
    const data = await api("/api/trash/purge", { method: "POST", body: JSON.stringify({}) });
    toast(`已清理 ${data.removed} 项，释放 ${data.freed_text}`, "ok");
    await loadTrash();
  } catch (err) { toast(err.message, "err"); }
});

$("purgeAllBtn").addEventListener("click", async () => {
  if (!confirm("立即清空回收站全部内容？此操作不可恢复。")) return;
  try {
    const data = await api("/api/trash/purge", { method: "POST", body: JSON.stringify({ retention_days: 0 }) });
    toast(`已清空 ${data.removed} 项，释放 ${data.freed_text}`, "ok");
    await loadTrash();
  } catch (err) { toast(err.message, "err"); }
});

// ---------------- 实时事件 ----------------
function connectEvents() {
  const source = new EventSource("/api/events");
  source.addEventListener("approval_created", (event) => {
    const item = JSON.parse(event.data);
    toast(`收到受控请求：${OP_TEXT[item.operation] || item.operation} ${item.path}`, "err");
    loadApprovals();
    loadState();
  });
  source.addEventListener("approval_updated", () => { loadApprovals(); loadState(); });
  source.onerror = () => { setTimeout(connectEvents, 5000); source.close(); };
}

(async function boot() {
  // 先按 hash 切好标签，再拉数据：否则要等三个请求串行返回，页面会先闪一下【访问路径】
  const wanted = location.hash.slice(1);
  try {
    await loadState();
    if (wanted) activateTab(wanted);
    await loadDrives();
    await loadApprovals();
    connectEvents();
  } catch (err) {
    toast("控制台连接失败：" + err.message + "（请确认网关已启动）", "err");
  }
})();
