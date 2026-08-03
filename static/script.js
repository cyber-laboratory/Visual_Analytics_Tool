
let host_AInput, host_BInput, uploadBtn, clearBtn;
let loadingOverlay;
let refreshWarpBtn;
let packetDensityChart;

function init() {
  uploadBtn.addEventListener("click", handleUpload);
  host_AInput.addEventListener("change", () => _updateFileInfoLabel(host_AInput, document.getElementById("host_AFileInfo")));
  host_BInput.addEventListener("change", () => _updateFileInfoLabel(host_BInput, document.getElementById("host_BFileInfo")));
  clearBtn.addEventListener("click",     clearAll);
  if (refreshWarpBtn) {
    refreshWarpBtn.addEventListener("click", () => {
      if (typeof window.loadDtwWarping === "function") window.loadDtwWarping(0, getDtwParams(), true);
    });
  }

  initIpCombos();

  const addCondBtn = document.getElementById("addConditionBtn");
  if (addCondBtn) {
    addCondBtn.addEventListener("click", () => {
      const container = document.getElementById("dtwConditions");
      if (!container) return;
      addConditionRow(container);
    });
  }
}

function _formatBytes(n) {
  if (n == null) return "";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let u = -1;
  do { n /= 1024; u++; } while (n >= 1024 && u < units.length - 1);
  return `${n.toFixed(1)} ${units[u]}`;
}

function _updateFileInfoLabel(inputEl, labelEl) {
  if (!inputEl || !labelEl) return;
  const f = inputEl.files && inputEl.files[0];
  labelEl.innerHTML = "";
  if (!f) {
    const empty = document.createElement("span");
    empty.className = "file-name-empty";
    empty.textContent = "No file selected";
    labelEl.appendChild(empty);
    return;
  }
  const name = document.createElement("span");
  name.className = "file-name-text";
  name.textContent = f.name;
  const size = document.createElement("span");
  size.className = "file-name-size";
  size.textContent = `(${_formatBytes(f.size)})`;
  labelEl.appendChild(name);
  labelEl.appendChild(size);
}

function _setLoadingProgress(percent, text) {
  const wrap = document.getElementById("loadingProgressWrap");
  const bar = document.getElementById("loadingProgressBar");
  const label = document.getElementById("loadingText");
  if (wrap) wrap.style.display = percent === null ? "none" : "block";
  if (bar && percent !== null) bar.style.width = `${percent}%`;
  if (label && text) label.textContent = text;
}

const _UPLOAD_PROCESSING_STAGES = [
  "Parsing packets…",
  "Analyzing traffic patterns…",
  "Classifying flows…",
  "Indexing conversations…",
  "Still working - large captures take longer…",
];

function _uploadWithProgress(url, formData) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    let stageTimer = null;
    let processingStarted = false;
    const stopStages = () => {
      if (stageTimer) { clearInterval(stageTimer); stageTimer = null; }
    };
    const startProcessingStages = () => {
      if (processingStarted) return;
      processingStarted = true;
      _setLoadingProgress(null, _UPLOAD_PROCESSING_STAGES[0]);
      let stage = 1;
      stageTimer = setInterval(() => {
        const i = Math.min(stage, _UPLOAD_PROCESSING_STAGES.length - 1);
        _setLoadingProgress(null, _UPLOAD_PROCESSING_STAGES[i]);
        stage++;
      }, 4000);
    };
    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      const pct = Math.min(100, Math.round((e.loaded / e.total) * 100));
      _setLoadingProgress(pct, `Uploading… ${pct}% (${_formatBytes(e.loaded)} / ${_formatBytes(e.total)})`);
      if (pct >= 100) startProcessingStages();
    };
    xhr.upload.onload = startProcessingStages;
    xhr.onload = () => {
      stopStages();
      if (xhr.status >= 200 && xhr.status < 300) {
        try { resolve(JSON.parse(xhr.responseText)); }
        catch (e) { reject(new Error("Server returned an invalid response")); }
      } else {
        let msg = xhr.statusText || `HTTP ${xhr.status}`;
        try { msg = JSON.parse(xhr.responseText).error || msg; } catch (e) {}
        reject(new Error(msg));
      }
    };
    xhr.onerror = () => { stopStages(); reject(new Error("Network error during upload")); };
    xhr.send(formData);
  });
}

async function handleUpload() {
  const v = host_AInput.files[0], a = host_BInput.files[0];
  if (!v && !a) return alert("Select at least one PCAP, PCAPNG, or CSV file!");

  loadingOverlay.style.display = "flex";
  _setLoadingProgress(0, "Preparing upload…");
  resetState();
  try {
    const fd = new FormData();
    if (v) fd.append("host_A", v);
    if (a) fd.append("host_B", a);
    const uploadData = await _uploadWithProgress("/upload", fd);
    _setLoadingProgress(null, "Rendering…");

    if (uploadData.unique_ips) {
      populateIpDropdowns(uploadData.unique_ips);
    }

    _applyDtwColumnAvailability(uploadData.dtw_columns_available);

    if (typeof loadForecastFiles === "function") loadForecastFiles();

    await updateDensityChart();
    if (typeof window.clearDtwWarpingCache === "function") window.clearDtwWarpingCache();
    refreshDtwVisualization();
  } catch (e) {
    console.error("Upload failed", e);
    alert(`Upload failed: ${e.message}`);
  } finally {
    loadingOverlay.style.display = "none";
    _setLoadingProgress(null, "");
  }
}

function resetState() {
  const dtwWarpDetails = document.getElementById("dtwWarpDetails");
  if (dtwWarpDetails) {
    dtwWarpDetails.textContent = "Click a marker to view aligned host_A/host_B packet details.";
  }
}

async function clearAll() {
  localStorage.clear();
  await fetch("/clear", { method: "POST" }).catch(() => {});
  resetState();

  host_AInput.value = "";
  host_BInput.value = "";
  _updateFileInfoLabel(host_AInput, document.getElementById("host_AFileInfo"));
  _updateFileInfoLabel(host_BInput, document.getElementById("host_BFileInfo"));
  _applyDtwColumnAvailability(null);

  if (typeof loadForecastFiles === "function") loadForecastFiles();

  await updateDensityChart();
  if (typeof window.clearDtwWarpingCache === "function") window.clearDtwWarpingCache();
  refreshDtwVisualization();
}

async function resetView() {
  try {
    updateDensityChart();
    refreshDtwVisualization();
  } catch (e) {
    console.error("Reset failed", e);
  }
}

async function fetchDensity(role, interval=1) {
  const res  = await fetch(`/packets/${role}/density?interval=${interval}`);
  const data = await res.json();
  return (data.points || []).map(p => [p.t, p.count]);
}

function _densityFmtCount(n) {
  return `${n} packet${n === 1 ? "" : "s"}`;
}

async function updateDensityChart() {
  const [vData, aData] = await Promise.all([
    fetchDensity("host_A"),
    fetchDensity("host_B"),
  ]);
  const labels = Array.from(new Set([
    ...vData.map(d=>d[0]), ...aData.map(d=>d[0])
  ])).sort((a,b)=>a-b);
  const vMap = new Map(vData), aMap = new Map(aData);
  const host_ASeries   = labels.map(t=>vMap.get(t)||0);
  const host_BSeries = labels.map(t=>aMap.get(t)||0);
  const xMs = labels.map(t => t * 1000);

  const traces = [
    {
      x: xMs, y: host_ASeries, customdata: host_ASeries.map(_densityFmtCount),
      name: "Host_A", mode: "lines+markers", fill: "tozeroy",
      line: { color: "#4C6EF5", shape: "linear" },
      marker: { size: 4 },
      hovertemplate: "Host_A: %{customdata}<extra></extra>",
    },
    {
      x: xMs, y: host_BSeries, customdata: host_BSeries.map(_densityFmtCount),
      name: "Host_B", mode: "lines+markers", fill: "tozeroy",
      line: { color: "#F03E3E", shape: "linear" },
      marker: { size: 4 },
      hovertemplate: "Host_B: %{customdata}<extra></extra>",
    },
  ];

  const layout = {
    margin: { t: 10, r: 20, b: 40, l: 55 },
    xaxis: { type: "date" },
    yaxis: { title: "Packets", rangemode: "tozero", fixedrange: true },
    hovermode: "x unified",
    showlegend: true,
    legend: { orientation: "h", y: 1.15 },
  };

  const isFirstRender = !packetDensityChart;
  packetDensityChart = document.getElementById("packetDensityChart");
  await Plotly.react(packetDensityChart, traces, layout, { responsive: true, displaylogo: false });

  if (isFirstRender) {
    packetDensityChart.on("plotly_relayout", (ev) => {
      if (ev["xaxis.autorange"]) resetView();
    });
  }
}

async function onLoad() {
  host_AInput           = document.getElementById("host_AInput");
  host_BInput           = document.getElementById("host_BInput");
  uploadBtn              = document.getElementById("uploadBtn");
  clearBtn               = document.getElementById("clearBtn");
  loadingOverlay         = document.getElementById("loadingOverlay");
  refreshWarpBtn         = document.getElementById("refreshWarpBtn");

  localStorage.clear();
  await fetch("/clear", { method: "POST" }).catch(() => {});

  init();
  updateDensityChart();
}

function _applyDtwColumnAvailability(avail) {
  let selectionChanged = false;
  const cols = [...document.querySelectorAll(".dtwCol")];
  cols.forEach(cb => {
    const isAvailable = !avail || avail[cb.value] !== false;
    cb.disabled = !isAvailable;
    cb.closest(".col-pill")?.classList.toggle("col-pill--unavailable", !isAvailable);
    cb.closest(".col-pill")?.setAttribute(
      "title",
      isAvailable ? "" : "Not present in the uploaded capture(s) for both host_A and host_B."
    );
    if (!isAvailable && cb.checked) {
      cb.checked = false;
      selectionChanged = true;
    }
  });
  if (selectionChanged && !cols.some(cb => cb.checked)) {
    const fallback = cols.find(cb => !cb.disabled);
    if (fallback) fallback.checked = true;
  }
  if (selectionChanged) debouncedRefreshDtwVisualization();
}

function getDtwParams() {
  const algo = document.getElementById("algorithmSelect")?.value || "dtw";
  const params = { algo: algo };

  const host_AEl = document.getElementById("dtwHost_AIp");
  const host_BEl = document.getElementById("dtwHost_BIp");
  const host_AIp = host_AEl?.dataset.comboValue ?? host_AEl?.value;
  const host_BIp = host_BEl?.dataset.comboValue ?? host_BEl?.value;
  if (host_AIp) params.host_A_ip = host_AIp;
  if (host_BIp) params.host_B_ip = host_BIp;

  if (document.getElementById("dtwHost_ASrc")?.checked) params.host_A_src = "1";
  if (document.getElementById("dtwHost_ADst")?.checked) params.host_A_dst = "1";
  if (document.getElementById("dtwHost_BSrc")?.checked) params.host_B_src = "1";
  if (document.getElementById("dtwHost_BDst")?.checked) params.host_B_dst = "1";

  const checkedCols = [...document.querySelectorAll(".dtwCol:checked")].map(cb => cb.value);
  if (checkedCols.length) params.columns = checkedCols.join(",");

  if (document.getElementById("dtwNonzeroColumn")?.checked) {
    params.nonzero_column_only = "1";
  }

  params.filter_logic = document.querySelector('input[name="dtwLogic"]:checked')?.value || "AND";

  const condRows = document.querySelectorAll(".condition-row");
  const conditions = [];
  condRows.forEach(row => {
    const fieldEl = row.querySelector(".cond-field");
    const opEl    = row.querySelector(".cond-op");
    const field = fieldEl?.dataset.comboValue || fieldEl?.value;
    const op    = opEl?.dataset.comboValue    || opEl?.value;
    const value = row.querySelector(".cond-value")?.value.trim();
    if (field && value) conditions.push({ field, op, value });
  });
  if (conditions.length) params.conditions = JSON.stringify(conditions);

  const windowSize = document.getElementById("windowSize")?.value;
  const windowStride = document.getElementById("windowStride")?.value;
  if (windowSize && windowSize !== "") params.window_size = windowSize;
  if (windowStride && windowStride !== "") params.stride = windowStride;

  return params;
}

function _escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

const _measureCanvas = document.createElement('canvas');
function _measureText(text, font) {
  const ctx = _measureCanvas.getContext('2d');
  ctx.font = font;
  return ctx.measureText(text).width;
}

function attachCombo(inputEl) {
  inputEl.classList.add('combo-input');

  const dropdown = document.createElement('div');
  dropdown.className = 'combo-dropdown';
  document.body.appendChild(dropdown);

  let options = [];
  let isOpen = false;

  function positionDropdown() {
    const rect = inputEl.getBoundingClientRect();
    dropdown.style.top  = (rect.bottom + window.scrollY + 1) + 'px';
    dropdown.style.left = (rect.left   + window.scrollX)     + 'px';
    dropdown.style.width = Math.max(rect.width, 150) + 'px';
  }

  const MAX_ITEMS = 200;

  function normalise(opts) {
    return (opts || []).map(o => typeof o === 'string' ? { label: o, value: o } : o);
  }

  function showDropdown() {
    const filter = inputEl.readOnly ? '' : inputEl.value.toLowerCase();
    const filtered = filter
      ? options.filter(o => o.label.toLowerCase().includes(filter))
      : options;
    if (!filtered.length) { hideDropdown(); return; }
    const shown = filtered.slice(0, MAX_ITEMS);
    const extra = filtered.length - MAX_ITEMS;
    dropdown.innerHTML = shown
      .map(o => `<div class="combo-option" data-value="${_escHtml(o.value)}">${_escHtml(o.label)}</div>`)
      .join('') +
      (extra > 0 ? `<div class="combo-more">${extra} more - keep typing to filter</div>` : '');
    positionDropdown();
    dropdown.style.display = 'block';
    isOpen = true;
  }

  function hideDropdown() {
    dropdown.style.display = 'none';
    isOpen = false;
  }

  inputEl.addEventListener('click', showDropdown);
  inputEl.addEventListener('input', showDropdown);
  inputEl.addEventListener('blur', () => setTimeout(hideDropdown, 150));

  dropdown.addEventListener('mousedown', (e) => {
    const opt = e.target.closest('.combo-option');
    if (!opt) return;
    e.preventDefault();
    inputEl.value = opt.textContent;
    inputEl.dataset.comboValue = opt.dataset.value;
    hideDropdown();
    inputEl.dispatchEvent(new Event('change', { bubbles: true }));
  });

  return {
    setOptions(opts) {
      options = normalise(opts);
      if (isOpen) showDropdown();
      if (inputEl.readOnly && options.length) {
        const font = getComputedStyle(inputEl).font;
        const maxW = Math.max(...options.map(o => _measureText(o.label, font)));
        inputEl.style.width = Math.ceil(maxW + 22) + 'px';
      }
    },
    setValue(val) {
      const opt = options.find(o => o.value === val);
      if (opt) {
        inputEl.value = opt.label;
        inputEl.dataset.comboValue = opt.value;
      }
    }
  };
}

async function getUniqueFieldValues(field) {
  const res  = await fetch(`/packets/field-values?field=${encodeURIComponent(field)}`);
  const data = await res.json();
  return data.values || [];
}

const _ipCombos = {};

function initIpCombos() {
  ["dtwHost_AIp", "dtwHost_BIp"].forEach(id => {
    const el = document.getElementById(id);
    if (el && !_ipCombos[id]) _ipCombos[id] = attachCombo(el);
  });
}

function populateIpDropdowns(ips) {
  const opts = [{ label: 'Any', value: '' }, ...ips];
  Object.values(_ipCombos).forEach(c => c.setOptions(opts));
}

const _COND_FIELDS = [
  { label: 'Src IP',      value: 'src_ip' },
  { label: 'Dst IP',      value: 'dst_ip' },
  { label: 'Protocol',    value: 'protocol' },
  { label: 'Src Port',    value: 'src_port' },
  { label: 'Dst Port',    value: 'dst_port' },
  { label: 'Flags',       value: 'flags' },
  { label: 'HTTP Method', value: 'http_method' },
  { label: 'HTTP URI',    value: 'http_uri' },
];

function addConditionRow(container) {
  const row = document.createElement("div");
  row.className = "condition-row";
  row.innerHTML = `
    <input type="text" class="cond-field" readonly placeholder="Field…">
    <input type="text" class="cond-op"    readonly placeholder="Op…">
    <input type="text" class="cond-value" placeholder="value" autocomplete="off">
    <button type="button" class="remove-cond">✕</button>
  `;

  const fieldInput = row.querySelector(".cond-field");
  const opInput    = row.querySelector(".cond-op");
  const valueInput = row.querySelector(".cond-value");

  const fieldCombo = attachCombo(fieldInput);
  fieldCombo.setOptions(_COND_FIELDS);
  fieldInput.value = _COND_FIELDS[0].label;
  fieldInput.dataset.comboValue = _COND_FIELDS[0].value;

  const opCombo = attachCombo(opInput);
  opCombo.setOptions(['=', 'contains', '!=']);
  opInput.value = '=';
  opInput.dataset.comboValue = '=';

  const valueCombo = attachCombo(valueInput);
  getUniqueFieldValues(fieldInput.dataset.comboValue).then(v => valueCombo.setOptions(v));

  fieldInput.addEventListener("change", () => {
    getUniqueFieldValues(fieldInput.dataset.comboValue).then(v => valueCombo.setOptions(v));
  });

  row.querySelector(".remove-cond").addEventListener("click", () => row.remove());
  container.appendChild(row);
}

function refreshDtwVisualization() {
  const params = getDtwParams();
  if (typeof window.loadDtwWarping === "function") {
    window.loadDtwWarping(0, params);
  }
}

window.addEventListener("DOMContentLoaded", onLoad);

function debounce(fn, ms = 300) {
  let timer;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), ms);
  };
}
const debouncedRefreshDtwVisualization = debounce(refreshDtwVisualization, 400);

document.addEventListener("DOMContentLoaded", function() {
    const algorithmSelect = document.getElementById('algorithmSelect');
    if (algorithmSelect) {
        algorithmSelect.value = 'dtw';
        selectedAlgorithm = 'dtw';
        applyAlgorithmMode('dtw');
        algorithmSelect.addEventListener('change', function() {
            selectedAlgorithm = this.value;
            applyAlgorithmMode(selectedAlgorithm);
        });
    }

    const dtwParamsPanelEl = document.querySelector('.dtw-params-panel');
    if (dtwParamsPanelEl) {
        dtwParamsPanelEl.addEventListener('change', debouncedRefreshDtwVisualization);
        dtwParamsPanelEl.addEventListener('input', debouncedRefreshDtwVisualization);
        dtwParamsPanelEl.addEventListener('click', (e) => {
            if (e.target.closest('.remove-cond')) debouncedRefreshDtwVisualization();
        });
    }

    const runForecastBtn = document.getElementById('runForecastBtn');
    if (runForecastBtn) {
        runForecastBtn.addEventListener('click', runForecast);
    }

    const refreshFilesBtn = document.getElementById('refreshFilesBtn');
    if (refreshFilesBtn) {
        refreshFilesBtn.addEventListener('click', loadForecastFiles);
    }

    const forecastFileSelect = document.getElementById('forecastFileSelect');
    if (forecastFileSelect) {
        forecastFileSelect.addEventListener('change', () => loadForecastIps(forecastFileSelect.value));
    }

    const forecastConvertHost_A = document.getElementById('forecastConvertHost_A');
    const forecastConvertHost_B = document.getElementById('forecastConvertHost_B');
    if (forecastConvertHost_A) forecastConvertHost_A.addEventListener('click', () => _convertUploadForForecast('host_A'));
    if (forecastConvertHost_B) forecastConvertHost_B.addEventListener('click', () => _convertUploadForForecast('host_B'));

    const forecastIpSearch = document.getElementById('forecastIpSearch');
    if (forecastIpSearch) {
        forecastIpSearch.addEventListener('input', () => {
            _forecastIpSearch = forecastIpSearch.value;
            _renderForecastIpList();
        });
    }

    const forecastIpList = document.getElementById('forecastIpList');
    if (forecastIpList) {
        forecastIpList.addEventListener('change', (e) => {
            const cb = e.target.closest('.forecast-ip-checkbox');
            if (!cb) return;
            if (cb.checked) _forecastSelectedIps.add(cb.value);
            else _forecastSelectedIps.delete(cb.value);
            const summary = document.getElementById('forecastIpSummary');
            if (summary) {
                summary.textContent = _forecastSelectedIps.size
                    ? `${_forecastSelectedIps.size.toLocaleString()} of ${_forecastAllIps.length.toLocaleString()} selected`
                    : `All hosts (${_forecastAllIps.length.toLocaleString()})`;
            }
        });
    }

    const forecastIpSelectAll = document.getElementById('forecastIpSelectAll');
    if (forecastIpSelectAll) {
        forecastIpSelectAll.addEventListener('click', () => {
            _forecastAllIps.forEach(ip => _forecastSelectedIps.add(ip));
            _renderForecastIpList();
        });
    }

    const forecastIpSelectNone = document.getElementById('forecastIpSelectNone');
    if (forecastIpSelectNone) {
        forecastIpSelectNone.addEventListener('click', () => {
            _forecastSelectedIps.clear();
            _renderForecastIpList();
        });
    }

});
let selectedAlgorithm = 'dtw';

const _ML_ALGOS = new Set(['lstm', 'gru']);

function applyAlgorithmMode(algo) {
  const isML = _ML_ALGOS.has(algo);
  const forecastSection   = document.getElementById('forecastSection');
  const dtwParamsPanel    = document.querySelector('.dtw-params-panel');
  const dtwWarpingSection = document.querySelector('.dtw-warping-container');

  if (forecastSection)   forecastSection.style.display   = isML ? '' : 'none';
  if (dtwParamsPanel)    dtwParamsPanel.style.display    = isML ? 'none' : '';
  if (dtwWarpingSection) dtwWarpingSection.style.display = isML ? 'none' : '';

  if (isML) loadForecastFiles();
  else      refreshDtwVisualization();
}

async function loadForecastFiles() {
  const select = document.getElementById('forecastFileSelect');
  const statusEl = document.getElementById('forecastStatus');
  if (!select) return;
  try {
    const res  = await fetch('/forecast/files');
    const data = await res.json();
    const prev = select.value;
    select.innerHTML = '<option value="">- select a file -</option>';
    (data.files || []).forEach(f => {
      const opt = document.createElement('option');
      opt.value = f.name;
      opt.textContent = `${f.name} (${_formatBytes(f.size)})`;
      select.appendChild(opt);
    });
    if (prev && [...select.options].some(o => o.value === prev)) {
      select.value = prev;
      loadForecastIps(prev);
    }
    if (!data.models_ready) {
      statusEl.textContent = 'Warning: models not loaded on server - check data/ directory.';
    } else {
      statusEl.textContent = data.files.length
        ? `${data.files.length} file(s) available.`
        : 'No CSV files found in data/.';
    }
    _updateForecastConvertButtons(data.pcap_convert_ready, data.convertible_uploads || {});
  } catch (e) {
    statusEl.textContent = `Could not load file list: ${e.message}`;
  }
}

function _updateForecastConvertButtons(convertReady, convertibleUploads) {
  const cfg = [
    { role: 'host_A', btnId: 'forecastConvertHost_A' },
    { role: 'host_B', btnId: 'forecastConvertHost_B' },
  ];
  cfg.forEach(({ role, btnId }) => {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    const info = convertibleUploads[role] || { available: false };
    if (!convertReady) {
      btn.disabled = true;
      btn.title = 'PCAP-to-forecast conversion is unavailable on the server (cicflowmeter not installed).';
      btn.textContent = `Use ${role[0].toUpperCase()}${role.slice(1)} PCAP`;
    } else if (info.available) {
      btn.disabled = false;
      btn.textContent = `Use ${role[0].toUpperCase()}${role.slice(1)} PCAP`;
      btn.title = `Extract flow features from ${info.name} and add it to the forecast file list.`;
    } else {
      btn.disabled = true;
      btn.textContent = `Use ${role[0].toUpperCase()}${role.slice(1)} PCAP`;
      btn.title = info.name
        ? `${info.name} is a CSV, not a PCAP - flow-feature extraction needs the original packet capture.`
        : `Upload a ${role} PCAP above first.`;
    }
  });
}

function _setConvertProgress(percent) {
  const wrap = document.getElementById('forecastConvertProgressWrap');
  const bar = document.getElementById('forecastConvertProgressBar');
  if (wrap) wrap.style.display = percent === null ? 'none' : 'block';
  if (bar && percent !== null) bar.style.width = `${percent}%`;
}

const FORECAST_CONVERT_POLL_MS = 700;

async function _convertUploadForForecast(role) {
  const statusEl = document.getElementById('forecastConvertStatus');
  const btn = document.getElementById(role === 'host_A' ? 'forecastConvertHost_A' : 'forecastConvertHost_B');
  if (btn) btn.disabled = true;
  if (statusEl) statusEl.textContent = `Starting conversion of the ${role} PCAP…`;
  _setConvertProgress(0);

  try {
    const startRes = await fetch('/forecast/convert-upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role }),
    });
    const startData = await startRes.json();
    if (!startRes.ok) {
      if (statusEl) statusEl.textContent = `Conversion failed: ${startData.error || startRes.statusText}`;
      return;
    }

    const jobId = startData.job_id;
    while (true) {
      await new Promise(r => setTimeout(r, FORECAST_CONVERT_POLL_MS));
      const sRes = await fetch(`/forecast/convert-status?job_id=${jobId}`);
      const s = await sRes.json();
      if (!sRes.ok) {
        if (statusEl) statusEl.textContent = `Conversion failed: ${s.error || sRes.statusText}`;
        break;
      }

      if (s.status === 'counting') {
        if (statusEl) statusEl.textContent = 'Counting packets in the capture…';
      } else if (s.status === 'converting') {
        const pct = s.percent;
        _setConvertProgress(pct);
        const pctLabel = pct != null ? `${pct}%` : '…';
        const countLabel = s.total ? `${s.processed.toLocaleString()} / ${s.total.toLocaleString()} packets` : '';
        if (statusEl) statusEl.textContent = `Extracting flow features… ${pctLabel} (${countLabel})`;
      } else if (s.status === 'done') {
        _setConvertProgress(100);
        if (statusEl) statusEl.textContent = `Done - ${s.result.filename} (${s.result.rows.toLocaleString()} flow windows). Selected below.`;
        await loadForecastFiles();
        const select = document.getElementById('forecastFileSelect');
        if (select) {
          select.value = s.result.filename;
          await loadForecastIps(s.result.filename);
        }
        break;
      } else if (s.status === 'error') {
        if (statusEl) statusEl.textContent = `Conversion failed: ${s.error}`;
        break;
      }
    }
  } catch (e) {
    if (statusEl) statusEl.textContent = `Conversion failed: ${e.message}`;
  } finally {
    _setConvertProgress(null);
    await loadForecastFiles();
  }
}

const FORECAST_IP_ROW_HEIGHT = 24;
const FORECAST_IP_OVERSCAN = 8;
let _forecastAllIps = [];
let _forecastIpFiltered = [];
let _forecastSelectedIps = new Set();
let _forecastIpSearch = '';
let _forecastIpLastClickedIdx = null;
let _forecastIpScrollBound = false;

function _forecastIpControlsEnabled(enabled) {
  ['forecastIpSearch', 'forecastIpSelectAll', 'forecastIpSelectNone'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.disabled = !enabled;
  });
}

function _forecastIpSummaryText() {
  return _forecastSelectedIps.size
    ? `${_forecastSelectedIps.size.toLocaleString()} of ${_forecastAllIps.length.toLocaleString()} selected`
    : `All hosts (${_forecastAllIps.length.toLocaleString()})`;
}

function _forecastIpRenderVisibleRows() {
  const list = document.getElementById('forecastIpList');
  if (!list) return;
  const filtered = _forecastIpFiltered;
  const scrollTop = list.scrollTop;
  const viewportH = list.clientHeight || 260;
  const startIdx = Math.max(0, Math.floor(scrollTop / FORECAST_IP_ROW_HEIGHT) - FORECAST_IP_OVERSCAN);
  const endIdx = Math.min(filtered.length, Math.ceil((scrollTop + viewportH) / FORECAST_IP_ROW_HEIGHT) + FORECAST_IP_OVERSCAN);

  list.querySelectorAll('.forecast-ip-row').forEach(el => el.remove());

  const frag = document.createDocumentFragment();
  for (let i = startIdx; i < endIdx; i++) {
    const ip = filtered[i];
    const row = document.createElement('label');
    row.className = 'forecast-ip-row';
    row.style.top = `${i * FORECAST_IP_ROW_HEIGHT}px`;
    row.dataset.idx = String(i);
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'forecast-ip-checkbox';
    cb.value = ip;
    cb.checked = _forecastSelectedIps.has(ip);
    const span = document.createElement('span');
    span.textContent = ip;
    row.appendChild(cb);
    row.appendChild(span);
    frag.appendChild(row);
  }
  list.appendChild(frag);
}

function _renderForecastIpList() {
  const list = document.getElementById('forecastIpList');
  const summary = document.getElementById('forecastIpSummary');
  if (!list) return;

  const term = _forecastIpSearch.trim().toLowerCase();
  _forecastIpFiltered = term
    ? _forecastAllIps.filter(ip => ip.toLowerCase().includes(term))
    : _forecastAllIps;

  list.querySelectorAll('.forecast-ip-row, .forecast-ip-empty').forEach(el => el.remove());

  let spacer = document.getElementById('forecastIpSpacer');
  if (!spacer) {
    spacer = document.createElement('div');
    spacer.id = 'forecastIpSpacer';
    spacer.className = 'forecast-ip-spacer';
    list.appendChild(spacer);
  }

  if (!_forecastIpFiltered.length) {
    spacer.style.height = '0px';
    const empty = document.createElement('div');
    empty.className = 'forecast-ip-empty';
    empty.textContent = _forecastAllIps.length ? 'No hosts match.' : 'No hosts found in this file.';
    list.appendChild(empty);
  } else {
    spacer.style.height = `${_forecastIpFiltered.length * FORECAST_IP_ROW_HEIGHT}px`;
    _forecastIpRenderVisibleRows();
  }

  if (summary) summary.textContent = _forecastIpSummaryText();

  if (!_forecastIpScrollBound) {
    let scheduled = false;
    list.addEventListener('scroll', () => {
      if (scheduled) return;
      scheduled = true;
      requestAnimationFrame(() => { scheduled = false; _forecastIpRenderVisibleRows(); });
    });
    list.addEventListener('click', (e) => {
      const cb = e.target.closest('.forecast-ip-checkbox');
      if (!cb) return;
      const row = cb.closest('.forecast-ip-row');
      const idx = Number(row.dataset.idx);
      const checkedNow = cb.checked;

      if (e.shiftKey && _forecastIpLastClickedIdx !== null) {
        const lo = Math.min(_forecastIpLastClickedIdx, idx);
        const hi = Math.max(_forecastIpLastClickedIdx, idx);
        for (let i = lo; i <= hi; i++) {
          const ip = _forecastIpFiltered[i];
          if (checkedNow) _forecastSelectedIps.add(ip);
          else _forecastSelectedIps.delete(ip);
        }
      } else if (checkedNow) {
        _forecastSelectedIps.add(cb.value);
      } else {
        _forecastSelectedIps.delete(cb.value);
      }
      _forecastIpLastClickedIdx = idx;
      _forecastIpRenderVisibleRows();
      const summaryEl = document.getElementById('forecastIpSummary');
      if (summaryEl) summaryEl.textContent = _forecastIpSummaryText();
    });
    _forecastIpScrollBound = true;
  }
}

async function loadForecastIps(filename) {
  const list = document.getElementById('forecastIpList');
  const summary = document.getElementById('forecastIpSummary');
  const searchInput = document.getElementById('forecastIpSearch');
  if (!list) return;

  _forecastAllIps = [];
  _forecastIpFiltered = [];
  _forecastSelectedIps = new Set();
  _forecastIpSearch = '';
  _forecastIpLastClickedIdx = null;
  if (searchInput) searchInput.value = '';
  if (summary) summary.textContent = '';
  _forecastIpControlsEnabled(false);

  if (!filename) {
    list.innerHTML = '<div class="forecast-ip-placeholder">Select a file to list its hosts.</div>';
    return;
  }

  list.innerHTML = '<div class="forecast-ip-placeholder"><span class="mini-spinner"></span> Reading hosts from file… large files can take a while.</div>';
  try {
    const res  = await fetch(`/forecast/ips?filename=${encodeURIComponent(filename)}`);
    const data = await res.json();
    if (!res.ok) {
      list.innerHTML = `<div class="forecast-ip-empty">${_escHtml(data.error || 'Could not load hosts.')}</div>`;
      return;
    }
    _forecastAllIps = data.ips || [];
    list.innerHTML = '';
    _forecastIpControlsEnabled(true);
    _renderForecastIpList();
  } catch (e) {
    list.innerHTML = `<div class="forecast-ip-empty">Could not load host list: ${_escHtml(e.message)}</div>`;
  }
}

function _setForecastBusy(busy, message) {
  const overlay = document.getElementById('forecastLoading');
  const overlayText = document.getElementById('forecastLoadingText');
  if (overlay) overlay.style.display = busy ? 'flex' : 'none';
  if (overlayText && message) overlayText.textContent = message;
  const runBtn = document.getElementById('runForecastBtn');
  if (runBtn) runBtn.disabled = busy;
}

async function runForecast() {
  const select   = document.getElementById('forecastFileSelect');
  const filename = select?.value;
  if (!filename) { alert('Select a CSV file from the dropdown first.'); return; }

  const algo     = document.getElementById('algorithmSelect')?.value || 'lstm';
  const statusEl = document.getElementById('forecastStatus');
  statusEl.textContent = 'Reading CSV & computing… large files can take a while before the first points appear.';

  const srcIps = [..._forecastSelectedIps];

  _setForecastBusy(true, 'Reading CSV & computing…');
  try {
    const res = await fetch('/forecast', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename, model_name: algo, src_ips: srcIps }),
    });

    if (!res.ok || !res.body) {
      const data = await res.json().catch(() => ({}));
      statusEl.textContent = `Error: ${data.error || res.statusText}`;
      return;
    }

    _setForecastBusy(true, 'Forecasting…');
    const count = await streamForecastChart(res.body, algo.toUpperCase(), statusEl, srcIps.length > 0, filename);
    statusEl.textContent = `Forecasted ${count.toLocaleString()} windows.`;
  } catch (e) {
    statusEl.textContent = `Request failed: ${e.message}`;
  } finally {
    _setForecastBusy(false);
  }
}

const FORECAST_CHUNK_SIZE = 5000;
const FORECAST_MAX_BUCKETS_PER_HOST = 2000;
const FORECAST_TAIL_EXACT_POINTS = 50;
const FORECAST_DEFAULT_HOST_CAP = 40;
const FORECAST_RENDER_MIN_INTERVAL_MS = 600;
const FORECAST_PALETTE = [
  '#4C6EF5', '#F03E3E', '#37B24D', '#F59F00',
  '#AE3EC9', '#1098AD', '#E64980', '#F76707',
];

let _fc = null;

function _newForecastSession(modelLabel, hasExplicitSelection, filename) {
  return {
    modelLabel,
    hasExplicitSelection: !!hasExplicitSelection,
    filename,
    hosts: new Map(),
    hostOrder: [],
    totalCount: 0,
    futurePoints: [],
  };
}

function _forecastGetHost(sess, ip) {
  let h = sess.hosts.get(ip);
  if (!h) {
    h = {
      chunks: [],
      curX: new Float64Array(FORECAST_CHUNK_SIZE),
      curY: new Float32Array(FORECAST_CHUNK_SIZE),
      curEnd: new Float64Array(FORECAST_CHUNK_SIZE),
      curN: 0,
      total: 0,
    };
    sess.hosts.set(ip, h);
    sess.hostOrder.push(ip);
  }
  return h;
}

function _forecastPushRow(sess, row) {
  sess.totalCount++;

  if (row.kind === 'future') {
    _forecastGetHost(sess, row.src_ip);
    sess.futurePoints.push({
      ip: row.src_ip,
      x: row.window_start_ts * 1000,
      y: row.predicted_malicious_rate,
      end: row.window_end_ts * 1000,
    });
    return;
  }

  const h = _forecastGetHost(sess, row.src_ip);
  h.curX[h.curN] = row.window_start_ts * 1000;
  h.curY[h.curN] = row.predicted_malicious_rate;
  h.curEnd[h.curN] = row.window_end_ts * 1000;
  h.curN++;
  h.total++;
  if (h.curN >= FORECAST_CHUNK_SIZE) {
    h.chunks.push({ x: h.curX, y: h.curY, end: h.curEnd, n: h.curN });
    h.curX = new Float64Array(FORECAST_CHUNK_SIZE);
    h.curY = new Float32Array(FORECAST_CHUNK_SIZE);
    h.curEnd = new Float64Array(FORECAST_CHUNK_SIZE);
    h.curN = 0;
  }
}

function _forecastDecimateHost(h) {
  const total = h.total;
  if (total === 0) return { x: [], y: [], end: [] };
  if (total <= FORECAST_MAX_BUCKETS_PER_HOST * 2) {
    const x = new Array(total);
    const y = new Array(total);
    const end = new Array(total);
    let idx = 0;
    for (const c of h.chunks) {
      for (let i = 0; i < c.n; i++) { x[idx] = c.x[i]; y[idx] = c.y[i]; end[idx] = c.end[i]; idx++; }
    }
    for (let i = 0; i < h.curN; i++) { x[idx] = h.curX[i]; y[idx] = h.curY[i]; end[idx] = h.curEnd[i]; idx++; }
    return { x, y, end };
  }

  const tailCount = Math.min(FORECAST_TAIL_EXACT_POINTS, total);
  const headCount = total - tailCount;
  const bucketSize = headCount / FORECAST_MAX_BUCKETS_PER_HOST;
  const outX = [];
  const outY = [];
  const outEnd = [];
  let globalIdx = 0;
  let bucketStart = 0;
  let minY = Infinity, minX = 0, minEnd = 0;
  let maxY = -Infinity, maxX = 0, maxEnd = 0;

  const consume = (xv, yv, ev) => {
    if (globalIdx >= headCount) {
      outX.push(xv); outY.push(yv); outEnd.push(ev);
      globalIdx++;
      return;
    }
    if (yv < minY) { minY = yv; minX = xv; minEnd = ev; }
    if (yv > maxY) { maxY = yv; maxX = xv; maxEnd = ev; }
    globalIdx++;
    if (globalIdx - bucketStart >= bucketSize || globalIdx === headCount) {
      if (minX <= maxX) { outX.push(minX, maxX); outY.push(minY, maxY); outEnd.push(minEnd, maxEnd); }
      else { outX.push(maxX, minX); outY.push(maxY, minY); outEnd.push(maxEnd, minEnd); }
      bucketStart = globalIdx;
      minY = Infinity; maxY = -Infinity;
    }
  };

  for (const c of h.chunks) for (let i = 0; i < c.n; i++) consume(c.x[i], c.y[i], c.end[i]);
  for (let i = 0; i < h.curN; i++) consume(h.curX[i], h.curY[i], h.curEnd[i]);

  return { x: outX, y: outY, end: outEnd };
}

function _forecastLayout(modelLabel) {
  return {
    title: `${modelLabel} - Malicious Rate per Host`,
    xaxis: { title: 'Time', type: 'date' },
    yaxis: { title: 'Predicted Malicious Rate', range: [0, 1] },
    legend: { orientation: 'v' },
    height: 420,
    margin: { t: 50, b: 60 },
  };
}

let _forecastClickBound = false;
let _forecastPinnedPoint = null;
let _forecastPointClickFlag = false;

function _forecastPositionPinnedCard(container, pt, hostIp, startLabel, endLabel, color) {
  const card = document.getElementById('forecastPinnedCard');
  if (!card) return;
  const xa = pt.xaxis || container._fullLayout.xaxis;
  const ya = pt.yaxis || container._fullLayout.yaxis;
  const pointLeft = xa._offset + xa.d2p(pt.x);
  const pointTop  = ya._offset + ya.d2p(pt.y);
  card.style.left = `${pointLeft + 14}px`;
  card.style.top = `${pointTop}px`;
  card.style.setProperty('--pin-color', color);
  card.innerHTML = `<b>${hostIp}</b>Start: ${startLabel}<br>End: ${endLabel}<br>Predicted rate: ${pt.y.toFixed(4)}`;
  card.style.display = '';
}

function _forecastHidePinnedCard() {
  const card = document.getElementById('forecastPinnedCard');
  if (card) card.style.display = 'none';
}

async function _renderForecastChart(sess) {
  _forecastPinnedPoint = null;
  _forecastHidePinnedCard();
  const hostsToPlot = sess.hasExplicitSelection
    ? sess.hostOrder
    : sess.hostOrder.slice(0, FORECAST_DEFAULT_HOST_CAP);
  const plottedSet = new Set(hostsToPlot);
  const hostColor = new Map(hostsToPlot.map((ip, i) => [ip, FORECAST_PALETTE[i % FORECAST_PALETTE.length]]));

  const lastRealPoint = new Map();
  const lineTraces = hostsToPlot.map((ip) => {
    const h = sess.hosts.get(ip);
    const { x, y, end } = _forecastDecimateHost(h);
    const color = hostColor.get(ip);
    const xIso = x.map(ms => new Date(ms).toISOString());
    if (xIso.length) lastRealPoint.set(ip, { xIso: xIso[xIso.length - 1], y: y[y.length - 1] });
    return {
      name: ip,
      legendgroup: ip,
      x: xIso,
      y,
      customdata: end.map(ms => [new Date(ms).toISOString(), ip]),
      mode: 'lines+markers',
      type: 'scatter',
      marker: { size: 3, color },
      line: { color, width: 1 },
      hovertemplate: '<b>%{fullData.name}</b><br>Start: %{x}<br>End: %{customdata[0]}<br>Predicted rate: %{y:.4f}<extra></extra>',
    };
  });

  const future = sess.futurePoints.filter(p => plottedSet.has(p.ip));

  const futureTraces = future.map(p => ({
    legendgroup: p.ip,
    showlegend: false,
    x: [new Date(p.x).toISOString()],
    y: [p.y],
    customdata: [[new Date(p.end).toISOString(), p.ip]],
    mode: 'markers',
    type: 'scatter',
    marker: { size: 11, symbol: 'star', color: hostColor.get(p.ip), line: { color: '#263238', width: 1 } },
    hovertemplate: `<b>${p.ip}</b><br>Future forecast for: %{x}<br>Predicted rate: %{y:.4f}<extra></extra>`,
  }));

  const futureLegendKey = {
    name: 'Future forecast',
    x: [], y: [],
    mode: 'markers',
    type: 'scatter',
    marker: { size: 11, symbol: 'star', color: '#546E7A', line: { color: '#263238', width: 1 } },
    hoverinfo: 'skip',
    showlegend: true,
  };

  const connectorTraces = future
    .map(p => {
      const anchor = lastRealPoint.get(p.ip);
      if (!anchor) return null;
      return {
        legendgroup: p.ip,
        x: [anchor.xIso, new Date(p.x).toISOString()],
        y: [anchor.y, p.y],
        mode: 'lines',
        type: 'scatter',
        line: { color: hostColor.get(p.ip), width: 1, dash: 'dot' },
        showlegend: false,
        hoverinfo: 'skip',
      };
    })
    .filter(Boolean);

  const traces = [...lineTraces, ...connectorTraces, ...futureTraces, futureLegendKey];

  await Plotly.react('forecastChart', traces, _forecastLayout(sess.modelLabel), { responsive: true });

  if (!_forecastClickBound) {
    const container = document.getElementById('forecastChart');
    if (container && typeof container.on === 'function') {
      container.on('plotly_click', (ev) => {
        const pt = ev.points && ev.points[0];
        _forecastPointClickFlag = true;
        if (!pt || !pt.customdata || !_fc) return;

        const [endIso, hostIp] = pt.customdata;
        const samePoint = _forecastPinnedPoint
          && _forecastPinnedPoint.curveNumber === pt.curveNumber
          && _forecastPinnedPoint.pointNumber === pt.pointNumber;
        if (samePoint) {
          _forecastPinnedPoint = null;
          _forecastHidePinnedCard();
        } else {
          _forecastPinnedPoint = { curveNumber: pt.curveNumber, pointNumber: pt.pointNumber };
          const startLabel = new Date(pt.x).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
          const endLabel = new Date(endIso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
          const fd = pt.fullData || {};
          const color = (fd.marker && fd.marker.color) || (fd.line && fd.line.color) || '#37474F';
          _forecastPositionPinnedCard(container, pt, hostIp, startLabel, endLabel, color);
        }

        _handleForecastPointClick(_fc, pt.x, endIso, hostIp);
      });

      container.addEventListener('click', () => {
        setTimeout(() => {
          if (_forecastPointClickFlag) { _forecastPointClickFlag = false; return; }
          if (_forecastPinnedPoint) {
            _forecastPinnedPoint = null;
            _forecastHidePinnedCard();
          }
        }, 0);
      });

      const _repositionPinnedCard = () => {
        if (!_forecastPinnedPoint) return;
        const gd = container._fullLayout ? container : null;
        if (!gd) return;
        const trace = gd.data && gd.data[_forecastPinnedPoint.curveNumber];
        if (!trace) { _forecastPinnedPoint = null; _forecastHidePinnedCard(); return; }
        const i = _forecastPinnedPoint.pointNumber;
        const x = trace.x[i], y = trace.y[i];
        const cd = trace.customdata && trace.customdata[i];
        if (x === undefined || y === undefined || !cd) return;
        const [endIso, hostIp] = cd;
        const startLabel = new Date(x).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
        const endLabel = new Date(endIso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
        const fd = gd._fullData ? gd._fullData[_forecastPinnedPoint.curveNumber] : trace;
        const color = (fd.marker && fd.marker.color) || (fd.line && fd.line.color) || '#37474F';
        const xa = gd._fullLayout.xaxis, ya = gd._fullLayout.yaxis;
        _forecastPositionPinnedCard(container, { x, y, xaxis: xa, yaxis: ya }, hostIp, startLabel, endLabel, color);
      };
      container.on('plotly_relayout', _repositionPinnedCard);
      container.on('plotly_relayouting', _repositionPinnedCard);
      window.addEventListener('resize', () => setTimeout(_repositionPinnedCard, 0));

      _forecastClickBound = true;
    }
  }

  const note = document.getElementById('forecastViewNote');
  if (note) {
    note.textContent = (!sess.hasExplicitSelection && sess.hostOrder.length > FORECAST_DEFAULT_HOST_CAP)
      ? `Showing a sample of ${FORECAST_DEFAULT_HOST_CAP} of ${sess.hostOrder.length} hosts. To see specific hosts, check them in the host filter above (shift+click to select a range) and run again.`
      : '';
  }
}

async function _handleForecastPointClick(sess, startIso, endIso, hostIp) {
  const detailsEl = document.getElementById('forecastWindowDetails');
  if (!detailsEl) return;

  const startTs = new Date(startIso).getTime() / 1000;
  const endTs = new Date(endIso).getTime() / 1000;
  detailsEl.textContent = `Loading flow record(s) for ${hostIp} between ${new Date(startIso).toLocaleString()} and ${new Date(endIso).toLocaleString()}…`;

  try {
    const qs = new URLSearchParams({
      filename: sess.filename, src_ip: hostIp, start_ts: startTs, end_ts: endTs,
    });
    const res = await fetch(`/forecast/window?${qs}`);
    const data = await res.json();
    if (!res.ok) {
      detailsEl.textContent = `Could not load flow records: ${data.error || res.statusText}`;
      return;
    }

    const rows = data.rows || [];
    if (!rows.length) {
      detailsEl.textContent = `No flow records found for ${hostIp} in this window (${new Date(startIso).toLocaleString()} - ${new Date(endIso).toLocaleString()}).`;
      return;
    }

    const lines = [
      `${rows.length} flow record(s) feeding this window's prediction for ${hostIp}:`,
      '',
    ];
    rows.forEach((r, i) => {
      lines.push(`- Record ${i + 1} -`);
      Object.entries(r).forEach(([k, v]) => lines.push(`${k}: ${v === null || v === undefined ? 'N/A' : v}`));
      lines.push('');
    });
    detailsEl.textContent = lines.join('\n');
  } catch (e) {
    detailsEl.textContent = `Could not load flow records for this window: ${e.message}`;
  }
}

async function streamForecastChart(bodyStream, modelLabel, statusEl, hasExplicitSelection, filename) {
  const sess = _newForecastSession(modelLabel, hasExplicitSelection, filename);
  _fc = sess;

  let lastRender = 0;
  let rowsSinceCheck = 0;

  const handleLine = async (line) => {
    if (!line) return;
    const row = JSON.parse(line);
    if (row.type === 'done') {
      sess.totalCount = row.count;
      return;
    }
    _forecastPushRow(sess, row);
    rowsSinceCheck++;
    if (rowsSinceCheck < 200) return;
    rowsSinceCheck = 0;
    const now = performance.now();
    if (now - lastRender >= FORECAST_RENDER_MIN_INTERVAL_MS) {
      lastRender = now;
      await _renderForecastChart(sess);
      statusEl.textContent = `Forecasting… ${sess.totalCount.toLocaleString()} windows so far`;
    }
  };

  const reader  = bodyStream.getReader();
  const decoder = new TextDecoder();
  let buf = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      await handleLine(line);
    }
  }
  if (buf.trim()) await handleLine(buf);

  await _renderForecastChart(sess);
  return sess.totalCount;
}
