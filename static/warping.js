const DTW_COLUMN_INFO_KEYS = {
  len: 'len', src_port: 'src_port', dst_port: 'dst_port',
  payload_len: 'payload_len', ttl: 'ttl', window: 'window',
  ulen: 'ulen', icmp_type: 'type',
};

function formatPacketSummary(packet) {
  if (!packet) {
    return "N/A";
  }

  const info = packet.info || {};
  const lines = [
    `Packet ID: ${packet.id ?? "N/A"}`,
    `Time: ${packet.timestamp ? new Date(packet.timestamp * 1000).toLocaleString() : "N/A"}`,
    `Source: ${packet.src_ip || "N/A"}:${info.src_port ?? ""}`,
    `Destination: ${packet.dst_ip || "N/A"}:${info.dst_port ?? ""}`,
    `Protocol: ${packet.protocol || "N/A"}`,
  ];
  if (packet.flow_id) {
    lines.push(`Flow: ${packet.flow_id}`);
  }

  lines.push("", "Values");
  Object.entries(DTW_COLUMN_INFO_KEYS).forEach(([dtwCol, infoKey]) => {
    const val = info[infoKey];
    if (val !== undefined && val !== null) {
      lines.push(`  ${DTW_COLUMN_LABELS[dtwCol] || dtwCol}: ${val}`);
    }
  });

  if (info.flags) {
    lines.push("", `Flags: ${info.flags}`);
  }

  const httpLines = [];
  if (info.http_method) httpLines.push(`Method: ${info.http_method}`);
  if (info.http_host) httpLines.push(`Host: ${info.http_host}`);
  if (info.http_uri) httpLines.push(`URI: ${info.http_uri}`);
  if (info.http_status) httpLines.push(`Status: ${info.http_status}${info.http_reason ? ` ${info.http_reason}` : ''}`);
  if (info.http_location) httpLines.push(`Location: ${info.http_location}`);
  if (info.http_set_cookie) httpLines.push(`Set-Cookie: ${info.http_set_cookie}`);
  if (info.http_body) httpLines.push(`Body: ${info.http_body}`);
  if (httpLines.length) {
    lines.push("", "HTTP", ...httpLines.map(l => `  ${l}`));
  }

  return lines.join("\n");
}

function renderWarpPairDetails(points, side, idx) {
  const details = document.getElementById("dtwWarpDetails");
  if (!details) return;

  if (!points || !points.length) {
    details.textContent = `No aligned packet pair found for this ${side} index (${idx}).`;
    return;
  }

  const lines = [];
  points.forEach((p, i) => {
    if (i > 0) lines.push("", "─".repeat(30), "");
    lines.push(`Pair ${i + 1}/${points.length} - alignment distance: ${p.distance.toFixed(2)}`);
    lines.push("");
    lines.push("Host_A packet");
    lines.push(formatPacketSummary(p.host_A_packet));
    lines.push("");
    lines.push("Host_B packet");
    lines.push(formatPacketSummary(p.host_B_packet));
  });
  details.textContent = lines.join("\n");
}

const DTW_COLUMN_LABELS = {
  len: 'Length',
  src_port: 'Src Port',
  dst_port: 'Dst Port',
  payload_len: 'Payload Len',
  ttl: 'TTL',
  window: 'TCP Window',
  ulen: 'UDP Len',
  icmp_type: 'ICMP Type',
};

let _dtwLastData = null;
let _dtwCurrentPage = 0;
let _dtwCurrentParams = {};

let _dtwPageCache = new Map();
let _dtwPageCacheKey = null;

function _updateWindowPager(page, numPages, data) {
  const pager = document.getElementById('dtwWindowPager');
  const label = document.getElementById('dtwWindowLabel');
  const prevBtn = document.getElementById('dtwWindowPrev');
  const nextBtn = document.getElementById('dtwWindowNext');
  const jumpInput = document.getElementById('dtwWindowJump');
  const goBtn = document.getElementById('dtwWindowGo');
  if (!pager) return;

  if (!numPages || numPages <= 1) {
    pager.style.display = 'none';
    return;
  }
  pager.style.display = '';
  if (label) {
    const vOff = data?.host_A_offset ?? 0;
    const vTotal = data?.host_A_total ?? 0;
    const vCount = data?.host_A_seq?.length ?? 0;
    label.textContent = vTotal
      ? `Window ${page + 1}/${numPages} (packets ${vOff + 1}-${vOff + vCount} of ${vTotal})`
      : `Window ${page + 1}/${numPages}`;
  }
  if (prevBtn) prevBtn.disabled = page <= 0;
  if (nextBtn) nextBtn.disabled = page >= numPages - 1;
  if (jumpInput) {
    jumpInput.max = numPages;
    jumpInput.placeholder = String(page + 1);
  }
  if (goBtn) goBtn.disabled = false;
}

function _renderWarpingFromData(container, details, data) {
  const host_AVectors = data.host_A_seq || [];
  const host_BVectors = data.host_B_seq || [];
  const columns = (data.columns && data.columns.length) ? data.columns : ['len'];
  const path = data.path || [];
  const points = data.points || [];

  const pairsByHost_A = new Map();
  const pairsByHost_B = new Map();
  points.forEach(p => {
    if (!pairsByHost_A.has(p.host_A_index)) pairsByHost_A.set(p.host_A_index, []);
    pairsByHost_A.get(p.host_A_index).push(p);
    if (!pairsByHost_B.has(p.host_B_index)) pairsByHost_B.set(p.host_B_index, []);
    pairsByHost_B.get(p.host_B_index).push(p);
  });

  const n = host_AVectors.length;
  const m = host_BVectors.length;
  const s_x = host_AVectors.map((_, i) => i);
  const q_x = host_BVectors.map((_, j) => j);

  const colValues = (vectors, colIdx) => vectors.map(v => Number((v || [])[colIdx] ?? 0));

  const pad = (arr) => {
    const min = Math.min(...arr);
    const max = Math.max(...arr);
    if (min === max) return [min - 1, max + 1];
    const r = max - min;
    return [min - 0.05 * r, max + 0.05 * r];
  };

  const xDataMax = Math.max(n, m) - 1;
  const xPad = Math.max(1, xDataMax * 0.02);
  const xBounds = [-xPad, xDataMax + xPad];

  const topDomainStart = 0.55;
  const topHeight = 0.42;
  const bottomDomainStart = 0.07;
  const bottomHeight = 0.42;

  const col = columns[0] || 'len';
  const label = DTW_COLUMN_LABELS[col] || col;
  const vVals = colValues(host_AVectors, 0);
  const aVals = colValues(host_BVectors, 0);
  const [smin, smax] = pad(vVals);
  const [qmin, qmax] = pad(aVals);
  const traces = [
    {
      x: s_x,
      y: vVals,
      mode: 'lines+markers',
      name: 'Host_A',
      line: { color: '#4C6EF5' },
      marker: { size: 6 },
      hovertemplate: `Host_A index: %{x}<br>${label}: %{y}<extra></extra>`
    },
    {
      x: q_x,
      y: aVals,
      mode: 'lines+markers',
      name: 'Host_B',
      yaxis: 'y2',
      line: { color: '#F03E3E' },
      marker: { size: 6 },
      hovertemplate: `Host_B index: %{x}<br>${label}: %{y}<extra></extra>`
    },
  ];
  const yaxisRange = [smin, smax];
  const y2axisRange = [qmin, qmax];
  const yaxisTitle = `Host_A - ${label}`;
  const y2axisTitle = `Host_B - ${label}`;
  const connectorHost_AVals = vVals;
  const connectorHost_BVals = aVals;

  const windowSuffix = (data.num_pages && data.num_pages > 1)
    ? ` - window ${(data.page || 0) + 1}/${data.num_pages}`
    : '';
  const layout = {
    title: `DTW warping (distance: ${Number(data.distance).toFixed(2)})${windowSuffix}`,
    xaxis: { title: 'index', domain: [0, 1], range: xBounds.slice(), autorange: false, anchor: 'y2' },
    yaxis: { title: yaxisTitle, domain: [topDomainStart, topDomainStart + topHeight], range: yaxisRange, fixedrange: true },
    yaxis2: { title: y2axisTitle, domain: [bottomDomainStart, bottomDomainStart + bottomHeight], range: y2axisRange, anchor: 'x', fixedrange: true },
    margin: { t: 60, b: 40 },
    hovermode: 'closest',
    showlegend: true
  };

  const [pvmin, pvmax] = pad(connectorHost_AVals);
  const [pamin, pamax] = pad(connectorHost_BVals);
  const buildConnectorPath = (pairs) => {
    let d = '';
    for (const [vi, aj] of pairs) {
      const vnorm = (connectorHost_AVals[vi] - pvmin) / (pvmax - pvmin || 1);
      const vpaper = topDomainStart + vnorm * topHeight;
      const qnorm = (connectorHost_BVals[aj] - pamin) / (pamax - pamin || 1);
      const qpaper = bottomDomainStart + qnorm * bottomHeight;
      d += `M${vi},${vpaper.toFixed(4)}L${aj},${qpaper.toFixed(4)}`;
    }
    return d;
  };

  const connectorPath = buildConnectorPath(path);
  const baseShapes = connectorPath ? [{
    type: 'path',
    xref: 'x',
    yref: 'paper',
    path: connectorPath,
    line: { color: 'rgba(150,150,150,0.35)', width: 0.7 },
  }] : [];

  const getPaperY = (side, idx) => {
    const vals = side === 'host_A' ? connectorHost_AVals : connectorHost_BVals;
    const [mn, mx] = side === 'host_A' ? [pvmin, pvmax] : [pamin, pamax];
    const domainStart = side === 'host_A' ? topDomainStart : bottomDomainStart;
    const height = side === 'host_A' ? topHeight : bottomHeight;
    return domainStart + ((vals[idx] - mn) / (mx - mn || 1)) * height;
  };
  layout.shapes = baseShapes;

  Plotly.newPlot(container, traces, layout, {responsive: true, displaylogo: false}).then(() => {
    const getVisibleXRange = () => {
      const r = container.layout && container.layout.xaxis && container.layout.xaxis.range;
      return (r && r.length === 2) ? r : xBounds;
    };

    const buildOffscreenAnnotations = (pairs) => {
      const [visMin, visMax] = getVisibleXRange();
      let offLeft = false, offRight = false;
      pairs.forEach(([vi, aj]) => {
        [vi, aj].forEach(idx => {
          if (idx < visMin) offLeft = true;
          else if (idx > visMax) offRight = true;
        });
      });
      const base = {
        yref: 'paper', y: 0.52, yanchor: 'middle', showarrow: false,
        font: { size: 10, color: '#8a6d00' },
        bgcolor: 'rgba(255, 224, 0, 0.9)', bordercolor: '#8a6d00', borderpad: 3,
      };
      const anns = [];
      if (offLeft) anns.push({ ...base, x: visMin, xref: 'x', xanchor: 'left', text: '◀ connected packet off-screen' });
      if (offRight) anns.push({ ...base, x: visMax, xref: 'x', xanchor: 'right', text: 'connected packet off-screen ▶' });
      return anns;
    };

    let pinnedHighlight = null;
    let lastHighlightKey = null;
    const applyHighlight = (highlight, force = false) => {
      const pairs = highlight ? highlight.pairs : null;
      const key = (pairs && pairs.length) ? pairs.map(p => p.join(':')).join(',') : '';
      if (!force && key === lastHighlightKey) return;
      lastHighlightKey = key;
      let hPath = '';
      if (pairs && pairs.length) {
        for (const [vi, aj] of pairs) {
          const vpaper = getPaperY('host_A', vi);
          const qpaper = getPaperY('host_B', aj);
          hPath += `M${vi},${vpaper.toFixed(4)}L${aj},${qpaper.toFixed(4)}`;
        }
      }
      const shapes = hPath ? [...baseShapes, {
        type: 'path',
        xref: 'x',
        yref: 'paper',
        path: hPath,
        line: { color: 'rgba(255, 224, 0, 0.85)', width: 4 },
      }] : baseShapes;
      const annotations = (pairs && pairs.length) ? buildOffscreenAnnotations(pairs) : [];
      Plotly.relayout(container, { shapes, annotations });
    };

    let clamping = false;
    container.on('plotly_relayout', (ev) => {
      if (clamping) return;
      const x0 = ev['xaxis.range[0]'];
      const x1 = ev['xaxis.range[1]'];
      if (x0 === undefined || x1 === undefined) return;
      const clampedX0 = Math.max(x0, xBounds[0]);
      const clampedX1 = Math.min(x1, xBounds[1]);
      if (clampedX1 <= clampedX0) return;
      if (clampedX0 !== x0 || clampedX1 !== x1) {
        clamping = true;
        Plotly.relayout(container, { 'xaxis.range': [clampedX0, clampedX1] })
          .finally(() => {
            clamping = false;
            applyHighlight(pinnedHighlight, true);
          });
      } else {
        applyHighlight(pinnedHighlight, true);
      }
    });

    const highlightForPoint = (pt) => {
      if (!pt || !pt.fullData || !pt.fullData.name) return null;
      let pts = null;
      if (pt.fullData.name === 'Host_A') pts = pairsByHost_A.get(pt.x);
      else if (pt.fullData.name === 'Host_B') pts = pairsByHost_B.get(pt.x);
      if (!pts) return null;
      return { pairs: pts.map(p => [p.host_A_index, p.host_B_index]) };
    };

    container.on('plotly_hover', (ev) => {
      const highlight = highlightForPoint(ev.points && ev.points[0]);
      if (highlight) applyHighlight(highlight);
    });

    container.on('plotly_unhover', () => {
      applyHighlight(pinnedHighlight);
    });

    container.on('plotly_click', (ev) => {
      const pt = ev.points && ev.points[0];
      if (!pt || !pt.fullData || !pt.fullData.name) return;
      const highlight = highlightForPoint(pt);
      if (highlight) {
        pinnedHighlight = highlight;
        applyHighlight(highlight);
      }
      if (pt.fullData.name === 'Host_A') {
        renderWarpPairDetails(pairsByHost_A.get(pt.x), 'host_A', pt.x);
        return;
      }
      if (pt.fullData.name === 'Host_B') {
        renderWarpPairDetails(pairsByHost_B.get(pt.x), 'host_B', pt.x);
        return;
      }
    });
  });

  window._dtw_last = { host_AVectors, host_BVectors, columns, path, points };
}

function _dtwLoadFailed(container, details, message) {
  container.innerHTML = '<p>No warping data available.</p>';
  if (details) details.textContent = message || 'No data';
  _updateWindowPager(0, 1);
}

const DTW_WARPING_POLL_MS = 600;

async function loadDtwWarping(page = 0, extraParams = {}, forceRefresh = false) {
  const container = document.getElementById('dtwWarping');
  const details = document.getElementById('dtwWarpDetails');
  const loadingOverlay = document.getElementById('dtwWarpingLoading');
  const loadingText = loadingOverlay ? loadingOverlay.querySelector('.section-loading-text') : null;
  if (!container) return;

  _dtwCurrentPage = page;
  _dtwCurrentParams = extraParams;

  const paramsKey = JSON.stringify(extraParams);
  if (paramsKey !== _dtwPageCacheKey) {
    _dtwPageCacheKey = paramsKey;
    _dtwPageCache = new Map();
  }

  if (!forceRefresh && _dtwPageCache.has(page)) {
    const cached = _dtwPageCache.get(page);
    _dtwLastData = cached;
    _renderWarpingFromData(container, details, cached);
    _updateWindowPager(cached.page || 0, cached.num_pages || 1, cached);
    return;
  }

  if (loadingOverlay) loadingOverlay.style.display = 'flex';
  if (loadingText) loadingText.textContent = 'Starting DTW computation…';

  try {
    const qs = new URLSearchParams({ page, ...extraParams });
    const startRes = await fetch(`/dtw-warping?${qs}`, { method: 'POST' });
    const startData = await startRes.json();
    if (!startRes.ok || !startData.job_id) {
      _dtwLoadFailed(container, details, startData.error);
      return;
    }

    if (loadingText) loadingText.textContent = 'Computing DTW alignment…';

    let data = null;
    while (!data) {
      await new Promise(r => setTimeout(r, DTW_WARPING_POLL_MS));
      const sRes = await fetch(`/dtw-warping/status?job_id=${startData.job_id}`);
      const s = await sRes.json();
      if (!sRes.ok || s.status === 'error') {
        _dtwLoadFailed(container, details, s.error);
        return;
      }
      if (s.status === 'done') data = s.result;
    }

    if (!data.host_A_seq) {
      _dtwLoadFailed(container, details, 'No data');
      return;
    }

    if (loadingText) loadingText.textContent = 'Rendering warping plot…';
    if (paramsKey === _dtwPageCacheKey) _dtwPageCache.set(data.page || 0, data);
    _dtwLastData = data;
    _renderWarpingFromData(container, details, data);
    _updateWindowPager(data.page || 0, data.num_pages || 1, data);
  } catch (error) {
    console.error('Warping load failed', error);
    if (details) details.textContent = 'Failed to load the warping plot.';
    container.innerHTML = '<p>Failed to load warping plot.</p>';
  } finally {
    if (loadingOverlay) loadingOverlay.style.display = 'none';
    if (loadingText) loadingText.textContent = 'Refreshing warping…';
  }
}

window.loadDtwWarping = loadDtwWarping;

window.clearDtwWarpingCache = () => {
  _dtwPageCache = new Map();
  _dtwPageCacheKey = null;
};

document.addEventListener('DOMContentLoaded', () => {
  const prevBtn = document.getElementById('dtwWindowPrev');
  const nextBtn = document.getElementById('dtwWindowNext');
  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      if (_dtwCurrentPage > 0) loadDtwWarping(_dtwCurrentPage - 1, _dtwCurrentParams);
    });
  }
  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      loadDtwWarping(_dtwCurrentPage + 1, _dtwCurrentParams);
    });
  }

  const jumpInput = document.getElementById('dtwWindowJump');
  const goBtn = document.getElementById('dtwWindowGo');
  const doJump = () => {
    if (!jumpInput) return;
    const raw = parseInt(jumpInput.value, 10);
    if (!Number.isFinite(raw)) return;
    const numPages = _dtwLastData?.num_pages || 1;
    const clamped = Math.min(Math.max(raw, 1), numPages);
    jumpInput.value = '';
    loadDtwWarping(clamped - 1, _dtwCurrentParams);
  };
  if (goBtn) goBtn.addEventListener('click', doJump);
  if (jumpInput) {
    jumpInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') doJump();
    });
  }
});
