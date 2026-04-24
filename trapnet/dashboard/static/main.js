'use strict';

const SCANNER_COLORS = {
  METASPLOIT:         '#ff4444',
  MASSCAN:            '#ff8800',
  NMAP:               '#ffcc00',
  CREDENTIAL_STUFFER: '#aa44ff',
  SHODAN:             '#4488ff',
  GENERIC_SCANNER:    '#888888',
  unknown:            '#444444',
};

const SCANNER_ROW_CLASS = {
  METASPLOIT:         'row-metasploit',
  MASSCAN:            'row-masscan',
  NMAP:               'row-nmap',
  CREDENTIAL_STUFFER: 'row-credential',
  SHODAN:             'row-shodan',
  GENERIC_SCANNER:    'row-generic',
};

const SCANNER_BADGE_CLASS = {
  METASPLOIT:         'badge-metasploit',
  MASSCAN:            'badge-masscan',
  NMAP:               'badge-nmap',
  CREDENTIAL_STUFFER: 'badge-credential',
  SHODAN:             'badge-shodan',
  GENERIC_SCANNER:    'badge-generic',
};

let freqChart = null;
let scannerChart = null;

function showError() {
  const el = document.getElementById('error-indicator');
  if (el) el.style.display = 'inline';
}

function hideError() {
  const el = document.getElementById('error-indicator');
  if (el) el.style.display = 'none';
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setHtml(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function fetchStats() {
  const resp = await fetch('/api/stats');
  if (!resp.ok) throw new Error('/api/stats returned ' + resp.status);
  return resp.json();
}

async function fetchRecent() {
  const resp = await fetch('/api/recent');
  if (!resp.ok) throw new Error('/api/recent returned ' + resp.status);
  return resp.json();
}

function renderStats(stats) {
  const total = stats.total_connections || 0;
  setText('header-total', total.toLocaleString());
  setText('stat-total', total.toLocaleString());

  const scannerTypes = (stats.scanner_breakdown || []).filter(
    r => r.scanner_type !== 'unknown'
  ).length;
  setText('stat-scanners', scannerTypes);

  const topService = (stats.top_services || [])[0];
  setText('stat-top-service', topService ? topService.service : '-');

  const topIp = (stats.top_ips || [])[0];
  setText('stat-top-ip', topIp ? topIp.src_ip : '-');
}

function renderFreqChart(stats) {
  const buckets = stats.connections_last_24h || [];
  const labels = buckets.map(b => b.hour.slice(11, 16));
  const data = buckets.map(b => b.count);

  if (freqChart) {
    freqChart.data.labels = labels;
    freqChart.data.datasets[0].data = data;
    freqChart.update();
    return;
  }

  const ctx = document.getElementById('chart-frequency');
  if (!ctx) return;

  freqChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Connections',
        data,
        backgroundColor: '#4a9eff',
        borderWidth: 0,
        borderRadius: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: '#888', font: { size: 10 } },
          grid: { color: '#0f3460' },
        },
        y: {
          ticks: { color: '#888', font: { size: 10 }, precision: 0 },
          grid: { color: '#0f3460' },
          beginAtZero: true,
        },
      },
    },
  });
}

function renderScannerChart(stats) {
  const breakdown = stats.scanner_breakdown || [];
  const labels = breakdown.map(r => r.scanner_type);
  const data = breakdown.map(r => r.count);
  const colors = labels.map(l => SCANNER_COLORS[l] || SCANNER_COLORS.unknown);

  if (scannerChart) {
    scannerChart.data.labels = labels;
    scannerChart.data.datasets[0].data = data;
    scannerChart.data.datasets[0].backgroundColor = colors;
    scannerChart.update();
    return;
  }

  const ctx = document.getElementById('chart-scanner');
  if (!ctx) return;

  scannerChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors,
        borderWidth: 1,
        borderColor: '#16213e',
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#aaa', font: { size: 11 }, padding: 12 },
        },
      },
    },
  });
}

function renderServicesTable(stats) {
  const rows = (stats.top_services || []).map(r =>
    '<tr><td>' + escHtml(r.service) + '</td><td>' + r.count + '</td></tr>'
  ).join('');
  setHtml('table-services', rows ||
    '<tr><td colspan="2" style="color:#555">No data</td></tr>');
}

function renderIpsTable(stats) {
  const rows = (stats.top_ips || []).map(r =>
    '<tr><td class="mono">' + escHtml(r.src_ip) + '</td><td>' + r.count + '</td></tr>'
  ).join('');
  setHtml('table-ips', rows ||
    '<tr><td colspan="2" style="color:#555">No data</td></tr>');
}

function renderFeed(rows) {
  const html = rows.map(r => {
    const rowClass = SCANNER_ROW_CLASS[r.scanner_type] || '';
    const badgeClass = SCANNER_BADGE_CLASS[r.scanner_type] || '';
    const scannerLabel = r.scanner_type
      ? '<span class="badge ' + badgeClass + '">' + escHtml(r.scanner_type) + '</span>'
      : '<span style="color:#555">-</span>';
    const raw = r.payload || '';
    const payload = raw
      ? escHtml(raw.slice(0, 40)) + (raw.length > 40 ? '...' : '')
      : '-';
    const ts = r.timestamp
      ? r.timestamp.slice(0, 19).replace('T', ' ')
      : '-';

    return '<tr class="' + rowClass + '">'
      + '<td class="mono">' + ts + '</td>'
      + '<td class="mono">' + escHtml(r.src_ip || '-') + '</td>'
      + '<td>' + escHtml(r.country || '-') + '</td>'
      + '<td>' + escHtml(r.service || '-') + '</td>'
      + '<td>' + scannerLabel + '</td>'
      + '<td class="mono">' + payload + '</td>'
      + '</tr>';
  }).join('');

  setHtml('table-feed', html ||
    '<tr><td colspan="6" style="color:#555">No connections yet</td></tr>');
}

async function refresh() {
  try {
    const [stats, rows] = await Promise.all([fetchStats(), fetchRecent()]);
    hideError();
    renderStats(stats);
    renderFreqChart(stats);
    renderScannerChart(stats);
    renderServicesTable(stats);
    renderIpsTable(stats);
    renderFeed(rows);
  } catch (err) {
    console.log('dashboard fetch error:', err);
    showError();
  }
}

refresh();
setInterval(refresh, 30000);
