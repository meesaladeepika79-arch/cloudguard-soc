/**
 * Cloud Security Monitoring Dashboard Frontend Logic
 * Chart.js rendering, AJAX scanner invocation, status updates, and filter handlers.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Initialize dashboard if on dashboard page
  if (document.getElementById('riskDonutChart')) {
    loadDashboardData();
  }

  // Load alert badge count
  updateAlertBadge();
});

// Global Chart Instances
let riskDonutChart = null;
let resourceTypeBarChart = null;
let scoreHistoryLineChart = null;

function loadDashboardData() {
  fetch('/api/dashboard-stats')
    .then(response => response.json())
    .then(data => {
      // Update KPI Counter Values
      document.getElementById('kpi-total-resources').innerText = data.total_resources;
      document.getElementById('kpi-total-issues').innerText = data.total_issues;
      document.getElementById('kpi-critical').innerText = data.critical_issues;
      document.getElementById('kpi-high').innerText = data.high_issues;
      document.getElementById('kpi-medium').innerText = data.medium_issues;
      document.getElementById('kpi-low').innerText = data.low_issues;

      // Update Security Score Display
      const scoreElement = document.getElementById('kpi-score-val');
      const ratingBadge = document.getElementById('kpi-score-rating');
      const scoreGauge = document.getElementById('score-gauge-fill');
      
      if (scoreElement) scoreElement.innerText = data.security_score;
      if (ratingBadge) {
        ratingBadge.innerText = data.rating_info.rating;
        ratingBadge.className = `badge ${data.rating_info.badge}`;
      }
      if (scoreGauge) {
        scoreGauge.style.width = `${data.security_score}%`;
        scoreGauge.style.backgroundColor = data.rating_info.color;
      }

      // Render Charts
      renderRiskDonutChart(data.risk_distribution);
      renderResourceTypeBarChart(data.issues_by_resource_type);
      renderScoreHistoryLineChart(data.score_history);

      // Render Recent Scans Table
      renderRecentScans(data.recent_scans);

      // Render Recent Alerts
      renderRecentAlerts(data.recent_alerts);

      // Render Top Problems Panel
      loadTopProblems();
    })
    .catch(err => console.error('Error loading dashboard stats:', err));
}

function renderRiskDonutChart(riskData) {
  const ctx = document.getElementById('riskDonutChart').getContext('2d');
  
  if (riskDonutChart) {
    riskDonutChart.destroy();
  }

  riskDonutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: riskData.labels,
      datasets: [{
        data: riskData.data,
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
        borderWidth: 2,
        borderColor: '#120028'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: 'rgba(245, 230, 200, 0.7)', font: { family: 'Raleway', size: 12 } }
        }
      },
      cutout: '70%'
    }
  });
}

function renderResourceTypeBarChart(typeData) {
  const ctx = document.getElementById('resourceTypeBarChart').getContext('2d');

  if (resourceTypeBarChart) {
    resourceTypeBarChart.destroy();
  }

  resourceTypeBarChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: typeData.labels.length > 0 ? typeData.labels : ['No Issues'],
      datasets: [{
        label: 'Security Issues',
        data: typeData.data.length > 0 ? typeData.data : [0],
        backgroundColor: '#d4af37',
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(212, 175, 55, 0.1)' },
          ticks: { color: 'rgba(245, 230, 200, 0.65)', font: { family: 'Raleway' }, precision: 0 }
        },
        x: {
          grid: { display: false },
          ticks: { color: 'rgba(245, 230, 200, 0.65)', font: { family: 'Raleway' } }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderScoreHistoryLineChart(historyData) {
  const ctx = document.getElementById('scoreHistoryLineChart').getContext('2d');

  if (scoreHistoryLineChart) {
    scoreHistoryLineChart.destroy();
  }

  scoreHistoryLineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: historyData.labels,
      datasets: [{
        label: 'Security Score',
        data: historyData.data,
        borderColor: '#d4af37',
        backgroundColor: 'rgba(212, 175, 55, 0.15)',
        fill: true,
        tension: 0.3,
        pointBackgroundColor: '#f0d060',
        pointRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          min: 0,
          max: 100,
          grid: { color: 'rgba(212, 175, 55, 0.1)' },
          ticks: { color: 'rgba(245, 230, 200, 0.65)', font: { family: 'Raleway' } }
        },
        x: {
          grid: { display: false },
          ticks: { color: 'rgba(245, 230, 200, 0.65)', font: { family: 'Raleway' } }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderRecentScans(scans) {
  const tbody = document.getElementById('recent-scans-tbody');
  if (!tbody) return;

  if (!scans || scans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center text-dim py-3">No scans recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = scans.map(s => `
    <tr>
      <td class="font-mono royal-gold-text">${s.scan_id}</td>
      <td><span class="royal-status-badge">${s.scan_mode}</span></td>
      <td>${s.completed_at || s.started_at}</td>
      <td>${s.resources_scanned} resources</td>
      <td>
        <span class="fw-bold ${s.security_score >= 80 ? 'text-success' : s.security_score >= 60 ? 'text-warning' : 'text-danger'}">
          ${s.security_score}/100
        </span>
      </td>
    </tr>
  `).join('');
}

function renderRecentAlerts(alerts) {
  const container = document.getElementById('recent-alerts-list');
  if (!container) return;

  if (!alerts || alerts.length === 0) {
    container.innerHTML = `<div class="p-3 text-center text-dim">No security alerts detected.</div>`;
    return;
  }

  container.innerHTML = alerts.map(a => `
    <div class="d-flex align-items-center justify-content-between p-2 mb-2 rounded" style="background: rgba(10, 0, 25, 0.6); border: 1px solid rgba(212, 175, 55, 0.2);">
      <div class="d-flex align-items-center gap-2">
        <span class="badge ${a.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${a.severity}</span>
        <span class="small text-royal">${a.message}</span>
      </div>
      <span class="small text-dim font-mono ms-2">${a.created_at}</span>
    </div>
  `).join('');
}

function loadTopProblems() {
  fetch('/api/dashboard/top-problems')
    .then(res => res.json())
    .then(data => renderTopProblems(data))
    .catch(err => console.error('Error loading top problems:', err));
}

function getSeverityColor(sev) {
  switch (sev) {
    case 'CRITICAL': return { bg: 'rgba(239,68,68,0.12)', border: '#ef4444', text: '#fca5a5', badge: 'badge-critical' };
    case 'HIGH':     return { bg: 'rgba(249,115,22,0.12)', border: '#f97316', text: '#fdba74', badge: 'badge-high' };
    case 'MEDIUM':   return { bg: 'rgba(234,179,8,0.12)',  border: '#eab308', text: '#fde047', badge: 'badge-medium' };
    default:         return { bg: 'rgba(59,130,246,0.12)', border: '#3b82f6', text: '#93c5fd', badge: 'badge-low' };
  }
}

function renderTopProblems(problems) {
  const container = document.getElementById('top-problems-container');
  if (!container) return;

  if (!problems || problems.length === 0) {
    container.innerHTML = `
      <div class="text-center py-5">
        <i class="fa-solid fa-shield-check fa-3x text-success mb-3"></i>
        <div class="text-success fw-bold fs-5">No Active Problems Found</div>
        <div class="text-muted small mt-1">All security checks passed or findings are resolved.</div>
      </div>`;
    return;
  }

  const cards = problems.map(p => {
    const c = getSeverityColor(p.severity);
    const iconMap = { CRITICAL: 'fa-radiation', HIGH: 'fa-triangle-exclamation', MEDIUM: 'fa-circle-exclamation', LOW: 'fa-circle-info' };
    const icon = iconMap[p.severity] || 'fa-circle-info';

    return `
      <div class="mb-3 p-3 rounded" style="background:${c.bg}; border-left: 4px solid ${c.border}; border-top: 1px solid ${c.border}40; border-right: 1px solid ${c.border}20; border-bottom: 1px solid ${c.border}20;">
        <div class="d-flex align-items-start justify-content-between gap-3 flex-wrap">
          <div class="flex-grow-1">
            <div class="d-flex align-items-center gap-2 mb-2">
              <span class="badge ${c.badge}">
                <i class="fa-solid ${icon} me-1"></i>${p.severity}
              </span>
              <span class="badge bg-dark border border-secondary text-light small">${p.resource_type}</span>
              <span class="text-dim font-mono small">${p.finding_id}</span>
            </div>
            <div class="fw-bold text-light mb-1" style="font-size:1rem;">${p.title}</div>
            <div class="small mb-2" style="color:${c.text};">
              <i class="fa-solid fa-server me-1"></i> Affected: <strong>${p.resource_name}</strong>
            </div>
            <div class="small text-dim mb-2">${p.description}</div>
            <div class="small p-2 rounded" style="background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08);">
              <i class="fa-solid fa-wrench me-1 text-success"></i>
              <span class="text-light"><strong>Fix:</strong> ${p.recommendation}</span>
            </div>
          </div>
          <div class="d-flex flex-column gap-2 align-items-end" style="min-width:130px;">
            <a href="/findings/${p.id}" class="btn btn-sm btn-outline-info w-100">
              <i class="fa-solid fa-circle-info me-1"></i> Details
            </a>
            <button onclick="dashboardAutoFix(${p.id}, this)" class="btn btn-sm btn-warning w-100 fw-bold">
              <i class="fa-solid fa-bolt me-1"></i> 1-Click Fix
            </button>
            <span class="small text-dim font-mono text-end mt-1">${p.detected_at}</span>
          </div>
        </div>
      </div>`;
  }).join('');

  container.innerHTML = cards;
}

function dashboardAutoFix(findingId, btn) {
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Fixing...`;
  }

  fetch(`/api/findings/${findingId}/autofix`, { method: 'POST' })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        showSuccessToast();
        loadDashboardData();
      } else {
        alert("Auto-fix failed: " + (data.error || "Unknown error"));
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = `<i class="fa-solid fa-bolt me-1"></i> 1-Click Fix`;
        }
      }
    })
    .catch(err => {
      alert("Auto-fix error: " + err);
      if (btn) btn.disabled = false;
    });
}

function triggerScanExecution(demoMode = false, region = null, credentials = {}, onSuccess = null) {
  const scanBtn = document.getElementById('btn-run-scan');
  const modalProgress = document.getElementById('scan-progress-box');
  
  if (scanBtn) {
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> Scanning Cloud...`;
  }
  if (modalProgress) {
    modalProgress.classList.remove('d-none');
  }

  fetch('/api/scans/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ demo_mode: demoMode, region: region, ...credentials })
  })
  .then(res => res.json())
  .then(data => {
    if (modalProgress) modalProgress.classList.add('d-none');
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<i class="fa-solid fa-play me-2"></i> Start Security Scan`;
    }

    // Show Success Alert if scan was successful
    if (!data.error) {
      showSuccessToast();
      if (onSuccess) onSuccess();
    }

    // Refresh Dashboard or Scans table if present
    if (document.getElementById('riskDonutChart')) {
      loadDashboardData();
    }
    if (typeof loadScansTable === 'function') {
      loadScansTable();
    }
    updateAlertBadge();

    showRoyalScanResultModal(data);
  })
  .catch(err => {
    console.error('Scan failed:', err);
    if (modalProgress) modalProgress.classList.add('d-none');
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<i class="fa-solid fa-play me-2"></i> Start Security Scan`;
    }
    showRoyalScanResultModal({ mode: 'Error', resources_scanned: 0, security_score: 0, error: true });
  });
}

function showRoyalScanResultModal(data) {
  console.log('Scan Modal Data:', data);
  let modalEl = document.getElementById('royalScanModal');
  if (!modalEl) {
    const modalHtml = `
      <div class="modal fade" id="royalScanModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
          <div class="modal-content royal-modal text-center p-3">
            <div class="modal-header border-0 pb-1 justify-content-center">
              <h4 class="modal-title royal-heading" style="color: var(--royal-gold-light);"><i class="fa-solid fa-shield-halved me-2 royal-gold-text"></i> Security Scan Telemetry</h4>
            </div>
            <div class="modal-body py-3" id="royalScanModalBody"></div>
            <div class="modal-footer border-0 justify-content-center pt-1">
              <button type="button" class="btn royal-scan-btn px-4" data-bs-dismiss="modal">Acknowledge</button>
            </div>
          </div>
        </div>
      </div>`;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    modalEl = document.getElementById('royalScanModal');
  }

  const modalBody = document.getElementById('royalScanModalBody');
  if (modalBody) {
    if (data.error) {
      modalBody.innerHTML = `<div class="royal-alert-box alert-danger m-0 justify-content-center"><i class="fa-solid fa-circle-exclamation me-2"></i>${data.message || 'Security scan execution encountered an error.'}</div>`;
    } else {
      modalBody.innerHTML = `
        <div class="mb-3">
          <div style="background: #22c55e; color: white; padding: 15px; border-radius: 8px; font-weight: bold; font-size: 16px; margin-bottom: 15px;">
            <i class="fa-solid fa-circle-check me-2"></i>Security Scan Successful! ✓
          </div>
        </div>
        <div class="mb-3">
          <span class="badge royal-status-badge fs-6 py-2 px-3 me-2"><i class="fa-solid fa-microchip me-1"></i> Mode: ${data.mode}</span>
          <span class="badge royal-status-badge fs-6 py-2 px-3"><i class="fa-solid fa-server me-1"></i> Scanned: ${data.resources_scanned} Assets</span>
        </div>
        <div class="soc-card p-3 my-3" style="border: 2px solid var(--royal-gold); background: rgba(10, 0, 25, 0.85); box-shadow: 0 0 35px rgba(212, 175, 55, 0.4);">
          <div class="kpi-title text-center mb-1">EVALUATED POSTURE SCORE</div>
          <div class="display-3 fw-bold ${data.security_score >= 80 ? 'text-success' : data.security_score >= 60 ? 'text-warning' : 'text-danger'}" style="text-shadow: 0 0 20px currentColor;">
            ${data.security_score} / 100
          </div>
          <div class="small text-dim mt-1">Audit complete across S3, EC2, IAM, SG & RDS rules</div>
        </div>
      `;
    }
  }

  const bsModal = new bootstrap.Modal(modalEl);
  bsModal.show();
}

function showSuccessToast() {
  // Create success notification
  const toastHtml = `
    <div id="successToast" style="
      position: fixed;
      top: 20px;
      right: 20px;
      background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
      color: white;
      padding: 20px 30px;
      border-radius: 8px;
      box-shadow: 0 8px 24px rgba(34, 197, 94, 0.4);
      font-size: 16px;
      font-weight: bold;
      z-index: 9999;
      animation: slideIn 0.5s ease-out;
      display: flex;
      align-items: center;
      gap: 10px;
    ">
      <i class="fa-solid fa-circle-check" style="font-size: 20px;"></i>
      <span>Security Scan Successful! ✓</span>
    </div>
    <style>
      @keyframes slideIn {
        from {
          transform: translateX(400px);
          opacity: 0;
        }
        to {
          transform: translateX(0);
          opacity: 1;
        }
      }
      @keyframes slideOut {
        from {
          transform: translateX(0);
          opacity: 1;
        }
        to {
          transform: translateX(400px);
          opacity: 0;
        }
      }
    </style>
  `;
  
  // Remove old toast if exists
  const oldToast = document.getElementById('successToast');
  if (oldToast) oldToast.remove();
  
  // Insert new toast
  document.body.insertAdjacentHTML('beforeend', toastHtml);
  
  // Auto-remove after 4 seconds
  setTimeout(() => {
    const toast = document.getElementById('successToast');
    if (toast) {
      toast.style.animation = 'slideOut 0.5s ease-out';
      setTimeout(() => toast.remove(), 500);
    }
  }, 4000);
}

function updateFindingStatus(findingId, newStatus) {
  fetch(`/api/findings/${findingId}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus })
  })
  .then(res => res.json())
  .then(data => {
    if (data.message) {
      if (typeof loadFindingsTable === 'function') {
        loadFindingsTable();
      } else {
        window.location.reload();
      }
    }
  })
  .catch(err => console.error('Status update failed:', err));
}

function updateAlertBadge() {
  const badge = document.getElementById('alert-count-badge');
  if (!badge) return;

  fetch('/api/alerts/count')
    .then(res => res.json())
    .then(data => {
      if (data.unread_count > 0) {
        badge.innerText = data.unread_count;
        badge.classList.remove('d-none');
      } else {
        badge.classList.add('d-none');
      }
    })
    .catch(() => {});
}
