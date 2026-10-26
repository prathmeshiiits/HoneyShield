'use strict';

document.addEventListener('DOMContentLoaded', () => {
  const escapeHtml = (str) => {
    if (!str && str !== 0) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  };

  const menuToggle = document.getElementById('menuToggle');
  const navDrawer = document.getElementById('navDrawer');
  const drawerBackdrop = document.getElementById('drawerBackdrop');
  const drawerClose = document.getElementById('drawerClose');
  let drawerCloseTimer = null;

  const openDrawer = () => {
    if (!menuToggle || !navDrawer || !drawerBackdrop) return;
    if (drawerCloseTimer) window.clearTimeout(drawerCloseTimer);
    navDrawer.hidden = false;
    drawerBackdrop.hidden = false;
    window.requestAnimationFrame(() => {
      navDrawer.classList.add('is-open');
      drawerBackdrop.classList.add('is-visible');
    });
    navDrawer.setAttribute('aria-hidden', 'false');
    menuToggle.setAttribute('aria-expanded', 'true');
    menuToggle.setAttribute('aria-label', 'Close navigation menu');
    drawerClose?.focus();
  };

  const closeDrawer = () => {
    if (!menuToggle || !navDrawer || !drawerBackdrop) return;
    navDrawer.classList.remove('is-open');
    drawerBackdrop.classList.remove('is-visible');
    navDrawer.setAttribute('aria-hidden', 'true');
    menuToggle.setAttribute('aria-expanded', 'false');
    menuToggle.setAttribute('aria-label', 'Open navigation menu');
    drawerCloseTimer = window.setTimeout(() => {
      if (!navDrawer.classList.contains('is-open')) {
        navDrawer.hidden = true;
        drawerBackdrop.hidden = true;
      }
    }, 230);
  };

  menuToggle?.addEventListener('click', () => {
    if (navDrawer?.classList.contains('is-open')) closeDrawer();
    else openDrawer();
  });
  drawerClose?.addEventListener('click', closeDrawer);
  drawerBackdrop?.addEventListener('click', closeDrawer);
  navDrawer?.querySelectorAll('a').forEach((link) => link.addEventListener('click', closeDrawer));

  const disclosure = document.getElementById('demoDisclosure');
  const disclosureContinue = document.getElementById('demoDisclosureContinue');
  const disclosureClose = document.getElementById('demoDisclosureClose');
  const disclosureStorageKey = 'honeyshield-demo-disclosure-seen';
  const closeDisclosure = () => {
    if (!disclosure) return;
    disclosure.hidden = true;
    try { window.sessionStorage.setItem(disclosureStorageKey, '1'); } catch (_error) { /* storage may be disabled */ }
    document.getElementById('username')?.focus();
  };
  if (disclosure) {
    let alreadySeen = false;
    try { alreadySeen = window.sessionStorage.getItem(disclosureStorageKey) === '1'; } catch (_error) { alreadySeen = false; }
    if (!alreadySeen) {
      disclosure.hidden = false;
      disclosureContinue?.focus();
    }
    disclosureContinue?.addEventListener('click', closeDisclosure);
    disclosureClose?.addEventListener('click', closeDisclosure);
  }

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      if (disclosure && !disclosure.hidden) closeDisclosure();
      if (navDrawer?.classList.contains('is-open')) closeDrawer();
      if (invModal && !invModal.hidden) closeInvestigation();
      if (canaryModal && !canaryModal.hidden) closeCanary();
    }
    if (event.key === 'Tab' && disclosure && !disclosure.hidden) {
      const focusable = [disclosureClose, disclosureContinue].filter((element) => element && !element.disabled);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  });

  document.querySelectorAll('[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const message = form.getAttribute('data-confirm') || 'Are you sure?';
      if (!window.confirm(message)) event.preventDefault();
    });
  });

  document.querySelectorAll('.flash-close').forEach((button) => {
    button.addEventListener('click', () => button.closest('.flash')?.remove());
  });

  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      const value = button.getAttribute('data-copy') || '';
      try {
        await navigator.clipboard.writeText(value);
        button.textContent = 'Copied';
      } catch (_error) {
        const field = document.createElement('textarea');
        field.value = value;
        field.setAttribute('readonly', '');
        field.style.position = 'fixed';
        field.style.opacity = '0';
        document.body.appendChild(field);
        field.select();
        const copied = document.execCommand('copy');
        field.remove();
        button.textContent = copied ? 'Copied' : 'Select text';
      }
      window.setTimeout(() => { button.textContent = 'Copy'; }, 1800);
    });
  });

  const fillDemoBtn = document.getElementById('fillDemoBtn');
  fillDemoBtn?.addEventListener('click', () => {
    const userField = document.getElementById('username');
    const passField = document.getElementById('password');
    if (userField && passField) {
      userField.value = 'demo';
      passField.value = 'ShieldDemo!2026';
      userField.focus();
    }
  });

  // --- HoneyShield SOC Telemetry & Interactive Visualizations ---
  const attemptsSvgChart = document.getElementById('attemptsSvgChart');
  const attemptsChartEmpty = document.getElementById('attemptsChartEmpty');
  const attemptsChartLoading = document.getElementById('attemptsChartLoading');
  const attemptsChartError = document.getElementById('attemptsChartError');
  const attemptsChartTooltip = document.getElementById('attemptsChartTooltip');
  const attemptsChartRetryBtn = document.getElementById('attemptsChartRetryBtn');
  const chartPills = document.querySelectorAll('.chart-pill');
  let currentChartWindow = 3600; // default 1h for immediate operational visibility

  const renderRiskDistribution = (summary) => {
    const s = summary || {};
    const total = s.sessions || 0;
    const low = s.low_sessions || 0;
    const elevated = s.elevated_sessions || 0;
    const high = s.high_sessions || 0;

    const lowPct = total > 0 ? (low * 100) / total : 0;
    const elvPct = total > 0 ? (elevated * 100) / total : 0;
    const hghPct = total > 0 ? (high * 100) / total : 0;

    const segLow = document.getElementById('distSegmentLow');
    const segElv = document.getElementById('distSegmentElevated');
    const segHgh = document.getElementById('distSegmentHigh');
    const emptyMsg = document.getElementById('distEmptyMsg');

    if (emptyMsg) {
      if (total === 0) emptyMsg.classList.remove('hidden');
      else emptyMsg.classList.add('hidden');
    }

    if (segLow) {
      segLow.style.width = `${lowPct}%`;
      segLow.setAttribute('title', `Low risk: ${low} (${Math.round(lowPct)}%)`);
      let lbl = segLow.querySelector('.dist-seg-label');
      if (!lbl) {
        lbl = document.createElement('span');
        lbl.className = 'dist-seg-label';
        segLow.appendChild(lbl);
      }
      lbl.textContent = lowPct >= 14 ? `${Math.round(lowPct)}%` : '';
    }
    if (segElv) {
      segElv.style.width = `${elvPct}%`;
      segElv.setAttribute('title', `Elevated risk: ${elevated} (${Math.round(elvPct)}%)`);
      let lbl = segElv.querySelector('.dist-seg-label');
      if (!lbl) {
        lbl = document.createElement('span');
        lbl.className = 'dist-seg-label';
        segElv.appendChild(lbl);
      }
      lbl.textContent = elvPct >= 14 ? `${Math.round(elvPct)}%` : '';
    }
    if (segHgh) {
      segHgh.style.width = `${hghPct}%`;
      segHgh.setAttribute('title', `High risk: ${high} (${Math.round(hghPct)}%)`);
      let lbl = segHgh.querySelector('.dist-seg-label');
      if (!lbl) {
        lbl = document.createElement('span');
        lbl.className = 'dist-seg-label';
        segHgh.appendChild(lbl);
      }
      lbl.textContent = hghPct >= 14 ? `${Math.round(hghPct)}%` : '';
    }

    // Update Counts
    const cntLow = document.getElementById('distCountLow');
    if (cntLow) cntLow.textContent = String(low);
    const cntElv = document.getElementById('distCountElevated');
    if (cntElv) cntElv.textContent = String(elevated);
    const cntHgh = document.getElementById('distCountHigh');
    if (cntHgh) cntHgh.textContent = String(high);

    // Update Percentage Tags
    const pctLow = document.getElementById('distPctLow');
    if (pctLow) pctLow.textContent = `${Math.round(lowPct)}%`;
    const pctElv = document.getElementById('distPctElevated');
    if (pctElv) pctElv.textContent = `${Math.round(elvPct)}%`;
    const pctHgh = document.getElementById('distPctHigh');
    if (pctHgh) pctHgh.textContent = `${Math.round(hghPct)}%`;
  };

  const renderAttemptsChart = (buckets) => {
    if (!attemptsSvgChart) return;
    attemptsSvgChart.innerHTML = '';

    if (!buckets || buckets.length === 0) {
      if (attemptsChartEmpty) attemptsChartEmpty.classList.remove('hidden');
      return;
    }
    if (attemptsChartEmpty) attemptsChartEmpty.classList.add('hidden');

    const width = 680;
    const height = 190;
    const pad = { top: 22, right: 25, bottom: 40, left: 45 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;

    // SVG Defs for striped simulation patterns
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');

    // Striped pattern for simulated failed
    const patF = document.createElementNS('http://www.w3.org/2000/svg', 'pattern');
    patF.setAttribute('id', 'simPatFailed');
    patF.setAttribute('width', '6');
    patF.setAttribute('height', '6');
    patF.setAttribute('patternUnits', 'userSpaceOnUse');
    patF.setAttribute('patternTransform', 'rotate(45)');
    const pRectF = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    pRectF.setAttribute('width', '6');
    pRectF.setAttribute('height', '6');
    pRectF.setAttribute('fill', 'rgba(255, 128, 140, 0.35)');
    const pLineF = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    pLineF.setAttribute('x1', '0'); pLineF.setAttribute('y1', '0');
    pLineF.setAttribute('x2', '0'); pLineF.setAttribute('y2', '6');
    pLineF.setAttribute('stroke', '#ff808c');
    pLineF.setAttribute('stroke-width', '2.5');
    patF.appendChild(pRectF);
    patF.appendChild(pLineF);
    defs.appendChild(patF);

    // Striped pattern for simulated success
    const patS = document.createElementNS('http://www.w3.org/2000/svg', 'pattern');
    patS.setAttribute('id', 'simPatSuccess');
    patS.setAttribute('width', '6');
    patS.setAttribute('height', '6');
    patS.setAttribute('patternUnits', 'userSpaceOnUse');
    patS.setAttribute('patternTransform', 'rotate(45)');
    const pRectS = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    pRectS.setAttribute('width', '6');
    pRectS.setAttribute('height', '6');
    pRectS.setAttribute('fill', 'rgba(105, 216, 244, 0.35)');
    const pLineS = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    pLineS.setAttribute('x1', '0'); pLineS.setAttribute('y1', '0');
    pLineS.setAttribute('x2', '0'); pLineS.setAttribute('y2', '6');
    pLineS.setAttribute('stroke', '#69d8f4');
    pLineS.setAttribute('stroke-width', '2.5');
    patS.appendChild(pRectS);
    patS.appendChild(pLineS);
    defs.appendChild(patS);

    attemptsSvgChart.appendChild(defs);

    const maxVal = Math.max(4, ...buckets.map((b) => Math.max(b.failed || 0, b.success || 0)));

    // Grid lines & Y-axis labels
    const ticks = 4;
    for (let i = 0; i <= ticks; i++) {
      const yVal = Math.round((maxVal / ticks) * i);
      const yPos = pad.top + plotH - (plotH / ticks) * i;

      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', String(pad.left));
      line.setAttribute('y1', String(yPos));
      line.setAttribute('x2', String(pad.left + plotW));
      line.setAttribute('y2', String(yPos));
      line.setAttribute('class', 'grid-line');
      attemptsSvgChart.appendChild(line);

      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('x', String(pad.left - 8));
      text.setAttribute('y', String(yPos + 3));
      text.setAttribute('text-anchor', 'end');
      text.textContent = String(yVal);
      attemptsSvgChart.appendChild(text);
    }

    // Baseline axis
    const axis = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    axis.setAttribute('x1', String(pad.left));
    axis.setAttribute('y1', String(pad.top + plotH));
    axis.setAttribute('x2', String(pad.left + plotW));
    axis.setAttribute('y2', String(pad.top + plotH));
    axis.setAttribute('class', 'axis-line');
    attemptsSvgChart.appendChild(axis);

    const n = buckets.length;
    const slotW = plotW / n;
    const maxBarWidth = Math.max(8, Math.min(22, (slotW - 8) / 2));
    const gap = 3;
    const clusterW = maxBarWidth * 2 + gap;

    buckets.forEach((b, idx) => {
      const slotX = pad.left + idx * slotW;
      const centerX = slotX + slotW / 2;
      const clusterStart = centerX - clusterW / 2;

      // Transparent interactive hover hitbox covering the full column
      const hitbox = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      hitbox.setAttribute('x', String(slotX));
      hitbox.setAttribute('y', String(pad.top));
      hitbox.setAttribute('width', String(slotW));
      hitbox.setAttribute('height', String(plotH));
      hitbox.setAttribute('class', 'hitbox');
      attemptsSvgChart.appendChild(hitbox);

      // Tooltip interaction
      const showTooltip = (evt) => {
        if (!attemptsChartTooltip) return;
        const shortTime = b.bucket.replace('T', ' ').replace('Z', ' UTC');
        const bFailed = b.browser_failed ?? (b.failed - (b.simulated_failed || 0));
        const sFailed = b.simulated_failed ?? 0;
        const bSuccess = b.browser_success ?? (b.success - (b.simulated_success || 0));
        const sSuccess = b.simulated_success ?? 0;
        const total = b.total ?? (b.failed + b.success);

        attemptsChartTooltip.innerHTML = `
          <div class="tooltip-header"><strong>${shortTime}</strong></div>
          <div class="tooltip-row"><span class="legend-dot dot-failed"></span> Failed: <strong>${b.failed}</strong> <small class="muted">(Live: ${bFailed}, Sim: ${sFailed})</small></div>
          <div class="tooltip-row"><span class="legend-dot dot-success"></span> Accepted: <strong>${b.success}</strong> <small class="muted">(Live: ${bSuccess}, Sim: ${sSuccess})</small></div>
          <div class="tooltip-row muted"><small>Total in bucket: ${total}</small></div>
        `;
        attemptsChartTooltip.hidden = false;
        const rect = attemptsSvgChart.getBoundingClientRect();
        const tipX = evt.clientX - rect.left + 12;
        const tipY = evt.clientY - rect.top - 20;
        attemptsChartTooltip.style.left = `${Math.min(tipX, rect.width - 180)}px`;
        attemptsChartTooltip.style.top = `${Math.max(10, tipY)}px`;
      };

      hitbox.addEventListener('mousemove', showTooltip);
      hitbox.addEventListener('mouseenter', showTooltip);
      hitbox.addEventListener('mouseleave', () => {
        if (attemptsChartTooltip) attemptsChartTooltip.hidden = true;
      });

      // Failed bar (coral)
      const fTotal = b.failed || 0;
      const fBrowser = b.browser_failed ?? (b.failed - (b.simulated_failed || 0));
      const fSim = b.simulated_failed ?? 0;

      if (fTotal > 0) {
        const totalH = (fTotal / maxVal) * plotH;
        const bH = (fBrowser / maxVal) * plotH;
        const sH = (fSim / maxVal) * plotH;
        const xPos = clusterStart;

        // Browser segment (solid coral)
        if (fBrowser > 0) {
          const rectB = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
          rectB.setAttribute('x', String(xPos));
          rectB.setAttribute('y', String(pad.top + plotH - bH));
          rectB.setAttribute('width', String(maxBarWidth));
          rectB.setAttribute('height', String(bH));
          rectB.setAttribute('rx', '2');
          rectB.setAttribute('fill', 'var(--red)');
          attemptsSvgChart.appendChild(rectB);
        }

        // Simulated segment (striped pattern)
        if (fSim > 0) {
          const rectS = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
          rectS.setAttribute('x', String(xPos));
          rectS.setAttribute('y', String(pad.top + plotH - totalH));
          rectS.setAttribute('width', String(maxBarWidth));
          rectS.setAttribute('height', String(sH));
          rectS.setAttribute('rx', '2');
          rectS.setAttribute('fill', 'url(#simPatFailed)');
          rectS.setAttribute('stroke', 'var(--red)');
          rectS.setAttribute('stroke-width', '0.5');
          attemptsSvgChart.appendChild(rectS);
        }
      }

      // Success bar (cyan)
      const sTotal = b.success || 0;
      const sBrowser = b.browser_success ?? (b.success - (b.simulated_success || 0));
      const sSim = b.simulated_success ?? 0;

      if (sTotal > 0) {
        const totalH = (sTotal / maxVal) * plotH;
        const bH = (sBrowser / maxVal) * plotH;
        const sH = (sSim / maxVal) * plotH;
        const xPos = clusterStart + maxBarWidth + gap;

        // Browser segment (solid cyan)
        if (sBrowser > 0) {
          const rectB = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
          rectB.setAttribute('x', String(xPos));
          rectB.setAttribute('y', String(pad.top + plotH - bH));
          rectB.setAttribute('width', String(maxBarWidth));
          rectB.setAttribute('height', String(bH));
          rectB.setAttribute('rx', '2');
          rectB.setAttribute('fill', 'var(--cyan)');
          attemptsSvgChart.appendChild(rectB);
        }

        // Simulated segment (striped pattern)
        if (sSim > 0) {
          const rectS = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
          rectS.setAttribute('x', String(xPos));
          rectS.setAttribute('y', String(pad.top + plotH - totalH));
          rectS.setAttribute('width', String(maxBarWidth));
          rectS.setAttribute('height', String(sH));
          rectS.setAttribute('rx', '2');
          rectS.setAttribute('fill', 'url(#simPatSuccess)');
          rectS.setAttribute('stroke', 'var(--cyan)');
          rectS.setAttribute('stroke-width', '0.5');
          attemptsSvgChart.appendChild(rectS);
        }
      }

      // Time label on X axis
      const labelInterval = n > 12 ? Math.ceil(n / 6) : 1;
      if (idx % labelInterval === 0 || idx === n - 1) {
        const labelText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        labelText.setAttribute('x', String(centerX));
        labelText.setAttribute('y', String(pad.top + plotH + 18));
        labelText.setAttribute('text-anchor', 'middle');
        const shortTime = b.bucket.substring(11, 16);
        labelText.textContent = shortTime;
        attemptsSvgChart.appendChild(labelText);
      }
    });
  };

  const loadAttemptsChart = async (windowSeconds) => {
    if (!attemptsSvgChart) return;
    if (attemptsChartLoading) attemptsChartLoading.classList.remove('hidden');
    if (attemptsChartError) attemptsChartError.classList.add('hidden');

    try {
      const resp = await fetch(`/api/chart/attempts?window=${windowSeconds}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      renderAttemptsChart(data.buckets || []);
    } catch (_err) {
      if (attemptsChartEmpty) attemptsChartEmpty.classList.add('hidden');
      if (attemptsChartError) attemptsChartError.classList.remove('hidden');
      attemptsSvgChart.innerHTML = '';
    } finally {
      if (attemptsChartLoading) attemptsChartLoading.classList.add('hidden');
    }
  };

  attemptsChartRetryBtn?.addEventListener('click', () => {
    loadAttemptsChart(currentChartWindow);
  });

  chartPills.forEach((pill) => {
    pill.addEventListener('click', () => {
      chartPills.forEach((p) => {
        p.classList.remove('active');
        p.setAttribute('aria-pressed', 'false');
      });
      pill.classList.add('active');
      pill.setAttribute('aria-pressed', 'true');
      currentChartWindow = pill.getAttribute('data-window') || '3600';
      loadAttemptsChart(currentChartWindow);
    });
  });

  // Initial chart and risk distribution load if on admin control room
  if (attemptsSvgChart) {
    loadAttemptsChart(currentChartWindow);
    fetch('/api/metrics')
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data && data.summary) renderRiskDistribution(data.summary);
      })
      .catch(() => {});
  }

  // Refresh Telemetry Button
  const refreshMetricsBtn = document.getElementById('refreshMetricsBtn');
  const refreshSpinner = document.getElementById('refreshSpinner');
  const freshnessText = document.getElementById('freshnessText');

  refreshMetricsBtn?.addEventListener('click', async () => {
    if (refreshSpinner) refreshSpinner.classList.add('spinning');
    try {
      const [metricsResp] = await Promise.all([
        fetch('/api/metrics'),
        loadAttemptsChart(currentChartWindow),
      ]);

      if (metricsResp && metricsResp.ok) {
        const data = await metricsResp.json();
        const s = data.summary || {};

        // Update KPIs
        const kpiSessions = document.getElementById('kpiSessions');
        if (kpiSessions) kpiSessions.textContent = String(s.sessions ?? 0);

        const kpiAttempts = document.getElementById('kpiAttempts');
        if (kpiAttempts) {
          kpiAttempts.innerHTML = `${s.failed_attempts ?? 0} <span class="metric-subval muted">/ ${s.total_attempts ?? 0}</span>`;
        }

        const kpiElevated = document.getElementById('kpiElevated');
        if (kpiElevated) kpiElevated.textContent = String(s.elevated_sessions ?? 0);

        const kpiHighRisk = document.getElementById('kpiHighRisk');
        if (kpiHighRisk) kpiHighRisk.textContent = String(s.high_sessions ?? 0);

        const kpiDecoys = document.getElementById('kpiDecoys');
        if (kpiDecoys) kpiDecoys.textContent = String(s.decoys ?? 0);

        const kpiInteractions = document.getElementById('kpiInteractions');
        if (kpiInteractions) kpiInteractions.textContent = String(s.interactions ?? 0);

        // Update Risk Distribution Bar and tags
        renderRiskDistribution(s);

        // Update Freshness status
        if (freshnessText) {
          const now = new Date();
          const padZero = (n) => String(n).padStart(2, '0');
          freshnessText.textContent = `Sync: ${padZero(now.getHours())}:${padZero(now.getMinutes())}:${padZero(now.getSeconds())}`;
        }
      }
    } catch (_err) {
      if (freshnessText) freshnessText.textContent = 'Sync: Retry';
    } finally {
      if (refreshSpinner) refreshSpinner.classList.remove('spinning');
    }
  });

  // --- Session Deep-Dive Investigation Modal ---
  const invModal = document.getElementById('investigationModal');
  const invBackdrop = document.getElementById('investigationBackdrop');
  const closeInvBtn = document.getElementById('closeInvestigationBtn');
  const closeInvBtnBottom = document.getElementById('closeInvBtnBottom');

  const closeInvestigation = () => {
    if (!invModal || !invBackdrop) return;
    invModal.hidden = true;
    invBackdrop.hidden = true;
  };

  closeInvBtn?.addEventListener('click', closeInvestigation);
  closeInvBtnBottom?.addEventListener('click', closeInvestigation);
  invBackdrop?.addEventListener('click', closeInvestigation);

  const openInvestigation = async (sessionKey) => {
    if (!invModal || !invBackdrop) return;
    invModal.hidden = false;
    invBackdrop.hidden = false;

    const keyDisplay = document.getElementById('invSessionKeyDisplay');
    if (keyDisplay) keyDisplay.textContent = sessionKey;

    const signalsGrid = document.getElementById('invSignalsGrid');
    if (signalsGrid) {
      signalsGrid.innerHTML = '<div class="muted" style="padding:10px;">Loading heuristic signals...</div>';
    }
    const timelineEl = document.getElementById('invTimeline');
    if (timelineEl) {
      timelineEl.innerHTML = '<div class="muted" style="padding:10px;">Loading session events...</div>';
    }

    try {
      const resp = await fetch(`/api/session/${encodeURIComponent(sessionKey)}`);
      if (!resp.ok) {
        if (signalsGrid) signalsGrid.innerHTML = '<div class="text-red">Failed to load session details.</div>';
        return;
      }
      const resJson = await resp.json();
      const data = resJson.session || resJson;

      // Copy session ID button
      const copySidBtn = document.getElementById('invCopySidBtn');
      if (copySidBtn) copySidBtn.setAttribute('data-copy', sessionKey);

      // Export Buttons
      const expJsonBtn = document.getElementById('invExportJsonBtn');
      if (expJsonBtn) expJsonBtn.href = `/admin/session/${encodeURIComponent(sessionKey)}/export?format=json`;
      const expCsvBtn = document.getElementById('invExportCsvBtn');
      if (expCsvBtn) expCsvBtn.href = `/admin/session/${encodeURIComponent(sessionKey)}/export?format=csv`;

      // Top metrics
      const riskScore = document.getElementById('invRiskScoreDisplay');
      if (riskScore) riskScore.textContent = String(data.risk_score ?? 0);

      const bandBadge = document.getElementById('invRiskBandBadge');
      if (bandBadge) {
        bandBadge.textContent = data.risk_band || 'LOW';
        bandBadge.className = `risk-badge risk-badge-${(data.risk_band || 'low').toLowerCase()}`;
      }

      const decisionBadge = document.getElementById('invDecisionBadge');
      if (decisionBadge) {
        decisionBadge.textContent = (data.decision || 'NORMAL').toUpperCase();
      }

      const decoyState = document.getElementById('invDecoyStateBadge');
      if (decoyState) {
        decoyState.textContent = data.decoy_active ? 'Active Sandbox' : 'Inactive';
        decoyState.className = data.decoy_active ? 'status-chip status-danger' : 'status-chip status-safe';
      }

      const eventsCount = document.getElementById('invEventsCount');
      if (eventsCount) eventsCount.textContent = String(data.events_count || 0);

      const timelineCount = document.getElementById('invTimelineCount');
      if (timelineCount) timelineCount.textContent = `${data.events ? data.events.length : 0} events recorded`;

      // Attack-Path Reconstruction Pipeline
      const pipelineEl = document.getElementById('invAttackPathPipeline');
      if (pipelineEl && data.attack_path) {
        pipelineEl.innerHTML = '';
        data.attack_path.forEach((step, idx) => {
          const stepDiv = document.createElement('div');
          stepDiv.className = `attack-step step-status-${step.status || 'info'}`;
          stepDiv.innerHTML = `
            <div class="step-node-col">
              <span class="step-num-circle">${step.step}</span>
              ${idx < data.attack_path.length - 1 ? '<div class="step-line"></div>' : ''}
            </div>
            <div class="step-card card-surface">
              <div class="step-card-top">
                <strong class="step-title">${escapeHtml(step.title)}</strong>
                <span class="step-badge badge-${step.status || 'info'}">${escapeHtml(step.badge)}</span>
              </div>
              <p class="step-desc">${escapeHtml(step.description)}</p>
              <div class="step-meta">
                <small class="muted">Timestamp: ${escapeHtml(step.timestamp || '')}</small>
                ${step.event_id ? `<span class="event-ref-tag">Event #${step.event_id}</span>` : ''}
              </div>
            </div>
          `;
          pipelineEl.appendChild(stepDiv);
        });
      }

      // 7 Signals Grid
      if (signalsGrid && data.signal_contributions) {
        signalsGrid.innerHTML = '';
        data.signal_contributions.forEach((sig) => {
          const card = document.createElement('div');
          card.className = `inv-signal-card ${sig.triggered ? 'signal-active' : ''}`;

          const topRow = document.createElement('div');
          topRow.className = 'inv-signal-top';

          const title = document.createElement('strong');
          title.className = 'inv-signal-title';
          title.textContent = sig.name.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

          const badge = document.createElement('span');
          badge.className = `inv-signal-badge ${sig.triggered ? 'badge-triggered' : 'badge-normal'}`;
          badge.textContent = sig.triggered ? `+${sig.weight} TRIGGERED` : `+${sig.weight} NORMAL`;

          topRow.appendChild(title);
          topRow.appendChild(badge);

          const desc = document.createElement('p');
          desc.className = 'inv-signal-desc';
          desc.textContent = sig.description || '';

          const evidDiv = document.createElement('div');
          evidDiv.className = 'inv-signal-evidence';
          evidDiv.innerHTML = sig.triggered
            ? `<span class="evidence-tag tag-active">Active Contribution: +${sig.weight} pts</span>`
            : '<span class="evidence-tag tag-inactive">Within normal baseline</span>';

          card.appendChild(topRow);
          card.appendChild(desc);
          card.appendChild(evidDiv);
          signalsGrid.appendChild(card);
        });
      }

      // Chronological Timeline with expandable technical inspection
      if (timelineEl && data.events) {
        timelineEl.innerHTML = '';
        if (data.events.length === 0) {
          timelineEl.innerHTML = '<div class="muted">No events recorded for this session.</div>';
        } else {
          data.events.forEach((ev) => {
            const item = document.createElement('div');
            item.className = 'timeline-item';

            const dot = document.createElement('span');
            let dotClass = 'timeline-dot ';
            const evType = ev.event_type || '';
            if (evType.includes('activated') || evType.includes('admin_resource')) {
              dotClass += 'dot-danger';
            } else if (evType.includes('decoy')) {
              dotClass += 'dot-violet';
            } else if (evType.includes('failed')) {
              dotClass += 'dot-amber';
            } else {
              dotClass += 'dot-cyan';
            }
            dot.className = dotClass;

            const body = document.createElement('div');
            body.className = 'timeline-body';

            const titleRow = document.createElement('div');
            titleRow.className = 'timeline-title-row';
            const titleStrong = document.createElement('strong');
            titleStrong.textContent = evType.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
            titleRow.appendChild(titleStrong);

            const evIdBadge = document.createElement('span');
            evIdBadge.className = 'event-id-badge';
            evIdBadge.textContent = `#${ev.id}`;
            titleRow.appendChild(evIdBadge);

            const timeSmall = document.createElement('small');
            const intervalText = ev.interval_seconds !== null && ev.interval_seconds !== undefined
              ? ` · ${Number(ev.interval_seconds).toFixed(2)}s interval`
              : '';
            timeSmall.textContent = `${ev.event_at}${intervalText}`;

            body.appendChild(titleRow);
            body.appendChild(timeSmall);

            if (ev.details && (ev.details.label || ev.details.reason || ev.details.note)) {
              const p = document.createElement('p');
              p.textContent = ev.details.label || ev.details.reason || ev.details.note;
              body.appendChild(p);
            }

            // Expandable raw telemetry details
            const detailsEl = document.createElement('details');
            detailsEl.className = 'timeline-expandable';
            detailsEl.innerHTML = `
              <summary class="timeline-summary-toggle">Inspect raw telemetry details</summary>
              <div class="timeline-raw-details">
                <div class="raw-row"><span>Event ID</span><code>${ev.id}</code></div>
                <div class="raw-row"><span>Timestamp UTC</span><code>${escapeHtml(ev.event_at)}</code></div>
                <div class="raw-row"><span>Interval Seconds</span><code>${ev.interval_seconds !== null ? ev.interval_seconds : 'N/A (first event)'}</code></div>
                ${ev.username_fingerprint ? `<div class="raw-row"><span>HMAC Fingerprint</span><code>${escapeHtml(ev.username_fingerprint)}</code></div>` : ''}
                <div class="raw-row"><span>Details Payload</span><pre><code>${escapeHtml(JSON.stringify(ev.details || {}, null, 2))}</code></pre></div>
              </div>
            `;
            body.appendChild(detailsEl);

            item.appendChild(dot);
            item.appendChild(body);
            timelineEl.appendChild(item);
          });
        }
      }

      // Decoy Action Link
      const decoyWrap = document.getElementById('invDecoyActionWrap');
      const decoyBtn = document.getElementById('invDecoyBtn');
      if (decoyWrap && decoyBtn) {
        if (data.decoy_active) {
          decoyWrap.hidden = false;
          decoyBtn.href = `/admin/decoy/${encodeURIComponent(sessionKey)}`;
        } else {
          decoyWrap.hidden = true;
        }
      }

      // Full Flight Recorder Link
      const fullPageBtn = document.getElementById('invFullPageBtn');
      if (fullPageBtn) {
        fullPageBtn.href = `/admin/session/${encodeURIComponent(sessionKey)}`;
      }
    } catch (_err) {
      if (signalsGrid) signalsGrid.innerHTML = '<div class="text-red">Error querying session details.</div>';
    }
  };

  // Inspect session button delegation
  document.addEventListener('click', (event) => {
    const target = event.target;
    if (target && target.classList && target.classList.contains('inspect-session-btn')) {
      const sessionKey = target.getAttribute('data-session-key');
      if (sessionKey) openInvestigation(sessionKey);
    }
  });

  // KPI card click to filter & inspect
  document.querySelectorAll('.clickable-kpi').forEach((card) => {
    card.addEventListener('click', () => {
      const filterType = card.getAttribute('data-kpi-filter');
      const band = card.getAttribute('data-kpi-band');
      const currentUrl = new URL(window.location.href);

      if (filterType === 'interactions') {
        const stream = document.getElementById('event-stream');
        if (stream) {
          stream.scrollIntoView({ behavior: 'smooth' });
          stream.classList.add('highlight-panel');
          setTimeout(() => stream.classList.remove('highlight-panel'), 1600);
        }
        return;
      }
      if (filterType === 'attempts') {
        const chart = document.getElementById('attemptsChartCard');
        if (chart) {
          chart.scrollIntoView({ behavior: 'smooth' });
          chart.classList.add('highlight-panel');
          setTimeout(() => chart.classList.remove('highlight-panel'), 1600);
        }
        return;
      }

      if (band) {
        if (currentUrl.searchParams.get('band') === band) {
          currentUrl.searchParams.delete('band');
          window.location.href = currentUrl.pathname + (currentUrl.search ? currentUrl.search : '');
        } else {
          currentUrl.searchParams.set('band', band);
          window.location.href = currentUrl.pathname + currentUrl.search;
        }
      } else {
        window.location.href = '/admin';
      }
    });
  });

  // Risk distribution bar segments click to filter
  document.getElementById('distSegmentLow')?.addEventListener('click', () => {
    window.location.href = '/admin?band=LOW';
  });
  document.getElementById('distSegmentElevated')?.addEventListener('click', () => {
    window.location.href = '/admin?band=ELEVATED';
  });
  document.getElementById('distSegmentHigh')?.addEventListener('click', () => {
    window.location.href = '/admin?band=HIGH';
  });

  // Top shared filter bar time pills synchronization
  const sharedForm = document.getElementById('socSharedFilterForm');
  const sharedTimeInput = document.getElementById('sharedTimeFilter');
  if (sharedForm && sharedTimeInput) {
    const sharedPills = sharedForm.querySelectorAll('.chart-pill');
    sharedPills.forEach((p) => {
      p.addEventListener('click', () => {
        const win = p.getAttribute('data-window') || 'all';
        sharedTimeInput.value = win;
        sharedForm.submit();
      });
    });
  }

  // Smooth KPI count-up animation on initial page load
  if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    const animateCount = (el, target) => {
      if (!el || isNaN(target) || target <= 0) return;
      const duration = 380;
      const start = performance.now();
      const step = (now) => {
        const progress = Math.min(1, (now - start) / duration);
        const current = Math.floor(progress * target);
        el.textContent = String(current);
        if (progress < 1) requestAnimationFrame(step);
        else el.textContent = String(target);
      };
      requestAnimationFrame(step);
    };
    const sEl = document.getElementById('kpiSessions');
    if (sEl) {
      const sVal = parseInt(sEl.textContent.trim(), 10);
      if (!isNaN(sVal) && sVal > 0) animateCount(sEl, sVal);
    }
    const eEl = document.getElementById('kpiElevated');
    if (eEl) {
      const eVal = parseInt(eEl.textContent.trim(), 10);
      if (!isNaN(eVal) && eVal > 0) animateCount(eEl, eVal);
    }
    const hEl = document.getElementById('kpiHighRisk');
    if (hEl) {
      const hVal = parseInt(hEl.textContent.trim(), 10);
      if (!isNaN(hVal) && hVal > 0) animateCount(hEl, hVal);
    }
    const dEl = document.getElementById('kpiDecoys');
    if (dEl) {
      const dVal = parseInt(dEl.textContent.trim(), 10);
      if (!isNaN(dVal) && dVal > 0) animateCount(dEl, dVal);
    }
  }

  // --- Synthetic Canary Modal Controller ---
  const canaryModal = document.getElementById('canaryModal');
  const canaryBackdrop = document.getElementById('canaryBackdrop');
  const closeCanaryBtn = document.getElementById('closeCanaryBtn');
  const closeCanaryBtnBottom = document.getElementById('closeCanaryBtnBottom');

  const closeCanary = () => {
    if (!canaryModal || !canaryBackdrop) return;
    canaryModal.hidden = true;
    canaryBackdrop.hidden = true;
  };

  closeCanaryBtn?.addEventListener('click', closeCanary);
  closeCanaryBtnBottom?.addEventListener('click', closeCanary);
  canaryBackdrop?.addEventListener('click', closeCanary);

  const openCanaryModal = async (canaryId) => {
    if (!canaryModal || !canaryBackdrop) return;
    try {
      const resp = await fetch(`/decoy/canary/${encodeURIComponent(canaryId)}`);
      if (!resp.ok) return;
      const data = await resp.json();
      const canary = data.canary || {};

      const titleEl = document.getElementById('canaryModalTitle');
      if (titleEl) titleEl.textContent = canary.title || 'Canary Object';

      const warningEl = document.getElementById('canaryWarningText');
      if (warningEl) warningEl.textContent = canary.warning || 'Synthetic decoy object.';

      const tokenEl = document.getElementById('canaryTokenValue');
      if (tokenEl) tokenEl.textContent = canary.canary_token || (canary.data ? JSON.stringify(canary.data, null, 2) : 'HS-CANARY-ACTIVE');

      const idEl = document.getElementById('canaryObjectId');
      if (idEl) idEl.textContent = canary.object_id || canaryId;

      const classEl = document.getElementById('canaryClassification');
      if (classEl) classEl.textContent = canary.classification || 'Synthetic Lure';

      canaryModal.hidden = false;
      canaryBackdrop.hidden = false;
    } catch (_err) {
      // non-blocking fallback
    }
  };

  // Canary trigger button delegation
  document.addEventListener('click', (event) => {
    const target = event.target;
    if (target && target.classList && target.classList.contains('canary-action-btn')) {
      const canaryId = target.getAttribute('data-canary');
      if (canaryId) {
        event.preventDefault();
        openCanaryModal(canaryId);
      }
    }
  });

  // --- Scenario Lab: What-If Policy Threshold Controller ---
  const whatifSlider = document.getElementById('whatifSlider');
  const whatifSessionSelect = document.getElementById('whatifSessionSelect');
  const sliderValueText = document.getElementById('sliderValueText');
  const whatifThresholdVal = document.getElementById('whatifThresholdVal');
  const whatifScoreVal = document.getElementById('whatifScoreVal');
  const whatifBandVal = document.getElementById('whatifBandVal');
  const whatifDecisionVal = document.getElementById('whatifDecisionVal');
  const whatifImpactText = document.getElementById('whatifImpactText');
  const activeScoreVal = document.getElementById('activeScoreVal');
  const activeBandVal = document.getElementById('activeBandVal');
  const activeDecisionVal = document.getElementById('activeDecisionVal');

  if (whatifSlider && whatifSessionSelect) {
    let whatifDebounceTimer = null;

    const runWhatIfEvaluation = async () => {
      const sessionKey = whatifSessionSelect.value;
      const threshold = parseInt(whatifSlider.value, 10) || 50;
      if (sliderValueText) sliderValueText.textContent = String(threshold);
      if (whatifThresholdVal) whatifThresholdVal.textContent = `${threshold} / 100`;

      if (!sessionKey) return;

      try {
        const resp = await fetch('/api/lab/whatif', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_key: sessionKey, threshold: threshold })
        });
        if (!resp.ok) return;
        const data = await resp.json();

        // Update Active Policy box
        if (activeScoreVal) activeScoreVal.textContent = String(data.active_score ?? '—');
        if (activeBandVal) activeBandVal.textContent = String(data.active_band ?? '—');
        if (activeDecisionVal) {
          activeDecisionVal.textContent = data.active_decision === 'CONTAIN' ? 'CONTAIN (Decoy)' : 'ALLOW (Normal)';
          activeDecisionVal.className = data.active_decision === 'CONTAIN' ? 'text-red' : 'text-green';
        }

        // Update What-If Candidate Policy box
        if (whatifScoreVal) whatifScoreVal.textContent = String(data.whatif_score ?? '—');
        if (whatifBandVal) whatifBandVal.textContent = String(data.whatif_band ?? '—');
        if (whatifDecisionVal) {
          whatifDecisionVal.textContent = data.whatif_decision === 'CONTAIN' ? 'CONTAIN (Decoy)' : 'ALLOW (Normal)';
          whatifDecisionVal.className = data.whatif_decision === 'CONTAIN' ? 'text-red' : 'text-green';
        }

        // Update Impact banner
        if (whatifImpactText && data.impact_analysis) {
          whatifImpactText.textContent = data.impact_analysis;
        }
      } catch (_err) {
        // non-blocking fallback
      }
    };

    whatifSlider.addEventListener('input', () => {
      const val = whatifSlider.value;
      if (sliderValueText) sliderValueText.textContent = String(val);
      if (whatifThresholdVal) whatifThresholdVal.textContent = `${val} / 100`;
      clearTimeout(whatifDebounceTimer);
      whatifDebounceTimer = setTimeout(runWhatIfEvaluation, 120);
    });

    whatifSessionSelect.addEventListener('change', runWhatIfEvaluation);

    // Initial run if session selected
    if (whatifSessionSelect.value) {
      runWhatIfEvaluation();
    }
  }

  // Interactive Demonstration: Same Login, Two Realities
  const btnBoth = document.getElementById('btnRealityBoth');
  const btnNormal = document.getElementById('btnRealityNormal');
  const btnAttacker = document.getElementById('btnRealityAttacker');
  const cardLegit = document.getElementById('realityCardLegit');
  const cardAttacker = document.getElementById('realityCardAttacker');

  if (btnBoth && btnNormal && btnAttacker && cardLegit && cardAttacker) {
    const setRealityMode = (mode) => {
      [btnBoth, btnNormal, btnAttacker].forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      if (mode === 'normal') {
        btnNormal.classList.add('active');
        btnNormal.setAttribute('aria-selected', 'true');
        cardLegit.style.display = 'flex';
        cardAttacker.style.display = 'none';
      } else if (mode === 'attacker') {
        btnAttacker.classList.add('active');
        btnAttacker.setAttribute('aria-selected', 'true');
        cardLegit.style.display = 'none';
        cardAttacker.style.display = 'flex';
      } else {
        btnBoth.classList.add('active');
        btnBoth.setAttribute('aria-selected', 'true');
        cardLegit.style.display = 'flex';
        cardAttacker.style.display = 'flex';
      }
    };

    btnBoth.addEventListener('click', () => setRealityMode('both'));
    btnNormal.addEventListener('click', () => setRealityMode('normal'));
    btnAttacker.addEventListener('click', () => setRealityMode('attacker'));
  }

  // Prevent bfcache from restoring stale protected workspace state after logout
  window.addEventListener('pageshow', (event) => {
    if (event.persisted && window.location.pathname.includes('/dashboard')) {
      window.location.reload();
    }
  });
});
