/**
 * PROMPTASTRA - Security Overview Dashboard JavaScript
 * Renders high-performance interactive Canvas timeline chart for threat telemetry.
 */

document.addEventListener('DOMContentLoaded', () => {
  initThreatTimelineChart();
});

function initThreatTimelineChart() {
  const canvas = document.getElementById('threatTimelineCanvas');
  const container = document.getElementById('threatTimelineChartWrap');
  if (!canvas || !container) return;

  const ctx = canvas.getContext('2d');

  // 24-hour demo telemetry data series
  const data = [
    { time: "00:00", allowed: 4200, blocked: 310, reviewed: 42 },
    { time: "02:00", allowed: 3800, blocked: 280, reviewed: 31 },
    { time: "04:00", allowed: 3100, blocked: 190, reviewed: 25 },
    { time: "06:00", allowed: 4600, blocked: 390, reviewed: 50 },
    { time: "08:00", allowed: 8900, blocked: 720, reviewed: 94 },
    { time: "10:00", allowed: 14200, blocked: 1280, reviewed: 160 },
    { time: "12:00", allowed: 13800, blocked: 1150, reviewed: 145 },
    { time: "14:00", allowed: 15400, blocked: 1420, reviewed: 180 },
    { time: "16:00", allowed: 16100, blocked: 1510, reviewed: 192 },
    { time: "18:00", allowed: 12300, blocked: 1020, reviewed: 130 },
    { time: "20:00", allowed: 9400, blocked: 790, reviewed: 98 },
    { time: "22:00", allowed: 6100, blocked: 480, reviewed: 60 }
  ];

  let mouseX = -1;

  function resizeCanvas() {
    const dpr = window.devicePixelRatio || 1;
    const rect = container.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    render(rect.width, rect.height);
  }

  function render(width, height) {
    ctx.clearRect(0, 0, width, height);

    const padLeft = 45;
    const padRight = 20;
    const padTop = 20;
    const padBottom = 30;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    const maxVal = 18000;
    const ySteps = 4;

    // Draw horizontal grid lines & labels
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    ctx.fillStyle = '#64748b';
    ctx.font = '10px JetBrains Mono, monospace';
    ctx.textAlign = 'right';

    for (let i = 0; i <= ySteps; i++) {
      const yVal = Math.round((maxVal / ySteps) * i);
      const yPos = padTop + plotH - (plotH * (i / ySteps));
      
      ctx.beginPath();
      ctx.moveTo(padLeft, yPos);
      ctx.lineTo(width - padRight, yPos);
      ctx.stroke();

      ctx.fillText((yVal / 1000).toFixed(0) + 'k', padLeft - 8, yPos + 3);
    }

    const n = data.length;
    const stepX = plotW / (n - 1);

    // Compute point coordinates
    const allowedPts = [];
    const blockedPts = [];
    const reviewPts = [];

    data.forEach((d, i) => {
      const x = padLeft + i * stepX;
      const yAllowed = padTop + plotH - (d.allowed / maxVal) * plotH;
      const yBlocked = padTop + plotH - (d.blocked * 10 / maxVal) * plotH; // scaled 10x for visual clarity
      const yReview = padTop + plotH - (d.reviewed * 30 / maxVal) * plotH;

      allowedPts.push({ x, y: yAllowed });
      blockedPts.push({ x, y: yBlocked });
      reviewPts.push({ x, y: yReview });

      // Draw X axis timestamps
      ctx.textAlign = 'center';
      ctx.fillStyle = '#64748b';
      ctx.fillText(d.time, x, height - 10);
    });

    // Draw Blocked Attack Area Gradient (Crimson)
    const blockGrad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
    blockGrad.addColorStop(0, 'rgba(239, 68, 68, 0.25)');
    blockGrad.addColorStop(1, 'rgba(239, 68, 68, 0.0)');

    ctx.beginPath();
    ctx.moveTo(blockedPts[0].x, padTop + plotH);
    blockedPts.forEach(pt => ctx.lineTo(pt.x, pt.y));
    ctx.lineTo(blockedPts[n - 1].x, padTop + plotH);
    ctx.closePath();
    ctx.fillStyle = blockGrad;
    ctx.fill();

    // Draw Lines
    drawLine(ctx, allowedPts, '#38bdf8', 2);
    drawLine(ctx, blockedPts, '#ef4444', 2.5);
    drawLine(ctx, reviewPts, '#f59e0b', 1.8, [4, 4]);

    // Draw Points on Blocked Attacks
    blockedPts.forEach(pt => {
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = '#ef4444';
      ctx.fill();
      ctx.strokeStyle = '#0f172a';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });

    // Interactive Hover Crosshair
    if (mouseX >= padLeft && mouseX <= width - padRight) {
      const idx = Math.min(Math.max(0, Math.round((mouseX - padLeft) / stepX)), n - 1);
      const hoveredX = padLeft + idx * stepX;
      const curData = data[idx];

      // Vertical line
      ctx.beginPath();
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 3]);
      ctx.moveTo(hoveredX, padTop);
      ctx.lineTo(hoveredX, padTop + plotH);
      ctx.stroke();
      ctx.setLineDash([]);

      // Tooltip Card
      const ttW = 140;
      const ttH = 68;
      let ttX = hoveredX + 12;
      if (ttX + ttW > width - padRight) ttX = hoveredX - ttW - 12;
      const ttY = padTop + 10;

      ctx.fillStyle = 'rgba(15, 23, 42, 0.92)';
      ctx.strokeStyle = '#334155';
      ctx.lineWidth = 1;
      roundRect(ctx, ttX, ttY, ttW, ttH, 6);
      ctx.fill();
      ctx.stroke();

      ctx.textAlign = 'left';
      ctx.fillStyle = '#94a3b8';
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.fillText(`TIME: ${curData.time}`, ttX + 10, ttY + 16);

      ctx.fillStyle = '#38bdf8';
      ctx.fillText(`ALLOW: ${curData.allowed.toLocaleString()}`, ttX + 10, ttY + 32);

      ctx.fillStyle = '#ef4444';
      ctx.fillText(`BLOCK: ${curData.blocked.toLocaleString()}`, ttX + 10, ttY + 48);

      ctx.fillStyle = '#f59e0b';
      ctx.fillText(`REVIEW: ${curData.reviewed}`, ttX + 10, ttY + 62);
    }
  }

  function drawLine(ctx, points, color, width, dash = []) {
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = width;
    ctx.setLineDash(dash);
    points.forEach((pt, i) => {
      if (i === 0) ctx.moveTo(pt.x, pt.y);
      else ctx.lineTo(pt.x, pt.y);
    });
    ctx.stroke();
    ctx.setLineDash([]);
  }

  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }

  container.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    mouseX = e.clientX - rect.left;
    const curRect = container.getBoundingClientRect();
    render(curRect.width, curRect.height);
  });

  container.addEventListener('mouseleave', () => {
    mouseX = -1;
    const curRect = container.getBoundingClientRect();
    render(curRect.width, curRect.height);
  });

  window.addEventListener('resize', resizeCanvas);
  resizeCanvas();
}
