/**
 * PROMPTASTRA & PROMPTGUARD
 * Global Application Core JavaScript
 * Handles brand opening reveal, mobile navigation, toast system, and global state.
 */

document.addEventListener('DOMContentLoaded', () => {
  initBrandReveal();
  initMobileNavigation();
  initGlobalToastSystem();

  // Register PWA Service Worker
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js')
        .then((reg) => console.log('[PWA] Service Worker registered with scope:', reg.scope))
        .catch((err) => console.warn('[PWA] Service Worker registration failed:', err));
    });
  }
});

/* ==========================================================================
   PROMPTASTRA BRAND REVEAL ORCHESTRATION
   ========================================================================== */
function initBrandReveal() {
  const overlay = document.getElementById('brand-opening-overlay');
  const skipBtn = document.getElementById('btn-skip-reveal');
  const replayBtn = document.getElementById('btn-replay-intro');

  if (!overlay) return;

  // Check for reduced motion preference
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReducedMotion) {
    overlay.classList.add('hide-reveal');
    return;
  }

  // Check if shown in current session
  const hasSeenIntro = sessionStorage.getItem('promptastra_intro_viewed');

  if (hasSeenIntro) {
    overlay.classList.add('hide-reveal');
  } else {
    // Sequence timing: 1.8s total smooth reveal
    const introTimer = setTimeout(() => {
      dismissReveal(overlay);
      sessionStorage.setItem('promptastra_intro_viewed', 'true');
    }, 1900);

    if (skipBtn) {
      skipBtn.addEventListener('click', () => {
        clearTimeout(introTimer);
        dismissReveal(overlay);
        sessionStorage.setItem('promptastra_intro_viewed', 'true');
      });
    }
  }

  // Replay functionality
  if (replayBtn) {
    replayBtn.addEventListener('click', () => {
      overlay.classList.remove('hide-reveal');
      
      const card = overlay.querySelector('.reveal-card');
      if (card) {
        card.style.animation = 'none';
        void card.offsetWidth; // force reflow
        card.style.animation = '';
      }

      const progress = overlay.querySelector('.reveal-progress-fill');
      if (progress) {
        progress.style.animation = 'none';
        void progress.offsetWidth;
        progress.style.animation = '';
      }

      setTimeout(() => {
        dismissReveal(overlay);
      }, 2100);
    });
  }
}

function dismissReveal(overlay) {
  overlay.classList.add('hide-reveal');
}

/* ==========================================================================
   MOBILE NAVIGATION TOGGLE
   ========================================================================== */
function initMobileNavigation() {
  const toggleBtn = document.getElementById('mobileSidebarToggle');
  const sidebar = document.getElementById('appSidebar');

  if (!toggleBtn || !sidebar) return;

  toggleBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    sidebar.classList.toggle('sidebar-open');
  });

  document.addEventListener('click', (e) => {
    if (sidebar.classList.contains('sidebar-open') && !sidebar.contains(e.target) && !toggleBtn.contains(e.target)) {
      sidebar.classList.remove('sidebar-open');
    }
  });
}

/* ==========================================================================
   ENTERPRISE TOAST NOTIFICATION SYSTEM
   ========================================================================== */
function initGlobalToastSystem() {
  window.showToast = function(type = 'info', title = '', message = '', duration = 3500) {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast-item toast-${type}`;

    let iconSvg = '';
    let strokeColor = '#38bdf8';

    if (type === 'success') {
      strokeColor = '#10b981';
      iconSvg = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="${strokeColor}" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
    } else if (type === 'warning') {
      strokeColor = '#f59e0b';
      iconSvg = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="${strokeColor}" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
    } else if (type === 'error') {
      strokeColor = '#ef4444';
      iconSvg = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="${strokeColor}" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
    } else {
      iconSvg = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="${strokeColor}" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
    }

    toast.innerHTML = `
      <div class="toast-icon-wrap" style="display:flex; align-items:center; justify-content:center; width:28px; height:28px; min-width:28px; flex-shrink:0;">
        ${iconSvg}
      </div>
      <div class="toast-content" style="display:flex; flex-direction:column; gap:2px;">
        <div class="toast-title" style="font-size:0.85rem; font-weight:600; color:#f8fafc;">${title}</div>
        <div class="toast-msg" style="font-size:0.75rem; color:#94a3b8; line-height:1.35;">${message}</div>
      </div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('toast-leave');
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(8px)';
      toast.style.transition = 'all 0.25s ease';
      setTimeout(() => {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
      }, 250);
    }, duration);
  };
}