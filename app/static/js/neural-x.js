/* NEURAL-X Main Application JS */

// Animate score bars on load
document.addEventListener('DOMContentLoaded', () => {
  // Animate score bars
  document.querySelectorAll('.score-bar').forEach(bar => {
    const targetWidth = bar.style.width;
    bar.style.width = '0';
    setTimeout(() => { bar.style.width = targetWidth; }, 200);
  });

  // Animate stat values
  document.querySelectorAll('.stat-value').forEach(el => {
    const target = parseInt(el.textContent, 10);
    if (!isNaN(target) && target > 0) {
      let current = 0;
      const increment = Math.ceil(target / 40);
      const timer = setInterval(() => {
        current = Math.min(current + increment, target);
        el.textContent = current;
        if (current >= target) clearInterval(timer);
      }, 30);
    }
  });

  // Auto-dismiss flash messages after 5s
  document.querySelectorAll('.alert.fade.show').forEach(alert => {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
    }, 5000);
  });

  // Tooltip init
  document.querySelectorAll('[title]').forEach(el => {
    new bootstrap.Tooltip(el, { trigger: 'hover', placement: 'top' });
  });
});

// URL preview on input
const urlInput = document.getElementById('urlInput');
if (urlInput) {
  urlInput.addEventListener('input', debounce(function () {
    const val = this.value.trim();
    if (val.length > 10) {
      terminalLog(`[ INPUT ] Target set: ${val.substring(0, 60)}`, 'info');
    }
  }, 800));
}

function debounce(fn, delay) {
  let timer;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

// Copy to clipboard helper
function copyText(text) {
  navigator.clipboard.writeText(text).then(() => {
    terminalLog('[ SYS ] Copied to clipboard', 'success');
  });
}
