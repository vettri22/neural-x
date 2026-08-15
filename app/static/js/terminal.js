/* NEURAL-X Security Terminal */

let terminalMinimized = false;

function terminalLog(message, type = 'info') {
  const log = document.getElementById('terminal-log');
  if (!log) return;
  const line = document.createElement('div');
  line.className = `t-line t-${type}`;
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
  line.textContent = `[${ts}] ${message}`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;

  // Keep log trimmed to 200 lines
  while (log.children.length > 200) {
    log.removeChild(log.firstChild);
  }
}

function clearTerminal() {
  const log = document.getElementById('terminal-log');
  if (log) log.innerHTML = '<div class="t-line t-system">[ Terminal cleared ]</div>';
}

function toggleTerminal() {
  const panel = document.getElementById('terminal-panel');
  if (!panel) return;
  terminalMinimized = !terminalMinimized;
  panel.classList.toggle('minimized', terminalMinimized);
}

// Auto-log page load
document.addEventListener('DOMContentLoaded', () => {
  terminalLog(`[ SYS ] Page loaded: ${window.location.pathname}`, 'system');
});
