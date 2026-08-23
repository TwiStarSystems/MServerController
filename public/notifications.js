/* Notification bell + panel — shared across all pages */

let _notifPanelOpen = false;
let _notifSocketBound = false;

function toggleNotifPanel() {
  _notifPanelOpen ? closeNotifPanel() : openNotifPanel();
}

function openNotifPanel() {
  _notifPanelOpen = true;
  document.getElementById('notif-panel').classList.add('open');
  document.getElementById('notif-panel').setAttribute('aria-hidden', 'false');
  document.getElementById('notif-overlay').classList.add('open');
  loadNotifications();
}

function closeNotifPanel() {
  _notifPanelOpen = false;
  document.getElementById('notif-panel').classList.remove('open');
  document.getElementById('notif-panel').setAttribute('aria-hidden', 'true');
  document.getElementById('notif-overlay').classList.remove('open');
}

async function loadNotifications() {
  try {
    const resp = await fetch('/api/notifications');
    if (!resp.ok) return;
    const data = await resp.json();
    _renderNotifList(data.notifications || []);
    _updateBadge(data.unreadCount || 0);
  } catch (e) {
    console.error('Failed to load notifications:', e);
  }
}

async function refreshNotifBadge() {
  try {
    const resp = await fetch('/api/notifications/unread-count');
    if (!resp.ok) return;
    const data = await resp.json();
    _updateBadge(data.unreadCount || 0);
  } catch (e) { /* silent */ }
}

function _updateBadge(count) {
  const badge = document.getElementById('notif-badge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count > 99 ? '99+' : count;
    badge.style.display = '';
  } else {
    badge.style.display = 'none';
  }
}

function _renderNotifList(notifications) {
  const list = document.getElementById('notif-list');
  if (!list) return;

  if (notifications.length === 0) {
    list.innerHTML = '<div class="jobs-empty">No notifications.</div>';
    return;
  }

  list.innerHTML = notifications.map(n => {
    const readClass = n.read ? 'notif-read' : 'notif-unread';
    const typeIcon = _notifTypeIcon(n.type);
    const timeAgo = _timeAgo(n.created);
    const approvalBtns = (n.type === 'approval_request' && n.refType === 'pending_action' && n.refId)
      ? `<div class="notif-actions">
           <button class="btn btn-small btn-success" onclick="approveFromNotif('${escapeAttr(n.refId)}', '${escapeAttr(n.id)}')">Approve</button>
           <button class="btn btn-small btn-danger" onclick="rejectFromNotif('${escapeAttr(n.refId)}', '${escapeAttr(n.id)}')">Reject</button>
         </div>` : '';

    return `<div class="notif-item ${readClass}" data-id="${escapeAttrValue(n.id)}">
      <div class="notif-item-header">
        <span class="notif-icon">${typeIcon}</span>
        <span class="notif-title">${escapeHtml(n.title)}</span>
        <span class="notif-time">${timeAgo}</span>
      </div>
      ${n.message ? `<div class="notif-message">${escapeHtml(n.message)}</div>` : ''}
      ${approvalBtns}
      <div class="notif-item-controls">
        ${!n.read ? `<button class="btn-link" onclick="markNotifRead('${escapeAttr(n.id)}')">Mark read</button>` : ''}
        <button class="btn-link" onclick="dismissNotif('${escapeAttr(n.id)}')">Dismiss</button>
      </div>
    </div>`;
  }).join('');
}

function _notifTypeIcon(type) {
  switch (type) {
    case 'approval_request': return '⏳';
    case 'action_notify':    return 'ℹ️';
    case 'action_approved':  return '✅';
    case 'action_rejected':  return '❌';
    default:                 return '🔔';
  }
}

function _timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

async function markNotifRead(id) {
  await fetch(`/api/notifications/${id}/read`, { method: 'POST' });
  loadNotifications();
}

async function dismissNotif(id) {
  await fetch(`/api/notifications/${id}/dismiss`, { method: 'POST' });
  loadNotifications();
}

async function markAllNotifsRead() {
  await fetch('/api/notifications/read-all', { method: 'POST' });
  loadNotifications();
}

async function dismissAllNotifs() {
  await fetch('/api/notifications/dismiss-all', { method: 'POST' });
  loadNotifications();
}

async function approveFromNotif(actionId, notifId) {
  try {
    const resp = await fetch(`/api/admin/pending-actions/${actionId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    if (resp.ok) {
      dismissNotif(notifId);
    } else {
      const err = await resp.json();
      alert('Approval failed: ' + (err.error || 'Unknown error'));
    }
  } catch (e) {
    alert('Approval failed: ' + e.message);
  }
}

async function rejectFromNotif(actionId, notifId) {
  const note = prompt('Rejection reason (optional):') || '';
  try {
    const resp = await fetch(`/api/admin/pending-actions/${actionId}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note })
    });
    if (resp.ok) {
      dismissNotif(notifId);
    } else {
      const err = await resp.json();
      alert('Rejection failed: ' + (err.error || 'Unknown error'));
    }
  } catch (e) {
    alert('Rejection failed: ' + e.message);
  }
}

function _bindNotifSocket() {
  if (_notifSocketBound || typeof socket === 'undefined' || !socket) return;
  _notifSocketBound = true;
  socket.on('notification:new', (data) => {
    refreshNotifBadge();
    if (_notifPanelOpen) loadNotifications();
  });
}

// Initial badge load + socket binding (retry until socket is ready)
(function _initNotifs() {
  refreshNotifBadge();
  const interval = setInterval(() => {
    if (typeof socket !== 'undefined' && socket && socket.connected) {
      _bindNotifSocket();
      clearInterval(interval);
    }
  }, 500);
  // Also poll badge every 60s as fallback
  setInterval(refreshNotifBadge, 60000);
})();
