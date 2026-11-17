/* ==========================================================================
   校园网服务器账号自助申请 —— 管理后台脚本（v1.5：全部用户管理）
   所有管理请求均携带 X-Admin-Token 请求头；动态内容一律 textContent 写入。
   本脚本不包含任何用户移除逻辑。
   ========================================================================== */

(function () {
  'use strict';

  var REQUESTED_WITH = 'campus-signup';
  var TOKEN_KEY = 'campus-signup-admin-token';
  var DEFAULT_TIMEOUT_MS = 15000;
  var ANNOUNCEMENT_MAX_CHARS = 20000;
  var EMAIL_PATTERN = /^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/;

  var STATUS_MAP = {
    active: { label: '正常', className: 'status-active' },
    locked: { label: '已锁定', className: 'status-locked' },
    missing: { label: '系统缺失', className: 'status-missing' },
    unknown: { label: '未知', className: 'status-unknown' }
  };

  var SOURCE_MAP = {
    portal: '门户',
    imported: '已有'
  };

  var state = {
    token: '',
    enabled: false,
    loading: false,
    toggling: false,
    users: [],
    searchQuery: '',
    announcementUpdatedAt: '',
    toastTimer: 0,
    bindTarget: null
  };

  var elements = {};

  /* ===== 通用工具 ===== */

  function ApiError(code, message, status) {
    this.name = 'ApiError';
    this.code = code;
    this.message = message;
    this.status = status;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ApiError);
    }
  }

  ApiError.prototype = Object.create(Error.prototype);
  ApiError.prototype.constructor = ApiError;

  function fallbackMessageForStatus(status) {
    switch (status) {
      case 400: return '请求参数有误，请检查后重试。';
      case 403: return '无权限或 token 错误。';
      case 404: return '请求的记录不存在，请刷新列表后重试。';
      case 409: return '当前状态不允许该操作，请刷新列表后重试。';
      case 413: return '提交的数据过大。';
      case 429: return '操作过于频繁，请稍后再试。';
      case 500: return '服务器内部错误，请联系管理员。';
      default: return '请求失败，请稍后重试。';
    }
  }

  function errorFromResponse(status, data) {
    var code = data && data.error && data.error.code
      ? String(data.error.code)
      : 'HTTP_' + status;
    var message = data && data.error && data.error.message
      ? String(data.error.message)
      : fallbackMessageForStatus(status);
    return new ApiError(code, message, status);
  }

  function baseRequest(path, options, withAuth) {
    options = options || {};
    var method = options.method || 'GET';
    var timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    var headers = {
      Accept: 'application/json',
      'X-Requested-With': REQUESTED_WITH
    };
    if (withAuth) {
      headers['X-Admin-Token'] = state.token;
    }
    var payload;
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(options.body);
    }

    var controller = null;
    var timer = 0;
    if (typeof AbortController === 'function') {
      controller = new AbortController();
      timer = window.setTimeout(function () {
        controller.abort();
      }, timeoutMs);
    }

    return fetch(path, {
      method: method,
      headers: headers,
      body: payload,
      cache: 'no-store',
      credentials: 'same-origin',
      signal: controller ? controller.signal : undefined
    }).then(function (response) {
      if (timer) {
        window.clearTimeout(timer);
        timer = 0;
      }
      return response.json().catch(function () {
        return null;
      }).then(function (data) {
        if (!response.ok) {
          throw errorFromResponse(response.status, data);
        }
        if (!data || data.ok === false) {
          throw errorFromResponse(response.status, data);
        }
        return data;
      });
    }).catch(function (error) {
      if (timer) {
        window.clearTimeout(timer);
        timer = 0;
      }
      if (error instanceof ApiError) {
        throw error;
      }
      if (error && error.name === 'AbortError') {
        throw new ApiError('TIMEOUT', '请求超时，请稍后重试。', 0);
      }
      throw new ApiError('NETWORK', '网络连接失败，请检查网络后重试。', 0);
    });
  }

  function publicRequest(path, options) {
    return baseRequest(path, options, false);
  }

  function adminRequest(path, options) {
    return baseRequest(path, options, true);
  }

  function formatDateTime(value) {
    if (typeof value !== 'string' || !value) {
      return '';
    }
    var date = new Date(value);
    if (isNaN(date.getTime())) {
      return value;
    }
    function pad(number) {
      return number < 10 ? '0' + number : String(number);
    }
    return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' +
      pad(date.getDate()) + ' ' + pad(date.getHours()) + ':' +
      pad(date.getMinutes()) + ':' + pad(date.getSeconds());
  }

  function setText(element, text) {
    if (element) {
      element.textContent = text;
    }
  }

  function countCharacters(value) {
    return Array.from(value).length;
  }

  function readSavedToken() {
    try {
      return window.sessionStorage.getItem(TOKEN_KEY) || '';
    } catch (error) {
      return '';
    }
  }

  function saveToken(token) {
    try {
      window.sessionStorage.setItem(TOKEN_KEY, token);
    } catch (error) {
      /* 隐私模式下可能不可用，忽略即可 */
    }
  }

  function removeSavedToken() {
    try {
      window.sessionStorage.removeItem(TOKEN_KEY);
    } catch (error) {
      /* 忽略 */
    }
  }

  /* ===== 元素与初始化 ===== */

  function cacheElements() {
    elements.banner = document.getElementById('admin-banner');
    elements.feedback = document.getElementById('admin-feedback');

    elements.tokenForm = document.getElementById('token-form');
    elements.tokenInput = document.getElementById('admin-token');
    elements.tokenSubmit = document.getElementById('token-submit');
    elements.clearTokenButton = document.getElementById('clear-token');

    elements.panel = document.getElementById('admin-panel');
    elements.statTotal = document.getElementById('stat-total');
    elements.statActive = document.getElementById('stat-active');
    elements.statLocked = document.getElementById('stat-locked');
    elements.statMissing = document.getElementById('stat-missing');
    elements.statWithEmail = document.getElementById('stat-with-email');
    elements.statPortal = document.getElementById('stat-portal');
    elements.statImported = document.getElementById('stat-imported');

    elements.registrationState = document.getElementById('registration-state');
    elements.toggleButton = document.getElementById('toggle-registration');
    elements.refreshButton = document.getElementById('refresh-button');
    elements.searchInput = document.getElementById('user-search');
    elements.searchCount = document.getElementById('search-count');
    elements.usersBody = document.getElementById('users-body');

    elements.announcementInput = document.getElementById('announcement-input');
    elements.announcementCount = document.getElementById('announcement-count');
    elements.announcementUpdated = document.getElementById('announcement-updated');
    elements.announcementError = document.getElementById('announcement-error');
    elements.announcementStatus = document.getElementById('announcement-save-status');
    elements.reloadAnnouncement = document.getElementById('reload-announcement');
    elements.saveAnnouncement = document.getElementById('save-announcement');

    elements.passwordDialog = document.getElementById('password-dialog');
    elements.passwordDialogUsername = document.getElementById('password-dialog-username');
    elements.passwordDialogPassword = document.getElementById('password-dialog-password');
    elements.passwordDialogStatus = document.getElementById('password-dialog-status');
    elements.copyResetPassword = document.getElementById('copy-reset-password');
    elements.closePasswordDialog = document.getElementById('close-password-dialog');

    elements.bindEmailDialog = document.getElementById('bind-email-dialog');
    elements.bindEmailDialogUsername = document.getElementById('bind-email-dialog-username');
    elements.bindEmailInput = document.getElementById('bind-email-input');
    elements.bindEmailDialogError = document.getElementById('bind-email-dialog-error');
    elements.cancelBindEmail = document.getElementById('cancel-bind-email');
    elements.confirmBindEmail = document.getElementById('confirm-bind-email');

    elements.toast = document.getElementById('toast');
  }

  function init() {
    cacheElements();
    if (!elements.tokenForm) {
      return;
    }

    elements.tokenForm.addEventListener('submit', handleTokenSubmit);
    elements.clearTokenButton.addEventListener('click', handleClearToken);
    elements.refreshButton.addEventListener('click', function () {
      loadUsers();
    });
    elements.toggleButton.addEventListener('click', handleToggleRegistration);
    elements.searchInput.addEventListener('input', handleSearchInput);
    elements.usersBody.addEventListener('click', handleTableClick);

    elements.reloadAnnouncement.addEventListener('click', loadAnnouncementForEditor);
    elements.saveAnnouncement.addEventListener('click', saveAnnouncement);
    elements.announcementInput.addEventListener('input', updateAnnouncementCount);

    elements.copyResetPassword.addEventListener('click', function () {
      copyText(
        elements.passwordDialogPassword.textContent,
        '新密码已复制到剪贴板。',
        elements.passwordDialogStatus
      );
    });
    elements.closePasswordDialog.addEventListener('click', function () {
      closeDialog(elements.passwordDialog);
    });
    elements.passwordDialog.addEventListener('close', function () {
      setText(elements.passwordDialogPassword, '—');
      setText(elements.passwordDialogStatus, '');
      elements.passwordDialogStatus.removeAttribute('data-kind');
    });

    elements.cancelBindEmail.addEventListener('click', function () {
      closeDialog(elements.bindEmailDialog);
    });
    elements.confirmBindEmail.addEventListener('click', handleConfirmBindEmail);
    elements.bindEmailInput.addEventListener('keydown', function (event) {
      if (event.key === 'Enter') {
        event.preventDefault();
        handleConfirmBindEmail();
      }
    });
    elements.bindEmailDialog.addEventListener('close', function () {
      state.bindTarget = null;
      setText(elements.bindEmailDialogError, '');
      elements.bindEmailInput.value = '';
      setText(elements.confirmBindEmail, '确认绑定');
      elements.confirmBindEmail.disabled = false;
    });

    var saved = readSavedToken();
    if (saved) {
      state.token = saved;
      elements.tokenInput.value = saved;
      loadUsers({ silent: true });
    }
  }

  /* ===== 提示与错误 ===== */

  function showBanner(kind, message) {
    elements.banner.className = 'banner banner-' + kind;
    elements.banner.textContent = message;
  }

  function hideBanner() {
    elements.banner.className = 'banner';
    elements.banner.textContent = '';
  }

  function showFeedback(message, kind) {
    setText(elements.feedback, message);
    elements.feedback.setAttribute('data-kind', kind || 'ok');
  }

  function clearFeedback() {
    setText(elements.feedback, '');
    elements.feedback.removeAttribute('data-kind');
  }

  function showToast(message, kind) {
    if (!elements.toast) {
      return;
    }
    setText(elements.toast, message);
    elements.toast.setAttribute('data-kind', kind || 'ok');
    elements.toast.classList.add('is-visible');
    if (state.toastTimer) {
      window.clearTimeout(state.toastTimer);
    }
    state.toastTimer = window.setTimeout(function () {
      elements.toast.classList.remove('is-visible');
    }, 4500);
  }

  function showAuthError() {
    showBanner('error', '无权限或 token 错误，请检查管理员 token 后重试。');
    elements.panel.hidden = true;
    removeSavedToken();
    elements.tokenInput.focus();
  }

  function handleAdminError(error) {
    if (!error) {
      showToast('操作失败，请稍后重试。', 'error');
      return;
    }
    if (error.code === 'ADMIN_LOCKED') {
      showBanner('error', error.message || '管理员验证失败次数过多，请稍后再试。');
      elements.panel.hidden = true;
      removeSavedToken();
      elements.tokenInput.focus();
      return;
    }
    if (error.code === 'IP_NOT_ALLOWED') {
      showBanner('error', error.message || '当前网络地址不允许访问管理后台。');
      elements.panel.hidden = true;
      return;
    }
    if (error.code === 'USER_NOT_MANAGEABLE') {
      showToast(error.message || '该账号不支持管理操作。', 'error');
      loadUsers({ silent: true });
      return;
    }
    if (error.code === 'USER_MISSING') {
      showToast(error.message || '系统用户不存在，正在刷新列表。', 'error');
      loadUsers({ silent: true });
      return;
    }
    if (error.code === 'NOT_FOUND') {
      showToast(error.message || '记录不存在，正在刷新列表。', 'error');
      loadUsers({ silent: true });
      return;
    }
    if (error.code === 'ADMIN_AUTH' || error.status === 403) {
      showAuthError();
      return;
    }
    if (error.code === 'RATE_LIMITED') {
      showToast(error.message || '操作过于频繁，请稍后再试。', 'error');
      return;
    }
    showToast(error.message || '操作失败，请稍后重试。', 'error');
  }

  /* ===== 登录与数据加载 ===== */

  function handleTokenSubmit(event) {
    event.preventDefault();
    var token = elements.tokenInput.value.trim();
    if (!token) {
      showBanner('error', '请输入管理员 token 后再加载。');
      elements.tokenInput.focus();
      return;
    }
    state.token = token;
    saveToken(token);
    loadUsers();
  }

  function handleClearToken() {
    state.token = '';
    removeSavedToken();
    elements.tokenInput.value = '';
    elements.panel.hidden = true;
    hideBanner();
    clearFeedback();
    showFeedback('已清除当前浏览器会话中的管理员 token。', 'ok');
    elements.tokenInput.focus();
  }

  function setLoadingUi(loading) {
    elements.tokenSubmit.disabled = loading;
    setText(elements.tokenSubmit, loading ? '加载中…' : '加载');
    elements.refreshButton.disabled = loading;
    elements.panel.setAttribute('aria-busy', loading ? 'true' : 'false');
  }

  function loadUsers(options) {
    options = options || {};
    if (!state.token) {
      showBanner('error', '请输入管理员 token 后再加载。');
      return Promise.resolve();
    }
    if (state.loading) {
      return Promise.resolve();
    }
    state.loading = true;
    setLoadingUi(true);
    if (!options.silent) {
      clearFeedback();
    }

    return adminRequest('/api/admin/users', { timeoutMs: 20000 })
      .then(function (data) {
        hideBanner();
        updateStats(data.stats || {});
        var users = Array.isArray(data.users) ? data.users : [];
        state.users = users;
        renderRows(getFilteredUsers());
        updateSearchCount();
        elements.panel.hidden = false;
        if (!options.silent) {
          showFeedback('已加载 ' + users.length + ' 个用户。', 'ok');
        }
        refreshRegistrationStatus();
        loadAnnouncementForEditor();
      })
      .catch(function (error) {
        handleAdminError(error);
      })
      .then(function () {
        state.loading = false;
        setLoadingUi(false);
      });
  }

  function refreshRegistrationStatus() {
    return publicRequest('/api/health', { timeoutMs: 8000 })
      .then(function (data) {
        state.enabled = data.registration_enabled === true;
        updateRegistrationState();
      })
      .catch(function () {
        /* 读取失败时保持原状态，不阻塞用户列表 */
      });
  }

  function updateStats(stats) {
    setText(elements.statTotal, countValue(stats.total));
    setText(elements.statActive, countValue(stats.active));
    setText(elements.statLocked, countValue(stats.locked));
    setText(elements.statMissing, countValue(stats.missing));
    setText(elements.statWithEmail, countValue(stats.with_email));
    setText(elements.statPortal, countValue(stats.portal));
    setText(elements.statImported, countValue(stats.imported));
  }

  function countValue(value) {
    return typeof value === 'number' && isFinite(value) ? String(value) : '0';
  }

  function updateRegistrationState() {
    var enabled = state.enabled;
    setText(elements.registrationState, enabled ? '开放中' : '已暂停');
    elements.registrationState.classList.toggle('is-off', !enabled);
    elements.toggleButton.classList.toggle('btn-danger', enabled);
    elements.toggleButton.classList.toggle('btn-primary', !enabled);
    elements.toggleButton.classList.toggle('btn-ghost', false);
    setText(elements.toggleButton, enabled ? '暂停申请' : '开放申请');
  }

  /* ===== 客户端搜索 ===== */

  function handleSearchInput() {
    state.searchQuery = elements.searchInput.value.trim().toLowerCase();
    renderRows(getFilteredUsers());
    updateSearchCount();
  }

  function getFilteredUsers() {
    var query = state.searchQuery;
    if (!query) {
      return state.users;
    }
    return state.users.filter(function (user) {
      var fields = [user.username, user.real_name, user.email];
      return fields.some(function (field) {
        return typeof field === 'string' && field.toLowerCase().indexOf(query) !== -1;
      });
    });
  }

  function updateSearchCount() {
    if (!state.searchQuery) {
      setText(elements.searchCount, '');
      return;
    }
    setText(
      elements.searchCount,
      '显示 ' + getFilteredUsers().length + ' / ' + state.users.length + ' 个'
    );
  }

  /* ===== 列表渲染 ===== */

  function renderRows(users) {
    elements.usersBody.textContent = '';
    if (!users.length) {
      var emptyRow = document.createElement('tr');
      var emptyCell = document.createElement('td');
      emptyCell.colSpan = 8;
      emptyCell.className = 'empty-cell';
      setText(
        emptyCell,
        state.users.length ? '没有匹配的用户。' : '暂无用户记录。'
      );
      emptyRow.appendChild(emptyCell);
      elements.usersBody.appendChild(emptyRow);
      return;
    }
    users.forEach(function (user) {
      elements.usersBody.appendChild(buildRow(user));
    });
  }

  function appendCell(rowElement, content, className) {
    var cell = document.createElement('td');
    if (className) {
      cell.className = className;
    }
    if (content instanceof Node) {
      cell.appendChild(content);
    } else {
      setText(cell, content);
    }
    rowElement.appendChild(cell);
    return cell;
  }

  function buildRow(user) {
    var tr = document.createElement('tr');

    appendCell(tr, user.username || '—', 'cell-mono');
    appendCell(tr, user.real_name || '—');
    if (typeof user.email === 'string' && user.email) {
      appendCell(tr, user.email, 'cell-mono');
    } else {
      appendCell(tr, '—', 'cell-muted');
    }
    appendCell(tr, user.uid === null || user.uid === undefined ? '—' : String(user.uid));

    var home = user.home || '—';
    var homeCell = appendCell(tr, home, 'cell-mono cell-path');
    if (user.home) {
      homeCell.setAttribute('title', user.home);
    }

    var source = SOURCE_MAP[user.source] || '—';
    appendCell(tr, source);

    var osStatus = typeof user.os_status === 'string' ? user.os_status : 'unknown';
    var statusInfo = STATUS_MAP[osStatus] || STATUS_MAP.unknown;
    var statusCell = document.createElement('td');
    var badge = document.createElement('span');
    badge.className = 'badge ' + statusInfo.className;
    setText(badge, statusInfo.label);
    statusCell.appendChild(badge);
    tr.appendChild(statusCell);

    tr.appendChild(buildActionCell(user));
    return tr;
  }

  function buildActionCell(user) {
    var actionCell = document.createElement('td');
    var actions = document.createElement('div');
    actions.className = 'row-actions';

    var privileged = user.privileged === true;
    var missing = user.os_status === 'missing';
    var locked = user.locked === true || user.os_status === 'locked';
    var blocked = privileged || missing;

    var resetPasswordButton = buildActionButton(
      'reset-password',
      '重置密码',
      user.username,
      blocked
    );
    if (privileged) {
      resetPasswordButton.setAttribute('title', '特权账号不可操作');
    } else if (missing) {
      resetPasswordButton.setAttribute('title', '系统用户不存在，无法重置密码');
    }
    actions.appendChild(resetPasswordButton);

    var lockButton = buildActionButton(
      'toggle-lock',
      locked ? '解锁' : '锁定',
      user.username,
      blocked
    );
    if (privileged) {
      lockButton.setAttribute('title', '特权账号不可操作');
    } else if (missing) {
      lockButton.setAttribute('title', '系统用户不存在，无法锁定或解锁');
    }
    actions.appendChild(lockButton);

    var bindButton = buildActionButton('bind-email', '绑定邮箱', user.username, blocked);
    if (privileged) {
      bindButton.setAttribute('title', '特权账号不可操作');
    } else if (missing) {
      bindButton.setAttribute('title', '系统用户不存在，无法绑定邮箱');
    }
    actions.appendChild(bindButton);

    if (user.registration_id !== null && user.registration_id !== undefined) {
      var resetIpButton = buildActionButton(
        'reset-ip',
        '重置 IP',
        user.username,
        privileged,
        user.registration_id
      );
      if (privileged) {
        resetIpButton.setAttribute('title', '特权账号不可操作');
      }
      actions.appendChild(resetIpButton);
    }

    if (privileged) {
      var note = document.createElement('span');
      note.className = 'privileged-note';
      setText(note, '特权账号不可操作');
      actions.appendChild(note);
    }

    actionCell.appendChild(actions);
    return actionCell;
  }

  function buildActionButton(action, label, username, disabled, registrationId) {
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-ghost btn-small';
    button.setAttribute('data-action', action);
    button.setAttribute('data-username', username || '');
    if (registrationId !== undefined && registrationId !== null) {
      button.setAttribute('data-registration-id', String(registrationId));
    }
    setText(button, label);
    if (disabled) {
      button.disabled = true;
    }
    return button;
  }

  function findUser(username) {
    var target = String(username);
    for (var index = 0; index < state.users.length; index += 1) {
      if (String(state.users[index].username) === target) {
        return state.users[index];
      }
    }
    return null;
  }

  function handleTableClick(event) {
    var button = event.target.closest('button[data-action]');
    if (!button || button.disabled) {
      return;
    }
    var user = findUser(button.getAttribute('data-username'));
    if (!user) {
      return;
    }
    var action = button.getAttribute('data-action');
    if (action === 'reset-password') {
      requestResetPassword(user, button);
    } else if (action === 'toggle-lock') {
      requestToggleLock(user, button);
    } else if (action === 'bind-email') {
      openBindEmailDialog(user);
    } else if (action === 'reset-ip') {
      requestResetIp(user, button);
    }
  }

  function withButtonBusy(button, task) {
    var originalText = button.textContent;
    button.disabled = true;
    setText(button, '处理中…');
    return Promise.resolve()
      .then(task)
      .catch(function (error) {
        handleAdminError(error);
      })
      .then(function () {
        button.disabled = false;
        setText(button, originalText);
      });
  }

  /* ===== 行操作：重置密码、锁定/解锁、绑定邮箱、重置 IP ===== */

  function requestResetPassword(user, button) {
    var confirmed = window.confirm(
      '确定要为账号「' + user.username + '」重置密码吗？\n\n' +
      '系统将生成新的强密码，旧密码立即失效。新密码只会显示一次，请在关闭弹窗前复制保存。'
    );
    if (!confirmed) {
      return;
    }
    withButtonBusy(button, function () {
      return adminRequest('/api/admin/reset-password', {
        method: 'POST',
        body: { username: user.username }
      }).then(function (data) {
        openPasswordDialog(
          typeof data.username === 'string' && data.username ? data.username : user.username,
          typeof data.password === 'string' ? data.password : ''
        );
        showToast('账号「' + user.username + '」的密码已重置。', 'ok');
        return loadUsers({ silent: true });
      });
    });
  }

  function requestToggleLock(user, button) {
    var currentlyLocked = user.locked === true || user.os_status === 'locked';
    var targetLocked = !currentlyLocked;
    var actionLabel = targetLocked ? '锁定' : '解锁';
    var detail = targetLocked
      ? '锁定后该用户将无法通过密码登录服务器。'
      : '解锁后该用户可以恢复登录。';
    var confirmed = window.confirm(
      '确定要' + actionLabel + '账号「' + user.username + '」吗？\n\n' + detail
    );
    if (!confirmed) {
      return;
    }
    withButtonBusy(button, function () {
      return adminRequest('/api/admin/set-locked', {
        method: 'POST',
        body: { username: user.username, locked: targetLocked }
      }).then(function (data) {
        var lockedNow = data.locked === true;
        showToast(
          '账号「' + user.username + '」已' + (lockedNow ? '锁定' : '解锁') + '。',
          'ok'
        );
        return loadUsers({ silent: true });
      });
    });
  }

  function requestResetIp(user, button) {
    var confirmed = window.confirm(
      '确定要重置账号「' + user.username + '」的申请 IP 吗？\n\n' +
      '此操作只释放该门户账号的申请 IP，不会移除系统用户。'
    );
    if (!confirmed) {
      return;
    }
    withButtonBusy(button, function () {
      return adminRequest('/api/admin/reset-ip', {
        method: 'POST',
        body: { id: user.registration_id }
      }).then(function () {
        showToast('已重置账号「' + user.username + '」的申请 IP。', 'ok');
        return loadUsers({ silent: true });
      });
    });
  }

  function openBindEmailDialog(user) {
    state.bindTarget = user;
    setText(elements.bindEmailDialogUsername, user.username || '—');
    elements.bindEmailInput.value = typeof user.email === 'string' ? user.email : '';
    setText(elements.bindEmailDialogError, '');
    setText(elements.confirmBindEmail, '确认绑定');
    elements.confirmBindEmail.disabled = false;
    openDialog(elements.bindEmailDialog);
    window.setTimeout(function () {
      elements.bindEmailInput.focus();
    }, 30);
  }

  function handleConfirmBindEmail() {
    var user = state.bindTarget;
    if (!user) {
      return;
    }
    setText(elements.bindEmailDialogError, '');
    var email = elements.bindEmailInput.value.trim().toLowerCase();
    if (!email) {
      setText(elements.bindEmailDialogError, '请输入学校邮箱。');
      elements.bindEmailInput.focus();
      return;
    }
    if (email.length > 254 || !EMAIL_PATTERN.test(email)) {
      setText(elements.bindEmailDialogError, '邮箱格式不正确，请填写完整的学校邮箱地址。');
      elements.bindEmailInput.focus();
      return;
    }

    elements.confirmBindEmail.disabled = true;
    setText(elements.confirmBindEmail, '绑定中…');
    adminRequest('/api/admin/bind-email', {
      method: 'POST',
      body: { username: user.username, email: email }
    }).then(function () {
      closeDialog(elements.bindEmailDialog);
      showToast('已为账号「' + user.username + '」绑定邮箱。', 'ok');
      return loadUsers({ silent: true });
    }).catch(function (error) {
      handleAdminError(error);
      setText(elements.bindEmailDialogError, error.message || '绑定邮箱失败，请稍后重试。');
      elements.confirmBindEmail.disabled = false;
      setText(elements.confirmBindEmail, '确认绑定');
    });
  }

  /* ===== 申请开关 ===== */

  function handleToggleRegistration() {
    if (state.toggling || state.loading) {
      return;
    }
    var target = !state.enabled;
    state.toggling = true;
    elements.toggleButton.disabled = true;
    setText(elements.toggleButton, target ? '正在开放…' : '正在暂停…');
    clearFeedback();

    adminRequest('/api/admin/set-registration', {
      method: 'POST',
      body: { enabled: target }
    }).then(function (data) {
      state.enabled = data.registration_enabled === true;
      updateRegistrationState();
      showToast(state.enabled ? '已开放账号申请。' : '已暂停账号申请。', 'ok');
    }).catch(function (error) {
      handleAdminError(error);
    }).then(function () {
      state.toggling = false;
      elements.toggleButton.disabled = false;
      updateRegistrationState();
    });
  }

  /* ===== 公告编辑 ===== */

  function loadAnnouncementForEditor() {
    setText(elements.announcementError, '');
    setText(elements.announcementStatus, '正在读取公告…');
    elements.announcementInput.disabled = true;
    elements.reloadAnnouncement.disabled = true;

    publicRequest('/api/announcement', { timeoutMs: 10000 })
      .then(function (data) {
        var content = typeof data.content === 'string' ? data.content : '';
        state.announcementUpdatedAt = typeof data.updated_at === 'string' ? data.updated_at : '';
        elements.announcementInput.value = content;
        updateAnnouncementCount();
        updateAnnouncementUpdatedText();
        setText(elements.announcementStatus, '');
      })
      .catch(function () {
        setText(elements.announcementError, '读取公告失败，请点击「重新读取」重试。');
        setText(elements.announcementStatus, '');
      })
      .then(function () {
        elements.announcementInput.disabled = false;
        elements.reloadAnnouncement.disabled = false;
      });
  }

  function updateAnnouncementCount() {
    var count = countCharacters(elements.announcementInput.value);
    setText(elements.announcementCount, count + ' / ' + ANNOUNCEMENT_MAX_CHARS + ' 字符');
    elements.announcementCount.classList.toggle('is-over', count > ANNOUNCEMENT_MAX_CHARS);
  }

  function updateAnnouncementUpdatedText() {
    setText(
      elements.announcementUpdated,
      state.announcementUpdatedAt
        ? '更新时间：' + formatDateTime(state.announcementUpdatedAt)
        : '公告暂无更新时间'
    );
  }

  function saveAnnouncement() {
    var content = elements.announcementInput.value;
    var count = countCharacters(content);
    if (count === 0) {
      setText(elements.announcementError, '公告内容不能为空。');
      elements.announcementInput.focus();
      return;
    }
    if (count > ANNOUNCEMENT_MAX_CHARS) {
      setText(elements.announcementError, '公告内容超过 ' + ANNOUNCEMENT_MAX_CHARS + ' 字符上限。');
      return;
    }
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(content)) {
      setText(elements.announcementError, '公告内容包含不允许的控制字符。');
      return;
    }

    setText(elements.announcementError, '');
    elements.saveAnnouncement.disabled = true;
    setText(elements.saveAnnouncement, '保存中…');

    adminRequest('/api/admin/announcement', {
      method: 'POST',
      body: { content: content },
      timeoutMs: 15000
    }).then(function (data) {
      state.announcementUpdatedAt = typeof data.updated_at === 'string' ? data.updated_at : '';
      updateAnnouncementUpdatedText();
      updateAnnouncementCount();
      setText(
        elements.announcementStatus,
        '公告已保存' +
        (state.announcementUpdatedAt ? '，更新时间：' + formatDateTime(state.announcementUpdatedAt) : '') +
        '。'
      );
      showToast('公告已保存，首页将立即生效。', 'ok');
    }).catch(function (error) {
      handleAdminError(error);
      setText(elements.announcementError, error.message || '保存公告失败，请稍后重试。');
    }).then(function () {
      elements.saveAnnouncement.disabled = false;
      setText(elements.saveAnnouncement, '保存公告');
    });
  }

  /* ===== 弹窗 ===== */

  function openDialog(dialog) {
    if (!dialog) {
      return;
    }
    if (typeof dialog.showModal === 'function') {
      if (!dialog.open) {
        dialog.showModal();
      }
    } else {
      dialog.setAttribute('open', '');
    }
  }

  function closeDialog(dialog) {
    if (!dialog) {
      return;
    }
    if (typeof dialog.close === 'function') {
      if (dialog.open) {
        dialog.close();
      }
    } else {
      dialog.removeAttribute('open');
    }
  }

  function openPasswordDialog(username, password) {
    setText(elements.passwordDialogUsername, username || '—');
    setText(elements.passwordDialogPassword, password || '—');
    setText(elements.passwordDialogStatus, '');
    elements.passwordDialogStatus.removeAttribute('data-kind');
    openDialog(elements.passwordDialog);
  }

  /* ===== 复制 ===== */

  function fallbackCopy(text) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', 'readonly');
    textarea.className = 'copy-helper';
    document.body.appendChild(textarea);
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    var succeeded = false;
    try {
      succeeded = document.execCommand('copy');
    } catch (error) {
      succeeded = false;
    }
    document.body.removeChild(textarea);
    if (!succeeded) {
      throw new Error('复制命令不可用');
    }
  }

  function copyText(text, successMessage, statusElement) {
    if (!text || text === '—') {
      return;
    }
    var status = statusElement || elements.toast;
    var promise;
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function' &&
        window.isSecureContext) {
      promise = navigator.clipboard.writeText(text);
    } else {
      promise = Promise.reject(new Error('剪贴板接口不可用'));
    }
    promise.then(function () {
      if (status === elements.toast) {
        showToast(successMessage, 'ok');
      } else {
        setText(status, successMessage);
        status.setAttribute('data-kind', 'ok');
      }
    }).catch(function () {
      try {
        fallbackCopy(text);
        if (status === elements.toast) {
          showToast(successMessage, 'ok');
        } else {
          setText(status, successMessage);
          status.setAttribute('data-kind', 'ok');
        }
      } catch (error) {
        if (status === elements.toast) {
          showToast('复制失败，请手动选中文本复制。', 'error');
        } else {
          setText(status, '复制失败，请手动选中文本复制。');
          status.setAttribute('data-kind', 'error');
        }
      }
    });
  }

  /* ===== 启动 ===== */

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
