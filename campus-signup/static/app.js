/* ==========================================================================
   校园网服务器账号自助申请 —— 申请页脚本
   仅使用原生浏览器 API，无外部依赖。所有动态文本均通过 textContent 写入。
   ========================================================================== */

(function () {
  'use strict';

  var REQUESTED_WITH = 'campus-signup';
  var NAME_DEBOUNCE_MS = 350;
  var DEFAULT_TIMEOUT_MS = 15000;
  var REGISTER_TIMEOUT_MS = 45000;
  var ANNOUNCEMENT_TIMEOUT_MS = 10000;
  var DEFAULT_COOLDOWN_SECONDS = 60;
  var DEFAULT_CODE_TTL_SECONDS = 600;

  var EMAIL_PATTERN = /^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/;
  var FALLBACK_EMAIL_DOMAINS = ['mails.example.edu.cn', 'example.edu.cn'];

  var SYMBOL_PATTERN = /[!@#$%^&*()\-_=+\[\]{};,.?/|~]/;
  var SAFE_PASSWORD_PATTERN = /^[A-Za-z0-9!@#$%^&*()\-_=+\[\]{};,.?/|~]*$/;
  var STRENGTH_LABELS = ['很弱', '弱', '中等', '强', '很强'];

  var WEAK_TOKENS = [
    '123456789012', 'password1234', 'qwertyuiop12', 'administrator1',
    'p@ssw0rd1234', 'aa123456789', '123456', 'password', 'qwerty',
    'admin', '111111', 'abc123', 'letmein', 'iloveyou', 'welcome',
    'monkey', 'dragon', 'passw0rd', 'qwertyuiop', 'administrator'
  ];

  var FALLBACKS = {
    siteTitle: '校园网服务器账号自助申请',
    serverName: '实验室服务器',
    contact: '实验室管理员',
    sshHost: '10.0.0.10',
    sshPort: 22,
    sshIpv6Port: 2222,
    emailDomains: FALLBACK_EMAIL_DOMAINS
  };

  var state = {
    previewTimer: 0,
    previewSeq: 0,
    previewUsername: '',
    passwordVisible: false,
    submitting: false,
    generating: false,
    sendingCode: false,
    codeCooldownEnd: 0,
    codeCooldownTimer: 0,
    codeCooldownEmail: '',
    lastSentEmail: '',
    registrationEnabled: true,
    emailVerificationEnabled: true,
    allowedEmailDomains: FALLBACK_EMAIL_DOMAINS.slice(),
    completed: false,
    serverName: FALLBACKS.serverName,
    siteTitle: FALLBACKS.siteTitle,
    sshHost: FALLBACKS.sshHost,
    sshPort: FALLBACKS.sshPort,
    sshIpv6: '',
    sshIpv6Port: FALLBACKS.sshIpv6Port,
    result: null,
    copyTimer: 0,
    resetMode: false,
    resetSendingCode: false,
    resetCooldownEnd: 0,
    resetCooldownTimer: 0,
    resetCooldownEmail: '',
    resetLastSentEmail: '',
    resetPasswordVisible: false,
    resetGenerating: false,
    resetSubmitting: false,
    resetCompleted: false,
    entryMode: 'apply',
    bindSendingCode: false,
    bindCooldownEnd: 0,
    bindCooldownTimer: 0,
    bindCooldownEmail: '',
    bindLastSentEmail: '',
    bindPasswordVisible: false,
    bindSubmitting: false,
    bindCompleted: false,
    bindResult: null
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
      case 400: return '请求参数有误，请检查填写内容后重试。';
      case 403: return '请求被拒绝，请刷新页面后重试。';
      case 404: return '接口不存在，请确认服务已正确部署。';
      case 405: return '请求方式不受支持，请刷新页面后重试。';
      case 409: return '当前状态不允许该操作，请刷新页面后重试。';
      case 413: return '提交的数据过大，请精简后重试。';
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

  function parseRetryAfter(value) {
    if (!value) {
      return 0;
    }
    var seconds = parseInt(value, 10);
    if (!isNaN(seconds) && seconds > 0) {
      return seconds;
    }
    var date = new Date(value);
    if (!isNaN(date.getTime())) {
      var diff = Math.ceil((date.getTime() - Date.now()) / 1000);
      if (diff > 0) {
        return diff;
      }
    }
    return 0;
  }

  function requestJson(path, options) {
    options = options || {};
    var method = options.method || 'GET';
    var timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    var headers = {
      Accept: 'application/json',
      'X-Requested-With': REQUESTED_WITH
    };
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
          var apiError = errorFromResponse(response.status, data);
          var retryAfter = parseRetryAfter(response.headers.get('Retry-After'));
          if (retryAfter) {
            apiError.retryAfter = retryAfter;
          }
          throw apiError;
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
      throw new ApiError('NETWORK', '网络连接失败，请检查校园网连接后重试。', 0);
    });
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

  function prefersReducedMotion() {
    return window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function setText(element, text) {
    if (element) {
      element.textContent = text;
    }
  }

  /* ===== 页面元素与初始化 ===== */

  function cacheElements() {
    elements.banner = document.getElementById('service-banner');
    elements.siteTitles = document.querySelectorAll('[data-role="site-title"]');
    elements.serverNames = document.querySelectorAll('[data-role="server-name"]');
    elements.contacts = document.querySelectorAll('[data-role="contact"]');
    elements.footerLoginHint = document.getElementById('footer-login-hint');

    elements.form = document.getElementById('apply-form');
    elements.applySection = document.getElementById('apply-section');
    elements.nameInput = document.getElementById('real-name');
    elements.preview = document.getElementById('name-preview');
    elements.emailInput = document.getElementById('email');
    elements.emailHint = document.getElementById('email-hint');
    elements.emailStatus = document.getElementById('email-status');
    elements.emailCodeInput = document.getElementById('email-code');
    elements.sendCodeButton = document.getElementById('send-code');
    elements.footerEmailRule = document.getElementById('footer-email-rule');
    elements.passwordInput = document.getElementById('password');
    elements.toggleButton = document.getElementById('toggle-password');
    elements.generateButton = document.getElementById('generate-password');
    elements.strength = document.getElementById('password-strength');
    elements.strengthMeter = document.getElementById('strength-meter');
    elements.strengthText = document.getElementById('password-strength-text');
    elements.requirementItems = document.querySelectorAll('#pw-reqs .pw-req');
    elements.passwordWarning = document.getElementById('password-warning');
    elements.formError = document.getElementById('form-error');
    elements.submitButton = document.getElementById('submit-button');

    elements.announcementCard = document.getElementById('announcement-card');
    elements.announcementMeta = document.getElementById('announcement-meta');
    elements.announcementToggle = document.getElementById('announcement-toggle');
    elements.announcementBody = document.getElementById('announcement-body');
    elements.announcementContent = document.getElementById('announcement-content');

    elements.resultCard = document.getElementById('result-card');
    elements.resultSubtitle = document.getElementById('result-subtitle');
    elements.resultUsername = document.getElementById('result-username');
    elements.resultPassword = document.getElementById('result-password');
    elements.resultEmail = document.getElementById('result-email');
    elements.resultHome = document.getElementById('result-home');
    elements.resultWorkspace = document.getElementById('result-workspace');
    elements.resultSsh = document.getElementById('result-ssh');
    elements.resultSshIpv6 = document.getElementById('result-ssh-ipv6');
    elements.resultIpv6Item = document.getElementById('result-ipv6-item');
    elements.resultCreated = document.getElementById('result-created');
    elements.copyPasswordButton = document.getElementById('copy-password');
    elements.copySshButton = document.getElementById('copy-ssh');
    elements.copySshIpv6Button = document.getElementById('copy-ssh-ipv6');
    elements.copyAllButton = document.getElementById('copy-all');
    elements.copyStatus = document.getElementById('copy-status');

    elements.entrySwitch = document.getElementById('entry-switch');
    elements.entryApply = document.getElementById('entry-apply');
    elements.entryBind = document.getElementById('entry-bind');
    elements.entryReset = document.getElementById('entry-reset');
    elements.bindSection = document.getElementById('bind-section');
    elements.bindForm = document.getElementById('bind-form');
    elements.bindUsernameInput = document.getElementById('bind-username');
    elements.bindPasswordInput = document.getElementById('bind-password');
    elements.bindTogglePasswordButton = document.getElementById('bind-toggle-password');
    elements.bindEmailInput = document.getElementById('bind-email');
    elements.bindEmailHint = document.getElementById('bind-email-hint');
    elements.bindEmailStatus = document.getElementById('bind-email-status');
    elements.bindCodeInput = document.getElementById('bind-code');
    elements.bindSendCodeButton = document.getElementById('bind-send-code');
    elements.bindError = document.getElementById('bind-error');
    elements.bindSubmitButton = document.getElementById('bind-submit-button');
    elements.bindSuccess = document.getElementById('bind-success');
    elements.bindSuccessUsername = document.getElementById('bind-success-username');
    elements.bindSuccessEmail = document.getElementById('bind-success-email');
    elements.bindGoReset = document.getElementById('bind-go-reset');
    elements.bindBackApply = document.getElementById('bind-back-apply');

    elements.resetSection = document.getElementById('reset-section');
    elements.resetForm = document.getElementById('reset-form');
    elements.resetEmailInput = document.getElementById('reset-email');
    elements.resetEmailHint = document.getElementById('reset-email-hint');
    elements.resetEmailStatus = document.getElementById('reset-email-status');
    elements.resetCodeInput = document.getElementById('reset-code');
    elements.resetSendCodeButton = document.getElementById('reset-send-code');
    elements.resetPasswordInput = document.getElementById('reset-password');
    elements.resetTogglePasswordButton = document.getElementById('reset-toggle-password');
    elements.resetGenerateButton = document.getElementById('reset-generate-password');
    elements.resetStrength = document.getElementById('reset-password-strength');
    elements.resetStrengthMeter = document.getElementById('reset-strength-meter');
    elements.resetStrengthText = document.getElementById('reset-strength-text');
    elements.resetRequirementItems = document.querySelectorAll('#reset-pw-reqs .pw-req');
    elements.resetPasswordWarning = document.getElementById('reset-password-warning');
    elements.resetError = document.getElementById('reset-error');
    elements.resetSubmitButton = document.getElementById('reset-submit-button');
    elements.backToApply = document.getElementById('back-to-apply');
    elements.resetSuccess = document.getElementById('reset-success');
    elements.resetSuccessUsername = document.getElementById('reset-success-username');
    elements.resetLockedNote = document.getElementById('reset-locked-note');
    elements.resetBackButton = document.getElementById('reset-back-button');
  }

  function init() {
    cacheElements();
    if (!elements.form) {
      return;
    }

    elements.nameInput.addEventListener('input', handleNameInput);
    elements.emailInput.addEventListener('input', handleEmailInput);
    elements.emailCodeInput.addEventListener('input', handleEmailCodeInput);
    elements.sendCodeButton.addEventListener('click', handleSendCode);
    elements.passwordInput.addEventListener('input', handlePasswordInput);
    elements.toggleButton.addEventListener('click', handleTogglePassword);
    elements.generateButton.addEventListener('click', handleGeneratePassword);
    elements.form.addEventListener('submit', handleSubmit);
    elements.announcementToggle.addEventListener('click', handleAnnouncementToggle);

    elements.entryApply.addEventListener('click', function () { switchEntry('apply'); });
    elements.entryBind.addEventListener('click', function () { switchEntry('bind'); });
    elements.entryReset.addEventListener('click', function () { switchEntry('reset'); });
    elements.bindUsernameInput.addEventListener('input', clearBindError);
    elements.bindPasswordInput.addEventListener('input', clearBindError);
    elements.bindEmailInput.addEventListener('input', handleBindEmailInput);
    elements.bindCodeInput.addEventListener('input', handleBindCodeInput);
    elements.bindSendCodeButton.addEventListener('click', handleBindSendCode);
    elements.bindTogglePasswordButton.addEventListener('click', handleBindTogglePassword);
    elements.bindForm.addEventListener('submit', handleBindSubmit);
    elements.bindBackApply.addEventListener('click', function () { switchEntry('apply'); });
    elements.bindGoReset.addEventListener('click', handleBindGoReset);

    elements.backToApply.addEventListener('click', function () { switchEntry('apply'); });
    elements.resetBackButton.addEventListener('click', function () { switchEntry('apply'); });
    elements.resetEmailInput.addEventListener('input', handleResetEmailInput);
    elements.resetCodeInput.addEventListener('input', handleResetCodeInput);
    elements.resetSendCodeButton.addEventListener('click', handleResetSendCode);
    elements.resetPasswordInput.addEventListener('input', updateResetPasswordFeedback);
    elements.resetTogglePasswordButton.addEventListener('click', handleResetTogglePassword);
    elements.resetGenerateButton.addEventListener('click', handleResetGeneratePassword);
    elements.resetForm.addEventListener('submit', handleResetSubmit);

    elements.copyPasswordButton.addEventListener('click', function () {
      copyText(elements.resultPassword.textContent, '密码已复制到剪贴板。');
    });
    elements.copySshButton.addEventListener('click', function () {
      copyText(elements.resultSsh.textContent, '校内登录命令已复制到剪贴板。');
    });
    elements.copySshIpv6Button.addEventListener('click', function () {
      copyText(elements.resultSshIpv6.textContent, '校外登录命令已复制到剪贴板。');
    });
    elements.copyAllButton.addEventListener('click', function () {
      copyText(buildCopyAllText(), '账号信息已复制到剪贴板。');
    });

    updateRequirements('');
    updateStrength(0, STRENGTH_LABELS[0], false);
    updateEmailHint();
    setEmailStatus('idle', defaultEmailStatusText());
    updateSendCodeButton();
    setResetEmailStatus('idle', defaultResetEmailStatusText());
    updateResetPasswordFeedback();
    updateResetSendButton();
    setBindEmailStatus('idle', defaultBindEmailStatusText());
    updateBindSendButton();

    loadHealth();
    loadAnnouncement();
  }

  /* ===== 服务状态与界面文案 ===== */

  function showBanner(kind, message) {
    elements.banner.className = 'banner banner-' + kind;
    elements.banner.textContent = message;
  }

  function hideBanner() {
    elements.banner.className = 'banner';
    elements.banner.textContent = '';
  }

  function applyServerInfo(data) {
    var siteTitle = typeof data.site_title === 'string' && data.site_title.trim()
      ? data.site_title.trim()
      : FALLBACKS.siteTitle;
    var serverName = typeof data.server_name === 'string' && data.server_name.trim()
      ? data.server_name.trim()
      : FALLBACKS.serverName;
    var contact = typeof data.contact === 'string' && data.contact.trim()
      ? data.contact.trim()
      : FALLBACKS.contact;

    state.siteTitle = siteTitle;
    state.serverName = serverName;

    state.sshHost = typeof data.ssh_host === 'string' && data.ssh_host.trim()
      ? data.ssh_host.trim()
      : FALLBACKS.sshHost;
    state.sshPort = typeof data.ssh_port === 'number' && isFinite(data.ssh_port)
      ? data.ssh_port
      : FALLBACKS.sshPort;
    state.sshIpv6 = typeof data.ssh_ipv6 === 'string' ? data.ssh_ipv6.trim() : '';
    state.sshIpv6Port = typeof data.ssh_ipv6_port === 'number' && isFinite(data.ssh_ipv6_port)
      ? data.ssh_ipv6_port
      : FALLBACKS.sshIpv6Port;

    state.allowedEmailDomains = parseAllowedDomains(data.allowed_email_domains);
    state.emailVerificationEnabled = data.email_verification_enabled !== false;
    updateEmailHint();

    elements.siteTitles.forEach(function (element) {
      element.textContent = state.siteTitle;
    });
    elements.serverNames.forEach(function (element) {
      element.textContent = state.serverName;
    });
    elements.contacts.forEach(function (element) {
      element.textContent = contact;
    });
    document.title = state.siteTitle + ' · ' + state.serverName;

    if (elements.footerLoginHint) {
      var ipv6Part = state.sshIpv6
        ? '校外请使用 IPv6 直连（端口 ' + state.sshIpv6Port + '）。'
        : '校外请使用 IPv6 直连（默认端口 2222）。';
      elements.footerLoginHint.textContent =
        '校内使用 IPv4 直连（' + state.sshHost +
        (state.sshPort === 22 ? '' : '，端口 ' + state.sshPort) +
        '）；' + ipv6Part;
    }
  }

  function isFormAvailable() {
    return state.registrationEnabled && state.emailVerificationEnabled;
  }

  function isResetAvailable() {
    return state.emailVerificationEnabled;
  }

  function isBindAvailable() {
    return state.emailVerificationEnabled;
  }

  function setBindFormDisabled(disabled) {
    var controls = elements.bindForm.querySelectorAll('input, button');
    controls.forEach(function (control) {
      control.disabled = disabled;
    });
    elements.bindForm.setAttribute('aria-disabled', disabled ? 'true' : 'false');
    if (disabled) {
      elements.bindSendCodeButton.textContent = '发送验证码';
      setText(elements.bindSubmitButton, '暂不可用');
    } else {
      setText(elements.bindSubmitButton, '绑定邮箱');
      updateBindSendButton();
    }
  }

  function setResetFormDisabled(disabled) {
    var controls = elements.resetForm.querySelectorAll('input, button');
    controls.forEach(function (control) {
      control.disabled = disabled;
    });
    elements.resetForm.setAttribute('aria-disabled', disabled ? 'true' : 'false');
    if (disabled) {
      elements.resetSendCodeButton.textContent = '发送验证码';
      setText(elements.resetSubmitButton, '暂不可用');
    } else {
      setText(elements.resetSubmitButton, '重置密码');
      updateResetSendButton();
    }
  }

  function setFormDisabled(disabled) {
    var controls = elements.form.querySelectorAll('input, button');
    controls.forEach(function (control) {
      control.disabled = disabled;
    });
    elements.submitButton.textContent = disabled ? '申请已暂停' : '申请账号';
    elements.form.setAttribute('aria-disabled', disabled ? 'true' : 'false');
    if (disabled) {
      elements.sendCodeButton.textContent = '发送验证码';
    } else {
      updateSendCodeButton();
    }
  }

  function updateServiceAvailability() {
    var applyDisabled = !isFormAvailable();
    var bindDisabled = !isBindAvailable();
    var resetDisabled = !isResetAvailable();
    var reasons = [];
    if (!state.registrationEnabled) {
      reasons.push('申请通道已暂停：管理员暂时关闭了账号申请');
    }
    if (!state.emailVerificationEnabled) {
      reasons.push('邮箱验证服务维护中：暂时无法发送验证码、申请账号、绑定邮箱或重置密码');
    }
    if (applyDisabled) {
      setFormDisabled(true);
    } else {
      setFormDisabled(false);
    }
    setBindFormDisabled(bindDisabled);
    setResetFormDisabled(resetDisabled);
    elements.entryApply.disabled = applyDisabled;
    elements.entryBind.disabled = bindDisabled;
    elements.entryReset.disabled = resetDisabled;
    var activeAvailable = state.entryMode === 'apply'
      ? !applyDisabled
      : (state.entryMode === 'bind' ? !bindDisabled : !resetDisabled);
    if (!activeAvailable && !state.completed) {
      var fallback = !applyDisabled ? 'apply' : (!bindDisabled ? 'bind' : (!resetDisabled ? 'reset' : ''));
      if (fallback && fallback !== state.entryMode) {
        switchEntry(fallback);
      }
    }
    if (reasons.length) {
      showBanner('warn', reasons.join('；') + '，请稍后再试。');
    }
  }

  function setRegistrationEnabled(enabled) {
    state.registrationEnabled = enabled;
    updateServiceAvailability();
  }

  function setEmailVerificationEnabled(enabled) {
    state.emailVerificationEnabled = enabled;
    updateServiceAvailability();
  }

  function loadHealth() {
    requestJson('/api/health', { timeoutMs: 8000 }).then(function (data) {
      applyServerInfo(data);
      hideBanner();
      state.registrationEnabled = data.registration_enabled !== false;
      state.emailVerificationEnabled = data.email_verification_enabled !== false;
      updateServiceAvailability();
    }).catch(function () {
      showBanner('warn', '无法获取服务状态，页面可能无法正常提交，请检查网络或稍后刷新重试。');
    });
  }

  /* ===== 公告面板 ===== */

  function loadAnnouncement() {
    setText(elements.announcementContent, '正在加载公告…');
    setText(elements.announcementMeta, '正在加载公告…');
    elements.announcementContent.removeAttribute('data-state');

    requestJson('/api/announcement', { timeoutMs: ANNOUNCEMENT_TIMEOUT_MS })
      .then(function (data) {
        var content = typeof data.content === 'string' ? data.content : '';
        var updatedAt = typeof data.updated_at === 'string' ? data.updated_at : '';
        if (content) {
          setText(elements.announcementContent, content);
          elements.announcementContent.removeAttribute('data-state');
        } else {
          setText(elements.announcementContent, '管理员暂未发布公告内容。');
          elements.announcementContent.setAttribute('data-state', 'empty');
        }
        setText(
          elements.announcementMeta,
          updatedAt
            ? '更新时间：' + formatDateTime(updatedAt)
            : '公告暂无更新时间'
        );
        elements.announcementBody.scrollTop = 0;
      })
      .catch(function () {
        setText(
          elements.announcementContent,
          '公告加载失败，请稍后刷新页面重试。公告加载失败不影响账号申请。'
        );
        elements.announcementContent.setAttribute('data-state', 'error');
        setText(elements.announcementMeta, '公告加载失败');
      });
  }

  function handleAnnouncementToggle() {
    var collapsed = !elements.announcementBody.hidden;
    elements.announcementBody.hidden = collapsed;
    elements.announcementToggle.textContent = collapsed ? '展开' : '收起';
    elements.announcementToggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  }

  /* ===== 学校邮箱与验证码 ===== */

  function parseAllowedDomains(value) {
    if (!Array.isArray(value)) {
      return FALLBACK_EMAIL_DOMAINS.slice();
    }
    var domains = [];
    value.forEach(function (item) {
      if (typeof item === 'string') {
        var domain = item.trim().toLowerCase();
        if (domain && domains.indexOf(domain) === -1) {
          domains.push(domain);
        }
      }
    });
    return domains.length ? domains : FALLBACK_EMAIL_DOMAINS.slice();
  }

  function normalizeEmail(value) {
    return String(value || '').trim().toLowerCase();
  }

  function emailDomainOf(email) {
    var at = email.lastIndexOf('@');
    return at >= 0 ? email.slice(at + 1) : '';
  }

  function domainListText() {
    return state.allowedEmailDomains.map(function (domain) {
      return '@' + domain;
    }).join(' / ');
  }

  function defaultEmailStatusText() {
    return '验证码 10 分钟内有效，仅可使用一次。';
  }

  function updateEmailHint() {
    var list = domainListText();
    setText(elements.emailHint, '仅支持 ' + list + ' 邮箱');
    setText(elements.bindEmailHint, '仅支持 ' + list + ' 邮箱');
    setText(elements.resetEmailHint, '仅支持 ' + list + ' 邮箱');
    setText(
      elements.footerEmailRule,
      '仅限示例大学邮箱（' + list + '），一个邮箱仅可对应一个账号。'
    );
  }

  function setEmailStatus(stateName, text) {
    elements.emailStatus.setAttribute('data-state', stateName);
    elements.emailStatus.setAttribute('aria-busy', stateName === 'loading' ? 'true' : 'false');
    setText(elements.emailStatus, text);
  }

  function validateEmailLocally(email) {
    if (!email) {
      return '请先填写示例大学邮箱。';
    }
    if (email.length > 254) {
      return '邮箱长度不能超过 254 个字符。';
    }
    if (!EMAIL_PATTERN.test(email)) {
      return '邮箱格式不正确，请填写完整的示例大学邮箱地址。';
    }
    if (state.allowedEmailDomains.indexOf(emailDomainOf(email)) === -1) {
      return '请使用示例大学邮箱（' + domainListText() + '）。';
    }
    return '';
  }

  function handleEmailInput() {
    clearFormError();
    var email = normalizeEmail(elements.emailInput.value);
    if (state.lastSentEmail && email !== state.lastSentEmail) {
      state.lastSentEmail = '';
      stopCooldown();
      elements.emailCodeInput.value = '';
      setEmailStatus('idle', defaultEmailStatusText());
    }
    if (state.codeCooldownEmail && email !== state.codeCooldownEmail) {
      stopCooldown();
    }
  }

  function handleEmailCodeInput() {
    clearFormError();
    var raw = elements.emailCodeInput.value;
    var digits = raw.replace(/\D+/g, '').slice(0, 6);
    if (digits !== raw) {
      elements.emailCodeInput.value = digits;
    }
  }

  function formatCountdown(seconds) {
    var total = Math.max(0, Math.ceil(seconds));
    if (total >= 60) {
      var minutes = Math.floor(total / 60);
      var rest = total % 60;
      return minutes + ':' + (rest < 10 ? '0' + rest : String(rest));
    }
    return total + ' 秒';
  }

  function formatExpiresIn(seconds) {
    if (seconds >= 60 && seconds % 60 === 0) {
      return (seconds / 60) + ' 分钟';
    }
    return formatCountdown(seconds);
  }

  function updateSendCodeButton() {
    if (state.sendingCode) {
      elements.sendCodeButton.disabled = true;
      setText(elements.sendCodeButton, '发送中…');
      return;
    }
    var remaining = state.codeCooldownEnd
      ? Math.ceil((state.codeCooldownEnd - Date.now()) / 1000)
      : 0;
    if (remaining > 0) {
      elements.sendCodeButton.disabled = true;
      setText(elements.sendCodeButton, '重新发送（' + formatCountdown(remaining) + '）');
      return;
    }
    elements.sendCodeButton.disabled = !isFormAvailable();
    setText(elements.sendCodeButton, '发送验证码');
  }

  function stopCooldown() {
    if (state.codeCooldownTimer) {
      window.clearInterval(state.codeCooldownTimer);
      state.codeCooldownTimer = 0;
    }
    state.codeCooldownEnd = 0;
    state.codeCooldownEmail = '';
    updateSendCodeButton();
  }

  function tickCooldown() {
    var remaining = state.codeCooldownEnd
      ? Math.ceil((state.codeCooldownEnd - Date.now()) / 1000)
      : 0;
    if (remaining <= 0) {
      if (state.codeCooldownTimer) {
        window.clearInterval(state.codeCooldownTimer);
        state.codeCooldownTimer = 0;
      }
      state.codeCooldownEnd = 0;
    }
    updateSendCodeButton();
  }

  function startCooldown(seconds, email) {
    var total = typeof seconds === 'number' && isFinite(seconds) && seconds > 0
      ? Math.floor(seconds)
      : DEFAULT_COOLDOWN_SECONDS;
    if (state.codeCooldownTimer) {
      window.clearInterval(state.codeCooldownTimer);
    }
    state.codeCooldownEnd = Date.now() + total * 1000;
    state.codeCooldownEmail = email ? normalizeEmail(email) : '';
    state.codeCooldownTimer = window.setInterval(tickCooldown, 1000);
    updateSendCodeButton();
  }

  function handleSendCode() {
    if (state.sendingCode || !isFormAvailable()) {
      return;
    }
    clearFormError();
    var email = normalizeEmail(elements.emailInput.value);
    var localError = validateEmailLocally(email);
    if (localError) {
      setEmailStatus('error', localError);
      elements.emailInput.focus();
      return;
    }

    state.sendingCode = true;
    updateSendCodeButton();
    setEmailStatus('loading', '正在发送验证码，请稍候…');

    requestJson('/api/email/send-code', {
      method: 'POST',
      body: { email: email },
      timeoutMs: 20000
    }).then(function (data) {
      var sentEmail = typeof data.email === 'string' && data.email
        ? normalizeEmail(data.email)
        : email;
      var expiresIn = typeof data.expires_in === 'number' && data.expires_in > 0
        ? data.expires_in
        : DEFAULT_CODE_TTL_SECONDS;
      var cooldown = typeof data.cooldown === 'number' && data.cooldown > 0
        ? data.cooldown
        : DEFAULT_COOLDOWN_SECONDS;
      state.lastSentEmail = sentEmail;
      elements.emailCodeInput.value = '';
      var message = '验证码已发送至 ' + sentEmail + '，' +
        formatExpiresIn(expiresIn) + '内有效。';
      if (typeof data.debug_code === 'string' && data.debug_code) {
        message += '（本地测试验证码：' + data.debug_code + '）';
      }
      setEmailStatus('ok', message);
      startCooldown(cooldown, sentEmail);
      elements.emailCodeInput.focus();
    }).catch(function (error) {
      if (error.code === 'RATE_LIMITED') {
        var wait = error.retryAfter > 0 ? error.retryAfter : DEFAULT_COOLDOWN_SECONDS;
        setEmailStatus('error', error.message || '发送过于频繁，请稍后再试。');
        startCooldown(wait, email);
      } else if (error.code === 'EMAIL_DISABLED') {
        setEmailVerificationEnabled(false);
        setEmailStatus('error', error.message || '邮箱验证服务维护中，请稍后再试。');
      } else {
        setEmailStatus('error', error.message || '验证码发送失败，请稍后重试。');
      }
      if (error.code === 'INVALID_EMAIL' || error.code === 'EMAIL_REGISTERED' ||
          error.code === 'EMAIL_DISABLED') {
        elements.emailInput.focus();
      }
    }).then(function () {
      state.sendingCode = false;
      updateSendCodeButton();
    });
  }

  /* ===== 姓名预览 ===== */

  function setPreview(stateName, text) {
    elements.preview.setAttribute('data-state', stateName);
    elements.preview.setAttribute('aria-busy', stateName === 'loading' ? 'true' : 'false');
    setText(elements.preview, text);
  }

  function handleNameInput() {
    window.clearTimeout(state.previewTimer);
    state.previewUsername = '';
    clearFormError();

    var name = elements.nameInput.value.trim();
    if (!name) {
      setPreview('idle', '输入姓名后将自动检查用户名是否可用');
      return;
    }
    setPreview('loading', '正在检查姓名与用户名…');
    state.previewTimer = window.setTimeout(function () {
      runPreview(name);
    }, NAME_DEBOUNCE_MS);
  }

  function runPreview(name) {
    var seq = ++state.previewSeq;
    requestJson('/api/preview?name=' + encodeURIComponent(name), { timeoutMs: 10000 })
      .then(function (data) {
        if (seq !== state.previewSeq) {
          return;
        }
        state.previewUsername = typeof data.username === 'string' ? data.username : '';
        if (data.available === false) {
          setPreview(
            'error',
            data.note || '该姓名暂时无法分配用户名，请联系管理员。'
          );
          return;
        }
        var note = typeof data.note === 'string' ? data.note.trim() : '';
        if (note) {
          setPreview('warn', note);
        } else if (data.duplicate_index > 0 && data.username) {
          setPreview('warn', '已有同名账号，将分配：' + data.username);
        } else if (data.username) {
          setPreview('ok', '用户名：' + data.username);
        } else {
          setPreview('ok', '姓名可用');
        }
      })
      .catch(function (error) {
        if (seq !== state.previewSeq) {
          return;
        }
        state.previewUsername = '';
        if (error.code === 'INVALID_NAME' || error.code === 'USERNAME_EXHAUSTED') {
          setPreview('error', error.message);
        } else if (error.code === 'RATE_LIMITED') {
          setPreview('warn', '姓名检查过于频繁，请稍后再试。');
        } else {
          setPreview('error', error.message || '姓名检查失败，请稍后重试。');
        }
      });
  }

  /* ===== 密码：显示切换、生成、强度、要求 ===== */

  function handleTogglePassword() {
    state.passwordVisible = !state.passwordVisible;
    elements.passwordInput.type = state.passwordVisible ? 'text' : 'password';
    elements.toggleButton.textContent = state.passwordVisible ? '隐藏' : '显示';
    elements.toggleButton.setAttribute('aria-pressed', state.passwordVisible ? 'true' : 'false');
    elements.passwordInput.focus();
  }

  function handlePasswordInput() {
    clearFormError();
    updatePasswordFeedback();
  }

  function countCharacterClasses(value) {
    var classes = 0;
    if (/[a-z]/.test(value)) { classes += 1; }
    if (/[A-Z]/.test(value)) { classes += 1; }
    if (/[0-9]/.test(value)) { classes += 1; }
    if (SYMBOL_PATTERN.test(value)) { classes += 1; }
    return classes;
  }

  function estimateStrength(value, username) {
    if (!value) {
      return { score: 0, label: STRENGTH_LABELS[0] };
    }
    var classes = countCharacterClasses(value);
    var score = 0;

    if (value.length >= 8) { score += 1; }
    if (value.length >= 12) { score += 1; }
    if (value.length >= 16) { score += 1; }
    if (classes >= 3) { score += 1; }
    if (classes >= 4) { score += 1; }
    if (new Set(value).size >= 8) { score += 1; }

    if (value.length < 12) { score -= 1; }
    if (classes < 4) { score -= 1; }
    if (classes < 2) { score = Math.min(score, 1); }
    if (/(.)\1{2,}/.test(value)) { score -= 1; }
    if (/(.)\1{3,}/.test(value)) { score -= 1; }

    var lower = value.toLowerCase();
    if (WEAK_TOKENS.some(function (token) { return lower.indexOf(token) !== -1; })) {
      score = Math.min(score, 1);
    }
    if (username && lower.indexOf(String(username).toLowerCase()) !== -1) {
      score = Math.min(score, 1);
    }

    score = Math.max(0, Math.min(4, score));
    return { score: score, label: STRENGTH_LABELS[score] };
  }

  function updateStrength(score, label, hasValue) {
    var safeScore = Math.max(0, Math.min(4, score));
    elements.strength.setAttribute('data-score', String(safeScore));
    elements.strengthMeter.setAttribute('aria-valuenow', String(safeScore));
    elements.strengthMeter.setAttribute(
      'aria-valuetext',
      hasValue ? '密码强度：' + label : '请先输入密码'
    );
    var bars = elements.strength.querySelectorAll('.strength-bar');
    bars.forEach(function (bar, index) {
      bar.classList.toggle('is-filled', index < safeScore);
    });
    setText(
      elements.strengthText,
      hasValue ? '强度：' + label : '强度：请先输入密码'
    );
  }

  function updateRequirements(value) {
    var checks = {
      length: value.length >= 12,
      lower: /[a-z]/.test(value),
      upper: /[A-Z]/.test(value),
      digit: /[0-9]/.test(value),
      symbol: SYMBOL_PATTERN.test(value)
    };
    elements.requirementItems.forEach(function (item) {
      item.classList.toggle('is-met', Boolean(checks[item.getAttribute('data-req')]));
    });
  }

  function updatePasswordWarning(value, username) {
    var messages = [];
    if (value && !SAFE_PASSWORD_PATTERN.test(value)) {
      messages.push('密码含有不支持的字符；仅支持字母、数字和 !@#$%^&*()-_=+[]{};,.?/|~ 等符号。');
    }
    if (value && username && value.toLowerCase().indexOf(username.toLowerCase()) !== -1) {
      messages.push('密码不能包含用户名或姓名拼音，请修改。');
    }
    if (value && /(.)\1{3,}/.test(value)) {
      messages.push('密码不能包含 4 个及以上连续相同字符。');
    }
    if (messages.length) {
      setText(elements.passwordWarning, messages.join(' '));
      elements.passwordWarning.hidden = false;
    } else {
      setText(elements.passwordWarning, '');
      elements.passwordWarning.hidden = true;
    }
  }

  function updatePasswordFeedback() {
    var value = elements.passwordInput.value;
    var estimate = estimateStrength(value, state.previewUsername);
    updateStrength(estimate.score, estimate.label, value.length > 0);
    updateRequirements(value);
    updatePasswordWarning(value, state.previewUsername);
  }

  function handleGeneratePassword() {
    if (state.generating || !isFormAvailable()) {
      return;
    }
    state.generating = true;
    elements.generateButton.disabled = true;
    setText(elements.generateButton, '正在生成…');
    clearFormError();

    requestJson('/api/generate-password', {
      method: 'POST',
      body: {},
      timeoutMs: 10000
    }).then(function (data) {
      if (typeof data.password !== 'string' || !data.password) {
        showFormError('生成密码失败，请稍后重试。');
        return;
      }
      elements.passwordInput.value = data.password;
      elements.passwordInput.type = state.passwordVisible ? 'text' : 'password';
      updatePasswordFeedback();
      if (data.strength && typeof data.strength.score === 'number') {
        var score = Math.max(0, Math.min(4, data.strength.score));
        var label = typeof data.strength.label === 'string' && data.strength.label
          ? data.strength.label
          : STRENGTH_LABELS[score];
        updateStrength(score, label, true);
      }
      elements.passwordInput.focus();
    }).catch(function (error) {
      showFormError(error.message || '生成密码失败，请稍后重试。');
    }).then(function () {
      state.generating = false;
      elements.generateButton.disabled = !isFormAvailable();
      setText(elements.generateButton, '生成强密码');
    });
  }

  /* ===== 表单错误提示 ===== */

  function showFormError(message) {
    setText(elements.formError, message);
  }

  function clearFormError() {
    setText(elements.formError, '');
  }

  /* ===== 提交申请 ===== */

  function setSubmitLoading(loading) {
    elements.form.setAttribute('aria-busy', loading ? 'true' : 'false');
    if (loading) {
      elements.submitButton.disabled = true;
      elements.generateButton.disabled = true;
      elements.toggleButton.disabled = true;
      elements.sendCodeButton.disabled = true;
      setText(elements.submitButton, '正在提交…');
      return;
    }
    var available = isFormAvailable();
    elements.submitButton.disabled = !available;
    elements.generateButton.disabled = !available;
    elements.toggleButton.disabled = !available;
    updateSendCodeButton();
    setText(elements.submitButton, available ? '申请账号' : '申请已暂停');
  }

  function handleSubmit(event) {
    event.preventDefault();
    if (state.submitting || !isFormAvailable()) {
      return;
    }
    clearFormError();

    var name = elements.nameInput.value.trim();
    var password = elements.passwordInput.value;
    var email = normalizeEmail(elements.emailInput.value);
    var emailCode = elements.emailCodeInput.value.trim();

    if (!name) {
      showFormError('请输入真实姓名。');
      elements.nameInput.focus();
      return;
    }
    if (!password) {
      showFormError('请输入密码，或点击「生成强密码」自动生成。');
      elements.passwordInput.focus();
      return;
    }
    var emailError = validateEmailLocally(email);
    if (emailError) {
      showFormError(emailError);
      elements.emailInput.focus();
      return;
    }
    if (!/^\d{6}$/.test(emailCode)) {
      showFormError('请输入 6 位数字邮箱验证码。');
      elements.emailCodeInput.focus();
      return;
    }

    state.submitting = true;
    setSubmitLoading(true);

    requestJson('/api/register', {
      method: 'POST',
      body: {
        name: name,
        password: password,
        email: email,
        email_code: emailCode
      },
      timeoutMs: REGISTER_TIMEOUT_MS
    }).then(function (data) {
      renderSuccess(data.account || {}, password, name, email);
    }).catch(function (error) {
      handleRegisterError(error);
    }).then(function () {
      state.submitting = false;
      if (!state.completed) {
        setSubmitLoading(false);
      }
    });
  }

  function handleRegisterError(error) {
    if (error.code === 'REGISTRATION_DISABLED') {
      setRegistrationEnabled(false);
      showFormError(error.message || '当前暂未开放申请，请稍后再试。');
      return;
    }
    if (error.code === 'EMAIL_DISABLED') {
      setEmailVerificationEnabled(false);
      showFormError(error.message || '邮箱验证服务维护中，请稍后再试。');
      return;
    }
    if (error.code === 'EMAIL_REGISTERED') {
      showFormError(error.message || '该学校邮箱已注册过账号，一个邮箱仅可注册一个账号。');
      elements.emailInput.focus();
      return;
    }
    if (error.code === 'INVALID_EMAIL') {
      showFormError(error.message || '邮箱格式不正确，请使用示例大学邮箱。');
      elements.emailInput.focus();
      return;
    }
    if (error.code === 'EMAIL_CODE_INVALID' || error.code === 'EMAIL_CODE_EXPIRED' ||
        error.code === 'EMAIL_TOO_MANY_ATTEMPTS') {
      showFormError(error.message || '邮箱验证码校验失败，请重新获取验证码后重试。');
      elements.emailCodeInput.focus();
      return;
    }
    if (error.code === 'IP_LIMIT') {
      showFormError(error.message || '该校园网 IP 已申请过账号，无法重复申请。');
      return;
    }
    if (error.code === 'RATE_LIMITED') {
      showFormError(error.message || '提交过于频繁，请稍后再试。');
      return;
    }
    if (error.code === 'WEAK_PASSWORD') {
      showFormError(error.message || '密码强度不足，请修改后重试。');
      elements.passwordInput.focus();
      return;
    }
    if (error.code === 'INVALID_NAME') {
      showFormError(error.message || '姓名格式不正确，请填写真实中文姓名。');
      elements.nameInput.focus();
      return;
    }
    showFormError(error.message || '申请失败，请稍后重试。');
  }

  function buildSshLogin(username) {
    if (!username) {
      return '';
    }
    var portPart = state.sshPort === 22 ? '' : ' -p ' + state.sshPort;
    return 'ssh' + portPart + ' ' + username + '@' + state.sshHost;
  }

  function buildSshLoginIpv6(username) {
    if (!username || !state.sshIpv6) {
      return '';
    }
    return 'ssh -6 -p ' + state.sshIpv6Port + ' ' + username + '@' + state.sshIpv6;
  }

  function renderSuccess(account, submittedPassword, submittedName, submittedEmail) {
    state.completed = true;

    var username = typeof account.username === 'string' ? account.username : '';
    var realName = typeof account.real_name === 'string' && account.real_name
      ? account.real_name
      : submittedName;
    var email = typeof account.email === 'string' && account.email
      ? normalizeEmail(account.email)
      : normalizeEmail(submittedEmail);
    var home = typeof account.home === 'string' ? account.home : '';
    var workspace = typeof account.workspace === 'string' && account.workspace
      ? account.workspace
      : home;
    var sshLogin = typeof account.ssh_login === 'string' && account.ssh_login
      ? account.ssh_login
      : buildSshLogin(username);
    var sshLoginIpv6 = typeof account.ssh_login_ipv6 === 'string' && account.ssh_login_ipv6
      ? account.ssh_login_ipv6
      : buildSshLoginIpv6(username);

    state.result = {
      username: username,
      realName: realName,
      password: submittedPassword,
      email: email,
      home: home,
      workspace: workspace,
      sshLogin: sshLogin,
      sshLoginIpv6: sshLoginIpv6
    };

    setText(elements.resultUsername, username || '—');
    setText(elements.resultPassword, submittedPassword);
    setText(elements.resultEmail, email || '—');
    setText(elements.resultHome, home || '—');
    setText(elements.resultWorkspace, workspace || home || '—');
    setText(elements.resultSsh, sshLogin || '—');

    if (sshLoginIpv6) {
      setText(elements.resultSshIpv6, sshLoginIpv6);
      elements.resultIpv6Item.hidden = false;
    } else {
      elements.resultIpv6Item.hidden = true;
    }

    setText(
      elements.resultSubtitle,
      realName
        ? realName + '，你的服务器账号已创建。'
        : '你的服务器账号已创建。'
    );

    if (account.created_at) {
      setText(elements.resultCreated, '申请时间：' + formatDateTime(account.created_at) + '（本地时间）');
      elements.resultCreated.hidden = false;
    } else {
      elements.resultCreated.hidden = true;
    }

    hideBanner();
    clearFormError();
    setCopyStatus('', '');
    elements.applySection.hidden = true;
    elements.bindSection.hidden = true;
    elements.resetSection.hidden = true;
    elements.entrySwitch.hidden = true;
    elements.resultCard.hidden = false;

    elements.passwordInput.value = '';
    elements.nameInput.value = '';
    elements.emailInput.value = '';
    elements.emailCodeInput.value = '';
    setEmailStatus('idle', defaultEmailStatusText());
    stopCooldown();

    try {
      elements.resultCard.focus({ preventScroll: true });
    } catch (error) {
      elements.resultCard.focus();
    }
    try {
      elements.resultCard.scrollIntoView({
        behavior: prefersReducedMotion() ? 'auto' : 'smooth',
        block: 'start'
      });
    } catch (error) {
      elements.resultCard.scrollIntoView();
    }
  }

  /* ===== 绑定已有账号邮箱 ===== */

  function defaultBindEmailStatusText() {
    return '验证码将发送至该邮箱，10 分钟内有效。';
  }

  function setBindEmailStatus(stateName, text) {
    elements.bindEmailStatus.setAttribute('data-state', stateName);
    elements.bindEmailStatus.setAttribute('aria-busy', stateName === 'loading' ? 'true' : 'false');
    setText(elements.bindEmailStatus, text);
  }

  function showBindError(message) {
    setText(elements.bindError, message);
  }

  function clearBindError() {
    setText(elements.bindError, '');
  }

  function handleBindTogglePassword() {
    state.bindPasswordVisible = !state.bindPasswordVisible;
    elements.bindPasswordInput.type = state.bindPasswordVisible ? 'text' : 'password';
    setText(elements.bindTogglePasswordButton, state.bindPasswordVisible ? '隐藏' : '显示');
    elements.bindTogglePasswordButton.setAttribute(
      'aria-pressed',
      state.bindPasswordVisible ? 'true' : 'false'
    );
    elements.bindPasswordInput.focus();
  }

  function handleBindEmailInput() {
    clearBindError();
    var email = normalizeEmail(elements.bindEmailInput.value);
    if (state.bindLastSentEmail && email !== state.bindLastSentEmail) {
      state.bindLastSentEmail = '';
      stopBindCooldown();
      elements.bindCodeInput.value = '';
      setBindEmailStatus('idle', defaultBindEmailStatusText());
    }
    if (state.bindCooldownEmail && email !== state.bindCooldownEmail) {
      stopBindCooldown();
    }
  }

  function handleBindCodeInput() {
    clearBindError();
    var raw = elements.bindCodeInput.value;
    var digits = raw.replace(/\D+/g, '').slice(0, 6);
    if (digits !== raw) {
      elements.bindCodeInput.value = digits;
    }
  }

  function updateBindSendButton() {
    if (state.bindSendingCode) {
      elements.bindSendCodeButton.disabled = true;
      setText(elements.bindSendCodeButton, '发送中…');
      return;
    }
    var remaining = state.bindCooldownEnd
      ? Math.ceil((state.bindCooldownEnd - Date.now()) / 1000)
      : 0;
    if (remaining > 0) {
      elements.bindSendCodeButton.disabled = true;
      setText(elements.bindSendCodeButton, '重新发送（' + formatCountdown(remaining) + '）');
      return;
    }
    elements.bindSendCodeButton.disabled = !isBindAvailable();
    setText(elements.bindSendCodeButton, '发送验证码');
  }

  function stopBindCooldown() {
    if (state.bindCooldownTimer) {
      window.clearInterval(state.bindCooldownTimer);
      state.bindCooldownTimer = 0;
    }
    state.bindCooldownEnd = 0;
    state.bindCooldownEmail = '';
    updateBindSendButton();
  }

  function tickBindCooldown() {
    var remaining = state.bindCooldownEnd
      ? Math.ceil((state.bindCooldownEnd - Date.now()) / 1000)
      : 0;
    if (remaining <= 0) {
      if (state.bindCooldownTimer) {
        window.clearInterval(state.bindCooldownTimer);
        state.bindCooldownTimer = 0;
      }
      state.bindCooldownEnd = 0;
    }
    updateBindSendButton();
  }

  function startBindCooldown(seconds, email) {
    var total = typeof seconds === 'number' && isFinite(seconds) && seconds > 0
      ? Math.floor(seconds)
      : DEFAULT_COOLDOWN_SECONDS;
    if (state.bindCooldownTimer) {
      window.clearInterval(state.bindCooldownTimer);
    }
    state.bindCooldownEnd = Date.now() + total * 1000;
    state.bindCooldownEmail = email ? normalizeEmail(email) : '';
    state.bindCooldownTimer = window.setInterval(tickBindCooldown, 1000);
    updateBindSendButton();
  }

  function collectBindCredentials() {
    return {
      username: elements.bindUsernameInput.value.trim(),
      password: elements.bindPasswordInput.value,
      email: normalizeEmail(elements.bindEmailInput.value)
    };
  }

  function validateBindCredentials(credentials) {
    if (!credentials.username) {
      showBindError('请输入用户名。');
      elements.bindUsernameInput.focus();
      return false;
    }
    if (!credentials.password) {
      showBindError('请输入当前服务器密码。');
      elements.bindPasswordInput.focus();
      return false;
    }
    var emailError = validateEmailLocally(credentials.email);
    if (emailError) {
      showBindError(emailError);
      elements.bindEmailInput.focus();
      return false;
    }
    return true;
  }

  function handleBindSendCode() {
    if (state.bindSendingCode || !isBindAvailable()) {
      return;
    }
    clearBindError();
    var credentials = collectBindCredentials();
    if (!validateBindCredentials(credentials)) {
      return;
    }

    state.bindSendingCode = true;
    updateBindSendButton();
    setBindEmailStatus('loading', '正在发送验证码，请稍候…');

    requestJson('/api/email/bind-request', {
      method: 'POST',
      body: {
        username: credentials.username,
        password: credentials.password,
        email: credentials.email
      },
      timeoutMs: 30000
    }).then(function (data) {
      var sentEmail = typeof data.email === 'string' && data.email
        ? normalizeEmail(data.email)
        : credentials.email;
      var expiresIn = typeof data.expires_in === 'number' && data.expires_in > 0
        ? data.expires_in
        : DEFAULT_CODE_TTL_SECONDS;
      var cooldown = typeof data.cooldown === 'number' && data.cooldown > 0
        ? data.cooldown
        : DEFAULT_COOLDOWN_SECONDS;
      state.bindLastSentEmail = sentEmail;
      elements.bindCodeInput.value = '';
      var message = '验证码已发送至 ' + sentEmail + '，' +
        formatExpiresIn(expiresIn) + '内有效。';
      if (typeof data.debug_code === 'string' && data.debug_code) {
        message += '（本地测试验证码：' + data.debug_code + '）';
      }
      setBindEmailStatus('ok', message);
      startBindCooldown(cooldown, sentEmail);
      elements.bindCodeInput.focus();
    }).catch(function (error) {
      if (error.code === 'RATE_LIMITED') {
        var wait = error.retryAfter > 0 ? error.retryAfter : DEFAULT_COOLDOWN_SECONDS;
        setBindEmailStatus('error', error.message || '发送过于频繁，请稍后再试。');
        startBindCooldown(wait, credentials.email);
      } else {
        setBindEmailStatus('error', error.message || '验证码发送失败，请稍后重试。');
      }
      if (error.code === 'INVALID_CREDENTIALS') {
        elements.bindPasswordInput.focus();
      } else if (error.code === 'INVALID_USERNAME') {
        elements.bindUsernameInput.focus();
      } else if (error.code === 'INVALID_EMAIL' || error.code === 'EMAIL_ALREADY_BOUND' ||
                 error.code === 'EMAIL_DISABLED') {
        elements.bindEmailInput.focus();
      }
    }).then(function () {
      state.bindSendingCode = false;
      updateBindSendButton();
    });
  }

  function setBindSubmitLoading(loading) {
    elements.bindForm.setAttribute('aria-busy', loading ? 'true' : 'false');
    if (loading) {
      elements.bindSubmitButton.disabled = true;
      elements.bindSendCodeButton.disabled = true;
      elements.bindTogglePasswordButton.disabled = true;
      setText(elements.bindSubmitButton, '正在绑定…');
      return;
    }
    var available = isBindAvailable();
    elements.bindSubmitButton.disabled = !available;
    elements.bindTogglePasswordButton.disabled = !available;
    updateBindSendButton();
    setText(elements.bindSubmitButton, available ? '绑定邮箱' : '暂不可用');
  }

  function handleBindSubmit(event) {
    event.preventDefault();
    if (state.bindSubmitting || !isBindAvailable()) {
      return;
    }
    clearBindError();
    var credentials = collectBindCredentials();
    var code = elements.bindCodeInput.value.trim();

    if (!validateBindCredentials(credentials)) {
      return;
    }
    if (!/^\d{6}$/.test(code)) {
      showBindError('请输入 6 位数字邮箱验证码。');
      elements.bindCodeInput.focus();
      return;
    }

    state.bindSubmitting = true;
    setBindSubmitLoading(true);

    requestJson('/api/email/bind', {
      method: 'POST',
      body: {
        username: credentials.username,
        password: credentials.password,
        email: credentials.email,
        code: code
      },
      timeoutMs: REGISTER_TIMEOUT_MS
    }).then(function (data) {
      renderBindSuccess(data, credentials);
    }).catch(function (error) {
      handleBindError(error);
    }).then(function () {
      state.bindSubmitting = false;
      if (!state.bindCompleted) {
        setBindSubmitLoading(false);
      }
    });
  }

  function handleBindError(error) {
    if (error.code === 'EMAIL_CODE_INVALID' || error.code === 'EMAIL_CODE_EXPIRED' ||
        error.code === 'EMAIL_TOO_MANY_ATTEMPTS') {
      showBindError(error.message || '邮箱验证码校验失败，请重新获取验证码后重试。');
      elements.bindCodeInput.focus();
      return;
    }
    if (error.code === 'INVALID_CREDENTIALS') {
      showBindError(error.message || '用户名或密码错误，或该账号不支持自助操作。');
      elements.bindPasswordInput.focus();
      return;
    }
    if (error.code === 'INVALID_USERNAME') {
      showBindError(error.message || '用户名格式不正确。');
      elements.bindUsernameInput.focus();
      return;
    }
    if (error.code === 'INVALID_EMAIL' || error.code === 'EMAIL_ALREADY_BOUND' ||
        error.code === 'EMAIL_DISABLED') {
      showBindError(error.message || '邮箱校验失败，请检查后重试。');
      elements.bindEmailInput.focus();
      return;
    }
    showBindError(error.message || '绑定邮箱失败，请稍后重试。');
  }

  function renderBindSuccess(data, credentials) {
    state.bindCompleted = true;
    stopBindCooldown();
    clearBindError();
    var username = data && typeof data.username === 'string' && data.username
      ? data.username
      : credentials.username;
    var email = data && typeof data.email === 'string' && data.email
      ? normalizeEmail(data.email)
      : credentials.email;
    state.bindResult = { username: username, email: email };
    setText(elements.bindSuccessUsername, username || '—');
    setText(elements.bindSuccessEmail, email || '—');
    elements.bindForm.hidden = true;
    elements.bindSuccess.hidden = false;
    elements.bindCodeInput.value = '';
    elements.bindPasswordInput.value = '';
    setBindEmailStatus('idle', defaultBindEmailStatusText());
    try {
      elements.bindSuccess.focus({ preventScroll: true });
    } catch (error) {
      elements.bindSuccess.focus();
    }
    try {
      elements.bindSuccess.scrollIntoView({
        behavior: prefersReducedMotion() ? 'auto' : 'smooth',
        block: 'start'
      });
    } catch (error) {
      elements.bindSuccess.scrollIntoView();
    }
  }

  function resetBindFormState() {
    state.bindCompleted = false;
    state.bindLastSentEmail = '';
    state.bindResult = null;
    stopBindCooldown();
    elements.bindForm.reset();
    elements.bindForm.hidden = false;
    elements.bindSuccess.hidden = true;
    setBindEmailStatus('idle', defaultBindEmailStatusText());
    clearBindError();
    state.bindPasswordVisible = false;
    elements.bindPasswordInput.type = 'password';
    setText(elements.bindTogglePasswordButton, '显示');
    elements.bindTogglePasswordButton.setAttribute('aria-pressed', 'false');
    updateBindSendButton();
    setBindSubmitLoading(false);
  }

  function handleBindGoReset() {
    var email = state.bindResult && state.bindResult.email ? state.bindResult.email : '';
    switchEntry('reset');
    if (email) {
      elements.resetEmailInput.value = email;
      setResetEmailStatus('idle', defaultResetEmailStatusText());
    }
  }

  /* ===== 忘记密码：重置表单 ===== */

  function defaultResetEmailStatusText() {
    return '验证码将发送至该邮箱，10 分钟内有效。';
  }

  function setResetEmailStatus(stateName, text) {
    elements.resetEmailStatus.setAttribute('data-state', stateName);
    elements.resetEmailStatus.setAttribute('aria-busy', stateName === 'loading' ? 'true' : 'false');
    setText(elements.resetEmailStatus, text);
  }

  function showResetError(message) {
    setText(elements.resetError, message);
  }

  function clearResetError() {
    setText(elements.resetError, '');
  }

  function updateResetStrength(score, label, hasValue) {
    var safeScore = Math.max(0, Math.min(4, score));
    elements.resetStrength.setAttribute('data-score', String(safeScore));
    elements.resetStrengthMeter.setAttribute('aria-valuenow', String(safeScore));
    elements.resetStrengthMeter.setAttribute(
      'aria-valuetext',
      hasValue ? '新密码强度：' + label : '请先输入新密码'
    );
    var bars = elements.resetStrength.querySelectorAll('.strength-bar');
    bars.forEach(function (bar, index) {
      bar.classList.toggle('is-filled', index < safeScore);
    });
    setText(
      elements.resetStrengthText,
      hasValue ? '强度：' + label : '强度：请先输入密码'
    );
  }

  function updateResetRequirements(value) {
    var checks = {
      length: value.length >= 12,
      lower: /[a-z]/.test(value),
      upper: /[A-Z]/.test(value),
      digit: /[0-9]/.test(value),
      symbol: SYMBOL_PATTERN.test(value)
    };
    elements.resetRequirementItems.forEach(function (item) {
      item.classList.toggle('is-met', Boolean(checks[item.getAttribute('data-req')]));
    });
  }

  function updateResetPasswordWarning(value) {
    var messages = [];
    if (value && !SAFE_PASSWORD_PATTERN.test(value)) {
      messages.push('密码含有不支持的字符；仅支持字母、数字和 !@#$%^&*()-_=+[]{};,.?/|~ 等符号。');
    }
    if (value && /(.)\1{3,}/.test(value)) {
      messages.push('密码不能包含 4 个及以上连续相同字符。');
    }
    if (messages.length) {
      setText(elements.resetPasswordWarning, messages.join(' '));
      elements.resetPasswordWarning.hidden = false;
    } else {
      setText(elements.resetPasswordWarning, '');
      elements.resetPasswordWarning.hidden = true;
    }
  }

  function updateResetPasswordFeedback() {
    var value = elements.resetPasswordInput.value;
    var estimate = estimateStrength(value, '');
    updateResetStrength(estimate.score, estimate.label, value.length > 0);
    updateResetRequirements(value);
    updateResetPasswordWarning(value);
  }

  function handleResetTogglePassword() {
    state.resetPasswordVisible = !state.resetPasswordVisible;
    elements.resetPasswordInput.type = state.resetPasswordVisible ? 'text' : 'password';
    setText(elements.resetTogglePasswordButton, state.resetPasswordVisible ? '隐藏' : '显示');
    elements.resetTogglePasswordButton.setAttribute(
      'aria-pressed',
      state.resetPasswordVisible ? 'true' : 'false'
    );
    elements.resetPasswordInput.focus();
  }

  function handleResetEmailInput() {
    clearResetError();
    var email = normalizeEmail(elements.resetEmailInput.value);
    if (state.resetLastSentEmail && email !== state.resetLastSentEmail) {
      state.resetLastSentEmail = '';
      stopResetCooldown();
      elements.resetCodeInput.value = '';
      setResetEmailStatus('idle', defaultResetEmailStatusText());
    }
    if (state.resetCooldownEmail && email !== state.resetCooldownEmail) {
      stopResetCooldown();
    }
  }

  function handleResetCodeInput() {
    clearResetError();
    var raw = elements.resetCodeInput.value;
    var digits = raw.replace(/\D+/g, '').slice(0, 6);
    if (digits !== raw) {
      elements.resetCodeInput.value = digits;
    }
  }

  function updateResetSendButton() {
    if (state.resetSendingCode) {
      elements.resetSendCodeButton.disabled = true;
      setText(elements.resetSendCodeButton, '发送中…');
      return;
    }
    var remaining = state.resetCooldownEnd
      ? Math.ceil((state.resetCooldownEnd - Date.now()) / 1000)
      : 0;
    if (remaining > 0) {
      elements.resetSendCodeButton.disabled = true;
      setText(elements.resetSendCodeButton, '重新发送（' + formatCountdown(remaining) + '）');
      return;
    }
    elements.resetSendCodeButton.disabled = !isResetAvailable();
    setText(elements.resetSendCodeButton, '发送验证码');
  }

  function stopResetCooldown() {
    if (state.resetCooldownTimer) {
      window.clearInterval(state.resetCooldownTimer);
      state.resetCooldownTimer = 0;
    }
    state.resetCooldownEnd = 0;
    state.resetCooldownEmail = '';
    updateResetSendButton();
  }

  function tickResetCooldown() {
    var remaining = state.resetCooldownEnd
      ? Math.ceil((state.resetCooldownEnd - Date.now()) / 1000)
      : 0;
    if (remaining <= 0) {
      if (state.resetCooldownTimer) {
        window.clearInterval(state.resetCooldownTimer);
        state.resetCooldownTimer = 0;
      }
      state.resetCooldownEnd = 0;
    }
    updateResetSendButton();
  }

  function startResetCooldown(seconds, email) {
    var total = typeof seconds === 'number' && isFinite(seconds) && seconds > 0
      ? Math.floor(seconds)
      : DEFAULT_COOLDOWN_SECONDS;
    if (state.resetCooldownTimer) {
      window.clearInterval(state.resetCooldownTimer);
    }
    state.resetCooldownEnd = Date.now() + total * 1000;
    state.resetCooldownEmail = email ? normalizeEmail(email) : '';
    state.resetCooldownTimer = window.setInterval(tickResetCooldown, 1000);
    updateResetSendButton();
  }

  function handleResetSendCode() {
    if (state.resetSendingCode || !isResetAvailable()) {
      return;
    }
    clearResetError();
    var email = normalizeEmail(elements.resetEmailInput.value);
    var localError = validateEmailLocally(email);
    if (localError) {
      setResetEmailStatus('error', localError);
      elements.resetEmailInput.focus();
      return;
    }

    state.resetSendingCode = true;
    updateResetSendButton();
    setResetEmailStatus('loading', '正在发送验证码，请稍候…');

    requestJson('/api/password/reset-request', {
      method: 'POST',
      body: { email: email },
      timeoutMs: 20000
    }).then(function (data) {
      var sentEmail = typeof data.email === 'string' && data.email
        ? normalizeEmail(data.email)
        : email;
      var expiresIn = typeof data.expires_in === 'number' && data.expires_in > 0
        ? data.expires_in
        : DEFAULT_CODE_TTL_SECONDS;
      var cooldown = typeof data.cooldown === 'number' && data.cooldown > 0
        ? data.cooldown
        : DEFAULT_COOLDOWN_SECONDS;
      state.resetLastSentEmail = sentEmail;
      elements.resetCodeInput.value = '';
      var message = '验证码已发送至 ' + sentEmail + '，' +
        formatExpiresIn(expiresIn) + '内有效。';
      if (typeof data.debug_code === 'string' && data.debug_code) {
        message += '（本地测试验证码：' + data.debug_code + '）';
      }
      setResetEmailStatus('ok', message);
      startResetCooldown(cooldown, sentEmail);
      elements.resetCodeInput.focus();
    }).catch(function (error) {
      if (error.code === 'RATE_LIMITED') {
        var wait = error.retryAfter > 0 ? error.retryAfter : DEFAULT_COOLDOWN_SECONDS;
        setResetEmailStatus('error', error.message || '发送过于频繁，请稍后再试。');
        startResetCooldown(wait, email);
      } else {
        setResetEmailStatus('error', error.message || '验证码发送失败，请稍后重试。');
      }
      if (error.code === 'INVALID_EMAIL' || error.code === 'EMAIL_NOT_FOUND' ||
          error.code === 'EMAIL_DISABLED') {
        elements.resetEmailInput.focus();
      }
    }).then(function () {
      state.resetSendingCode = false;
      updateResetSendButton();
    });
  }

  function handleResetGeneratePassword() {
    if (state.resetGenerating || !isResetAvailable()) {
      return;
    }
    state.resetGenerating = true;
    elements.resetGenerateButton.disabled = true;
    setText(elements.resetGenerateButton, '正在生成…');
    clearResetError();

    requestJson('/api/generate-password', {
      method: 'POST',
      body: {},
      timeoutMs: 10000
    }).then(function (data) {
      if (typeof data.password !== 'string' || !data.password) {
        showResetError('生成密码失败，请稍后重试。');
        return;
      }
      elements.resetPasswordInput.value = data.password;
      elements.resetPasswordInput.type = state.resetPasswordVisible ? 'text' : 'password';
      updateResetPasswordFeedback();
      if (data.strength && typeof data.strength.score === 'number') {
        var score = Math.max(0, Math.min(4, data.strength.score));
        var label = typeof data.strength.label === 'string' && data.strength.label
          ? data.strength.label
          : STRENGTH_LABELS[score];
        updateResetStrength(score, label, true);
      }
      elements.resetPasswordInput.focus();
    }).catch(function (error) {
      showResetError(error.message || '生成密码失败，请稍后重试。');
    }).then(function () {
      state.resetGenerating = false;
      elements.resetGenerateButton.disabled = !isResetAvailable();
      setText(elements.resetGenerateButton, '生成强密码');
    });
  }

  function setResetSubmitLoading(loading) {
    elements.resetForm.setAttribute('aria-busy', loading ? 'true' : 'false');
    if (loading) {
      elements.resetSubmitButton.disabled = true;
      elements.resetSendCodeButton.disabled = true;
      elements.resetTogglePasswordButton.disabled = true;
      elements.resetGenerateButton.disabled = true;
      elements.backToApply.disabled = true;
      setText(elements.resetSubmitButton, '正在重置…');
      return;
    }
    var available = isResetAvailable();
    elements.resetSubmitButton.disabled = !available;
    elements.resetTogglePasswordButton.disabled = !available;
    elements.resetGenerateButton.disabled = !available;
    elements.backToApply.disabled = false;
    updateResetSendButton();
    setText(elements.resetSubmitButton, available ? '重置密码' : '暂不可用');
  }

  function handleResetSubmit(event) {
    event.preventDefault();
    if (state.resetSubmitting || !isResetAvailable()) {
      return;
    }
    clearResetError();

    var email = normalizeEmail(elements.resetEmailInput.value);
    var code = elements.resetCodeInput.value.trim();
    var password = elements.resetPasswordInput.value;

    if (!email) {
      showResetError('请输入注册时使用的学校邮箱。');
      elements.resetEmailInput.focus();
      return;
    }
    var emailError = validateEmailLocally(email);
    if (emailError) {
      showResetError(emailError);
      elements.resetEmailInput.focus();
      return;
    }
    if (!/^\d{6}$/.test(code)) {
      showResetError('请输入 6 位数字邮箱验证码。');
      elements.resetCodeInput.focus();
      return;
    }
    if (!password) {
      showResetError('请输入新密码。');
      elements.resetPasswordInput.focus();
      return;
    }

    state.resetSubmitting = true;
    setResetSubmitLoading(true);

    requestJson('/api/password/reset', {
      method: 'POST',
      body: {
        email: email,
        code: code,
        new_password: password
      },
      timeoutMs: REGISTER_TIMEOUT_MS
    }).then(function (data) {
      renderResetSuccess(data);
    }).catch(function (error) {
      handleResetError(error);
    }).then(function () {
      state.resetSubmitting = false;
      if (!state.resetCompleted) {
        setResetSubmitLoading(false);
      }
    });
  }

  function handleResetError(error) {
    if (error.code === 'EMAIL_CODE_INVALID' || error.code === 'EMAIL_CODE_EXPIRED' ||
        error.code === 'EMAIL_TOO_MANY_ATTEMPTS') {
      showResetError(error.message || '邮箱验证码校验失败，请重新获取验证码后重试。');
      elements.resetCodeInput.focus();
      return;
    }
    if (error.code === 'WEAK_PASSWORD') {
      showResetError(error.message || '新密码强度不足，请修改后重试。');
      elements.resetPasswordInput.focus();
      return;
    }
    if (error.code === 'EMAIL_NOT_FOUND' || error.code === 'INVALID_EMAIL') {
      showResetError(error.message || '该邮箱未注册或格式不正确。');
      elements.resetEmailInput.focus();
      return;
    }
    if (error.code === 'EMAIL_DISABLED' || error.code === 'USER_MISSING' ||
        error.code === 'RATE_LIMITED') {
      showResetError(error.message || '重置密码失败，请稍后重试。');
      return;
    }
    showResetError(error.message || '重置密码失败，请稍后重试。');
  }

  function renderResetSuccess(data) {
    state.resetCompleted = true;
    stopResetCooldown();
    clearResetError();
    var username = data && typeof data.username === 'string' ? data.username : '';
    setText(elements.resetSuccessUsername, username || '—');
    elements.resetLockedNote.hidden = !(data && data.locked === true);
    elements.resetForm.hidden = true;
    elements.resetSuccess.hidden = false;
    elements.resetCodeInput.value = '';
    elements.resetPasswordInput.value = '';
    setResetEmailStatus('idle', defaultResetEmailStatusText());
    try {
      elements.resetSuccess.focus({ preventScroll: true });
    } catch (error) {
      elements.resetSuccess.focus();
    }
    try {
      elements.resetSuccess.scrollIntoView({
        behavior: prefersReducedMotion() ? 'auto' : 'smooth',
        block: 'start'
      });
    } catch (error) {
      elements.resetSuccess.scrollIntoView();
    }
  }

  function resetResetFormState() {
    state.resetCompleted = false;
    state.resetLastSentEmail = '';
    stopResetCooldown();
    elements.resetForm.reset();
    elements.resetForm.hidden = false;
    elements.resetSuccess.hidden = true;
    elements.resetLockedNote.hidden = true;
    setResetEmailStatus('idle', defaultResetEmailStatusText());
    clearResetError();
    state.resetPasswordVisible = false;
    elements.resetPasswordInput.type = 'password';
    setText(elements.resetTogglePasswordButton, '显示');
    elements.resetTogglePasswordButton.setAttribute('aria-pressed', 'false');
    updateResetPasswordFeedback();
    updateResetSendButton();
    setResetSubmitLoading(false);
  }

  function setEntryTab(mode) {
    var tabs = {
      apply: elements.entryApply,
      bind: elements.entryBind,
      reset: elements.entryReset
    };
    Object.keys(tabs).forEach(function (key) {
      var active = key === mode;
      tabs[key].classList.toggle('is-active', active);
      tabs[key].setAttribute('aria-pressed', active ? 'true' : 'false');
    });
  }

  function switchEntry(mode) {
    if (mode === 'apply' && !isFormAvailable()) {
      showBanner('warn', '申请通道已暂停，暂时无法申请账号，请稍后再试。');
      return;
    }
    if (mode === 'bind' && !isBindAvailable()) {
      showBanner('warn', '邮箱验证服务维护中，暂时无法绑定邮箱，请稍后再试。');
      return;
    }
    if (mode === 'reset' && !isResetAvailable()) {
      showBanner('warn', '邮箱验证服务维护中，暂时无法重置密码，请稍后再试。');
      return;
    }
    if (mode === 'bind' && state.bindCompleted) {
      resetBindFormState();
    }
    if (mode === 'reset' && state.resetCompleted) {
      resetResetFormState();
    }
    elements.applySection.hidden = mode !== 'apply';
    elements.bindSection.hidden = mode !== 'bind';
    elements.resetSection.hidden = mode !== 'reset';
    elements.resultCard.hidden = true;
    elements.entrySwitch.hidden = false;
    state.entryMode = mode;
    setEntryTab(mode);

    var section = mode === 'apply'
      ? elements.applySection
      : (mode === 'bind' ? elements.bindSection : elements.resetSection);
    try {
      section.focus({ preventScroll: true });
    } catch (error) {
      /* 忽略不支持 focus 选项的浏览器 */
    }
    try {
      section.scrollIntoView({
        behavior: prefersReducedMotion() ? 'auto' : 'smooth',
        block: 'start'
      });
    } catch (error) {
      section.scrollIntoView();
    }
    var focusInput = mode === 'apply'
      ? elements.nameInput
      : (mode === 'bind' ? elements.bindUsernameInput : elements.resetEmailInput);
    try {
      focusInput.focus({ preventScroll: true });
    } catch (error) {
      focusInput.focus();
    }
  }

  /* ===== 复制功能 ===== */

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

  function copyText(text, successMessage) {
    if (!text) {
      return;
    }
    var promise;
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function' &&
        window.isSecureContext) {
      promise = navigator.clipboard.writeText(text);
    } else {
      promise = Promise.reject(new Error('剪贴板接口不可用'));
    }
    promise.then(function () {
      setCopyStatus(successMessage, 'ok');
    }).catch(function () {
      try {
        fallbackCopy(text);
        setCopyStatus(successMessage, 'ok');
      } catch (error) {
        setCopyStatus('复制失败，请手动选中文本后复制。', 'error');
      }
    });
  }

  function setCopyStatus(message, kind) {
    setText(elements.copyStatus, message);
    if (kind) {
      elements.copyStatus.setAttribute('data-kind', kind);
    } else {
      elements.copyStatus.removeAttribute('data-kind');
    }
    if (state.copyTimer) {
      window.clearTimeout(state.copyTimer);
      state.copyTimer = 0;
    }
    if (message) {
      state.copyTimer = window.setTimeout(function () {
        setText(elements.copyStatus, '');
        elements.copyStatus.removeAttribute('data-kind');
      }, 6000);
    }
  }

  function buildCopyAllText() {
    var result = state.result;
    if (!result) {
      return '';
    }
    var lines = [
      '校园网服务器账号信息',
      '服务器：' + state.serverName,
      '姓名：' + (result.realName || '—'),
      '学校邮箱：' + (result.email || '—'),
      '用户名：' + result.username,
      '密码：' + result.password,
      '家目录：' + (result.home || '—'),
      '工作目录：' + (result.workspace || result.home || '—'),
      '校内登录（IPv4）：' + (result.sshLogin || '—')
    ];
    if (result.sshLoginIpv6) {
      lines.push('校外登录（IPv6）：' + result.sshLoginIpv6);
    }
    lines.push(
      '',
      '密码明文仅显示这一次，请妥善保存；首次登录后请立即执行 passwd 修改密码。',
      '家目录位于数据盘 /home，无需额外挂载；本账号为普通用户，无管理员权限。'
    );
    return lines.join('\n');
  }

  /* ===== 启动 ===== */

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
