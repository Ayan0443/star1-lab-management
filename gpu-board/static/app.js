(function () {
  "use strict";

  var API_HEADER = "star1-gpu-board";
  var state = null;
  var me = null;
  var timers = { state: null, usage: null };
  var busy = { state: false, usage: false };

  function $(id) {
    return document.getElementById(id);
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function pad(value) {
    return value < 10 ? "0" + value : String(value);
  }

  function fmtTime(ts) {
    var d = new Date(ts * 1000);
    return pad(d.getHours()) + ":" + pad(d.getMinutes());
  }

  function fmtDate(ts) {
    var d = new Date(ts * 1000);
    return pad(d.getMonth() + 1) + "-" + pad(d.getDate());
  }

  function fmtDateTime(ts) {
    return fmtDate(ts) + " " + fmtTime(ts);
  }

  function fmtRange(start, end) {
    if (fmtDate(start) === fmtDate(end)) {
      return fmtDateTime(start) + " – " + fmtTime(end);
    }
    return fmtDateTime(start) + " – " + fmtDateTime(end);
  }

  function fmtDuration(seconds) {
    seconds = Math.max(0, Math.floor(seconds || 0));
    var days = Math.floor(seconds / 86400);
    var hours = Math.floor((seconds % 86400) / 3600);
    var minutes = Math.floor((seconds % 3600) / 60);
    if (days > 0) return days + " 天 " + hours + " 小时";
    if (hours > 0) return hours + " 小时 " + minutes + " 分";
    return Math.max(1, minutes) + " 分钟";
  }

  function fmtGiB(mib) {
    return (mib / 1024).toFixed(1);
  }

  function api(path, options) {
    var opts = options || {};
    opts.credentials = "same-origin";
    opts.headers = opts.headers || {};
    opts.headers["X-Requested-With"] = API_HEADER;
    if (opts.body) opts.headers["Content-Type"] = "application/json";
    return fetch(path, opts).then(function (response) {
      return response
        .json()
        .catch(function () {
          return null;
        })
        .then(function (data) {
          if (!response.ok) {
            var message = (data && data.error && data.error.message) || "请求失败（" + response.status + "）";
            throw new Error(message);
          }
          return data;
        });
    });
  }

  function showMsg(node, text, isError) {
    node.textContent = text;
    node.className = "msg " + (isError ? "error" : "ok");
    node.hidden = false;
    window.clearTimeout(node._hideTimer);
    node._hideTimer = window.setTimeout(function () {
      node.hidden = true;
    }, 8000);
  }

  /* ---------- 账号 ---------- */

  function renderAccount() {
    var account = $("account");
    account.textContent = "";
    var host = state && state.host ? state.host : "";
    account.appendChild(el("span", "muted", host ? "主机 " + host : "只读监控"));
    if (me) {
      var label = me.role === "admin" ? "管理员" : me.real_name + "（" + me.username + "）";
      account.appendChild(el("span", "user-chip", label));
      var logoutBtn = el("button", "btn btn-ghost btn-small", "退出");
      logoutBtn.type = "button";
      logoutBtn.addEventListener("click", logout);
      account.appendChild(logoutBtn);
    } else {
      var loginBtn = el("button", "btn btn-ghost btn-small", "登录");
      loginBtn.type = "button";
      loginBtn.addEventListener("click", showLogin);
      account.appendChild(loginBtn);
    }
  }

  function buildSnippets(token) {
    var origin = window.location.origin;
    var boardMcp = "/opt/star1-gpu-board/mcp_server.py";
    $("snippet-claude").textContent =
      "claude mcp add star1-gpu \\\n" +
      "  -e GPU_BOARD_URL=" + origin + " \\\n" +
      "  -e GPU_BOARD_TOKEN=" + token + " \\\n" +
      "  -- python3 " + boardMcp;
    $("snippet-codex").textContent =
      "[mcp_servers.star1-gpu]\n" +
      'command = "python3"\n' +
      'args = ["' + boardMcp + '"]\n' +
      "env = { GPU_BOARD_URL = \"" + origin + "\", GPU_BOARD_TOKEN = \"" + token + "\" }";
    $("snippet-dsh").textContent =
      "# 在 DSH profile 里新增一个仅配置的 MCP bundle，cordis.patch.yml 内容示例：\n" +
      "- insert:\n" +
      "    - id: star1-gpu-mcp\n" +
      "      name: '@deepseek-ai/dsh-mcp-client'\n" +
      "      config:\n" +
      "        serverName: star1-gpu\n" +
      "        transport: stdio\n" +
      "        command: python3\n" +
      "        args: ['" + boardMcp + "']\n" +
      "        env:\n" +
      "          GPU_BOARD_URL: '" + origin + "'\n" +
      "          GPU_BOARD_TOKEN: '" + token + "'\n" +
      "        failOnStartupError: true";
  }

  function renderTokens(tokens) {
    var container = $("token-list");
    if (!container) return;
    container.textContent = "";
    if (!tokens || !tokens.length) {
      container.appendChild(el("p", "empty", "还没有 token。生成后把命令贴到 agent 配置里即可。"));
      return;
    }
    var table = el("table", "table");
    var thead = el("thead");
    var headRow = el("tr");
    ["备注", "前缀", "创建时间", "最近使用", "操作"].forEach(function (text) {
      headRow.appendChild(el("th", null, text));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = el("tbody");
    tokens.forEach(function (token) {
      var tr = el("tr");
      tr.appendChild(el("td", null, token.name));
      tr.appendChild(el("td", "time", token.prefix + "…"));
      tr.appendChild(el("td", "time", fmtDateTime(token.created_ts)));
      tr.appendChild(el("td", "time", token.last_used_ts ? fmtDateTime(token.last_used_ts) : "未使用"));
      var action = el("td");
      var btn = el("button", "btn-link", "撤销");
      btn.type = "button";
      btn.addEventListener("click", function () {
        revokeToken(token.id, token.name);
      });
      action.appendChild(btn);
      tr.appendChild(action);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);
  }

  function loadTokens() {
    if (!me || me.role !== "user" || me.via === "token") {
      $("agent-section").hidden = true;
      return;
    }
    api("/api/tokens")
      .then(function (data) {
        $("agent-section").hidden = false;
        renderTokens(data.tokens || []);
      })
      .catch(function () {
        $("agent-section").hidden = true;
      });
  }

  function createToken(event) {
    if (event) event.preventDefault();
    var name = $("token-name").value.trim() || "agent";
    api("/api/tokens", { method: "POST", body: JSON.stringify({ name: name }) })
      .then(function (data) {
        $("token-value").textContent = data.token;
        buildSnippets(data.token);
        $("token-new").hidden = false;
        $("token-name").value = "";
        showMsg($("token-msg"), "token 已生成（只显示这一次）", false);
        loadTokens();
      })
      .catch(function (error) {
        showMsg($("token-msg"), error.message, true);
      });
  }

  function revokeToken(id, name) {
    if (!window.confirm("撤销 token「" + name + "」？使用它的 agent 将立即失效。")) return;
    api("/api/tokens/revoke", { method: "POST", body: JSON.stringify({ id: id }) })
      .then(function () {
        loadTokens();
      })
      .catch(function (error) {
        showMsg($("token-msg"), error.message, true);
      });
  }

  function copyToken() {
    var text = $("token-value").textContent;
    if (!text) return;
    var done = function () {
      showMsg($("token-msg"), "已复制到剪贴板", false);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(function () {
        window.prompt("请手动复制 token：", text);
      });
    } else {
      window.prompt("请手动复制 token：", text);
    }
  }

  function showLogin() {
    $("guest-note").hidden = true;
    $("login-panel").hidden = false;
    $("login-username").focus();
  }

  function login(event) {
    if (event) event.preventDefault();
    var username = $("login-username").value.trim().toLowerCase();
    var password = $("login-password").value;
    var msg = $("login-msg");
    if (!username || !password) {
      showMsg(msg, "请输入用户名和密码", true);
      return;
    }
    api("/api/login", {
      method: "POST",
      body: JSON.stringify({ username: username, password: password }),
    })
      .then(function (data) {
        me = data.me;
        $("login-password").value = "";
        $("login-msg").hidden = true;
        $("login-panel").hidden = true;
        $("guest-note").hidden = true;
        $("booking-body").hidden = false;
        renderAccount();
        setDefaultTimes();
        refreshState();
      })
      .catch(function (error) {
        showMsg(msg, error.message, true);
      });
  }

  function logout() {
    api("/api/logout", { method: "POST", body: "{}" })
      .catch(function () {})
      .then(function () {
        me = null;
        $("booking-body").hidden = true;
        $("login-panel").hidden = true;
        $("guest-note").hidden = false;
        renderAccount();
        refreshState();
      });
  }

  /* ---------- 概览 ---------- */

  function renderSummary() {
    if (!state) return;
    var summary = state.summary || {};
    $("stat-free").textContent = summary.free || 0;
    $("stat-busy").textContent = summary.busy || 0;
    $("stat-unregistered").textContent = summary.unregistered || 0;
    $("stat-conflict").textContent = summary.conflict || 0;
    var now = Math.floor(Date.now() / 1000);
    var upcoming = (state.bookings || []).filter(function (booking) {
      return booking.end_ts > now && booking.start_ts < now + 86400;
    });
    $("stat-bookings").textContent = upcoming.length;
    var load = state.load && state.load.length ? state.load[0] : null;
    $("stat-load").textContent = load === null ? "–" : load.toFixed(1);
    $("stat-updated").textContent = fmtTime(state.ts);
    $("site-title").textContent = state.site_title || "star1 GPU 预约台";
    $("site-subtitle").textContent = state.site_subtitle || "";
    if (state.contact) $("contact").textContent = state.contact;
    if (state.limits) {
      $("booking-rules").textContent =
        "单次 " +
        state.limits.min_minutes +
        " 分钟 – " +
        state.limits.max_hours +
        " 小时，最多提前 " +
        state.limits.max_days_ahead +
        " 天；每人最多 " +
        state.limits.max_future_bookings +
        " 个未结束预约";
    }
    $("update-hint").textContent = state.error ? state.error : "每 30 秒采集一次，页面每 10 秒刷新";
  }

  /* ---------- GPU 卡片 ---------- */

  function statusOf(gpu) {
    if (gpu.conflict) return { cls: "pill-danger", text: "预约冲突", card: "is-danger" };
    if (gpu.unregistered) return { cls: "pill-warn", text: "未登记", card: "is-warn" };
    if (gpu.procs && gpu.procs.length) return { cls: "pill-busy", text: "占用", card: "" };
    if (gpu.booking) return { cls: "pill-reserved", text: "已预约", card: "is-warn" };
    return { cls: "pill-free", text: "空闲", card: "is-free" };
  }

  function metric(label, valueText, percent, barClass) {
    var wrap = el("div", "metric");
    var line = el("div", "metric-line");
    line.appendChild(el("span", null, label));
    line.appendChild(el("span", "value", valueText));
    wrap.appendChild(line);
    var bar = el("div", "bar" + (barClass ? " " + barClass : ""));
    var fill = el("span");
    fill.style.width = Math.max(0, Math.min(100, percent)) + "%";
    bar.appendChild(fill);
    wrap.appendChild(bar);
    return wrap;
  }

  function renderGpuCard(gpu) {
    var status = statusOf(gpu);
    var card = el("div", "gpu-card " + status.card);
    var head = el("div", "gpu-head");
    var name = el("div", "gpu-name", "GPU " + gpu.index);
    name.appendChild(el("span", "gpu-tag", "A100 80G"));
    head.appendChild(name);
    head.appendChild(el("span", "pill " + status.cls, status.text));
    card.appendChild(head);

    var metrics = el("div", "gpu-metrics");
    var memPercent = gpu.mem_total ? (gpu.mem_used / gpu.mem_total) * 100 : 0;
    metrics.appendChild(
      metric("利用率", gpu.util + "%", gpu.util, gpu.util >= 90 ? "bar-hot" : "")
    );
    metrics.appendChild(
      metric(
        "显存",
        fmtGiB(gpu.mem_used) + " / " + fmtGiB(gpu.mem_total) + " GiB",
        memPercent,
        "bar-mem"
      )
    );
    card.appendChild(metrics);

    var procs = el("div", "procs");
    if (gpu.procs && gpu.procs.length) {
      gpu.procs.forEach(function (proc) {
        var row = el("div", "proc");
        var line = el("div", "proc-line");
        var userText = proc.user;
        if (proc.real_name && proc.real_name !== proc.user) userText = proc.real_name + "（" + proc.user + "）";
        line.appendChild(el("span", "proc-user", userText));
        line.appendChild(el("span", "proc-meta", fmtDuration(proc.etime_s) + " · " + fmtGiB(proc.mem) + " GiB"));
        row.appendChild(line);
        row.appendChild(el("div", "proc-cmd", proc.cmd || ""));
        procs.appendChild(row);
      });
    } else {
      procs.appendChild(el("div", "proc-meta", "当前没有 GPU 进程"));
    }
    card.appendChild(procs);

    var bookingLine = el("div", "booking-line");
    if (gpu.booking) {
      var owner = gpu.booking.real_name || gpu.booking.username;
      bookingLine.appendChild(document.createTextNode("当前预约："));
      bookingLine.appendChild(el("strong", null, owner));
      bookingLine.appendChild(document.createTextNode(" " + gpu.booking.time_label + " · " + gpu.booking.purpose));
    } else if (gpu.next_booking) {
      var next = gpu.next_booking;
      bookingLine.appendChild(document.createTextNode("下一预约："));
      bookingLine.appendChild(el("strong", null, next.real_name || next.username));
      bookingLine.appendChild(document.createTextNode(" " + next.time_label + " · " + next.purpose));
    } else if (!gpu.procs || !gpu.procs.length) {
      bookingLine.appendChild(document.createTextNode("暂无预约，空闲可约"));
    } else {
      bookingLine.appendChild(document.createTextNode("暂无预约，占用未登记"));
    }
    card.appendChild(bookingLine);
    return card;
  }

  function renderGpus() {
    if (!state) return;
    var grid = $("gpu-grid");
    grid.textContent = "";
    (state.gpus || []).forEach(function (gpu) {
      grid.appendChild(renderGpuCard(gpu));
    });
    if (!(state.gpus || []).length) {
      grid.appendChild(el("div", "panel muted", "暂时读不到 GPU 状态，请稍后刷新。"));
    }
  }

  /* ---------- 预约列表 ---------- */

  function renderBookings() {
    var container = $("booking-list");
    if (!container) return;
    var now = Math.floor(Date.now() / 1000);
    var rows = (state.bookings || [])
      .filter(function (booking) {
        return booking.end_ts > now && booking.start_ts < now + 86400;
      })
      .sort(function (a, b) {
        return a.start_ts - b.start_ts;
      });
    container.textContent = "";
    if (!rows.length) {
      container.appendChild(el("p", "empty", "未来 24 小时暂时没有预约。"));
      return;
    }
    var table = el("table", "table");
    var thead = el("thead");
    var headRow = el("tr");
    ["显卡", "时间", "用户", "状态", "用途", "操作"].forEach(function (text) {
      headRow.appendChild(el("th", null, text));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = el("tbody");
    rows.forEach(function (booking) {
      var tr = el("tr");
      tr.appendChild(el("td", "time", "GPU " + booking.gpu));
      tr.appendChild(el("td", "time", fmtRange(booking.start_ts, booking.end_ts)));
      var userText = booking.real_name || booking.username;
      var userCell = el("td", null, userText);
      if (booking.real_name && booking.real_name !== booking.username) {
        userCell.appendChild(el("div", "muted-cell", booking.username));
      }
      tr.appendChild(userCell);
      var running = booking.start_ts <= now && now < booking.end_ts;
      tr.appendChild(el("td", null, running ? "进行中" : "未开始"));
      tr.appendChild(el("td", "muted-cell", booking.purpose));
      var actionCell = el("td");
      if (me && (me.role === "admin" || me.username === booking.username)) {
        var cancelBtn = el("button", "btn-link", "取消");
        cancelBtn.type = "button";
        cancelBtn.addEventListener("click", function () {
          cancelBooking(booking.id);
        });
        actionCell.appendChild(cancelBtn);
      }
      tr.appendChild(actionCell);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);
  }

  function cancelBooking(id) {
    if (!window.confirm("确认取消这个预约？")) return;
    api("/api/bookings/cancel", {
      method: "POST",
      body: JSON.stringify({ id: id }),
    })
      .then(function () {
        refreshState();
      })
      .catch(function (error) {
        showMsg($("booking-msg"), error.message, true);
      });
  }

  /* ---------- 预约表单 ---------- */

  function localInputValue(date) {
    return (
      date.getFullYear() +
      "-" +
      pad(date.getMonth() + 1) +
      "-" +
      pad(date.getDate()) +
      "T" +
      pad(date.getHours()) +
      ":" +
      pad(date.getMinutes())
    );
  }

  function setDefaultTimes() {
    var startInput = $("bk-start");
    var endInput = $("bk-end");
    if (!startInput || !endInput) return;
    if (!startInput.value) {
      var start = new Date();
      start.setSeconds(0, 0);
      start.setMinutes(Math.ceil((start.getMinutes() + 30) / 30) * 30);
      startInput.value = localInputValue(start);
      var end = new Date(start.getTime() + 2 * 3600 * 1000);
      endInput.value = localInputValue(end);
    }
  }

  function renderGpuOptions() {
    var select = $("bk-gpu");
    if (!select) return;
    var current = select.value;
    select.textContent = "";
    var auto = el("option", null, "自动分配（优先空闲卡）");
    auto.value = "-1";
    select.appendChild(auto);
    (state && state.gpus ? state.gpus : []).forEach(function (gpu) {
      var option = el("option", null, "GPU " + gpu.index);
      option.value = String(gpu.index);
      select.appendChild(option);
    });
    if (current) select.value = current;
  }

  function submitBooking(event) {
    if (event) event.preventDefault();
    var msg = $("booking-msg");
    var startInput = $("bk-start");
    var endInput = $("bk-end");
    var start = new Date(startInput.value);
    var end = new Date(endInput.value);
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      showMsg(msg, "请填写开始和结束时间", true);
      return;
    }
    if (end.getTime() <= start.getTime()) {
      showMsg(msg, "结束时间必须晚于开始时间", true);
      return;
    }
    api("/api/bookings", {
      method: "POST",
      body: JSON.stringify({
        gpu: Number($("bk-gpu").value),
        start: Math.floor(start.getTime() / 1000),
        end: Math.floor(end.getTime() / 1000),
        purpose: $("bk-purpose").value.trim(),
      }),
    })
      .then(function (data) {
        var booking = data.booking;
        showMsg(
          msg,
          "已预约 GPU " + booking.gpu + "：" + fmtRange(booking.start_ts, booking.end_ts),
          false
        );
        $("bk-purpose").value = "";
        refreshState();
      })
      .catch(function (error) {
        showMsg(msg, error.message, true);
      });
  }

  /* ---------- 使用统计 ---------- */

  function renderUsage(usage) {
    var container = $("usage");
    if (!container) return;
    container.textContent = "";
    if (!usage || !(usage.users || []).length) {
      container.appendChild(
        el("p", "empty", "暂无采样数据。服务刚启动时需要积累几分钟的 GPU 采样，之后每小时更新。")
      );
      return;
    }
    var table = el("table", "table");
    var thead = el("thead");
    var headRow = el("tr");
    ["用户", "卡时", "占比"].forEach(function (text) {
      headRow.appendChild(el("th", null, text));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = el("tbody");
    usage.users.forEach(function (user) {
      var tr = el("tr");
      var userCell = el("td", null, user.real_name || user.username);
      if (user.real_name && user.real_name !== user.username) {
        userCell.appendChild(el("div", "muted-cell", user.username));
      }
      tr.appendChild(userCell);
      tr.appendChild(el("td", null, user.hours + " h"));
      var percentCell = el("td");
      var wrap = el("div", "usage-bar");
      var bar = el("div", "bar");
      var fill = el("span");
      fill.style.width = Math.max(0, Math.min(100, user.percent)) + "%";
      bar.appendChild(fill);
      wrap.appendChild(bar);
      wrap.appendChild(el("span", "muted", user.percent + "%"));
      percentCell.appendChild(wrap);
      tr.appendChild(percentCell);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);
    container.appendChild(
      el("p", "hint", "统计口径：每 " + usage.interval_seconds + " 秒记录一次「用户 × 显卡」占用，近 " + usage.days + " 天合计 " + usage.total_hours + " 卡时。")
    );
  }

  function refreshUsage() {
    if (busy.usage) return;
    busy.usage = true;
    api("/api/usage?days=7")
      .then(function (usage) {
        renderUsage(usage);
      })
      .catch(function () {
        $("usage").textContent = "";
        $("usage").appendChild(el("p", "empty", "使用统计加载失败，稍后自动重试。"));
      })
      .then(function () {
        busy.usage = false;
      });
  }

  /* ---------- 刷新 ---------- */

  function refreshState() {
    if (busy.state) return;
    busy.state = true;
    api("/api/state")
      .then(function (data) {
        state = data;
        me = data.me || me;
        if (me && me.role === "admin") {
          $("guest-note").hidden = true;
          $("login-panel").hidden = true;
          $("booking-body").hidden = false;
        }
        renderAccount();
        loadTokens();
        renderSummary();
        renderGpus();
        renderBookings();
        renderGpuOptions();
        setDefaultTimes();
        if (me) {
          $("guest-note").hidden = true;
          $("login-panel").hidden = true;
          $("booking-body").hidden = false;
        }
      })
      .catch(function () {
        $("update-hint").textContent = "连接失败，正在重试…";
      })
      .then(function () {
        busy.state = false;
      });
  }

  /* ---------- 初始化 ---------- */

  function init() {
    $("login-form").addEventListener("submit", login);
    $("guest-login").addEventListener("click", showLogin);
    $("token-form").addEventListener("submit", createToken);
    $("token-copy").addEventListener("click", copyToken);
    $("booking-form").addEventListener("submit", submitBooking);
    setDefaultTimes();
    refreshState();
    refreshUsage();
    window.setInterval(refreshState, 10000);
    window.setInterval(refreshUsage, 60000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
