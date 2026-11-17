(function () {
  "use strict";

  var API_HEADER = "star1-gpu-board";
  var me = null;
  var overview = null;

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

  function fmtDateTime(ts) {
    var d = new Date(ts * 1000);
    return (
      pad(d.getMonth() + 1) +
      "-" +
      pad(d.getDate()) +
      " " +
      pad(d.getHours()) +
      ":" +
      pad(d.getMinutes())
    );
  }

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
            var message =
              (data && data.error && data.error.message) || "请求失败（" + response.status + "）";
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

  function setLoginState() {
    $("admin-login-section").hidden = !!me;
    $("admin-body").hidden = !me;
    $("admin-status").textContent = me ? "管理员已登录" : "未登录";
  }

  function login(event) {
    if (event) event.preventDefault();
    var token = $("admin-token").value;
    var msg = $("admin-login-msg");
    if (!token) {
      showMsg(msg, "请输入管理员口令", true);
      return;
    }
    api("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({ token: token }),
    })
      .then(function (data) {
        me = data.me;
        $("admin-token").value = "";
        $("admin-login-msg").hidden = true;
        setLoginState();
        loadOverview();
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
        setLoginState();
      });
  }

  function loadMe() {
    return api("/api/me")
      .then(function (data) {
        me = data.me || null;
        setLoginState();
        if (me && me.role === "admin") loadOverview();
      })
      .catch(function () {
        setLoginState();
      });
  }

  function loadOverview() {
    if (!me) return;
    api("/api/admin/overview?days=30")
      .then(function (data) {
        overview = data;
        renderBookings();
        renderCreateForm();
        renderUsage();
        renderUsers();
      })
      .catch(function (error) {
        showMsg($("admin-booking-msg"), error.message, true);
      });
  }

  function renderBookings() {
    var container = $("admin-booking-list");
    container.textContent = "";
    var rows = (overview ? overview.bookings || [] : []).slice().sort(function (a, b) {
      return a.start_ts - b.start_ts;
    });
    if (!rows.length) {
      container.appendChild(el("p", "empty", "近 24 小时与未来 7 天没有预约。"));
      return;
    }
    var table = el("table", "table");
    var thead = el("thead");
    var headRow = el("tr");
    ["编号", "显卡", "时间", "用户", "用途", "创建者", "操作"].forEach(function (text) {
      headRow.appendChild(el("th", null, text));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = el("tbody");
    var now = Math.floor(Date.now() / 1000);
    rows.forEach(function (booking) {
      var tr = el("tr");
      tr.appendChild(el("td", "time", "#" + booking.id));
      tr.appendChild(el("td", "time", "GPU " + booking.gpu));
      tr.appendChild(
        el("td", "time", fmtDateTime(booking.start_ts) + " – " + fmtDateTime(booking.end_ts))
      );
      var userCell = el("td", null, booking.real_name || booking.username);
      userCell.appendChild(el("div", "muted-cell", booking.username));
      tr.appendChild(userCell);
      tr.appendChild(el("td", "muted-cell", booking.purpose));
      tr.appendChild(el("td", "muted-cell", booking.created_by || booking.username));
      var action = el("td");
      if (booking.status === "active" && booking.end_ts > now) {
        var btn = el("button", "btn-link", "取消");
        btn.type = "button";
        btn.addEventListener("click", function () {
          cancelBooking(booking.id);
        });
        action.appendChild(btn);
      }
      tr.appendChild(action);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);
  }

  function cancelBooking(id) {
    if (!window.confirm("确认取消预约 #" + id + "？")) return;
    api("/api/admin/cancel", { method: "POST", body: JSON.stringify({ id: id }) })
      .then(function () {
        loadOverview();
      })
      .catch(function (error) {
        showMsg($("admin-booking-msg"), error.message, true);
      });
  }

  function renderCreateForm() {
    var userSelect = $("admin-bk-user");
    var gpuSelect = $("admin-bk-gpu");
    var currentUser = userSelect.value;
    var currentGpu = gpuSelect.value;
    userSelect.textContent = "";
    gpuSelect.textContent = "";
    var auto = el("option", null, "自动分配");
    auto.value = "-1";
    gpuSelect.appendChild(auto);
    for (var index = 0; index < 8; index += 1) {
      var option = el("option", null, "GPU " + index);
      option.value = String(index);
      gpuSelect.appendChild(option);
    }
    var users = (overview ? overview.users || [] : []).filter(function (user) {
      return !user.privileged;
    });
    users.forEach(function (user) {
      var option = el("option", null, user.real_name + "（" + user.username + "）");
      option.value = user.username;
      userSelect.appendChild(option);
    });
    if (currentUser) userSelect.value = currentUser;
    if (currentGpu) gpuSelect.value = currentGpu;
    if (!$("admin-bk-start").value) {
      var start = new Date();
      start.setSeconds(0, 0);
      start.setMinutes(Math.ceil((start.getMinutes() + 30) / 30) * 30);
      $("admin-bk-start").value = localInputValue(start);
      $("admin-bk-end").value = localInputValue(new Date(start.getTime() + 2 * 3600 * 1000));
    }
  }

  function createBooking(event) {
    if (event) event.preventDefault();
    var start = new Date($("admin-bk-start").value);
    var end = new Date($("admin-bk-end").value);
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      showMsg($("admin-booking-msg"), "请填写开始和结束时间", true);
      return;
    }
    api("/api/admin/bookings", {
      method: "POST",
      body: JSON.stringify({
        username: $("admin-bk-user").value,
        gpu: Number($("admin-bk-gpu").value),
        start: Math.floor(start.getTime() / 1000),
        end: Math.floor(end.getTime() / 1000),
        purpose: $("admin-bk-purpose").value.trim(),
      }),
    })
      .then(function (data) {
        showMsg(
          $("admin-booking-msg"),
          "已创建预约 #" + data.booking.id + "（GPU " + data.booking.gpu + "）",
          false
        );
        $("admin-bk-purpose").value = "";
        loadOverview();
      })
      .catch(function (error) {
        showMsg($("admin-booking-msg"), error.message, true);
      });
  }

  function renderUsage() {
    var container = $("admin-usage");
    container.textContent = "";
    var usage = overview ? overview.usage : null;
    if (!usage || !(usage.users || []).length) {
      container.appendChild(el("p", "empty", "暂无采样数据。"));
      return;
    }
    $("admin-usage-meta").textContent =
      "近 " + usage.days + " 天 · 合计 " + usage.total_hours + " 卡时";
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
      var cell = el("td");
      var wrap = el("div", "usage-bar");
      var bar = el("div", "bar");
      var fill = el("span");
      fill.style.width = Math.max(0, Math.min(100, user.percent)) + "%";
      bar.appendChild(fill);
      wrap.appendChild(bar);
      wrap.appendChild(el("span", "muted", user.percent + "%"));
      cell.appendChild(wrap);
      tr.appendChild(cell);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);
  }

  function renderUsers() {
    var container = $("admin-users");
    container.textContent = "";
    var users = overview ? overview.users || [] : [];
    if (!users.length) {
      container.appendChild(el("p", "empty", "暂未获取到用户列表（provisioner 不可用？）"));
      return;
    }
    var table = el("table", "table");
    var thead = el("thead");
    var headRow = el("tr");
    ["用户名", "姓名", "UID", "状态"].forEach(function (text) {
      headRow.appendChild(el("th", null, text));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = el("tbody");
    users.forEach(function (user) {
      var tr = el("tr");
      tr.appendChild(el("td", null, user.username));
      tr.appendChild(el("td", null, user.real_name));
      tr.appendChild(el("td", "time", user.uid === null || user.uid === undefined ? "–" : user.uid));
      var status = [];
      if (user.locked) status.push("已锁定");
      if (user.privileged) status.push("特权账号");
      tr.appendChild(el("td", null, status.length ? status.join(" / ") : "正常"));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);
  }

  function init() {
    $("admin-login-form").addEventListener("submit", login);
    $("admin-create-form").addEventListener("submit", createBooking);
    $("admin-refresh").addEventListener("click", loadOverview);
    $("admin-logout").addEventListener("click", logout);
    loadMe();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
