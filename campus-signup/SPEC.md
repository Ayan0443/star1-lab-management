# SPEC — 校园网自助开户门户（star1）

> 版本 1.3 · 2026-10-26（v1.1 用户管理；v1.2 公告面板/使用说明/IPv6；**v1.3 学校邮箱验证码注册，一邮箱一号**）
> 项目根目录：`/Users/example/Documents/deepseek-harness/default-workspace/campus-signup`
> 本文件是并行开发（Lead / backend / frontend / qa）的唯一契约。所有实现必须严格遵守本文件；
> 如需偏离，先通知 Lead，由 Lead 更新 SPEC。

---

## 0. 文件所有权（写作用域，不得越界）

| 角色 | 允许写 |
|---|---|
| lead | `deploy/`、`vendor/`、`README.md`、`SPEC.md` |
| backend | `app/`（`server.py`、`provisioner.py`、`pinyin_util.py`、`security.py`） |
| frontend | `static/`（`index.html`、`app.js`、`style.css`、`admin.html`、`admin.js`、`favicon.svg`） |
| qa | `tests/` |

- 任何人**不得** SSH 到 star1、不得使用 sudo、不得修改服务器。
- 任何人**不得**修改本机 `/opt`、`/usr/local` 等系统目录；本地开发只在项目目录和 `/tmp` 下进行。
- `vendor/site-packages/` 已内置 pypinyin 0.55.0，**不要** pip install 任何包。
- 本机 Python 是 `/usr/bin/python3`（3.9.6）；服务器是 Python 3.12。代码必须兼容 Python **3.9+**
  （不要用 `match`、PEP 604 `X | Y` 类型标注、3.10+ 才有的 stdlib API）。

---

## 1. 目标与验收标准

在 star1（Ubuntu 24.04，IP `10.0.0.10`）部署一个**校园内网可访问**的自助开户网站：

1. 新用户在网页上填写**中文真实姓名**，系统自动转换为**汉语拼音全拼**作为 Linux 用户名（小写、无声调）。
2. 自动在服务器上创建 Linux 普通用户 + 家目录（工作目录）：
   - `useradd --create-home --user-group --shell /bin/bash --comment "<中文姓名>" <username>`
   - 家目录 `/home/<username>`，权限 `0750`（服务器 `HOME_MODE 0750` 默认即如此），owner 为该用户；
   - **普通权限**：不加入 `sudo` / `docker` / `adm` 等任何特权组，无 sudoers 权限；
   - 首次登录可用密码 SSH：`ssh <username>@10.0.0.10`。
3. 密码必须为强密码（服务端强制校验），页面提供**一键生成强密码**选项。
4. **同一校园网 IP 只能申请一个账号**（持久化、并发安全；管理员可重置）。
5. 网页通过浏览器在校园网打开（HTTP 自动跳转 HTTPS，自签名证书）。
6. **公告面板**：首页展示服务器使用说明（公告内容存 DB，可由管理员在 /admin 编辑；默认内容见 §12.4）。
7. **用户管理（管理员）**：/admin 在 token 鉴权后可查看已建账号及其系统状态，并支持：
   重置密码（服务端生成强密码、一次性显示）、锁定/解锁账号、删除账号（含家目录，二次确认）、
   重置申请 IP、暂停/开放申请、编辑公告。

**最终验收**（Lead 负责，在 star1 真实执行）：
- 从校园网 Mac 打开 `https://10.0.0.10:8444/` 正常（自签名警告可跳过）；`http://10.0.0.10:8082/` 跳转 HTTPS。
- 真实创建测试账号：`/etc/passwd` 有记录、`id` 无特权组、家目录 0750、密码哈希与提交值匹配、`su -` 可登录。
- 同名二次申请（不同 IP）自动得 `<base>2`；同一 IP 二次申请被拒绝。
- 弱密码 / 非法姓名 / 注入字符被拒绝；管理员接口无 token 被拒绝。
- `systemctl is-enabled` 两个服务为 enabled；重启服务后页面恢复。
- 测试账号与测试 IP 记录全部清理，不留垃圾账号。
- 管理员用户管理：锁定后 `passwd -S` 显示 L、解锁恢复 P；重置密码后新密码哈希匹配；删除后 `/etc/passwd`
  与家目录消失且该 IP 可重新申请；所有管理接口无 token → 403。
- 公告面板内容与默认公告一致，管理员修改后首页即时生效（DB 持久化，重启服务仍在）。
- 校外 IPv6 登录命令展示且已实测（`ssh -6 -p 2222 <user>@2001:db8::10`）。

---

## 2. 服务器环境事实（已核实，不要假设别的）

- star1：Ubuntu 24.04.4 LTS，Python 3.12.3，systemd 255，128 核，`/home` 15T（3.7T 可用）。
- `admin` 有免密 sudo；`PasswordAuthentication yes`（新用户可密码 SSH）。
- `/etc/login.defs`：`HOME_MODE 0750`、`UMASK 022`、`USERGROUPS_ENAB yes`；`/etc/skel` 含 `.bashrc`、`.profile`、`.condarc`。
- **家目录位于数据盘**：`/home` 是 `/dev/sda1`（15T）的挂载点，新建用户 `/home/<username>` 即在数据盘，无需额外挂载。
- **SSH 监听**：IPv4 `0.0.0.0:22`（校内直连）；IPv6 `[::]:2222`（校外直连）。
  本机 IPv6：`2001:db8::10`（即「机器一」；机器二为 `2001:db8::11`）。
- 服务器上**只允许运行 Python**；python 必须使用用户自己的 conda 环境（`/etc/skel/.condarc` 已带配置）。
- 管理员联系方式：管理员甲，邮箱 `admin@example.com`，电话/微信 `13800000000`（用于公告面板与页脚）。
- 已占用端口（勿用）：22, 2222, 2379/2380, 40380, 6443, 6800/6801, 7150, 8443, 8765, 9090, 10250, 51898/51899 等。
- 本项目端口：**HTTPS 8444**、**HTTP 8082**（均已确认为空且校园网可达）。
- 不要改动 ceph / etcd / k8s / libvirt / natfrp / conda / codex 等现有服务与用户数据。

---

## 3. 架构与目录

```
campus-signup/
├── SPEC.md                     # 本文件
├── app/
│   ├── server.py               # Web 服务（非 root，用户 signupapp）
│   ├── provisioner.py          # root 特权助手（Unix socket 服务）
│   ├── pinyin_util.py          # 姓名校验 + 拼音转换 + 多音姓氏补丁
│   └── security.py             # 密码策略 / 生成 / 强度 / 校验
├── static/                     # 前端（无外部资源/CDN）
├── vendor/site-packages/       # 内置 pypinyin 0.55.0（勿改）
├── deploy/                     # systemd 单元、install/uninstall、TLS、config 模板、announcement.default.txt
├── tests/                      # QA：单元测试 + mock 模式端到端测试
└── README.md                   # 运维/使用文档（Lead 最后写）
```

运行时（star1）：

```
浏览器 ──HTTPS 8444──► campus-signup-web (User=signupapp)
                              │  Unix socket /run/campus-signup/provision.sock (0660 root:signupapp)
                              ▼
                       campus-signup-provisioner (root) ──► useradd/chpasswd/mkdir
                              │
                       /var/lib/campus-signup/registrations.db (SQLite)
```

- 两个 systemd 服务：`campus-signup-web.service`、`campus-signup-provisioner.service`（Lead 在 deploy/ 实现）。
- Web 不直接调用 `useradd`，只通过 Unix socket 请求 provisioner；provisioner 只做「校验 + 建用户」，不做别的。
- SQLite 由 web 独占读写；provisioner 不碰数据库。

---

## 4. 配置 JSON

生产配置 `/etc/campus-signup/config.json`（root:signupapp 0640，由 install.sh 生成）；
本地 mock 测试用同样 schema。所有路径用绝对路径。

```json
{
  "mode": "production",
  "server": {
    "bind": "0.0.0.0",
    "public_host": "10.0.0.10",
    "ports": { "https": 8444, "http": 8082 }
  },
  "tls": {
    "enabled": true,
    "cert": "/etc/campus-signup/tls/server.crt",
    "key": "/etc/campus-signup/tls/server.key"
  },
  "paths": {
    "static": "/opt/campus-signup/static",
    "db": "/var/lib/campus-signup/registrations.db",
    "lock": "/var/lib/campus-signup/register.lock"
  },
  "provisioner": {
    "socket": "/run/campus-signup/provision.sock",
    "timeout_seconds": 30,
    "allowed_peer_uid": 0
  },
  "security": {
    "admin_token": "<随机 43 字符 token>",
    "allowed_client_cidrs": [],
    "trusted_proxies": []
  },
  "ui": {
    "server_name": "star1 实验室服务器",
    "site_title": "校园网服务器账号自助申请",
    "ssh_host": "10.0.0.10",
    "ssh_port": 22,
    "ssh_ipv6": "2001:db8::10",
    "ssh_ipv6_port": 2222,
    "contact": "管理员甲（邮箱 admin@example.com，电话/微信 13800000000）",
    "default_announcement": "<install.sh 从 deploy/announcement.default.txt 注入的公告文本>"
  },
  "rate_limits": {
    "preview":          { "window_seconds": 60,  "max_requests": 120 },
    "generate_password":{ "window_seconds": 60,  "max_requests": 30  },
    "register":         { "window_seconds": 600, "max_requests": 20  },
    "admin":            { "window_seconds": 60,  "max_requests": 60  },
    "announcement":     { "window_seconds": 60,  "max_requests": 120 }
  }
}
```

- `allowed_client_cidrs` 为空数组 = 不限制来源 IP；非空时按 `ipaddress` 判断，不在列表内返回 403 `IP_NOT_ALLOWED`。
- `trusted_proxies` 为空 = **永远信任 TCP 对端地址**，忽略 `X-Forwarded-For`。
- `provisioner.allowed_peer_uid`：provisioner 只接受该 uid 的连接（生产 = signupapp 的 uid，由 install.sh 写入；
  mock/本地测试可不启用 provisioner）。

mock 配置示例（QA 使用，路径可放 `/tmp`）：

```json
{
  "mode": "mock",
  "server": { "bind": "127.0.0.1", "public_host": "127.0.0.1", "ports": { "https": 18444, "http": 18082 } },
  "tls": { "enabled": false },
  "paths": { "static": "<项目绝对路径>/static", "db": "<tmp>/registrations.db", "lock": "<tmp>/register.lock" },
  "provisioner": { "socket": "<tmp>/provision.sock", "timeout_seconds": 10, "allowed_peer_uid": -1 },
  "security": { "admin_token": "test-admin-token-0123456789", "allowed_client_cidrs": [], "trusted_proxies": [] },
  "ui": { "server_name": "测试服务器", "site_title": "校园网服务器账号自助申请",
          "ssh_host": "127.0.0.1", "ssh_port": 22, "ssh_ipv6": "::1", "ssh_ipv6_port": 2222,
          "contact": "测试管理员", "default_announcement": "测试公告内容" },
  "rate_limits": { "preview": {"window_seconds": 60, "max_requests": 120},
                   "generate_password": {"window_seconds": 60, "max_requests": 120},
                   "register": {"window_seconds": 600, "max_requests": 50},
                   "admin": {"window_seconds": 60, "max_requests": 60},
                   "announcement": {"window_seconds": 60, "max_requests": 120} }
}
```

---

## 5. 数据模型（SQLite，web 进程负责建表/迁移）

```sql
CREATE TABLE IF NOT EXISTS registrations (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ip           TEXT    NOT NULL UNIQUE,          -- 规范化后的客户端 IP
  real_name    TEXT    NOT NULL,                 -- 中文姓名（规范化后）
  pinyin       TEXT    NOT NULL,                 -- 无声调全拼，如 zhangsan
  username     TEXT    NOT NULL UNIQUE,          -- 如 zhangsan / zhangsan2
  uid          INTEGER,
  gid          INTEGER,
  home         TEXT,
  workspace    TEXT,                             -- 预留，可等于 home
  status       TEXT    NOT NULL,                 -- 'provisioning' | 'active'
  created_at   TEXT    NOT NULL,                 -- UTC ISO8601，如 2026-10-24T07:05:00Z
  updated_at   TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
-- meta 初始：schema_version=1、registration_enabled=true、announcement=<ui.default_announcement>、announcement_updated_at=<UTC now>
```

- 建库后执行 `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`
- 每个请求独立 `sqlite3.connect`，用完关闭；不要跨线程共享连接。
- `home` 存 `/home/<username>`；`workspace` 暂存同一路径（家目录即工作目录）。

---

## 6. Provisioner（root 助手）契约

### 6.1 启动

`python3 app/provisioner.py --config /etc/campus-signup/config.json`

- 监听 `provisioner.socket` 的 Unix stream socket；启动时删除残留 socket 文件再 bind。
- `umask(0o077)` 后 bind；`chmod 0660`；`chgrp` 到 `signupapp` 组（找不到组则报错退出）。
- 校验 `SO_PEERCRED`：只接受 uid == `provisioner.allowed_peer_uid` 的连接；否则立即关闭（不回复）。
- 协议：**换行分隔 JSON**（每条请求一行，≤ 64KB；响应一行 JSON，UTF-8 不转义中文）。
- 并发：单线程串行处理即可（创建用户低频）；每连接一次或多次请求都可，读到 EOF 关闭。
- 日志：只输出到 stdout（journald）；记录事件、username、结果；**绝不记录密码、绝不记录请求明文**。
- SIGTERM/SIGINT 优雅退出并删除 socket 文件。

### 6.2 请求/响应

请求：

```json
{"op":"ping"}
{"op":"create_user","username":"zhangsan","real_name":"张三","password":"Str0ng#Passw0rd!"}
```

响应（成功）：

```json
{"ok":true,"username":"zhangsan","uid":1030,"gid":1030,"home":"/home/zhangsan","workspace":"/home/zhangsan","real_name":"张三"}
```

响应（失败）：

```json
{"ok":false,"error":{"code":"EXISTS|INVALID|INTERNAL","message":"..."}}
```

- `EXISTS`：系统里已有该用户名/用户组（web 可换下一个后缀重试）。
- `INVALID`：username/姓名/密码未通过校验。
- `INTERNAL`：useradd/chpasswd 等失败（message 不含敏感信息）。

### 6.3 create_user 执行步骤（必须按顺序，失败回滚）

1. 再次严格校验：`username` 匹配 `^[a-z][a-z0-9]{1,31}$`；`real_name` 经 `pinyin_util.normalize_real_name`
   合法；`password` 经 `security.validate_password` 合法。
2. `getent passwd <u>` 和 `getent group <u>` 任一存在 → `EXISTS`。
3. `useradd --create-home --user-group --shell /bin/bash --comment <real_name> -- <username>`
   （参数用 list 传给 subprocess，禁止 shell=True；env 设 `PATH=/usr/sbin:/usr/bin:/sbin:/bin`）。
4. 通过 stdin 执行 `chpasswd`（内容 `<username>:<password>\n`），密码**不得出现在 argv**。
5. `mkdir -p /home/<u>` 已由 useradd 完成；确保家目录 mode 0750（显式 `chmod 0750`，owner 必须是该用户）。
6. 校验：`pwd.getpwnam`、家目录 `stat`（owner/group 正确、mode 0750、is_dir）、
   `passwd -S <u>` 状态为 `P`；确认用户不在 `sudo`/`docker`/`adm`/`root` 等特权组。
7. 任意一步失败：尽力 `userdel --remove <u>` 回滚，返回 `INTERNAL`。
8. 成功返回 uid/gid/home；日志：`event=create_user username=... uid=... result=ok`。

额外硬性要求：
- 超时：每条子命令 `timeout=15`；整个 create_user ≤ `timeout_seconds`。
- 拒绝 `real_name` 中的控制字符/冒号/换行；拒绝 `password` 含 `:`、`\n`、`\r`、空格（web 侧已校验，这里再校验一次）。
- 不创建 `.ssh`、不改 sshd、不改 sudoers、不加任何组（除 useradd 默认同名组）。

### 6.4 管理运维操作（user_status / reset_password / set_lock / delete_user）

供 web 在管理员 token 鉴权通过后调用（用户管理功能）。provisioner 必须再次做安全限制：

- 仅接受 uid ≥ 1000 的普通账号；uid < 1000 → `INVALID`；
- 保护名单（永远拒绝）：`root`、`admin`、`signupapp`、`ops1`、`svc`、`nobody`；
- 若目标用户属于 `sudo`/`wheel`/`docker`/`adm`/`root` 等特权组 → `INVALID`；
- 所有参数严格校验；`password` 同时经 `security.validate_password`；
- 所有操作记录 journald 日志（event、username、result），**不记录密码**。

请求/响应：

```json
{"op":"user_status","usernames":["zhangsan","lisi"]}
{"op":"reset_password","username":"zhangsan","password":"<强密码>"}
{"op":"set_lock","username":"zhangsan","locked":true}
{"op":"delete_user","username":"zhangsan","expected_uid":1030}
```

- `user_status` 响应：
  `{"ok":true,"users":{"zhangsan":{"exists":true,"uid":1030,"gid":1030,"home":"/home/zhangsan","locked":false,"groups":["zhangsan"],"privileged":false},"lisi":{"exists":false}}}`
  - `locked`：读 `/etc/shadow` 密码字段是否以 `!`/`*` 开头；用户不存在 → `exists:false`；
  - 单次最多 200 个用户名。
- `reset_password` 响应 `{"ok":true,"username":"zhangsan"}`；通过 chpasswd stdin 设置，**不改变锁定状态**。
- `set_lock` 响应 `{"ok":true,"username":"zhangsan","locked":true}`；用 `usermod --lock/--unlock`。
- `delete_user`：校验 `expected_uid` 与系统 uid 一致，`userdel --remove <u>`；
  响应 `{"ok":true,"username":"zhangsan","deleted":true}`；用户已不存在 → `{"ok":true,"deleted":false}`；
  失败 → `INTERNAL`，message 提示「用户可能仍有运行中的进程」。

---

## 7. HTTP API 契约

- 公网页面：`GET /`（index.html）、`GET /static/*`（静态资源）、`GET /admin`（admin.html）。
- `GET /healthz`：两个端口都返回 `200 {"ok":true}`（用于运维探活，HTTP 端口不跳转）。
- 所有 JSON 响应 `Content-Type: application/json; charset=utf-8`；UTF-8 原样输出中文（`ensure_ascii=False`）。
- POST 要求 `Content-Type: application/json` 且请求头 `X-Requested-With: campus-signup`，否则 403 `BAD_REQUEST`。
- 请求体上限 **8KB**，超过返回 413 `PAYLOAD_TOO_LARGE`。
- 统一错误格式：

```json
{"ok":false,"error":{"code":"CODE","message":"中文提示"}}
```

- 错误码：`INVALID_NAME` `WEAK_PASSWORD` `INVALID_JSON` `INVALID_REQUEST` `REGISTRATION_DISABLED`
  `IP_LIMIT` `USERNAME_EXHAUSTED` `RATE_LIMITED` `ADMIN_AUTH` `IP_NOT_ALLOWED` `BAD_REQUEST`
  `METHOD_NOT_ALLOWED` `NOT_FOUND` `PAYLOAD_TOO_LARGE` `INTERNAL` `USER_MISSING`。

### 7.1 `GET /api/health`

```json
{"ok":true,"version":"1.0.0","registration_enabled":true,
 "server_name":"star1 实验室服务器","site_title":"校园网服务器账号自助申请",
 "contact":"管理员甲（邮箱 admin@example.com，电话/微信 13800000000）",
 "ssh_host":"10.0.0.10","ssh_port":22,
 "ssh_ipv6":"2001:db8::10","ssh_ipv6_port":2222}
```

前端用以上 ui 字段渲染页头、页脚联系方式与登录提示（默认公告内容另行经 §7.6 获取）。

### 7.2 `GET /api/preview?name=<URL 编码中文姓名>`

- 限流：`rate_limits.preview`（按客户端 IP）。
- 200：

```json
{"ok":true,"real_name":"张三","pinyin":"zhangsan","base_username":"zhangsan",
 "username":"zhangsan2","duplicate_index":2,"available":true,
 "note":"已有同名账号，将分配 zhangsan2"}
```

`duplicate_index`：0 = 用 base；2/3/… = 加后缀后的序号。`note` 为可直接展示的中文提示（无重名时为空串）。
- 400 `INVALID_NAME`：姓名不合法（message 用后端返回的中文校验提示）。
- 409 `USERNAME_EXHAUSTED`：base 后 1..999 全被占用（几乎不会发生）。

### 7.3 `POST /api/generate-password`

- 限流：`rate_limits.generate_password`。
- 200：

```json
{"ok":true,"password":"K7#mQ2$vX9!pR4@t","length":16,
 "strength":{"score":4,"label":"很强","percent":100}}
```

### 7.4 `POST /api/register`

请求：`{"name":"张三","password":"K7#mQ2$vX9!pR4@t"}`

处理顺序（**必须**）：
1. 校验姓名 → `INVALID_NAME`；校验密码强度（传 username 未知时不传；策略见 §9）→ `WEAK_PASSWORD`；
2. 检查 `registration_enabled`，关闭 → 409 `REGISTRATION_DISABLED`；
3. 客户端 IP 限制（cidr）→ 403 `IP_NOT_ALLOWED`；
4. 全局 flock（`paths.lock`）排他锁，覆盖 5~9；
5. 查该 IP 是否已有记录（任意 status）→ 409 `IP_LIMIT`（message 可带 `username`：`该校园网 IP 已申请过账号（用户名：zhangsan）`）；
6. 计算 pinyin/base；从 base、base2、base3 … 找第一个「DB 无记录 且 系统无该用户/组」的候选：
   - 系统检查：`pwd.getpwnam` / `grp.getgrnam`（web 进程可读），mock 模式查 mock 用户表；
   - 候选长度 ≤ 32；
7. 插入 `status='provisioning'` 行（username 已定）；
8. 调 provisioner `create_user`（超时）；若返回 `EXISTS`：删除该行，候选 +1，回到 6（最多 50 次）；
   若失败/超时：删除该行，返回 500 `INTERNAL`（不泄露细节）；
9. 成功：更新行为 `status='active'` + uid/gid/home/workspace，提交事务，释放锁；
10. 返回 201：

```json
{"ok":true,"account":{
  "username":"zhangsan2","real_name":"张三","pinyin":"zhangsan",
  "uid":1030,"gid":1030,"home":"/home/zhangsan2","workspace":"/home/zhangsan2",
  "ssh_login":"ssh zhangsan2@10.0.0.10",
  "ssh_login_ipv6":"ssh -6 -p 2222 zhangsan2@2001:db8::10",
  "created_at":"2026-10-24T07:05:00Z"}}
```

- 同一 IP 重复申请 → 409 `IP_LIMIT`（限流与 IP 检查都在，先查限流再查 IP）。
- `ssh_login` 由 `ui.ssh_host` + `ui.ssh_port`（22 时省略 `-p`）生成；`ssh_login_ipv6` 由
  `ui.ssh_ipv6` + `ui.ssh_ipv6_port` 生成（格式固定 `ssh -6 -p <port> <user>@<ipv6>`）。
- 返回中**不带密码**；页面显示的是用户自己刚输入/生成的值。
- 重复提交（双击）：第二次会命中 IP_LIMIT（第一次已建行），不会重复建用户。

### 7.5 管理员接口（token 鉴权）

鉴权：请求头 `X-Admin-Token: <admin_token>`（GET 也允许 `?token=`），必须 `hmac.compare_digest` 比较；
失败 403 `ADMIN_AUTH`。限流 `rate_limits.admin`。所有管理接口响应 `Cache-Control: no-store`。

- `GET /api/admin/registrations`：

```json
{"ok":true,"registration_enabled":true,
 "stats":{"total":3,"active":2,"provisioning":1,"locked":1,"missing":0},
 "registrations":[
   {"id":1,"ip":"10.0.133.240","real_name":"张三","pinyin":"zhangsan",
    "username":"zhangsan","uid":1030,"home":"/home/zhangsan","status":"active",
    "os_status":"active","privileged":false,
    "created_at":"2026-10-24T07:05:00Z"}]}
```

`os_status`：`active`（系统存在且未锁）/ `locked`（已锁定）/ `missing`（系统不存在）/ `unknown`（provisioner
暂不可用）。实现：web 调 provisioner `user_status` 批量查询（最多 200 个）；查询失败全部标 `unknown`，接口仍 200。

- `POST /api/admin/reset-password` body `{"id": 1}` → 服务端 `security.generate_password(16)` 生成强密码，
  调 provisioner `reset_password`；200：

```json
{"ok":true,"id":1,"username":"zhangsan","password":"K7#mQ2$vX9!pR4@t"}
```

  一次性返回，**不写数据库、不写日志**；系统用户不存在 → 409 `USER_MISSING`。
- `POST /api/admin/set-locked` body `{"id": 1, "locked": true}` → 200
  `{"ok":true,"id":1,"username":"zhangsan","locked":true}`；不存在 → 409 `USER_MISSING`。
- `POST /api/admin/delete-user` body `{"id": 1, "confirm_username": "zhangsan"}`：
  `confirm_username` 必须与记录 username 完全一致，否则 400 `INVALID_REQUEST`；
  调 provisioner `delete_user`（带 expected_uid），成功后删除 DB 行（释放 IP 与用户名）；
  200 `{"ok":true,"deleted":{"id":1,"ip":"10.0.133.240","username":"zhangsan"}}`；
  系统用户本就不存在时同样删除 DB 行，200 并带 `"os_user_existed":false`。
- `POST /api/admin/reset-ip` body `{"id": 1}` → 删除该注册记录（释放 IP，允许重新申请；**不删除系统用户**），
  200 `{"ok":true,"deleted":{"id":1,"ip":"10.0.133.240","username":"zhangsan"}}`；不存在 → 404 `NOT_FOUND`。
- `POST /api/admin/set-registration` body `{"enabled": false}` → 200 `{"ok":true,"registration_enabled":false}`。
- `POST /api/admin/announcement` body `{"content": "纯文本公告，可含换行"}` → 校验 1–20000 字符，
  除 `\n`/`\t` 外不允许其他控制字符；写入 meta `announcement` + `announcement_updated_at`；
  200 `{"ok":true,"updated_at":"2026-10-24T07:00:00Z"}`；非法 → 400 `INVALID_REQUEST`。

管理员页 `/admin` 只提供以上能力；不提供「修改用户名」「提权」等操作。

### 7.6 `GET /api/announcement`（公开）

- 限流 `rate_limits.announcement`，无需鉴权。
- 200：`{"ok":true,"content":"...","updated_at":"2026-10-24T07:00:00Z"}`（无更新时间时为空串）。

## 8. 姓名 / 拼音 / 用户名规则（`app/pinyin_util.py`）

公开函数（QA 会按签名测试，必须实现）：

```python
def normalize_real_name(raw):  # -> (normalized_name: str | None, error_message: str)
def name_to_pinyin(name):      # -> (pinyin: str | None, error_message: str)   # 无声调全拼小写
SINGLE_SURNAME_OVERRIDES = {...}   # 单字多音姓：{"单":"shan", ...}
COMPOUND_SURNAME_OVERRIDES = {...} # 复姓：{"尉迟":"yuchi", ...}
```

### 8.1 姓名校验 `normalize_real_name`

- 输入先 `strip()`（含全角空格），去掉姓名中间的空白字符；
- 允许：CJK 统一汉字 `U+4E00–U+9FFF`，以及间隔号 `·`（`U+00B7`，少数民族姓名）；
- 汉字个数 **2–10**（`·` 不计），总字符数 ≤ 24；
- 不允许数字、字母、标点（除 `·`）、控制字符；`·` 不能在开头/结尾、不能连续；
- 合法：返回 `(name, "")`；非法：返回 `(None, "中文提示")`，提示要具体（如「姓名需为 2–10 个汉字」）。

### 8.2 拼音转换 `name_to_pinyin`

1. 调用 `normalize_real_name`，非法直接返回其错误。
2. 去掉 `·` 后的汉字串用内置 pypinyin（`vendor/site-packages`，`lazy_pinyin(..., errors="default")`，
   每汉字一个音节）转换。
3. 多音姓氏补丁：
   - 姓名长度 ≥ 3 且前 2 字命中 `COMPOUND_SURNAME_OVERRIDES` → 前两个音节用表中读音；
   - 否则首字命中 `SINGLE_SURNAME_OVERRIDES` → 首音节用表中读音。
   - 补丁只影响**姓氏读音**，其余音节用 pypinyin 默认读音。
4. 拼接、转小写、只保留 `[a-z]`；结果长度需 **2–28**，否则返回错误（`姓名拼音过长，请联系管理员`）。
5. 返回 `(pinyin, "")`。

**必须通过的单元用例**（QA 会逐条断言）：

| 姓名 | 期望 |
|---|---|
| 张三 | zhangsan |
| 李四 | lisi |
| 王小明 | wangxiaoming |
| 欧阳锋 | ouyangfeng |
| 吕 | —— 合法（单字姓名不合法，2–10 汉字，所以「吕」返回错误） |
| 吕小布 | lvxiaobu |
| 曾小贤 | zengxiaoxian（曾姓不读 ceng） |
| 单伟 | shanwei |
| 解雨臣 | xieyuchen |
| 仇英 | qiuying |
| 区志强 | ouzhiqiang |
| 查良镛 | zhaliangyong |
| 朴树 | piaoshu |
| 缪斯 | miaosi |
| 尉健行 | yujianxing |
| 盖聂 | genie |
| 折可存 | shekecun |
| 尉迟恭 | yuchigong |
| 万俟明 | moqiming |
| 澹台灭明 | tantaiming 注：`澹台灭明` = 4 汉字，tan tai mie ming → tantaimieming |
| 长孙无忌 | zhangsunwuji |
| 阿依古丽·买买提 | ayigulimaimaiti |
| 张三; rm -rf / | 非法（标点/空格/控制字符） |
| 张3 | 非法（含数字） |
| 张 | 非法（<2 汉字） |
| 张 三 | 合法 → zhangsan（去空格） |
| 张· | 非法（· 在结尾） |

补充：`lazy_pinyin("吕")` 返回 `["lv"]`；`Style.NORMAL` 无声调。

### 8.3 用户名规则（server.py 内实现，需可被 QA 黑盒验证）

- username = pinyin（小写字母数字）；保证 `^[a-z][a-z0-9]{1,31}$`；
- 首候选 = base；被占则 `base + 2`、`base + 3` …（重名后缀从 2 开始），长度 ≤ 32；
- 保留名单（即使系统里不存在也不可用）：`root admin administrator sudo wheel docker signupapp nobody daemon bin sys sync games man lp mail news uucp proxy backup list irc gnats systemd sshd service support operator`；
- 「被占」判定：DB 中已有该 username，或系统 `pwd.getpwnam`/`grp.getgrnam` 命中。

---

## 9. 密码策略（`app/security.py`）

公开函数（QA 按签名测试）：

```python
def generate_password(length=16)      # -> str
def validate_password(password, username)  # -> (ok: bool, error_message: str)
def estimate_strength(password)       # -> {"score": int(0-4), "label": str, "percent": int}
```

### 9.1 校验 `validate_password`

必须同时满足，否则返回 `(False, "具体中文提示")`：

- 长度 **12–64**；
- 至少 1 个小写字母、1 个大写字母、1 个数字、1 个符号；
- 符号限定集合：`!@#$%^&*()-_=+[]{};,.?/|~`（其余字符如空格、引号、反斜杠、冒号、中文、控制字符 → 拒绝）；
- 不得包含用户名（不区分大小写）；不得包含姓名全拼（username 即其拼音）；
- 不得是弱密码（内置列表，至少含 `123456789012`、`password1234`、`qwertyuiop12`、`administrator1`、
  `P@ssw0rd1234`、`Aa123456789!` 等，可自行扩充到 ~30 条）；
- 不得有 4 个及以上连续相同字符（如 `aaaa`）；
- 提示语要指出具体原因，例如「密码长度至少 12 位」「需包含大写字母」「密码不能包含用户名」「密码过于常见」。

### 9.2 生成 `generate_password`

- 默认 16 位；使用 `secrets` 模块（禁止 `random`）；
- 字符集：大小写字母 + 数字 + `!@#$%^&*()-_=+[]{};,.?/|~`，排除易混淆字符 `0O1lI` 与 `:`；
- 保证 4 类字符各至少 1 个，`secrets.SystemRandom().shuffle` 打乱；
- 生成结果必须能通过 `validate_password(pw, username="")`（空用户名时不检查包含关系）。

### 9.3 强度 `estimate_strength`

返回 0–4 分与中文标签（很弱/弱/中等/强/很强）+ percent(0–100)，仅用于 UI 展示，规则自定但单调合理
（长度、字符类别数、重复度参与）。

---

## 10. 一人一 IP 与并发

- 客户端 IP 获取：`self.client_address[0]`；用 `ipaddress` 规范化（IPv4-mapped IPv6 → IPv4；非法 → 拒绝）。
- `trusted_proxies` 非空且对端在其中时，才取 `X-Forwarded-For` 最右侧非本机地址。
- 并发：`fcntl.flock(lockfile, LOCK_EX)` 覆盖 register 的第 5–9 步；进程崩溃自动释放。
- 状态机：先插 `provisioning` 再建用户，成功后 `active`；异常删除行。任何残留由管理员重置 IP 处理。
- **mock 模式**：接受请求头 `X-Test-Client-IP` 覆盖客户端 IP（仅 `mode=="mock"` 时生效），用于测试一人一 IP。

---

## 11. 安全要求（web + provisioner）

- 安全响应头（所有响应）：
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`
  - `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`
  - API / HTML：`Cache-Control: no-store`
- 不设置 cookie；管理端 token 只放请求头（GET 可 query，仅限本机运维方便）；页面不把 token 写进 URL 以外地方。
- 输入：JSON 解析失败 → 400；未知字段忽略；字符串长度上限（name ≤ 64 字节、password ≤ 128 字节）。
- 输出：错误信息不回显堆栈/命令/路径细节；500 时 message = 「服务器内部错误，请联系管理员」。
- 日志：访问日志记录 IP、method、path、status、耗时；**绝不记录请求体/密码**；注册成功记录 username + IP。
- 管理 token 常量时间比较。
- 限流（每 IP 内存滑动窗口，可配置）：超限 429 + `Retry-After` 秒数。
- 静态文件：只允许白名单扩展名（.html/.js/.css/.svg/.png/.ico/.woff2）；禁止路径穿越（`..`、绝对路径、`/static/../`）。
- 服务进程：web 以 `signupapp` 运行；provisioner 以 root 运行但只暴露 create_user/ping。
- 所有子进程调用用 list 参数（禁止 shell）；密码只经 stdin 传给 chpasswd。
- 自签名 TLS：`ssl.PROTOCOL_TLS_SERVER`，最低 TLS1.2。
- 管理员危险操作（reset-password / set-locked / delete-user）必须 token 鉴权，并记录操作者 IP 与目标用户名；
  删除必须要求 `confirm_username` 与记录 username 完全一致。
- 管理接口返回的一次性密码只出现在响应体，禁止写日志/DB；前端仅内存展示，不持久化。
- 公告按**纯文本**处理：服务端限制长度与字符集；前端必须用 `textContent` 渲染（禁止 innerHTML），避免 XSS。

---

## 12. 前端要求（`static/`，无外部 CDN，纯 HTML/CSS/JS）

### 12.1 页面 `/`（index.html）

- 中文界面，移动端可用（viewport、响应式、大按钮），整体风格简洁专业（深色/浅色均可，自包含）。
- 顶部：`ui.site_title`、`ui.server_name`、简短说明（「填写真实姓名，系统自动创建拼音账号与工作目录」）。
- **公告面板**（宽屏两栏：左侧表单 + 右侧公告；窄屏上下堆叠）：页面加载 `GET /api/announcement`，
  用 `textContent` 渲染纯文本（`white-space: pre-wrap`），标题「服务器使用说明 / 公告」，支持「展开/收起」，
  显示更新时间；内容较长时面板内部滚动（max-height，例如 60vh）。公告加载失败时显示友好提示，不影响开户。
- 表单：
  - **真实姓名**（text）：输入后 350ms 防抖调 `/api/preview`，显示：
    - 正常：`用户名：zhangsan`；
    - 重名：`已有同名账号，将分配：zhangsan2`（醒目提示）；
    - 错误：红色提示。
  - **密码**（password + 显示/隐藏切换）：
    - 「生成强密码」按钮 → `POST /api/generate-password` 填入；
    - 输入时本地调用强度条（4 段色条 + 文字），规则与 SPEC §9 一致（前端实现展示即可，最终以服务端为准）；
    - 帮助文案：「至少 12 位，含大小写字母、数字和符号」。
  - **提交按钮**「申请账号」：提交中禁用并显示 loading；成功后**整个表单替换为结果卡片**。
- 结果卡片（成功）：
  - 大号显示 **用户名**、**密码**（明文仅此一次，提醒「请立即保存，关闭页面后不再显示」）；
  - 家目录/工作目录 `home`（数据盘 `/home`，无需额外挂载）；
  - 校内登录：`ssh <username>@10.0.0.10`（IPv4，来自 `ui.ssh_host`；`ssh_login`）
  - 校外登录：`ssh -6 -p 2222 <username>@<ui.ssh_ipv6>`（IPv6，来自 `ui.ssh_ipv6`/`ui.ssh_ipv6_port`；`ssh_login_ipv6`）
  - 两条命令均等宽字体 + 复制按钮；
  - 提醒：首次登录后立即 `passwd` 修改密码；本账号为普通用户，无管理员权限；
  - 提供「复制全部信息」按钮。
- 错误统一在提交按钮上方以红色 alert 展示（含服务端 message）。
- 页脚：申请规则（一人一 IP、姓名须为真实中文姓名、密码规则）、管理员联系方式、服务名。
- 无内联 `<script>`/`<style>`（CSP 限制）：全部外链本地 `/static/app.js`、`/static/style.css`。
- 防重复提交；对 fetch 非 200 做容错；`X-Requested-With: campus-signup` 头必须带。
- 页面加载时 `GET /api/health`：若 `registration_enabled=false`，显示停用横幅并禁用表单。

### 12.2 页面 `/admin`（admin.html + admin.js）

- token 输入框（password 类型）+「加载」；token 存 `sessionStorage`（可留空每次输入）；所有请求带 `X-Admin-Token`。
- 顶部统计：总账号 / 正常 / 已锁定 / 系统缺失 / 申请状态（开放 / 暂停）。
- 注册列表表格列：时间、IP、姓名、用户名、UID、家目录、系统状态徽标（正常 / 已锁定 / 系统缺失 / 未知）、操作。
- 行内操作按钮（均需二次确认，删除为红色危险按钮）：
  - **重置密码**：`POST /api/admin/reset-password`，弹窗一次性显示新密码 + 复制按钮；
  - **锁定 / 解锁**：`POST /api/admin/set-locked`，按当前 os_status 切换；
  - **重置 IP**：`POST /api/admin/reset-ip`，确认后刷新；
  - **删除账号**：confirm 弹窗要求输入用户名确认，`POST /api/admin/delete-user`（带 confirm_username）。
- 顶栏「开放申请 / 暂停申请」开关（`POST /api/admin/set-registration`）。
- **公告编辑**：卡片内 textarea 显示当前公告（读取 `GET /api/announcement`），「保存公告」→
  `POST /api/admin/announcement`，显示字符数、保存结果与更新时间。
- 无 token / 403 时显示「无权限或 token 错误」；操作成功/失败用 toast 反馈，操作后自动刷新列表。
- 同样无外部资源、无内联脚本。

### 12.3 视觉/可用性

- 语义化标签、`label for`、`aria-live="polite"` 用于预览与错误提示；键盘可操作。
- 结果卡片可打印/复制；手机上按钮不小于 44px。
- 所有文案中文，不要出现英文占位符。
### 12.4 公告默认内容

Lead 提供 `deploy/announcement.default.txt`（install.sh 安装时注入 `ui.default_announcement`；server 首次
启动写入 DB meta `announcement`）。内容为纯文本，包含：

- 服务器地址 `10.0.0.10`（校园内网直连）与校外 IPv6 直连方式（机器一/机器二，SSH 端口 2222）；
- 账号说明：联系管理员开号、普通用户权限、使用问题联系管理员；
- 家目录在数据盘 `/home`，无需额外挂载；
- GPU 使用：`watch -n 1 nvidia-smi` 查看空闲卡，PyTorch 用 `torch.cuda.set_device(gpu_idx)` 指定 GPU；
- 仅可运行 Python，必须使用自己的 conda 环境；conda 创建/初始化/激活/删除/查看命令；
- 管理员联系方式（管理员甲，邮箱/电话/微信）。

前端只按纯文本渲染，**不得**在代码里硬编码公告内容。

---

## 13. Mock 模式（供 QA 本地端到端，无需 root / 无需 provisioner）

`python3 app/server.py --config <mock-config.json>`，当 `mode=="mock"`：

- 只启动 **一个** HTTP（明文）服务在 `server.ports.http`（忽略 https 与跳转）；
- 不连接 provisioner；用内置 mock provisioner：
  - 在 `<paths.db 所在目录>/mock-users/` 下创建 `<username>/`（mode 0750）模拟家目录；
  - 维护 `<dir>/mock-users/users.json`：`{"username": {"uid": 2000+n, "gid": ..., "home": "...", "real_name": ..., "locked": false}}`；
  - `username_taken` 查该文件；
  - 实现管理操作：`user_status`（exists/uid/gid/home/locked/groups=[username]/privileged=false）、
    `reset_password`（校验强密码后返回 ok，不存明文）、`set_lock`（改 locked 标记）、
    `delete_user`（删除 mock 家目录与 users.json 条目）；
- `paths.db`、`paths.lock`、`paths.static` 用配置值（QA 用 tempdir + 项目 static 绝对路径）；
- 接受 `X-Test-Client-IP` 作为客户端 IP（仅 mock）；
- 其余逻辑、校验、API 契约与生产一致。

---

## 14. 本地开发/测试命令

```bash
cd /Users/example/Documents/deepseek-harness/default-workspace/campus-signup

# 语法检查
python3 -m py_compile app/*.py
node --check static/app.js static/admin.js

# 单元测试（QA 提供）
python3 -m unittest discover -s tests -v

# mock 模式手工冒烟
python3 app/server.py --config /tmp/campus-signup-mock.json &
curl -s 'http://127.0.0.1:18082/api/health'
curl -s 'http://127.0.0.1:18082/api/preview?name=%E5%BC%A0%E4%B8%89'
curl -s -X POST 'http://127.0.0.1:18082/api/generate-password' -H 'X-Requested-With: campus-signup' -H 'Content-Type: application/json' -d '{}'
curl -s -X POST 'http://127.0.0.1:18082/api/register' -H 'X-Requested-With: campus-signup' -H 'Content-Type: application/json' -H 'X-Test-Client-IP: 10.0.0.1' -d '{"name":"张三","password":"<生成的密码>"}'
```

- pypinyin 已内置：app 内 `sys.path.insert(0, <项目根>/vendor/site-packages)` 即可 import。
- 不要在系统 Python 里 pip install；不要生成/提交 `__pycache__`。

---

## 15. 部署契约（Lead 负责，其他角色只读）

Lead 将在 star1 上：

1. 创建系统用户 `signupapp`（no-login）与目录：`/opt/campus-signup`、`/etc/campus-signup`、`/var/lib/campus-signup`；
2. 安装 `app/ static/ vendor/` 到 `/opt/campus-signup`；
3. 生成 `/etc/campus-signup/config.json`（含随机 admin token、`allowed_peer_uid`=signupapp uid、
   从 `deploy/announcement.default.txt` 注入的 `ui.default_announcement`）与
   自签名 TLS 证书（SAN：IP 10.0.0.10、IP 127.0.0.1、DNS localhost）；
4. 安装并 enable 两个 systemd 服务（web: User=signupapp；provisioner: root）；
5. 用真实请求做端到端验收（含用户管理：锁定/解锁/重置密码/删除、公告修改持久化、IPv6 登录命令展示），清理测试账号；
6. 写 README（访问地址、管理员 token 位置、日常运维、排障、回滚）。

其他角色不要执行任何 star1 操作。

---

## 16. 协作边界

- 只写自己作用域；发现别人文件有问题 → 报告 Lead，不要直接改。
- 本地不要起长期后台服务；测试结束清理 `/tmp` 与进程。
- 不新增第三方依赖；不引入 CDN；不修改 SPEC。
- 完成后向 Lead 报告：改了什么文件、跑过什么测试/结果、遗留风险。

---

## 17. 测试验收清单（QA 覆盖，Lead 最终复核）

本地 mock / 单元：
- [ ] 姓名校验/拼音表 §8.2 全部用例；
- [ ] 密码策略：长度、四类字符、用户名包含、弱密码、连续重复、非法符号；生成器 500 次全部通过校验；
- [ ] preview：正常/重名/非法；generate-password；health；
- [ ] register：成功（mock 家目录 0750 创建）、同 IP 第二人 409、不同 IP 同名 → 后缀 2、连续同名 → 3；
- [ ] 弱密码 → 400；非法姓名 → 400；缺 `X-Requested-With` → 403；超长 body → 413；未知路径 → 404；
- [ ] 管理员：无 token 403、错误 token 403、列表（含 os_status）、reset-ip 后可重新申请、停用申请后 register 409；
- [ ] 用户管理：reset-password 返回的密码满足强度策略；set-locked 后 os_status=locked，解锁恢复 active；
      delete-user confirm 不匹配 400、成功后列表移除且同 IP 可重新申请；不存在的 id 返回契约错误；
- [ ] 公告：GET /api/announcement 默认内容非空；管理员 POST 更新后 GET 立即生效（重启服务仍生效）；
      超长/非法内容 400；无 token 修改 403；
- [ ] 静态页面可访问（HTML 含中文标题、公告面板容器、引用本地 /static/*）；路径穿越 `/static/../app/server.py` 被拒；
- [ ] 日志/响应中不含密码。

---

## 18. v1.3 增量：学校邮箱验证码注册（覆盖前文冲突处）

### 18.1 目标与边界

- 申请账号**必须使用示例大学邮箱并通过邮箱验证码验证**；**一个邮箱只能注册一个账号**。
- 允许的邮箱域名（可配置）：`mails.example.edu.cn`（学生）、`example.edu.cn`（教职工）。
- 发信方式：SMTP（Coremail）：**`mails.example.edu.cn:465` + `security="ssl"`**，TLS 证书校验开启（已实测证书有效）；
  账号密码**只允许存在于服务器 `/etc/campus-signup/config.json`（0640 root:signupapp）**，禁止写进代码/仓库/日志/DB。
- 兼容历史：现有 `registrations` 记录 `email` 为 NULL（当前 2 条真实记录），保留显示，不强制补邮箱；
  这些旧记录不占邮箱唯一性。
- 原有规则保持：中文姓名→拼音用户名、重名加数字、强密码、一校园网 IP 一账号、普通用户权限、家目录 0750。

### 18.2 配置新增（生产 config.json）

```json
"email": {
  "enabled": true,
  "allowed_domains": ["mails.example.edu.cn", "example.edu.cn"],
  "smtp": {
    "host": "mails.example.edu.cn",
    "port": 465,
    "security": "ssl",
    "username": "<发件邮箱账号，如 huagd25@mails.example.edu.cn>",
    "password": "<SMTP 密码，仅部署时注入>",
    "from_name": "star1 实验室服务器",
    "from_addr": "<发件邮箱地址>",
    "tls_verify": true,
    "timeout_seconds": 20
  },
  "code_secret": "<install.sh 生成的 64 位 hex 随机密钥>",
  "code_ttl_seconds": 600,
  "resend_cooldown_seconds": 60,
  "max_verify_attempts": 5,
  "max_send_per_email_per_day": 10,
  "subject": "【star1 实验室服务器】账号申请验证码"
}
```

`rate_limits` 增加：`"email_send": { "window_seconds": 3600, "max_requests": 20 }`（按客户端 IP）。
`email.enabled=false` 时 send-code 返回 409 `EMAIL_DISABLED`（维护开关）。

### 18.3 数据库迁移（schema_version=2，启动时自动执行、保留旧数据）

```sql
ALTER TABLE registrations ADD COLUMN email TEXT;                       -- 仅当列不存在
CREATE UNIQUE INDEX IF NOT EXISTS idx_registrations_email ON registrations(email);

CREATE TABLE IF NOT EXISTS email_codes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT NOT NULL,
  code_hash  TEXT NOT NULL,          -- HMAC-SHA256(code_secret, email + ":" + code) 的 hex
  expires_at INTEGER NOT NULL,       -- unix 秒
  used       INTEGER NOT NULL DEFAULT 0,
  attempts   INTEGER NOT NULL DEFAULT 0,
  ip         TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_codes_email ON email_codes(email);
CREATE INDEX IF NOT EXISTS idx_email_codes_created ON email_codes(created_at);
```

- 每次 send-code 顺带清理超过 24 小时过期 / 30 天前的记录。
- 验证码只存 HMAC，不存明文；日志/响应/DB 均不得出现明文验证码（mock 模式除外）。

### 18.4 API 契约

#### `POST /api/email/send-code`
- 需 `Content-Type: application/json` + `X-Requested-With: campus-signup`；按 IP 限流 `rate_limits.email_send`。
- 请求：`{"email":"12345678@mails.example.edu.cn"}`
- 校验顺序：JSON → email 格式+域名（400 `INVALID_EMAIL`）→ 已注册（409 `EMAIL_REGISTERED`）
  → 60s 冷却与每日上限（429 `RATE_LIMITED`，带 `Retry-After`）→ 生成 6 位数字码（secrets）
  → 旧未用码置失效 → 存 HMAC → SMTP 发送。
- 200：`{"ok":true,"email":"...","expires_in":600,"cooldown":60}`
- 502 `EMAIL_SEND_FAILED`：SMTP 失败（message「验证码邮件发送失败，请稍后重试或联系管理员」，不暴露 SMTP 细节）。
- 邮件：主题=`email.subject`；正文纯文本，含 6 位验证码、10 分钟有效、非本人操作请忽略；
  From 使用 from_name/from_addr；To 只能是校验通过的 email；**不得把用户输入姓名等拼进邮件头**（防头注入）。
- 仅最新一条验证码有效（发新码时旧码标记 used=1）。

#### `POST /api/register`（变更）
请求：`{"name":"张三","password":"...","email":"12345678@mails.example.edu.cn","email_code":"123456"}`

处理顺序（在原有基础上插入）：
1. 姓名校验 `INVALID_NAME`；
2. 密码强度 `WEAK_PASSWORD`；
3. email 格式/域名 `INVALID_EMAIL`；
4. **邮箱是否已注册 → 409 `EMAIL_REGISTERED`（先于验证码校验；与 send-code 行为一致，不额外泄露信息）**；
5. 验证码校验：错误/不存在 `EMAIL_CODE_INVALID`、过期 `EMAIL_CODE_EXPIRED`、
   尝试次数≥5 `EMAIL_TOO_MANY_ATTEMPTS`（此时需重新发送）；以上校验失败返回 **400**；
6. `registration_enabled`、来源 IP 限制；
7. flock 内：IP 唯一 → **email 唯一（DB UNIQUE 兜底，冲突 409 `EMAIL_REGISTERED`）** → 选用户名 → provisioning 行（含 email）
   → 调 provisioner 建号 → active → **将该验证码 used=1**。
- 201 的 `account` 增加 `"email"` 字段；返回中仍不含密码。
- 任何验证码校验失败都不得创建用户或占用 IP/email。

#### `GET /api/health` 增加
`"email_verification_enabled": true, "allowed_email_domains": ["mails.example.edu.cn","example.edu.cn"]`

#### 管理员列表
每条 registration 增加 `"email"`（旧记录为 null）；管理页前端支持按 用户名/姓名/邮箱 客户端搜索；其它管理接口行为不变。

### 18.5 邮箱校验规则

- 去首尾空白、转小写；正则 `^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`；总长 ≤ 254。
- 域名必须精确属于 `email.allowed_domains`（大小写不敏感）。
- 规范化后存储；`registrations.email` UNIQUE，一邮箱一号（含换 IP 重试）。
- 错误提示示例：「请使用示例大学邮箱（@mails.example.edu.cn 或 @example.edu.cn）」。

### 18.6 Mock 与本地集成测试

- `mode=="mock"` 使用 mock 邮件发送器：不连真实 SMTP；生成验证码写入
  `<paths.db 目录>/mock-emails.jsonl`（email/code/created_at），并在 send-code 响应中返回 `"debug_code":"123456"`（仅 mock）。
  其余限流/冷却/一次性/过期逻辑与生产一致；QA 用 debug_code 跑通注册全流程。
- 另支持 `email.smtp.host=127.0.0.1` + 自定义 port 的 **本地 SMTP sink 集成测试**（QA 写最小 SMTP 服务器捕获邮件，
  验证 From/To/Subject/正文/头注入防护），无需外网。

### 18.7 部署与真实 E2E

- 服务器 `mails.example.edu.cn:465` 校园网内直达（已实测，无需公网出网/代理）；TLS 证书默认校验开启（已实测有效）。
- SMTP 账号密码与 `email.code_secret` 由 Lead 在部署后用受控命令注入 `config.json`（不写入仓库模板），重启服务生效。
- 真实 E2E（用 `huagd25@mails.example.edu.cn` 申请测试账号）：
  1) send-code 200；2) 通过 IMAP `mails.example.edu.cn:993` 读取该验证码；3) 用验证码注册成功；
  4) 同邮箱换 IP 再注册 → 409 `EMAIL_REGISTERED`；5) 错误验证码 → `EMAIL_CODE_INVALID`；
  6) 非学校邮箱 → `INVALID_EMAIL`；7) 校验系统账号/家目录/后台 email 字段；
  8) 清理测试账号与记录（现有 2 条真实注册不动）。
- `deploy/announcement.default.txt` 与微信群通知增加「申请须使用学校邮箱并完成邮箱验证」。

### 18.8 验收新增（QA + Lead）

- [ ] 允许域名通过；`@qq.com`/`@gmail.com` 等 → 400 `INVALID_EMAIL`；
- [ ] 同邮箱 60s 冷却、每日 10 条上限、按 IP 限流 429；
- [ ] 正确验证码注册成功；**一次性**：成功后同一码再次注册必须失败——已注册邮箱返回 409 `EMAIL_REGISTERED`
      （允许），或验证码层 `EMAIL_CODE_INVALID`（允许）；用该码给其他邮箱 → `EMAIL_CODE_INVALID`；
- [ ] 错误码 → 400 `EMAIL_CODE_INVALID`；过期 → 400 `EMAIL_CODE_EXPIRED`；错 5 次 → 400 `EMAIL_TOO_MANY_ATTEMPTS`；
- [ ] 同一邮箱第二次注册（不同 IP、任意验证码）→ **409 `EMAIL_REGISTERED`**（优先于验证码错误返回）；
- [ ] 验证码只存 HMAC，日志/响应/DB 无明文；SMTP 凭据不出现在代码/仓库/日志；
- [ ] 邮件真实到达（IMAP 读取）、主题/正文/From 正确、中文姓名无法注入邮件头；
- [ ] 历史 2 条无邮箱记录保留且后台显示 null；
- [ ] 后台列表含 email 字段，前端可按邮箱/用户名/姓名搜索。

---

## 19. v1.3 安全加固（用户明确要求，与 §18 同时实现）

> 背景：近期学校服务器被入侵事件较多。门户虽只在校园网可达，仍按「最小暴露、深度防御、可审计」加固。

### 19.1 管理后台鉴权加固

- 生产**只接受请求头 `X-Admin-Token`**；删除 `?token=` 查询参数支持（避免 token 进访问日志/Referer/历史记录）。
  仅当 `security.allow_query_token=true` 且来源 IP 为 127.0.0.1 时允许 query（默认 false）。
- 管理员鉴权失败锁定：同一 IP 在 15 分钟内失败 ≥10 次 → 该 IP 封禁 15 分钟（返回 403 `ADMIN_LOCKED`，
  记日志 `admin_auth_locked`）；成功鉴权清零。限流独立于现有 admin 限流。
- 新增 `security.admin_allowed_cidrs`（默认 `[]`=不限制）：非空时 `/admin` 页面与 `/api/admin/*` 仅允许这些 CIDR
  （部署时建议填校园网段 + 127.0.0.1/32 便于本机运维）。
- 管理 token 仍为常量时间比较、43 字符随机；前端不把 token 写入 URL、不打印到控制台；提供「清除 token」按钮。

### 19.2 连接与资源限制（防慢速/并发攻击）

- `ThreadingHTTPServer` 增加并发上限（默认 64，可配置）：超过时新连接立即收到 503 并关闭；
- 单连接读超时 30s、写超时 30s；请求行+头大小上限由 `http.server` 默认值保证（≤64KB）；
- 请求体上限：普通 POST 8KB（超出 413）；仅 `POST /api/admin/announcement` 256KB（正文 1–20000 字符）；
- HTTP 方法白名单：`GET`/`POST`/`HEAD`（HEAD 仅静态资源），其余 405；
- 静态文件仅白名单扩展名、无目录列表、`realpath` 前缀校验（已有）。

### 19.3 传输与响应头加固

- TLS：最低 TLS1.2，禁用压缩（`OP_NO_COMPRESSION`），仅启用 ECDHE+AESGCM/CHACHA20 类套件；
  自签名证书保留（SAN 10.0.0.10/127.0.0.1/localhost）。
- 所有响应头增加：
  - `Strict-Transport-Security: max-age=15552000`
  - `Cross-Origin-Opener-Policy: same-origin`、`Cross-Origin-Resource-Policy: same-origin`
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
  - 保留 CSP / nosniff / X-Frame-Options DENY / Referrer-Policy no-referrer / Cache-Control no-store（已有）
- `/admin` 与 `/api/*` 响应加 `X-Robots-Tag: noindex, nofollow`。

### 19.4 邮箱验证码防滥用（在 §18 基础上）

- send-code 限流叠加：每 IP `rate_limits.email_send`（默认 20 次/小时）+ 每邮箱 60s 冷却 + 每邮箱每天 10 条
  + **全局每天上限 `email.max_send_global_per_day`（默认 300 条）**；任一超限 429 `RATE_LIMITED`。
- 验证码：6 位 `secrets` 生成、HMAC-SHA256 存储、`hmac.compare_digest` 比较、10 分钟 TTL、最多 5 次尝试、一次性、
  发新码使旧码立即失效；**绝不在日志/响应/DB 中出现明文验证码**（mock 模式 debug_code 除外）。
- 邮件内容固定模板；收件人必须通过学校域名校验；用户输入只进入正文变量且不进入邮件头（防头注入）；
  发件人固定为配置值；SMTP 错误只记录类型，不泄露主机/账号细节。
- `/api/register` 的验证码失败不得消耗 IP 唯一名额、不得创建用户；校验顺序与 §18.4 一致。
- 前端：发送验证码按钮冷却、错误提示使用服务端 message；token 不落 localStorage。

### 19.5 部署暴露面加固

- 生产 `server.bind` 改为 **`10.0.0.10`**（只监听校园网卡）：不再监听 0.0.0.0，避免被服务器上
  k8s/libvirt/容器网桥内的进程访问；健康检查改用 `https://10.0.0.10:8444/healthz`。
- `security.admin_allowed_cidrs` 部署值建议 `["10.0.0.0/8", "127.0.0.1/32"]`（校园网 + 本机）。
- 文件权限：`config.json` 0640 root:signupapp（含 SMTP 密码，仅 web 可读）；TLS key 0640；代码 root:root 只读；
  DB 目录 0750 signupapp；`/run/campus-signup` 0750 root:signupapp；socket 0660。
- systemd 加固保持（NoNewPrivileges/ProtectSystem/CapabilityBoundingSet 空等）；web 服务不得获得 sudo。
- 部署前备份 DB；部署后核对历史记录完整。

### 19.6 审计与监控

- 安全事件日志（journald，结构化单行）：`admin_auth_fail`（ip/次数）、`admin_auth_locked`、`email_send`（email 掩码、
  ip、result）、`email_code_fail`（email 掩码、ip、attempts）、`register_ok/register_fail`（reason）；
  **不记录密码、验证码、SMTP 凭据、完整邮箱可只留掩码（如 h***5@mails.example.edu.cn）**。
- 访问日志：ip、method、path、status、耗时（不含 query 中的 token/验证码）。
- 运维侧：README 增加安全审计命令（sshd 配置、监听端口、特权账号、sudo 用户、失败登录统计、fail2ban 可用性），
  给出（不自动执行）SSH 加固建议；改动 sshd 前必须评估现有用户影响。

### 19.7 审计新增验收

- [ ] `/api/admin/*` 带 `?token=` 返回 403（未开启 allow_query_token）；仅 header 可用；
- [ ] 同 IP 连续 10 次错误 token → 后续返回 403 `ADMIN_LOCKED`，等待窗口后恢复；
- [ ] `admin_allowed_cidrs` 生效：非允许来源 → 403；
- [ ] 并发连接上限生效（压测/模拟 >N 连接返回 503，不影响正常请求）；
- [ ] 响应头包含 HSTS/COOP/CORP/Permissions-Policy/X-Robots-Tag；
- [ ] 邮件全局日上限、每邮箱/每 IP 限流均返回 429；
- [ ] 日志无明文验证码/SMTP 密码/token/完整邮箱（抽查 journald 与 access log）；
- [ ] 生产绑定 10.0.0.10，127.0.0.1/0.0.0.0 不再监听 8444/8082；从校园网 Mac 仍可访问；
- [ ] 历史 2 条真实注册在部署/迁移后仍存在。

---

## 20. 页面风格：简洁极简（v1.3.1，用户要求）

> 目标：像学校内部工具一样干净、克制、信息清晰。功能与安全要求不变，只调整视觉与信息密度。

### 20.1 申请页

- **浅色极简风**：白/浅灰底（如 `#f7f8fa`/`#fff`），卡片用细边框 + 很轻的阴影或不用阴影；
  **去掉**大面积渐变、发光、彩色光斑、装饰性图形、超大 hero 背景。
- 单一主色（如深蓝 `#2563eb` 或墨绿），仅用于主按钮/链接/焦点态；危险操作用红色；
  正文深灰 `#1f2937`，次要文字中灰 `#6b7280`；边框 `#e5e7eb`。
- 布局：页面最大宽度约 960–1100px 居中；标题（24–28px）+ 一行说明后直接进入表单；
  表单字段纵向排列、标签在上、输入框高约 40px、圆角 6–8px、留白充足（16–24px）。
- 减少冗余文案：只保留必要提示（邮箱规则、密码规则、一人一邮箱/IP、验证码一次性）；
  去掉 emoji、彩色 chip 墙、过多小标题/分割线。
- 公告面板改为**普通可折叠区块**（默认收起或展开均可）：标题「服务器使用说明」+ 纯文本内容，
  白底细边框，不要长卡片内滚动大段装饰；内容仍完整可读（可滚动，限制高度）。
- 结果卡片重新设计为清爽的键值列表（用户名/密码/邮箱/家目录/登录命令），密码依旧一次性提示。
- 移动端：单列、按钮全宽、字号不小于 14px、无横向滚动。

### 20.2 管理页

- 同样浅色极简：白底、细边框表格、斑马纹可选；统计用简单文字/小标签，不用彩色大卡片；
- 操作按钮小尺寸（次要按钮描边、删除红色）；表格可横向滚动；搜索框简单一行。
- 页头保留「返回申请页 / 清除 token」。

### 20.3 保留项

- 现有功能、字段、错误提示、无障碍（label/aria-live）、CSP/无外部资源/无内联脚本、移动端可用性不变；
- 保留 `favicon.svg`，配色与主色一致。

---

## 21. v1.4 忘记密码（学校邮箱验证自助重置）

### 21.1 流程

申请页提供「忘记密码？」入口（同一页面切换为重置表单，不新增页面路由）：

1. 输入学校邮箱 → `POST /api/password/reset-request`：
   校验格式/域名（400 INVALID_EMAIL）→ **IP 限流（429，先于已注册检查，防未注册邮箱被无限速枚举）**
   → 是否已注册（404 `EMAIL_NOT_FOUND`）→ `email.enabled`（409 `EMAIL_DISABLED`）
   → 每邮箱冷却/每日/全局限流（429）→ 生成 **purpose="reset"** 的 6 位验证码并发送邮件。
2. 输入验证码 + 新密码 → `POST /api/password/reset`：
   校验验证码（purpose=reset，一次性/10 分钟/5 次原子上限）→ 查 registration（email 唯一）→
   新密码强度校验（含用户名，复用 §9）→ 调 provisioner `reset_password(username,new_password)`
   （保留原有锁定状态）→ 标记 code used=1 → 返回 `{"ok":true,"username":"...","locked":false}`。
3. 失败：`EMAIL_CODE_INVALID` / `EMAIL_CODE_EXPIRED` / `EMAIL_TOO_MANY_ATTEMPTS` / `WEAK_PASSWORD` /
   `USER_MISSING`（系统账号不存在，需管理员处理）/ `EMAIL_NOT_FOUND` / `EMAIL_DISABLED` / `RATE_LIMITED`。
   重置失败不得消耗验证码（仅成功后标记 used）。
4. 前端成功提示「密码已重置，请用新密码登录」；`locked=true` 时提示「账号当前被锁定，需联系管理员解锁」。

### 21.2 DB 迁移（schema_version=3）

```sql
ALTER TABLE email_codes ADD COLUMN purpose TEXT NOT NULL DEFAULT 'register';  -- 仅当列不存在
CREATE INDEX IF NOT EXISTS idx_email_codes_purpose ON email_codes(purpose, email);
```

- 注册验证码 purpose=`register`；重置验证码 purpose=`reset`；校验必须按 purpose 过滤（**跨用途不可用**）。
- 旧记录默认 register；迁移保留数据。
- 发码冷却/每日上限/全局日限按 email 统计（不区分 purpose），防止绕过额度。

### 21.3 API 契约

#### `POST /api/password/reset-request`
- 与 send-code 相同：JSON + `X-Requested-With`、8KB body、IP 限流 `rate_limits.password_reset`
  （默认 `{window_seconds:3600,max_requests:20}`，**在已注册检查之前执行**）；每邮箱 60s 冷却 / 每日 10 条 / 全局每日 300 共享。
- body `{"email":"12345678@mails.example.edu.cn"}`
- 200 `{"ok":true,"email":"...","expires_in":600,"cooldown":60}`
- 404 `EMAIL_NOT_FOUND`；其它错误同 §18.4。

#### `POST /api/password/reset`
- body `{"email":"...","code":"123456","new_password":"..."}`
- 200 `{"ok":true,"username":"zhangsan","locked":false}`
- 校验顺序：email 格式 → email 已注册（404）→ 验证码(400) → 新密码强度(400 WEAK_PASSWORD) → provisioner。
- 不返回密码；日志只记录 `password_reset`（mask_email、username、locked、ip、result），不含验证码/密码。
- 账号被锁定：密码重置成功但 `locked=true`（不自动解锁）。

### 21.4 前端

- 申请页新增「忘记密码？」文字链接（表单下方或密码字段旁边），点击切换为**重置表单**（同页面、浅色极简风格）：
  学校邮箱 + 发送验证码（60s 倒计时，规则同注册）+ 6 位验证码 + 新密码（强度条/显示切换/生成按钮）+「重置密码」按钮；
- 重置成功：绿色提示 + `username` 与「返回账号申请」；`locked=true` 时额外提示需管理员解锁；
- 重置表单错误使用服务端 message；切回申请表单时保留原有状态；不影响注册流程；
- 保持无外部资源/无内联脚本/CSP/移动端可用/无障碍。

### 21.5 安全

- 验证码**用途绑定**：注册码不能用于重置、重置码不能用于注册（purpose 过滤）；
- 重置请求/提交均限流；验证码一次性 + 5 次上限原子占用（与 F10 修复一致）；
- 新密码与注册同等强度校验；重置不自动解锁；不泄露验证码/密码；
- `EMAIL_NOT_FOUND` 的信息级别与 send-code 的 `EMAIL_REGISTERED` 一致（不新增枚举面）。

### 21.6 验收（QA + Lead）

- [ ] 未注册邮箱 reset-request → 404 `EMAIL_NOT_FOUND`；非学校邮箱 → 400 `INVALID_EMAIL`；
- [ ] 已注册邮箱发码（purpose=reset）→ 用正确码重置成功；新密码强度校验通过（`crypt` 哈希匹配 + `su` 可登录）；
- [ ] 注册验证码不能用于重置（`EMAIL_CODE_INVALID`）；重置码不能用于注册；
- [ ] 错误码 → `EMAIL_CODE_INVALID`；过期 → `EMAIL_CODE_EXPIRED`；错 5 次 → `EMAIL_TOO_MANY_ATTEMPTS`（并发原子）；
- [ ] 弱新密码 → 400 `WEAK_PASSWORD`；`email.enabled=false` → 409 `EMAIL_DISABLED`；
- [ ] 被锁定账号：重置成功但 `locked=true`，管理员解锁后可用新密码登录；
- [ ] 日志/响应不含验证码与新密码；历史账号/数据不受影响。

---

## 22. v1.5 现有用户绑定邮箱 / 已有用户纳入管理 / 禁用删除用户

### 22.1 目标

- **现有用户可自助绑定学校邮箱**：必须同时验证「当前服务器密码」+「学校邮箱验证码」，防止他人抢占账号邮箱；
  绑定后该用户可使用 §21「忘记密码」自助重置密码。
- **管理后台纳入全部已有用户**：读取 `/etc/passwd` 中 uid≥1000 的普通用户（含门户创建 + 系统已有），
  在 `/admin` 统一查看状态并管理（重置密码/锁定解锁/绑定邮箱/重置申请 IP），特权账号只读展示、不可操作。
- **彻底禁用删除用户功能**：移除管理前端删除按钮/弹窗、移除 `/api/admin/delete-user` 路由、
  provisioner 拒绝 `delete_user` 操作（返回 INVALID「删除用户功能已禁用」）；任何用户数据不得被该功能删除。
- 邮箱唯一性跨「portal 注册」与「绑定」：**一个学校邮箱只能对应一个账号**。

### 22.2 DB 迁移（schema_version=4）

```sql
CREATE TABLE IF NOT EXISTS user_emails (
  username    TEXT PRIMARY KEY,
  email       TEXT NOT NULL UNIQUE,
  source      TEXT NOT NULL,          -- 'portal' | 'self' | 'admin'
  verified_at TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_emails_email ON user_emails(email);
```

- 启动迁移时回填：`INSERT OR IGNORE INTO user_emails(username,email,source,verified_at,created_at) SELECT username,email,'portal',... FROM registrations WHERE email IS NOT NULL`。
- 邮箱唯一性判定必须**同时查 `registrations.email` 与 `user_emails.email`**（两表 UNIQUE 双保险）。
- portal 注册成功时同步写 `user_emails(source='portal')`；`registrations.email` 保持同步。

### 22.3 Provisioner 新增/调整

- `list_users`：返回 uid≥1000 且 <65000 的普通用户列表（最多 500）：username/uid/gid/home/shell/real_name(gECOS)/
  groups/privileged/locked；不含 uid<1000 系统账号。供管理后台纳入已有用户。
- `verify_password` `{username,password}`：读 `/etc/shadow` 哈希并用 `crypt` 校验（绝不记录密码；常量时间比较）；
  返回 `{ok, exists, manageable, locked}`；`manageable` = uid≥1000 且不在保护名单且不属于特权组。
  用户不存在/不可管理时统一返回 `manageable=false`（避免账号枚举差异）。
- **禁用 `delete_user`**：dispatch 收到该 op 一律返回 `{"ok":false,"error":{"code":"INVALID","message":"删除用户功能已禁用"}}`；
  Web 侧删除路由，双重禁用。
- 其他 op（create_user/user_status/reset_password/set_lock）保持。

### 22.4 API 契约

#### 自助绑定邮箱（公开）
- `POST /api/email/bind-request` body `{"username":"zhangsan","password":"...","email":"12345678@mails.example.edu.cn"}`
  校验顺序：JSON/headers → username/email 格式与域名（400 INVALID_EMAIL/INVALID_USERNAME）→
  email 未被任何账号使用（409 `EMAIL_ALREADY_BOUND`）→ **IP 级 `rate_limits.bind`（默认 3600s/10 次）限流（429，先于密码校验，
  防止在线密码爆破与拖垮 provisioner）** → 调 provisioner `verify_password`（失败/不可管理 → 400 `INVALID_CREDENTIALS`，
  统一提示「用户名或密码错误，或该账号不支持自助操作」）→ 该账号已绑定邮箱（409 `EMAIL_ALREADY_BOUND`）→
  每邮箱冷却/每日/全局上限（429）→ 生成 **purpose='bind'** 的 6 位验证码并 SMTP 发送
  → 200 `{"ok":true,"email":"...","expires_in":600,"cooldown":60}`。
  另：同一 `username + IP` 密码校验失败 ≥5 次 → 锁定 15 分钟（429 `RATE_LIMITED`，错误信息保持统一、不泄露账号状态）。
- `POST /api/email/bind` body `{"username","password","email","code"}`
  校验顺序同上（**含先于 verify_password 的 IP/bind 限流与失败锁定**，以及再次 verify_password）→ 验证码 purpose=bind（一次性/10min/5 次原子上限）→
  **事务内再次检查邮箱唯一性** → `INSERT INTO user_emails(...,source='self')`；若 registrations 存在该用户名且 email 为空则同步
  → 200 `{"ok":true,"username":"...","email":"..."}`。
  错误码：INVALID_EMAIL/INVALID_USERNAME/INVALID_CREDENTIALS(400)/EMAIL_ALREADY_BOUND(409)/EMAIL_CODE_INVALID/EMAIL_CODE_EXPIRED/
  EMAIL_TOO_MANY_ATTEMPTS(400)/EMAIL_DISABLED(409)/RATE_LIMITED(429)。
- **忘记密码扩展**：reset-request/reset 的「邮箱→账号」查询同时查 `registrations.email` 与 `user_emails.email`；
  绑定邮箱的现有用户可自助重置；不可管理账号 → 409 `USER_NOT_MANAGEABLE`（提示联系管理员），失败不消耗验证码。
- 注册 send-code/register 的邮箱唯一性检查也纳入 `user_emails`。

#### 管理员接口（改为按 username 操作）
- `GET /api/admin/users`：返回全部用户（provisioner `list_users` + portal 记录合并、username 去重，portal 优先）：
  `username/real_name/email/uid/gid/home/source('portal'|'imported')/ip/registration_id/privileged/os_status(active|locked|missing|unknown)/locked`；
  stats `{total,active,locked,missing,with_email,portal,imported}`。
  provisioner 不可用时降级为仅 portal 记录，未匹配用户 os_status='unknown' 且接口仍 200。
- `POST /api/admin/reset-password {"username"}`：生成强密码 → provisioner reset_password → 200 `{ok,username,password}`（一次性，不落库/日志）；
  不存在/不可管理 → 409 `USER_MISSING`；特权账号 → 403 `USER_NOT_MANAGEABLE`。
- `POST /api/admin/set-locked {"username","locked"}`。
- `POST /api/admin/bind-email {"username","email"}`（管理员直接绑定，无需验证码）：email 域名/唯一性校验、
  账号存在且可管理预检、事务内写 `user_emails(source='admin')` 并同步 registrations.email（若空）→ 200。
- `POST /api/admin/reset-ip {"id"}` 保留（仅 portal registrations 行；导入用户无 IP 记录）。
- **删除 `POST /api/admin/delete-user`**：路由移除（请求 → 404/405）；前端删除相关按钮/弹窗/调用。
- 移除旧 `GET /api/admin/registrations`（前端改用 `/api/admin/users`）。
- `set-registration` / `announcement` 保留；所有写操作仍 token + 限流 + 审计日志（mask email、username、result、无密码/验证码）。

### 22.5 前端

- 申请页改为三个入口（同页面切换、浅色极简）：**申请账号 / 绑定已有账号邮箱 / 忘记密码**。
  - 绑定表单：用户名、当前服务器密码、学校邮箱（+ 发送验证码 60s 倒计时）、验证码、「绑定邮箱」；
    成功提示（可去忘记密码）；错误原样展示服务端 message。
- 管理页：
  - 改用 `GET /api/admin/users`；表格列：用户名 / 姓名 / 邮箱 / UID / 家目录 / 来源（门户/已有） / 系统状态 / 操作；
    统计：总数 / 正常 / 已锁定 / 系统缺失 / 已绑邮箱 / 门户 / 已有。
  - 操作：重置密码、锁定/解锁、**绑定邮箱**（输入邮箱，确认）、重置 IP（仅 registration_id 存在时显示）；
    **删除账号按钮、确认弹窗、相关 JS 全部移除**；保留公告编辑、暂停申请、清除 token、搜索（用户名/姓名/邮箱）。
- 绑定/忘记密码/管理操作的错误提示原样展示；无外部资源/无内联脚本/CSP/移动端/无障碍保持。

### 22.6 安全

- 自助绑定同时验证「当前密码 + 邮箱验证码」，密码校验在 root provisioner 内完成，密码只经 Unix socket，绝不落日志/DB；
- 统一 `INVALID_CREDENTIALS` 提示，不区分用户不存在/密码错误/不可管理，避免账号枚举；
- **绑定必须限流在密码校验之前**（`rate_limits.bind` 每 IP 10 次/小时）+ 同 username+IP 连续失败 5 次锁 15 分钟，
  防止在线密码爆破与 provisioner crypt DoS；失败日志带客户端 IP（不记密码）；
- 邮箱唯一性事务 + 双表检查；`purpose='bind'` 与 register/reset 验证码互相隔离；
- **删除用户功能彻底禁用**：web 路由不存在、provisioner 拒绝、前端无入口；任何删除 API 调用不得影响用户/家目录；
- 管理页所有写操作 token + 限流 + 审计日志；日志不含密码/验证码/完整邮箱（掩码）。

### 22.7 验收（QA + Lead）

- [ ] 现有普通用户（uid≥1000 非特权）自助绑定：错误密码 → 400 INVALID_CREDENTIALS；非学校邮箱 → 400；
      邮箱已被占用 → 409 EMAIL_ALREADY_BOUND；正确流程 → 200 且 user_emails 落库、registrations 同步（如有）；
- [ ] 已绑定账号重复绑定 → 409；一个邮箱不能注册第二个账号（注册 send-code 409）；
- [ ] 绑定后忘记密码：真实邮件取码 → 重置成功 → 新密码 crypt 匹配 + `su` 登录；
- [ ] 管理列表包含全部 uid≥1000 已有用户（含 portal 2 条与系统用户），字段/stats 正确；特权账号标注 privileged=true；
- [ ] 管理员对普通已有用户：重置密码/锁定/解锁/绑定邮箱成功；对特权账号 → 403 USER_NOT_MANAGEABLE；
- [ ] **删除用户功能不可用**：前端无按钮；`POST /api/admin/delete-user` → 404/405；provisioner `delete_user` → INVALID「已禁用」；
      用户与家目录不因该调用被删除；
- [ ] 旧 v1.4 功能回归：邮箱注册/忘记密码/公告/安全加固/一 IP 一号/历史记录保留；
- [ ] 日志无密码/验证码；测试数据清理且不触碰真实用户。
