# campus-signup — star1 校园网自助开户门户

在 star1（`10.0.0.10`，Ubuntu 24.04）上运行的自助开户网站：校园网内用户填写中文姓名、
**学校邮箱（@mails.example.edu.cn / @example.edu.cn）并完成邮箱验证码验证**、设置强密码，即可自动创建
**普通 Linux 账号 + 拼音用户名 + 数据盘家目录**；**一个校园网 IP、一个学校邮箱都只能申请一个账号**。
管理员可在 `/admin` 后台管理**全部已有服务器用户**（重置密码 / 锁定解锁 / 绑定邮箱 / 重置申请 IP）并编辑首页公告；
为安全考虑，**门户已禁用删除账号功能**。

- 本文件面向：服务器管理员（运维、部署、排障、回滚）。
- 技术契约（接口、规则、验收标准）：见 [SPEC.md](../SPEC.md)。

> **v1.5 更新（2026-10-26）**：① 现有用户可**自助绑定学校邮箱**（需当前密码+邮箱验证码），绑定后可用忘记密码；
> ② 管理后台纳入**全部已有 Linux 用户**（含 v1.5 前创建的账号），支持重置密码/锁定/绑定邮箱；
> ③ **删除账号功能已彻底禁用**（前端入口、管理 API、provisioner 操作均不可用）；④ 绑定接口增加防密码爆破限流。
>
> **v1.3 更新（2026-10-26）**：① 注册改为「学校邮箱 + 验证码」（一邮箱一号，SMTP 直连 `mails.example.edu.cn:465`）；
> ② 安全加固（管理锁/禁用 URL token、并发与请求限制、HSTS/COOP/CORP/Permissions-Policy、TLS 1.2+、
> 邮件全局日上限、日志脱敏、仅绑定校园网卡 10.0.0.10）；③ 页面改为浅色极简风；
> ④ 公告新增「SSH RSA 密钥登录教程」。

---

## 1. 访问入口

| 用途 | 地址 |
|---|---|
| 申请页面（校园网 / HTTPS） | <https://10.0.0.10:8444/> |
| 申请页面（HTTP，自动跳转 HTTPS） | <http://10.0.0.10:8082/> |
| 管理后台（需 token） | <https://10.0.0.10:8444/admin> |
| 探活接口 | `/healthz`（两个端口均返回 JSON） |

> 自签名证书：浏览器首次访问会提示「连接不是私密连接」，点「高级 → 继续前往 10.0.0.10」
> 或「访问此网站」即可，不是服务器故障。要消除提示需给服务器配正式证书/域名（见 §10）。
>
> 页面只面向校园网（IPv4 10.x）；校外访问服务器请用公告中的 IPv6 SSH 方式（端口 2222）。

### 管理员 token

token 随机生成、仅存于服务器：

```bash
sudo python3 -c 'import json;print(json.load(open("/etc/campus-signup/config.json"))["security"]["admin_token"])'
```

打开 `/admin`，粘贴 token 即可。token 等同管理员密码，请勿外传；如需重置见 §6。

---

## 2. 功能一览

**公开申请页**
- 中文真实姓名 → 自动转无声调全拼作为用户名（内置多音姓氏补丁：单 shan、曾 zeng、解 xie 等）。
- **学校邮箱 + 验证码**：仅允许 `@mails.example.edu.cn` / `@example.edu.cn`；发送 6 位验证码（10 分钟有效，
  60 秒重发冷却），验证通过才能注册；**一个邮箱只能注册一个账号**。
- **忘记密码**：申请页提供「忘记密码？」，输入学校邮箱 → 收验证码 → 设置新密码即可自助重置
  （验证码 10 分钟有效、一次性、5 次上限；账号被锁定需管理员解锁；重置接口同样限流）。
- **绑定已有账号邮箱**：已有服务器账号的用户可在申请页「绑定已有账号邮箱」入口，
  输入用户名 + 当前服务器密码 + 学校邮箱验证码完成绑定；绑定后即可使用忘记密码。
  一个学校邮箱只能绑定一个账号；绑定接口有防密码爆破限流（每 IP 10 次/小时 + 同账号连续失败 5 次锁 15 分钟）。
- 重名自动加数字后缀：`zhangsan` → `zhangsan2` → `zhangsan3` …（输入姓名时实时预览将分配的用户名）。
- 密码服务端强制强密码策略（≥12 位、大小写+数字+符号、不许含用户名、弱密码/重复字符拦截），
  页面提供「生成强密码」按钮和强度条。
- 同一校园网 IP 只能成功申请一个账号（SQLite 持久化 + 文件锁并发安全）。
- 提交成功显示一次性结果卡片：用户名、密码（仅本次显示）、家目录、校内/校外 IPv6 两条 SSH 登录命令、复制按钮。
- 首页「服务器使用说明」公告面板（默认可在 `/admin` 随时编辑）。

**管理后台 `/admin`**
- 列表纳入**全部已有服务器用户**（门户创建 + 系统已有 uid≥1000 账号），显示用户名/姓名/邮箱/UID/家目录/来源（门户/已有）/
  系统状态（正常 / 已锁定 / 系统缺失 / 未知）；统计含总数/正常/已锁定/系统缺失/已绑邮箱/门户/已有；支持按用户名/姓名/邮箱搜索。
- 每行操作：**重置密码**（服务端生成强密码，一次性显示）、**锁定/解锁**、**绑定邮箱**（管理员直接绑定）、
  **重置申请 IP**（释放该 IP 允许重新申请，不删用户，仅门户来源行显示）。特权账号只读展示、不可操作。
- 开放/暂停申请开关；公告编辑（纯文本，最多 20000 字符）。
- **删除账号功能已禁用**：页面无删除按钮，管理 API 无此路由，provisioner 拒绝删除操作。

**账号规则**
- 邮箱必须是本人学校邮箱（`@mails.example.edu.cn` 或 `@example.edu.cn`），一个邮箱只能对应一个账号；
  历史账号（v1.5 前创建）可在申请页「绑定已有账号邮箱」自助绑定（管理员也可在后台绑定），绑定后可用忘记密码。
- 用户名 = 姓名全拼小写（`^[a-z][a-z0-9]{1,31}$`），长度 ≤ 32；重名后缀从 2 开始。
- 家目录 `/home/<用户名>`（`/home` 即 15T 数据盘），权限 `0750`，无任何特权组、无 sudo。
- Shell `/bin/bash`，可用密码 SSH：校内 `ssh <user>@10.0.0.10`；校外 `ssh -6 -p 2222 <user>@2001:db8::10`。
- 姓名限制 2–10 个汉字；少数民族姓名可用间隔号 `·`；无法转换的姓名请联系管理员手工建号。

---

## 3. 架构与文件

```
浏览器 ──HTTPS 8444──► campus-signup-web（用户 signupapp，无特权）
                              │ /run/campus-signup/provision.sock（0660 root:signupapp，SO_PEERCRED 校验 uid）
                              ▼
                       campus-signup-provisioner（root）── useradd / chpasswd / usermod / userdel
                              │
                       /var/lib/campus-signup/registrations.db（SQLite，一人一 IP）
```

| 路径 | 说明 |
|---|---|
| `/opt/campus-signup/` | 程序：`app/`（server.py、provisioner.py、pinyin_util.py、security.py）、`static/`、内置 `vendor/`（pypinyin） |
| `/etc/campus-signup/config.json` | 配置（0640 root:signupapp，含 admin token、端口、UI、限流） |
| `/etc/campus-signup/tls/` | 自签名证书（8444 HTTPS） |
| `/var/lib/campus-signup/registrations.db` | 申请记录（用户名、IP、姓名、UID、时间、状态） |
| `/run/campus-signup/provision.sock` | web ↔ provisioner 的 Unix socket |
| systemd | `campus-signup-web.service`、`campus-signup-provisioner.service` |
| 日志 | journald：`journalctl -u campus-signup-web -f`；访问/操作日志均为结构化单行，**不含密码** |

项目目录（开发机打包用）：`app/`、`static/`、`vendor/`、`deploy/`、`tests/`、`SPEC.md`。

---

## 4. 日常运维

### 4.1 状态与日志

```bash
sudo systemctl status campus-signup-web campus-signup-provisioner
sudo journalctl -u campus-signup-web -n 100 --no-pager      # Web 访问/错误日志
sudo journalctl -u campus-signup-provisioner -n 100 --no-pager  # 建号/锁定/绑定等操作日志
curl -ks https://127.0.0.1:8444/healthz
sudo ss -tlnp | grep -E ':(8444|8082) '
```

### 4.2 重启 / 启停

```bash
sudo systemctl restart campus-signup-provisioner campus-signup-web
sudo systemctl stop campus-signup-web campus-signup-provisioner
sudo systemctl start campus-signup-provisioner campus-signup-web   # 顺序：先 provisioner
```

### 4.3 修改配置（端口、限流、UI、公告默认值等）

```bash
sudoedit /etc/campus-signup/config.json   # 保持 root:signupapp 0640
sudo systemctl restart campus-signup-provisioner campus-signup-web
```

- 改 HTTPS/HTTP 端口后需同步 `deploy/` 模板或直接改上述配置，并重启；防火墙/安全组放行新端口。
- 修改 `ui.contact`、`ui.site_title` 等会即时体现在页面页头/页脚（无需改代码）。
- `security.allowed_client_cidrs` 默认为空（不限制来源）；填如 `["10.0.0.0/8"]` 可限制来源网段。
- 限流在 `rate_limits`：注册默认 20 次/10 分钟/IP，生成密码 30 次/分钟/IP。

### 4.4 修改首页公告

两种方式（推荐第一种）：
1. `/admin` → 公告编辑 → 保存（存 SQLite meta，立即生效，重启不丢）。
2. 改配置里 `ui.default_announcement` 只影响**首次部署**的初始值；已有数据库以 DB 为准。

补充：管理接口 `POST /api/admin/announcement` 的请求体上限单独放宽到 **256KB**（公告正文 1–20000 字符），
其余接口仍为 8KB（超过返回 413）；公告字符数超限仍返回 400。

### 4.5 常见管理操作

```bash
# 查看本次系统里由门户创建的用户（UID>=1000 且 DB 有记录的见 /admin；这里列全部普通用户）
getent passwd | awk -F: '$3>=1000 && $3<65000 {print $1}' | sort

# 注意：门户已禁用删除账号功能。如确需在服务器终端人工处理账号（仅 root，风险自担）：
#   sudo userdel -r <用户名>   # 会连同家目录删除，操作前务必备份！

# 手工锁定 / 解锁
sudo usermod --lock <用户名>
sudo usermod --unlock <用户名>
sudo passwd -S <用户名>

# 手工重置密码（交互，不放 shell 历史）
sudo passwd <用户名>

# 重置管理员 token
sudo python3 - <<'EOF'
import json, secrets
p = "/etc/campus-signup/config.json"
c = json.load(open(p))
c["security"]["admin_token"] = secrets.token_urlsafe(32)
json.dump(c, open(p, "w"), ensure_ascii=False, indent=2)
print("new token:", c["security"]["admin_token"])
EOF
sudo systemctl restart campus-signup-web    # token 由 web 进程读取

# 备份数据库（建议定期）
sudo sqlite3 /var/lib/campus-signup/registrations.db ".backup '/root/registrations-$(date +%F).db'" 2>/dev/null \
  || sudo cp /var/lib/campus-signup/registrations.db /root/registrations-$(date +%F).db
```

> 说明：服务器未安装 `sqlite3` 命令行时用 `cp` 备份即可（WAL 模式下建议停 web 或同时拷贝 `-wal/-shm`）。

### 4.6 IP 限制/清理

- 用户重复申请被拒（提示该 IP 已申请）→ `/admin` 找到记录点「重置 IP」（只释放 IP，不删账号）。
- 门户已禁用删除账号功能；如需处理账号请联系管理员在服务器终端谨慎操作。

---

## 5. 部署 / 升级

### 5.1 首次部署（当前已部署，勿重复执行；供重装参考）

在开发机（macOS）打包并上传：

```bash
cd campus-signup
bash deploy/package.sh                     # 生成 /tmp/campus-signup-*.tar.gz
scp /tmp/campus-signup-*.tar.gz 10.0.0.10:/tmp/campus-signup-pkg.tar.gz
ssh 10.0.0.10 'rm -rf /tmp/campus-signup-pkg && mkdir -p /tmp/campus-signup-pkg \
  && tar xzf /tmp/campus-signup-pkg.tar.gz -C /tmp/campus-signup-pkg \
  && sudo bash /tmp/campus-signup-pkg/deploy/install.sh'
```

`install.sh` 会（幂等）：
1. 创建系统账号 `signupapp`（no-login）；
2. 安装代码到 `/opt/campus-signup`（属主 root，只读）；
3. 生成/迁移 `/etc/campus-signup/config.json`（首次生成随机 admin token；已存在则保留 token/公告等）；
4. 生成自签名 TLS 证书（SAN：10.0.0.10、127.0.0.1、localhost）；
5. 安装 tmpfiles 与两个 systemd 服务并 `enable --now`；
6. 健康检查并打印访问地址、管理员 token。

安装输出中的 **管理员 token** 请立即保存；也可随时用 §1 的命令读取。

### 5.2 升级

重复执行 5.1（`install.sh` 幂等：保留配置、证书、数据库与已建用户），安装脚本会重启服务。

### 5.3 卸载 / 回滚

```bash
# 停服务、删代码，保留配置与数据库
sudo bash /tmp/campus-signup-pkg/deploy/uninstall.sh

# 连配置、数据库、signupapp 账号一起删除
sudo bash /tmp/campus-signup-pkg/deploy/uninstall.sh --purge

# 注意：通过门户创建的普通用户不会自动删除：
getent passwd | awk -F: '$3>=1000 && $3<65000 {print $1}'
sudo userdel -r <用户名>
```

---

## 6. 安全说明

- 全站 HTTPS（自签名；TLS ≥1.2），密码不会明文经过校园网；HTTP 端口只做 301 跳转。
- Web 服务以无特权系统用户 `signupapp` 运行，systemd 加固（只读根、隐藏 /home、无 capability、仅 AF_UNIX/INET）。
- 建号/改密/删除等特权操作只能由 root provisioner 执行，socket 权限 0660 并用 `SO_PEERCRED` 校验调用者 uid；
  provisioner 只暴露 ping/create_user/user_status/reset_password/set_lock/delete_user，拒绝 UID<1000、特权组、保护名单（root/admin 等）。
- 所有子进程调用均为 list 参数、无 shell；密码只经 stdin 传给 `chpasswd`，不进 argv。
- 日志只记 IP/用户名/结果，**不记录密码**；管理接口返回的一次性密码不落库、不写日志。
- 管理员接口需要 token（常量时间比较）且限流；公告按纯文本渲染（textContent，防 XSS）。
- 一人一 IP 持久化 + `flock` 并发安全；注册/生成密码/预览均按 IP 限流。
- 建议：正式使用前把自签名证书换成校内 CA/Let's Encrypt 证书；token 定期轮换；`/admin` 仅管理员访问。

---

## 7. 排障

| 现象 | 排查 / 处理 |
|---|---|
| 浏览器打不开 8444 | `sudo ss -tlnp \| grep 8444`；`systemctl status campus-signup-web`；确认在同一校园网；`curl -ks https://10.0.0.10:8444/healthz` |
| 浏览器提示证书错误 | 正常（自签名），点「高级→继续前往」；或换正式证书 |
| 页面 502/空 | `journalctl -u campus-signup-web -n 100`；检查 config 是否合法 JSON、端口是否冲突 |
| 提交申请报「服务器内部错误」 | `journalctl -u campus-signup-provisioner -n 100`；常见：磁盘满、useradd 失败、`/home` 不可写 |
| 提示「该校园网 IP 已申请过账号」 | 正常限制；管理员在 `/admin` 重置该申请 IP 后可重新申请 |
| 提示「用户名/用户组已存在」后自动换后缀 | 正常：系统里已有同名拼音用户，自动用 `<name>2/3…` |
| 用户登录后 `conda: command not found` | 用户需 `source ~/.bashrc` 或重新登录；conda 初始化见公告 |
| provisioner 起不来（socket 未就绪） | 检查 `signupapp` 组是否存在；`/run/campus-signup` 权限应为 `root:signupapp 0750`；`systemd-tmpfiles --create /etc/tmpfiles.d/campus-signup.conf` |
| 新用户无法 SSH | 确认 `PasswordAuthentication yes`；`sshd` 未限制 AllowUsers；校内用 22 端口、校外 IPv6 用 2222 |
| 提示密码包含不允许字符 | 仅允许字母数字和 `!@#$%^&*()-_=+[]{};,.?/|~`，且不含空格/冒号 |

---

## 8. 自动化测试

本仓库只包含可离线运行的本地测试（mock 模式，无需 root、不连接真实 SMTP/学校邮箱）：

```bash
cd campus-signup
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

- 覆盖注册/邮箱验证码（mock sender）/忘记密码/绑定已有账号邮箱/管理后台/安全限流/数据库迁移等，
  当前约 170 项全部通过；
- 原线上验收脚本（`verify-v14.py` / `verify-v15.py` / `e2e.py`）依赖具体部署环境的真实 IP、邮箱与账号数据，
  未随本仓库公开；如需线上验收，可参照 `tests/` 的 mock 用例改写。

---

## 9. 已知限制 / 后续可选项

- 网页仅绑定 IPv4（校园网）；校外访问服务器走 IPv6 SSH。如要让校外也能打开申请页，可把
  `server.bind` 改为 `::` 并给证书补 IPv6 SAN（需确认学校 IPv6 入站放行 8444/8082）。
- 未接内网穿透（frp 等）；如需校外免 IPv6 访问可另加，注意不要在公网裸奔、保留 IP 限制逻辑。
- 验证码邮件通过学校邮箱 SMTP 发送（依赖学校邮件系统）；账号密码仍只在申请成功页面一次性展示（管理员重置后同理）。
- 身份证/学号等实名校验未接入（当前仅校验姓名拼音规则）；如需可接学校统一身份认证后再开号。
- 数据库建议定期备份（见 4.5）；`/home` 数据盘已有 3.7T 余量，未配置磁盘配额（quota）。
- conda 环境与用户数据由用户自行负责，门户不管理用户数据。

---

## 10. 联系

服务器与门户维护：管理员甲（邮箱 admin@example.com，电话/微信 13800000000）、管理员乙（微信 wechat_admin）。
用户问题处理：通过 `/admin` 查看账号状态，必要时重置密码/解锁/绑定邮箱；删除功能已禁用。

---

## 附录 A：邮箱验证运维（SMTP）

### A.1 配置/修改 SMTP 凭据（仅服务器 root，凭据不进仓库）

```bash
sudo python3 /opt/campus-signup/deploy/configure-email.py <<'JSON'
{
  "enabled": true,
  "allowed_domains": ["mails.example.edu.cn", "example.edu.cn"],
  "subject": "【star1 实验室服务器】账号申请验证码",
  "smtp": {
    "host": "mails.example.edu.cn",
    "port": 465,
    "security": "ssl",
    "username": "huagd25@mails.example.edu.cn",
    "password": "<发件邮箱的 SMTP 密码>",
    "from_addr": "huagd25@mails.example.edu.cn",
    "from_name": "star1 实验室服务器",
    "tls_verify": true
  }
}
JSON
sudo systemctl restart campus-signup-web
# 查看当前非敏感配置
sudo python3 /opt/campus-signup/deploy/configure-email.py --show
```

- 配置文件 `/etc/campus-signup/config.json`：0640 root:signupapp，**含 SMTP 密码，禁止外传/复制到仓库**。
- 发件账号需支持 SMTP；密码是邮箱的「客户端/SMTP 密码」，不是网页登录密码（学校 Coremail 实测用完整邮箱
  `huagd25@mails.example.edu.cn` 作为用户名，端口 465 SSL，证书校验有效）。
- 服务器需能直连 `mails.example.edu.cn:465`（校园网内可达）；若学校调整策略导致不通，先手工验证：
  `python3 - <<'PY'` 见 `deploy/configure-email.py` 注释；或 `openssl s_client -connect mails.example.edu.cn:465`。

### A.2 相关参数（config.email）

| 键 | 默认 | 说明 |
|---|---|---|
| `enabled` | true | 关闭后 send-code 返回 409 EMAIL_DISABLED（维护开关） |
| `allowed_domains` | `["mails.example.edu.cn","example.edu.cn"]` | 允许注册的邮箱域名 |
| `code_ttl_seconds` | 600 | 验证码有效期 |
| `resend_cooldown_seconds` | 60 | 同邮箱重发冷却 |
| `max_verify_attempts` | 5 | 最多错误尝试次数 |
| `max_send_per_email_per_day` | 10 | 单邮箱每日发送上限 |
| `max_send_global_per_day` | 300 | **全局每日发送上限（防邮件轰炸/滥用）** |
| `subject` | 见上 | 邮件主题 |

### A.3 忘记密码排障

| 现象 | 排查 |
|---|---|
| 提示「该邮箱未注册」 | 邮箱不是本门户创建账号时使用的邮箱；历史账号（v1.3 前）没有邮箱，需管理员重置密码 |
| 提示验证码错误/过期 | 10 分钟内有效、5 次上限；重新发送后旧码失效 |
| 重置成功但仍无法登录 | 账号可能被锁定（/admin 显示「已锁定」），需管理员解锁；或 SSH 密码登录被限制 |
| 不想自助重置 | 管理员可在 /admin 对账号「重置密码」并一次性告知新密码 |

### A.4 绑定邮箱排障（v1.5）

| 现象 | 排查 |
|---|---|
| 绑定提示「用户名或密码错误，或该账号不支持自助操作」 | 用户名/密码不对，或账号为特权/系统账号（不可自助绑定），或连续失败被临时锁定（15 分钟） |
| 绑定提示「该邮箱已被占用」 | 一个学校邮箱只能绑定一个账号；换本人其他学校邮箱或联系管理员处理 |
| 绑定后忘记密码仍失败 | 确认绑定邮箱与申请时一致；账号若被锁定需管理员解锁；特权账号不支持自助重置 |
| 已有账号找不到「绑定邮箱」入口 | 打开申请页顶部「绑定已有账号邮箱」；如邮箱服务维护中入口会禁用 |

### A.5 验证码/邮件排障

| 现象 | 排查 |
|---|---|
| 收不到验证码 | 先看垃圾邮件箱；确认邮箱是本人学校邮箱；检查 send-code 是否 429（冷却/日上限）；`journalctl -u campus-signup-web -n 100 \| grep email_send` |
| 502 EMAIL_SEND_FAILED | SMTP 不可达/账号密码失效；用 `configure-email.py --show` 核对配置；手工测试 SMTP 登录；检查学校邮箱是否关闭 SMTP 服务 |
| 提示 EMAIL_REGISTERED | 该邮箱已注册过账号（一邮箱一号）；忘记密码请联系管理员重置 |
| 验证码错误/过期 | 验证码 10 分钟内有效、最多 5 次尝试；重新发送后旧码立即失效 |
| 日志里找不到验证码 | 正常：验证码只存 HMAC，日志/DB/响应中都不出现明文（mock 模式除外） |
| 邮件被判垃圾邮件 | 学校邮箱可能拦截外发邮件；可在邮箱设置里将发件人加白名单，或联系管理员 |

---

## 附录 B：服务器安全加固与审计（2026-10-26）

### B.1 门户自身加固（v1.3 已实施，详见 SPEC §19）

- 管理后台：只认 `X-Admin-Token` 请求头（**禁用 URL ?token=**）；同 IP 连续失败 10 次锁 15 分钟；
  可选 `security.admin_allowed_cidrs`（默认校园网段+本机）；常量时间比较；无 Cookie/CSRF 面小。
- 网络：生产只绑定 **10.0.0.10**（校园网卡），不再监听 0.0.0.0；TLS ≥1.2、强套件、HSTS；
  并发上限 64、连接/请求超时、请求体 8KB（公告 256KB）、方法白名单。
- 邮箱验证码：6 位 `secrets`、HMAC-SHA256 存库、一次性、10 分钟过期、最多 5 次、发码冷却/每邮箱日限/IP 限流/全局日限 300；
  邮件头防注入；SMTP 失败只记类型；日志**不出现验证码/SMTP 密码/管理员 token/完整邮箱（掩码）**。
- 自助绑定邮箱：必须同时验证「当前服务器密码 + 邮箱验证码」；**限流在密码校验之前**（每 IP 10 次/小时），
  同账号+IP 连续失败 5 次锁 15 分钟，防止在线密码爆破与拖垮 root provisioner；错误提示统一，不泄露账号状态。
- **删除账号功能已禁用**：前端无入口、管理 API 路由移除、provisioner 拒绝 delete 操作，避免误删/被攻击删除。
- 账户与权限：web 进程 `signupapp` 无特权；特权操作只经 root provisioner Unix socket（SO_PEERCRED + 0660）；
  systemd 沙箱（NoNewPrivileges/ProtectSystem/CapabilityBoundingSet 空等）；建号用户无 sudo/无特权组。

### B.2 本次服务器审计快照（只读审计，未改动现有服务）

| 项目 | 现状 | 说明/建议 |
|---|---|---|
| fail2ban | **active + enabled，sshd jail 已启用** | 已具备 SSH 暴力破解封禁能力，保持运行 |
| sshd | `PasswordAuthentication yes`、`PermitRootLogin without-password`、`MaxAuthTries 6` | 新用户需密码登录，不能关密码认证；建议（评估后）`MaxAuthTries 3`、`LoginGraceTime 30` |
| SSH 监听 | IPv4 `0.0.0.0:22`、IPv6 `[::]:2222` | 如无必要可只保留校园网/IPv6 入口，需学校网络策略配合 |
| sudo 用户 | 部署时按需配置（建议只保留管理员账号） | 与用户核对是否都需要；建议最小化 sudo 成员 |
| 对外监听（非本机） | 22/2222、门户 8444/8082（v1.3 起仅校园网卡）、ceph 6800/6801/7150/8443/8765/40380、etcd 2379/2380、k8s 6443、kubelet 10250、prometheus 9090 | **k8s API 6443、etcd 2379/2380、kubelet 10250、prometheus 9090 在校园网可达，建议评估收紧**（不在本门户范围内，勿随意改动） |
| 门户文件权限 | config 0640 root:signupapp；TLS key 0640；DB 目录 0750 signupapp；代码 root:root 只读 | 符合最小权限 |
| 备份 | 部署前已备份 config/DB 到 `/root/campus-signup-*-backup-*.json|.db`（0600） | 定期备份 `registrations.db` |

> 提醒：`/etc/ssh/sshd_config` 与 k8s/ceph 配置属于全服务器共用，**修改前必须评估所有用户与服务影响**；
> 门户自身的安全不依赖修改这些共享配置。若需要我给出具体的 SSH/k8s 加固方案（含回滚），可另行安排。

### B.3 建议定期执行的检查

```bash
# 门户服务/端口/健康
sudo systemctl status campus-signup-web campus-signup-provisioner
sudo ss -tlnp | grep -E ':(8444|8082) '
curl -ks https://10.0.0.10:8444/healthz

# 安全事件（登录失败/锁定/验证码失败/发信）
sudo journalctl -u campus-signup-web -u campus-signup-provisioner --since '-1 day' | grep -E 'admin_auth|email_|register_'

# SSH 暴力破解（fail2ban）
sudo fail2ban-client status sshd

# 数据库备份
sudo cp /var/lib/campus-signup/registrations.db /root/registrations-$(date +%F).db
```
