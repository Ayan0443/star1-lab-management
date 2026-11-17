# 安全审查报告 — campus-signup `app/`

- 审查角色：QA
- 审查日期：2026-10-26（**v1.5 最终版 + F11 修复**：§18 邮箱验证码 + §19 安全加固 + §21 忘记密码 + §22 绑定邮箱/全用户管理/禁用删除）
- **审查对象：v1.5 最终版（含 F1/F2/F4/F5/F10、L1–L4、R1、L8、F11 修复）**：
  - `app/server.py`（3674 行，md5 `01d4526668632bb7e8752aec14989b84`，mtime 17:12:44；含 F11 rate_limits.bind/bind_lockout）
  - `app/email_sender.py`（294 行，md5 `fd85fe4aaed998ef88927585ca3af230`，mtime 17:03:49）
  - `app/provisioner.py`（926 行，md5 `e3e5ed0c649be5f6d8092f0bbe39fe48`，mtime 17:12:47；删除 userdel 死代码）
  - `app/security.py`（218 行，md5 `76cbf5275f31baedfe31838b3fac3a09`）
  - `app/pinyin_util.py`（223 行，md5 `53ab7f4d10463d2a2c3f9b7c8679542c`）
  - 关联只读检查：`deploy/`（systemd、install.sh、config 模板、configure-email.py、verify-v14.py）、`static/`（token/XSS/CSP spot-check）
- **star1 线上聚焦验收：v1.4 77/77 PASS ✅ + v1.5 60/60 PASS ✅**（Lead 执行 `deploy/verify-v14.py` / `verify-v15.py`；
  两次部署 hash 均与本地对应版本一致；v1.5 schema v4 迁移成功、2 条历史注册保留、测试数据已清理；见第 6 节）。
  **F11 已修复+本地 170 tests 最终绿 + v1.5 线上 60/60 全过 → 最终绿**。
- 审查方法：
  1. 静态代码审查（逐行阅读 `app/` 全部代码，重点 §6/§7/§9/§10/§11/§18/§19/§21）；
  2. mock 黑盒 E2E（`test_api_mock.py`）：邮箱注册/重置全流程、purpose 绑定、限流、HMAC、并发尝试上限、v1.2/v1.3→v3 迁移；
  3. **本地 SMTP sink 集成**（`test_email_smtp.py`）：stdlib socket 最小 SMTP，production 模式真实 smtplib，验证 From/To/Subject/
     正文 6 位码/头注入/SMTP 失败 502/失败不消耗额度；
  4. **production 路径 + fake provisioner 集成**（`test_password_reset_prod.py`）：真实 `SocketProvisioner.reset_password` 请求
     捕获（新密码一致且通过 §9 策略）、USER_MISSING 映射、失败不消耗验证码；
  5. §19 加固黑盒（`test_security_hardening.py`）：query token、ADMIN_LOCKED（可配置阈值/自动恢复/窗口过期）、admin CIDR、
     HSTS/COOP/CORP/Permissions-Policy/X-Robots-Tag、并发上限 503、方法白名单、日志脱敏、部署模板契约（含 v1.5 rate_limits.bind/bind_lockout）；
  6. 生产路径单元回归（`test_regression_prod_paths.py`：F1/F2/F4 fake 依赖）；
  7. 最小复现实验：F1 TypeError、F10 并发绕过尝试上限、R1 迁移崩溃、SMTP 真实投递/失败均已实测。
- 本机限制：macOS / Python 3.9.6（LibreSSL），无 root、无 Linux `SO_PEERCRED`、无真实 Coremail SMTP/IMAP、无 star1 访问；
  因此「真实 useradd/chpasswd/usermod/userdel」「生产 TLS/OpenSSL3 套件」「真实邮件到达」「star1 bind/systemd 权限」
  「真实 crypt 哈希/`su` 登录」只能代码审查 + 标注无法验证（第 3 节）。
- 版本追溯：v1.2 发现 F1–F9；v1.3 增加 §18/§19 → F10 与 L1–L7；v1.4 增加 §21 → R1 与 L8；
  v1.5 增加 §22（绑定邮箱/全用户管理/禁用删除）→ 新增 F11（bind 密码校验前无限速）与 L9–L12（F11/L9/L10 已修复并回归）。

## 结论摘要

- 未发现可直接导致**未授权建号 / 提权 / RCE / 密码泄漏 / 邮件头注入 / 验证码用途绕过**的高危漏洞；
  web → provisioner 的 Unix socket + SO_PEERCRED + 参数再校验信任边界保持正确。
- **v1.3 结论保持**：邮箱验证码 6 位 `secrets` + HMAC-SHA256 存储 + `hmac.compare_digest` + 原子尝试名额 + TTL + 一次性 +
  发新码失效；send-code 冷却/每邮箱/全局/IP 限流在 `BEGIN IMMEDIATE` 内校验；SMTP 凭据仅 config；邮件头注入防护；
  §19 加固（query token 默认禁、ADMIN_LOCKED 可配置、admin CIDR、并发 503、HSTS 等头、日志脱敏）全部实现并测试通过。
- **v1.4 新增（忘记密码）安全结论**：reset-request/reset 按 **purpose="reset"** 绑定验证码（注册码不能用于重置、反之亦然）；
  重置提交与请求共用 `password_reset` 限流桶（默认 20/h），冷却/每日/全局额度按 email 共享（不可通过换用途绕过）；
  新密码复用 §9 强度校验（含用户名包含检查），成功后不自动解锁（locked 状态保留并回显）；重置失败不消耗验证码；
  provisioner `reset_password` 只收到 username+新密码（密码经 Unix socket，不落日志/DB/响应）；日志 `password_reset`
  含 mask_email/username/locked/ip/result，无验证码/新密码/完整邮箱。
- **v1.5 新增（§22）安全结论**：自助绑定需「当前服务器密码 + 学校邮箱验证码」双因子，密码校验在 root provisioner
  以 `crypt` + `hmac.compare_digest` 完成（密码仅经 Unix socket，不落日志/DB/响应）；错误/不存在/不可管理统一
  `INVALID_CREDENTIALS`（提示逐字一致，避免账号枚举）；绑定写入 `user_emails(source=self)` 并在 `BEGIN IMMEDIATE`
  事务内二次检查邮箱/账号唯一性、同步 registrations.email、标记验证码 used=1；purpose=bind 与 register/reset 隔离；
  邮箱唯一性跨 registrations/user_emails 双表；**删除用户彻底禁用**（web 路由移除、provisioner dispatch 硬拒绝且不调
  userdel、前端无入口）；管理后台改为 `GET /api/admin/users` 合并 provisioner list_users 与 portal 记录
  （portal 优先、privileged 只读、provisioner 不可用降级 200），管理操作按 username 且特权/保护账号 403。
- **F11【中·已修复+回归】**：`bind-request`/`bind` 原先在 `verify_password` 之后才做 IP 限流 → 可无限速在线试密码
  （密码爆破 oracle）并触发 root provisioner `crypt`（单线程 DoS）。修复：新增 `rate_limits.bind`（默认 3600s/10 次，
  bind-request 与 bind 共享）**前移至 verify_password 之前** + `security.bind_lockout`（默认 15min 窗口内同
  username+IP 失败 5 次锁 15 分钟，429 统一提示）；`_bind_precheck` 日志补客户端 IP；provisioner 删除 userdel 死代码。
  回归：额度内错误密码 400 且消耗额度；额度耗尽后即便密码正确也 429；第 5 次失败即锁 15 分钟；非学校邮箱 400 不消耗额度；
  fake provisioner 断言 `verify_password` 调用次数有界。详见第 2 节。
- **修复状态**：F1/F2/F4/F5/F10、L1–L4、R1、L8、**F11** 均已修复并回归验证；L9/L10 已修复；
  F3 部分缓解；F6 因删除功能禁用而失效；F7–F9、L5–L7、L11–L12 为低风险/提示项。
- **最终绿**：本地 `./tests/run_all.sh` → **Ran 170 tests … OK**（~60s，第 5 节）+ star1 v1.5 线上聚焦验收
  **60/60 PASS**（`deploy/verify-v15.py`，部署 hash 与本地一致；schema v4 迁移成功、历史数据保留、测试数据清理，第 6 节）。

---

## 一、已确认无问题

### A. 基础安全（v1.2 基线复核）

1. **命令注入**：web 不调用子进程（仅 Unix socket JSON）；provisioner 全部 `subprocess.run(list(...))`，无 `shell=True`；
   `useradd --comment` 的姓名仅汉字/`·`、username 严格正则、`--` 分隔；`chpasswd` 只经 stdin：
   `provisioner.py:127-150, 275-293, 392-427, 568-581`。
2. **密码不泄漏**：密码/新密码仅 stdin→chpasswd 或 Unix socket JSON；日志只有 username/uid/result；
   一次性 reset 密码只在响应体；DB 无 password 列；黑盒测试校验 users.json/日志/SQLite（含 WAL）无明文密码：
   `server.py:123-190, 621-717`，`provisioner.py:417-427, 501-508`。
3. **provisioner socket 鉴权**：`SO_PEERCRED` uid 严格相等、取不到凭据即拒绝；socket umask 0077 + chmod 0660 + chgrp；
   `/run/campus-signup` 0750：`provisioner.py:629-642, 653-676, 718-731`。
4. **用户管理限制**：保护名单、uid≥1000、特权组拒绝、delete 带 expected_uid 二次校验：
   `provisioner.py:48-87, 314-327, 550-566`。
5. **管理员鉴权/CSRF**：`hmac.compare_digest`；无 cookie/CORS；POST 强制 JSON + `X-Requested-With`：
   `server.py:1478-1515, 2392-2476`。
6. **路径穿越**：静态扩展名白名单 + `..`/`.`/空段/反斜杠/NUL 拒绝 + realpath 前缀校验；固定页面白名单：
   `server.py:2887-2928`（黑盒 5 条攻击路径均 400/403/404）。
7. **SQLite 注入**：全部参数化；WAL + busy_timeout；`ip/username/email` UNIQUE：`server.py:123-190, 1024-1110, 2115-2390`。
8. **错误信息/版本**：500 通用文案；`Server: campus-signup`；不回显堆栈/命令/路径（traceback 仅 stderr，见 F7）：
   `server.py:1359-1380, 1248-1253`。
9. **安全响应头/缓存**：CSP/nosniff/DENY/no-referrer/HSTS/COOP/CORP/Permissions-Policy 全响应，
   API/HTML `Cache-Control: no-store`，`/admin` 与 `/api/*` 加 `X-Robots-Tag`：`server.py:97-121, 1241-1252, 1374-1389`。
10. **输入/请求体/IP**：普通 8KB→413、公告 256KB、name≤64/password≤128；IP 规范化 + trusted_proxies/mock 覆盖：
    `server.py:55-56, 1131-1152, 1478-1515`。
11. **并发/状态机**：注册 flock 覆盖 IP/email 唯一→建号→标记验证码；provisioning→active；失败回滚：
    `server.py:2242-2389`。
12. **TLS**：`PROTOCOL_TLS_SERVER` + min TLS1.2 + `OP_NO_COMPRESSION` + ECDHE AESGCM/CHACHA20 套件串（L5）：
    `server.py:3079-3099`。
13. **部署权限**：web `User=signupapp` + UMask 0027 + NoNewPrivileges + CapabilityBoundingSet 空 + ProtectSystem=strict；
    config/TLS key 0640 root:signupapp；DB 目录 0750；tmpfiles 0750；socket 0660：`deploy/`。
14. **日志注入**：结构化日志字段替换空白字符；访问日志仅 method/path（不含 query）：`server.py:204-219, 1254-1285`。

### B. v1.3 §18 邮箱验证码（保持）

15. **邮箱规范化/域名白名单**：strip+lower、≤254、正则、域名精确白名单（缺省回退学校域名），非法/CRLF→400：
    `email_sender.py:50-96`（黑盒覆盖 qq/gmail/子域伪造/CRLF）。
16. **校验顺序**：姓名→密码→email 格式→已注册 409（先于验证码）→验证码 400→enabled/cidr→flock（IP+email UNIQUE）→
    建号成功才 used=1：`server.py:2115-2389`（黑盒按 v1.3 定稿契约断言）。
17. **验证码存储/比较**：6 位 `secrets`；HMAC-SHA256(code_secret, email+":"+code) hex；`hmac.compare_digest`；
    仅最新同用途未用码有效、发新码旧码 used=1；TTL 10min；一次性：`server.py:266-430, 1569-1801`。
18. **F10 原子尝试上限**：原子条件 `UPDATE attempts=attempts+1 WHERE used=0 AND attempts<max` 先占名额，匹配成功归还；
    并发下最多 5 次 HMAC 比较、DB attempts≤5：`server.py:318-430`（回归 `EmailAttemptsConcurrencyTest`）。
19. **发送限流**：per-IP `email_send`（默认 20/h）；60s 冷却/每邮箱每日/全局每日（默认 300）在 `BEGIN IMMEDIATE` 内校验，
    超限 429+Retry-After：`server.py:1569-1801`（黑盒 4 类限流均验证）。
20. **SMTP 凭据/错误**：凭据仅 config→进程内存；异常只保留异常类型；502 固定中文不含主机/端口/账号；
    日志仅 `email_send ... kind=<类型>` 且邮箱掩码：`email_sender.py:154-271, 38-43`，`server.py:1595-1801`。
21. **邮件头注入**：所有头值去 `\r\n\0`；To 只可能是校验后邮箱；正文固定模板；姓名不进邮件；sink 实测：
    `email_sender.py:50-56, 99-123, 206-219`。
22. **mock 与生产隔离**：`debug_code` 仅 mock；mock 发件器写 `<db 目录>/mock-emails.jsonl`（0600）；生产真实 SMTP：
    `server.py:1980-1992, email_sender.py:125-151, 279-285`。
23. **历史数据兼容（schema_version=3）**：v1.2/v1.3 旧库自动迁移、历史 email=null 保留、旧码 purpose 默认 register：
    `server.py:1024-1075`（回归 `MigrationHistoricalDataTest`、`MigrationV13ToV3Test`）。
24. **health/admin 列表**：health 含 email 开关/域名；管理员列表每条 `email`（旧 null）：`server.py:1517-1542, 2478-2557`。
25. **SMTP 失败不消耗额度**：失败删除 email_codes 行，不占冷却/每邮箱/全局额度：`server.py:2031-2044, 1980-2020`（回归）。

### C. v1.3 §19 安全加固（保持）

26. **管理鉴权**：默认只接受 `X-Admin-Token`；`?token=` 默认 403，仅 allow_query_token+127.0.0.1 例外；常量时间；
    访问日志不含 query：`server.py:2392-2476, 1374-1389`。
27. **失败锁定可配置**：`security.admin_lockout.{window_seconds,max_failures,lockout_seconds}`（默认 900/10/900）、
    独立于限流、成功清零、窗口清理、内存 MAX_IPS=10000：`server.py:511-609, 918-940`（黑盒含 2s 自定义自动恢复）。
28. **admin CIDR**：限制 `/admin` 与 `/api/admin/*`，公开接口不受影响：`server.py:1161-1165, 1419-1422`（黑盒）。
29. **并发上限**：超限连接 503+Retry-After；`max_concurrent_connections` 默认 64；连接超时 30s：
    `server.py:76-77, 1268-1300, 2990-3070`（黑盒 8 上限 503+恢复+安全日志）。
30. **方法与静态资源**：GET/POST/HEAD（HEAD 仅静态），其余 405；静态白名单+realpath：`server.py:1322-1462, 2887-2928`。
31. **响应头**：HSTS/COOP/CORP/Permissions-Policy/CSP/nosniff/DENY/no-referrer/no-store/X-Robots-Tag：`server.py:97-121` 等（黑盒）。
32. **邮件防滥用**：per-IP+冷却+每邮箱每日+全局每日四层 429；验证码安全要素见 §18；register 验证码失败不占 IP/email。
33. **部署模板/脚本**：bind=10.0.0.10、max_concurrent_connections=64、allow_query_token=false、admin CIDR、admin_lockout
    900/10/900、SMTP username/password/code_secret 空占位、tls_verify=true、email_send 20/h、password_reset 20/h
    （`DeployConfigTemplateTest`）；install.sh 生成 43 字符 token + 64 hex code_secret；configure-email.py stdin/白名单/
    原子写 0640 root:signupapp/输出无密码；systemd 加固保持。
34. **审计日志**：admin_auth_fail/locked、email_send、email_code_fail、password_reset、register_ok/fail、
    connection_rejected；不含密码/验证码/SMTP 凭据/完整邮箱：`server.py:204-219, 1595-2044, 2478-2890`（黑盒抽查）。

### D. v1.4 §21 忘记密码（新增）

35. **流程/顺序**：`POST /api/password/reset-request`（格式 400→**IP 限流 429（先于已注册，L8 修复）**→已注册 404→enabled 409→发 reset 码）；
    `POST /api/password/reset`（限流→格式→已注册 404→enabled 409→验证码 400→新密码 400→provisioner）与 SPEC §21.1/§21.3
    一致：`server.py:1595-1801`（reset-request 限流顺序见 `server.py:1616-1629`；黑盒按契约断言）。
36. **purpose 用途绑定**：`_find_unused_email_code`/`verify_email_code` 按 `email=? AND purpose=? AND used=0` 过滤；
    注册码不能用于重置、重置码不能用于注册（黑盒跨用途用例均 `EMAIL_CODE_INVALID`）：`server.py:308-430`。
37. **原子尝试上限复用**：reset 验证码同样走 F10 原子名额机制；并发 8 请求实测最多 4 次错误比较、DB attempts≤5：
    `server.py:318-430`（回归 `PasswordResetAttemptsConcurrencyTest`）。
38. **新密码强度**：复用 `security.validate_password(new_password, username)`（含用户名包含/弱密码/重复/字符集）；
    弱新密码 400 `WEAK_PASSWORD` 且**不消耗验证码**：`server.py:1730-1749`（黑盒：弱失败后同码换强密码成功）。
39. **provisioner 调用与锁定**：调用 `reset_password(username,new_password)`（保留锁定态）；成功后查询 `user_status`
    返回 `locked`；不自动解锁（响应 locked=true 且后台仍 locked）：`server.py:1750-1801`；
    production 路径用 fake provisioner 捕获请求，断言密码一致且通过策略（`test_password_reset_prod.py`）。
40. **USER_MISSING 映射**：provisioner 返回 INVALID「用户不存在」→ 409 `USER_MISSING`；失败不消耗验证码
    （fake provisioner 恢复后同码重试成功）：`server.py:1758-1775`（production 路径实测）。
41. **一次性**：仅在重置成功后 `used=1`；失败（错误码/弱密码/provisioner 失败）不消耗；复用码 → `EMAIL_CODE_INVALID`：
    `server.py:1752-1770`（黑盒：成功后复用、失败重试）。
42. **限流**：`rate_limits.password_reset`（默认 3600s/20 次）同时用于 request 与 submit；冷却/每邮箱每日/全局每日按
    email 共享（不区分 purpose，防换用途绕过额度）：`server.py:1595-1801, 997`（黑盒：冷却/每邮箱每日/全局每日/IP 限流）。
43. **日志/响应**：`password_reset` 日志含 mask_email/username/locked/ip/result，无验证码/新密码；响应只含
    `{ok,username,locked}`；测试抽查日志无验证码/新密码/完整邮箱/SMTP 密码：`server.py:1776-1800`。
44. **迁移 v3**：`ALTER TABLE email_codes ADD COLUMN purpose … DEFAULT 'register'`（仅当不存在），
    `idx_email_codes_purpose` 在 ALTER 之后创建；v1.2（无 email/email_codes）与 v1.3（无 purpose）旧库升级均保留数据，
    旧码默认 register、不能用于重置：`server.py:146-163, 1024-1075`（回归 `MigrationHistoricalDataTest`、`MigrationV13ToV3Test`）。

### E. v1.5 §22 绑定邮箱 / 全用户管理 / 禁用删除（新增）

45. **user_emails 模型与迁移**：schema_version=4 新建 `user_emails(username PK, email UNIQUE, source, verified_at, created_at)`；
    启动时从 `registrations.email` 回填 `source='portal'`（INSERT OR IGNORE），旧库（v1.2/v1.3/v1.4）升级保留数据：
    `server.py:176-186, 1265-1290`（回归 `MigrationHistoricalDataTest`/`MigrationV13ToV4Test`/`MigrationV14ToV4Test`）。
46. **邮箱唯一性跨表**：send-code/register/bind 及 register-flock 均同时检查 `registrations.email` 与
    `user_emails.email`；portal 注册成功在 provisioning 事务内写 `user_emails(source='portal')`（失败回滚删除）：
    `server.py:1410-1470, 2800-2920`（回归：portal 同步/已绑定邮箱不能注册/迁移回填唯一性）。
47. **自助绑定流程**：`POST /api/email/bind-request`（username/email 格式 → 邮箱未占用 409 → verify_password 统一
    INVALID_CREDENTIALS → 已绑定 409 → email.enabled → IP/冷却/每日/全局限流 → purpose=bind 发码）；
    `POST /api/email/bind`（同上校验 → purpose=bind 验证码 400 → `BEGIN IMMEDIATE` 内二次检查唯一性 →
    INSERT user_emails(source='self') + 同步 registrations.email(空) + used=1 → 200）：
    `server.py:2072-2265`（`test_bind_email.py` 20 项，production + fake provisioner + SMTP sink）。
48. **验证码用途隔离/一次性/原子上限**：bind 验证码 purpose='bind'，register/reset 码互不可用；
    一次性（成功后 used=1；失败不消耗）；5 次尝试上限原子（并发 8 实测 ≤4 次错误比较、DB attempts≤5）：
    `server.py:302-430, 2120-2265`（回归 bind/register/reset 三套并发/跨用途用例）。
49. **绑定后忘记密码**：`lookup_account_by_email` 同时查 registrations.email 与 user_emails.email；
    reset-request/reset 对绑定邮箱的现有用户可自助重置；不可管理/系统缺失 → 409 `USER_NOT_MANAGEABLE`；
    成功后 crypt 校验由 provisioner 执行、失败不消耗验证码：`server.py:1424-1460, 1881-1920, 1902+`
    （production 路径实测 fake provisioner 收到 reset_password 且新密码通过策略）。
50. **管理后台全用户列表**：`GET /api/admin/users` 合并 provisioner `list_users` 与 portal 记录（username 去重、portal 优先），
    字段 `username/real_name/email/uid/gid/home/source/ip/registration_id/privileged/os_status/locked`，stats
    `total/active/locked/missing/with_email/portal/imported`；provisioner 不可用时降级仅 portal、os_status unknown、仍 200：
    `server.py:2985-3116`（production 实测含降级/特权标注）。
51. **管理操作按 username**：`reset-password`/`set-locked`/`bind-email` 以 username 定位，经 `_account_manageability`
    检查（保护名单/uid/特权组/系统缺失）；特权账号 403 USER_NOT_MANAGEABLE、不存在 409 USER_MISSING、
    非法用户名 400；reset-password 一次性密码仅响应体、不落库/日志；admin bind-email 写 source='admin' 并同步空 email：
    `server.py:1881-1900, 3174-3330`（production 回归含特权/保护账号 403、一次性密码不落日志）。
52. **reset-ip 仅 portal**：按 registration id 删除 registrations 行；imported 用户 registration_id=None 且无 IP；
    不触碰系统用户/绑定邮箱：`server.py:3117-3172`（production 实测 portal 200 / 随机 id 404）。
53. **旧接口移除**：`GET /api/admin/registrations` 已移除（404/405），前端改用 `/api/admin/users`：
    `server.py` 路由表；`test_api_mock`/`test_bind_email` 均断言。
54. **删除用户彻底禁用（双重）**：web 路由 `/api/admin/delete-user` 已移除（404/405）；provisioner `dispatch` 对所有
    `op=="delete_user"` 直接返回 INVALID「删除用户功能已禁用」且不进入任何子进程（不调 userdel）；前端删除按钮/弹窗/
    调用全部移除；调用前后用户/家目录/DB 不受影响：`provisioner.py:653-670`、`server.py` 路由表、
    `test_regression_prod_paths.py::DeleteUserDisabledRegressionTest`（mock run_command 断言 0 次调用）、
    `test_bind_email.py::test_05`、前端静态契约 `test_api_mock::test_static_v15_contract`。
55. **安全/审计**：bind/reset/admin 日志只有 username/mask_email/result/purpose/attempts，无密码/验证码/完整邮箱；
    `verify_password` 日志仅 username/manageable/matched 布尔；密码不落 DB/响应；统一 INVALID_CREDENTIALS 提示
    已用 production 用例逐字比对：`server.py:2072-2265, 2985-3330`、`provisioner.py:543-600`
    （`test_bind_email` 日志/响应断言）。
56. **前端**：申请页三入口（申请账号/绑定已有账号邮箱/忘记密码）；管理页改用 users 接口、绑定邮箱操作、
    无删除入口、无旧 registrations/delete-user 调用（静态契约测试断言）：`static/` 只读检查。

---

## 二、发现问题与修复状态

### 状态总表

| 编号 | 级别 | 问题 | 状态 |
|---|---|---|---|
| F1 | 中 | delete-user 系统用户缺失时 `int(None)` → 500 | ✅ 已修复（v1.5 起删除路由已移除，F1 场景失效） |
| F2 | 中 | provisioner 连接异常可能使 root 助手退出 | ✅ 已修复+回归 |
| F3 | 低 | HTTP 并发无上限/慢连接 | ✅ v1.3 已实现并发上限+30s 超时；保留可选优化 |
| F4 | 低 | 限流器 key 无界增长 | ✅ 已修复+回归 |
| F5 | 低 | 公告控制字符只拦 Cc 未拦 Cf | ✅ 已修复+回归 |
| F6 | 低 | delete_user 后家目录残留仍返回成功 | ✅ **失效**（v1.5 删除功能已彻底禁用） |
| F7 | 低 | 未预期异常 traceback 进 journald | 保留建议 |
| F8 | 低 | production 未校验 admin_token 非空 | 保留建议 |
| F9 | 提示 | trusted_proxies 启用后 XFF 伪造面 | 保留提示（当前未启用） |
| F10 | 中 | 并发绕过验证码 5 次尝试上限 | ✅ 已修复+回归 |
| L1 | 低 | admin_lockout 模板字段未实现读取 | ✅ 已修复+回归 |
| L2 | 低 | AdminAuthGuard 内存可被失败 IP 增长 | ✅ 已修复（MAX_IPS=10000） |
| L3 | 低 | send-code SMTP 失败消耗冷却/额度 | ✅ 已修复+回归 |
| L4 | 低 | email.enabled=false 时 register 未拦截 | ✅ 已修复+回归 |
| L5 | 低 | TLS 套件串 Ubuntu OpenSSL3 未实测 | 无法验证（本机 LibreSSL 通过） |
| L6 | 提示 | 同出口 IP 可锁管理员 15 分钟 | 按 SPEC 设计接受，README 提示 |
| L7 | 低 | send-code per-IP 限流在校验前消耗配额 | 保留建议 |
| **R1** | **中** | **v1.3→v3 迁移崩溃（`no such column: purpose`）** | ✅ **实现期发现并已修复+回归** |
| **L8** | **低** | reset-request 未注册邮箱 404 先于 IP 限流（枚举探测不受限） | ✅ **已修复+回归**（限流前移至已注册检查之前） |
| **F11** | **中** | bind-request/bind 在 verify_password 前无限速 → 密码爆破 oracle + provisioner crypt DoS | ✅ **已修复+回归**（rate_limits.bind 前置 + username/IP 失败锁定） |
| L9 | 低 | bind 前置校验失败日志 ip="-"（未记来源 IP） | ✅ 已修复（日志带客户端 IP） |
| L10 | 低 | provisioner `op_delete_user` 死代码仍保留（dispatch 已硬拒绝） | ✅ 已删除死代码 |
| L11 | 低 | bind 的「邮箱已被占用」先于密码校验返回 409（信息级别与 send-code 一致、已限流） | 按 SPEC 接受（残余） |
| L12 | 低 | 锁定账号可发起 bind（spec 未禁止；绑定/重置后仍 locked） | 待 Lead 决定 |

### F11【中 · 已修复 · 已验证】bind 密码校验前无限速：在线密码爆破 oracle + provisioner crypt DoS

- 【发现时位置】`_bind_precheck` 在 `verify_password` 之后才由 handler 做 IP 限流（旧 `server.py:1954-2054`）。
- 【复现（修复前）】同 IP 连续 10 次 bind-request（真实用户名+错误密码）全部 400、无 429，fake provisioner 收到 10 次
  `verify_password`；错误密码不消耗任何额度，正确密码才触发限流 → 可无限速爆破 + root provisioner crypt DoS。
- 【修复（v1.5 最终版）】
  - 新增 `rate_limits.bind`（默认 3600s/10 次），bind-request 与 bind **共用**，在 `_bind_precheck` 中
    **先于 verify_password** 检查（`server.py:83-86, 2072-2176`；额度检查在 2106-2112）；
  - 新增 `security.bind_lockout` + `BindAuthGuard`：同 username+IP 密码失败 ≥5 次 → 锁 15 分钟（窗口/阈值/时长可配置），
    锁定检查在 verify 之前、失败在 verify 后累计、成功清零；锁定期返回 429 `RATE_LIMITED` + Retry-After，
    提示与 400 统一 `BIND_LOCKED_MESSAGE`（`server.py:640-690, 2114-2160`）；
  - `_bind_precheck` 失败日志补客户端 IP（L9 修复）；provisioner 删除 `op_delete_user` 死代码，dispatch 仍硬拒绝
    delete_user（L10；`provisioner.py:653-670`）。
- 【回归验证】`test_bind_email.BindCredentialRateLimitTest`（3 项）：额度内错误密码 400 INVALID_CREDENTIALS 且
  消耗额度（verify 调用次数=3）；额度耗尽后正确密码也 429 且不再调 verify；非学校邮箱 400 不消耗额度；
  bind 提交与 bind-request 共享额度。`BindFailureLockTest`：4×400 + 第 5 次 429 锁定、锁定期正确密码 429
  且 verify 调用有界、换 IP 不受 username+IP 锁定影响。
- 【修复后复测】同 IP 错误密码达限额/锁定额度后 429（统一错误），`verify_password` 调用次数 ≤ 限额；全量 170 tests OK。

### R1【已修复 · 已验证】v1.3 旧库升级到 schema_version=3 崩溃

- 发现：QA 新增 `MigrationV13ToV3Test`（模拟 v1.3 DB：有 email、email_codes 无 purpose）启动即退出：
  `sqlite3.OperationalError: no such column: purpose`。
- 原因：`EMAIL_SCHEMA_SQL` 内的 `CREATE INDEX ... ON email_codes(purpose, email)` 在旧表 ALTER 加列之前执行，
  `CREATE TABLE IF NOT EXISTS` 不会修改已存在的旧表。
- **修复（当前版本）**：`EMAIL_SCHEMA_SQL` 不再包含 purpose 索引；`_init_db` 先 `ALTER TABLE … ADD COLUMN purpose
  DEFAULT 'register'`，再 `CREATE INDEX idx_email_codes_purpose`：`server.py:146-163, 1040-1058`。
- **验证**：`MigrationV13ToV3Test`（旧数据保留、purpose 默认 register、旧 register 码不能用于重置、新 reset 码可用）
  与 `MigrationHistoricalDataTest`（v1.2→v3）均通过。

### F10【已修复 · 已验证】并发绕过验证码尝试上限（v1.3 发现）

- 修复：原子条件 UPDATE 占用尝试名额，rowcount≠1 → TOO_MANY；匹配成功归还名额：`server.py:318-430`。
- 回归：`EmailAttemptsConcurrencyTest`（注册码）、`PasswordResetAttemptsConcurrencyTest`（重置码）——8 并发下
  成功比较 ≤4 次、DB attempts ≤5，正确码在超限后也被拒绝。

### F1/F2/F4/F5【已修复 · 已验证】（v1.2 结论保持，代码未回退）

- F1：`SocketProvisioner.delete_user(None)` 防御 + handler `os_user_existed=false` 分支 200+删行：
  `server.py:621-717, 2759-2844`；回归 `F1DeleteUserMissingSystemUserRegressionTest`。
- F2：provisioner `_send`/`handle_connection`/`serve_forever` 异常兜底：`provisioner.py:693-795`；回归 `F2…`。
- F4：`RateLimiter.MAX_KEYS=10000`+淘汰：`server.py:464-509`；回归 `F4…`。
- F5：`_contains_control_chars` 拒绝 Cc+Cf：`server.py:266-278`；黑盒公告 Cf 用例。

### 保留建议（低风险/非阻塞）

- **F6** 家目录残留：`provisioner.py:550-582`；建议 userdel 后校验/清理 `/home/<u>`。
- **F7** traceback 进 journald：`server.py:1359-1380`；建议默认只记异常类型。
- **F8** production admin_token 未 fail-fast：`server.py:435-463, 2392-2476`；建议长度≥32 否则启动失败。
- **F9** trusted_proxies 启用后 XFF 伪造面：`server.py:1131-1152`；当前部署未启用。
- **F3** 可选优化：固定线程池/连接速率限制（现已 503+超时缓解）。
- **L5** TLS 套件串在 Ubuntu OpenSSL3 未实测；若回退会记 `tls_ciphers_fallback`，建议 star1 启动日志确认。
- **L6** 管理员锁定 DoS（校园 NAT 共享 IP）：README 提示运维处置。
- **L7** send-code per-IP 限流先于 body 校验消耗配额（低）。
- **L8【已修复 · 已验证】**（v1.4 新发现）`reset-request` 原先对未注册邮箱返回 404 时尚未经过 `password_reset` IP 限流，
  可无限速探测邮箱是否已注册；SPEC §21.1/§21.3 已修订为「格式校验后先做 IP 限流，再做已注册检查」，backend 已实现：
  `server.py:1616-1629`；回归 `PasswordResetEnumerationRateLimitTest`（3 项：同一 IP 连续探测多个未注册邮箱超限 → 429；
  已注册邮箱超限同样先 429；其他 IP 不受影响）——通过。

---

## 三、本机无法验证项与线上验证结论

> 本地 macOS 环境无法覆盖的项，已由 Lead 在 star1 线上聚焦验收覆盖（`deploy/verify-v14.py` **77/77 PASS**；
> `deploy/verify-v15.py` **60/60 PASS**，第 6 节）；QA 按 SPEC 约束未直接访问服务器，以下「已线上验证」结论来源 Lead 的 E2E 结果。

### 3.1 已由 star1 线上聚焦验收覆盖（真实环境 PASS）

1. **真实 provisioner**：useradd/chpasswd/usermod/userdel 实际行为；新账号 UID≥1000、家目录 0750、`passwd -S` 状态 P、
   密码 `crypt` 哈希与提交值匹配、`su -` 可登录、无 sudo/特权组。
2. **忘记密码真实链路**：真实学校邮箱 reset-request → IMAP 取重置码 → 自助重置 200 → 新密码 crypt 匹配；
   一次性/跨用途隔离/弱密码不消耗/未注册 404 均实测。
3. **锁定账号**：重置成功但 `locked=true` 且系统仍为 L；管理员解锁后 P 且 `su` 可用新密码登录（不自动解锁）。
4. **系统用户缺失**：reset-password 409 USER_MISSING；自助重置 v1.5 统一 409 USER_NOT_MANAGEABLE（§22.4）。
   delete-user 在 v1.4 曾 200（F1 线上复验），**v1.5 已禁用：线上 POST → 404 且临时用户/家目录仍存在**。
5. **管理员能力**：列表 email/os_status、重名预览 exampleuser2、reset-ip 后重新申请、重名自动后缀 exampleuser2。
6. **安全项线上实测**：管理员失败锁定、日志无明文密码/SMTP 密码/完整邮箱、URL token 禁用、
   HSTS/COOP/CORP/Permissions-Policy/X-Robots 响应头、TLS、bind 仅 10.0.0.10（127.0.0.1/0.0.0.0 不监听）。
7. **真实邮件**：Coremail `mails.example.edu.cn:465` SSL + IMAP 取注册/重置验证码均可用。
8. **数据保护/清理**：2 条历史真实注册保留且未改动（email=null，schema v3 迁移成功）；测试数据全部清理
   （DB 仍为 exampleuser/exampleuserB，无验收测试账号）。
9. **Python 3.12 兼容**：star1 上以 Python 3.12 实际运行通过。
10. **页面/公告**：含邮箱验证篇、SSH 密钥篇、忘记密码入口、双管理员联系方式，页面可访问。

以下为 **v1.5 新增线上覆盖**（`verify-v15.py`，60/60 PASS）：
11. **已有用户自动纳入管理**：`/api/admin/users` 返回 ≥25 个系统普通用户 + 2 条 portal，字段/stats/privileged 正确；
    旧 `/api/admin/registrations` → 404、无 token → 403。
12. **真实自助绑定**：临时已有系统用户 bind-request → SMTP 发码 → IMAP 取 bind 码 → bind 200 → `user_emails(source=self)`；
    错误密码统一 400 INVALID_CREDENTIALS、非学校 400、重复绑定/已绑定邮箱注册 409；绑定后忘记密码真实邮件重置 200 →
    crypt 哈希匹配 + `su` 登录成功。
13. **F11 线上实测**：同 IP 连续错误密码触发 429、锁定期内正确密码仍 429、非学校邮箱先 400 且不消耗 bind 额度。
14. **管理员新接口**：reset-password（哈希匹配）/set-locked L /unlock P /bind-email(source=admin) 按 username 成功；
    特权 admin → 403 USER_NOT_MANAGEABLE；不存在 → 409 USER_MISSING。
15. **删除禁用**：`POST /api/admin/delete-user` → 404，临时用户与家目录仍存在。
16. **迁移/清理/日志**：schema v4 迁移成功、2 条历史注册保留未改动、测试数据清理后管理列表无临时用户；
    日志无测试密码/SMTP 密码/验证码/完整邮箱。

### 3.2 仍属残余/未单列（低风险）

1. **TLS 套件细节（L5）**：线上 TLS 可用，但未单列验证 OpenSSL3 下是否触发 `tls_ciphers_fallback` warning，
   建议运维在 star1 启动日志确认无该 warning。
2. **浏览器级 XSS/CSP DOM 渲染**：线上验证为 HTTP/服务端层面，未做真实浏览器 DOM 注入测试
   （服务端纯文本 + 前端全 textContent + CSP 已代码审查/静态检查）。
3. **默认 900s 管理员锁定窗口真实等待**：线上覆盖了失败锁定行为，本机用可配置 2s 窗口验证了
   「阈值/窗口过期/自动恢复」逻辑；默认 900s 的完整等待未实测（逻辑同一路径）。
4. **跨进程 flock 长时并发压测**：线上为功能级验证，未做极端并发压测（本地单进程并发 + UNIQUE 兜底验证）。
5. **journald 采集格式**：线上抽查了日志内容脱敏（无密码/验证码/完整邮箱），未验证具体 journald 字段采集配置。
6. **绑定表单浏览器级交互**：线上为 HTTP/API 级验证 + 本地静态/CSP 检查，未做真实浏览器 DOM/无障碍自动化测试。
7. **bind 低风险残余（L11/L12）**：邮箱已占用先于密码校验返回 409（信息级别同 send-code、已限流，SPEC 接受）；
   锁定账号仍可发起 bind（SPEC 未禁止）——均记录为残余，非实现缺陷。

## 四、Mock 与生产路径差异（测试盲区说明）

- mock：内置 MockProvisioner（不执行 useradd）+ MockEmailSender（写 `mock-emails.jsonl`，返回 `debug_code`，仅 mock 允许明文）+
  mock 数据库；`X-Test-Client-IP` 仅 mock 可用于模拟来源 IP。
- **SMTP sink（`test_email_smtp.py`）**：production 模式 + tls.enabled=false + `smtp.security="none"` + 本地 127.0.0.1，
  真实 smtplib/真实 SMTP 会话，但**未覆盖生产 `security="ssl"`+TLS 证书校验路径**。
- **fake provisioner（`test_password_reset_prod.py`）**：production 模式 + 本地 SMTP sink + 自建 Unix socket provisioner，
  验证真实 `SocketProvisioner` JSON 协议与 reset_password 请求内容；不执行真实系统命令。
- 真实 SMTP/IMAP、真实 provisioner、systemd 权限/绑定地址、crypt/su 由 Lead 在 star1 E2E 验收。

---

## 五、测试执行记录（本报告的安全结论证据）

最终版命令：`./tests/run_all.sh`（= `python3 -m unittest discover -s tests -v`，PYTHONDONTWRITEBYTECODE=1；
每次运行注入 `QA_RUN_TAG` 隔离临时目录/进程，支持并发跑测试互不干扰）。

- **结果：Ran 170 tests in ~60s — OK**（0 failure / 0 error / 0 skip；<120s）
  - `tests/test_pinyin.py`：14
  - `tests/test_security.py`：19
  - `tests/test_api_mock.py`：82（v1.2–v1.4 全量 + v1.5 users/按 username 管理/删除禁用/v4 迁移/user_emails 跨表）
  - `tests/test_bind_email.py`：20（production + fake provisioner + SMTP sink：绑定全流程/统一凭据错误/purpose 隔离/并发上限/限流/admin users 降级/特权 403/删除禁用/日志脱敏 + **F11 回归 4 项**）
  - `tests/test_email_smtp.py`：5（真实 smtplib 投递/头注入/SMTP 失败/失败不消耗额度/日志脱敏）
  - `tests/test_security_hardening.py`：22（§19 + 部署模板契约 + §21 password_reset 配置）
  - `tests/test_regression_prod_paths.py`：6（delete_user dispatch 禁用 ×2（含不调子进程）、F2×3、F4×1）
  - `tests/test_password_reset_prod.py`：2（production 路径 fake provisioner：reset_password 收到新密码且通过策略/失败不耗码）
- 覆盖 SPEC §17 + §18.8 + §19.7 + §21.6 验收清单（对照见下节）；
- **star1 线上聚焦验收（Lead）**：`deploy/verify-v14.py` → **77/77 PASS**（部署 hash 与本地一致，详见第 6 节）；
- 测试结束无残留子进程/临时目录（`run_all.sh` 含按 tag pkill 兜底 + tearDownClass 清理，PYTHONDONTWRITEBYTECODE）。
- 结论对应 v1.5 最终版 app：`server.py` md5 `01d4526668632bb7e8752aec14989b84`、
  `email_sender.py` md5 `fd85fe4aaed998ef88927585ca3af230`、`provisioner.py` md5 `e3e5ed0c…`；
  170 tests 全绿即最终绿；Lead 部署后请核对 hash 一致（`deploy/verify-v15.py` 已就绪）。

---

## 六、star1 线上聚焦验收结论（Lead 执行，v1.4 + v1.5）

> 两次验收均由 Lead 执行；QA 按 SPEC 权限约束未直接访问 star1，结论来自 Lead 的 E2E 结果与部署 hash 核对。

### 6.1 v1.5（最终版）：60/60 PASS ✅

- 时间：2026-10-26；对象：star1 部署的 v1.5 最终版 app，**部署 hash 与本地最终版一致**
  （`server.py 01d45266…`、`provisioner.py e3e5ed0c…`、`email_sender.py fd85fe4a…`）；
  脚本：`deploy/verify-v15.py`；结果：**60/60 PASS ✅**。
- 覆盖 7 类（均 PASS）：
  1) `/api/admin/users` 纳入 ≥25 个系统普通用户 + 2 条 portal，字段/stats/privileged 正确；旧 registrations 404、无 token 403；
  2) 临时已有用户自助绑定真实学校邮箱（SMTP 发码 → IMAP → bind 200 → `user_emails source=self`）；错误密码
     INVALID_CREDENTIALS、非学校 400、重复绑定 409、已绑定邮箱注册 409；
  3) 绑定后忘记密码真实邮件重置 200 → crypt 哈希匹配 + `su` 登录；
  4) F11：同 IP 连续错误密码触发 429、锁定期正确密码 429、非学校邮箱先 400 不耗额度；
  5) 管理员按 username：reset-password（哈希匹配）/锁定 L/解锁 P/bind-email source=admin；特权 admin → 403
     USER_NOT_MANAGEABLE；不存在 → 409 USER_MISSING；
  6) 删除禁用：`POST /api/admin/delete-user` → 404，临时用户与家目录仍存在；
  7) 日志无测试密码/SMTP 密码/验证码/完整邮箱；清理后历史记录未改动、管理列表无临时用户；schema v4 迁移成功、
     2 条历史注册保留。
- 与本地审查结论一致：未发现新的高危/中危问题；残余低风险项见 3.2。**v1.5 验收通过 → task-11 完成。**

### 6.2 v1.4（历史）：77/77 PASS ✅

- 对象：star1 部署的 v1.4 最终版 app（部署 hash 与本地 v1.4 一致）；脚本 `deploy/verify-v14.py`；结果 **77/77 PASS**。
- 覆盖 5 类（均 PASS）：
  1) 页面/公告/TLS/安全响应头/仅 bind 10.0.0.10/URL token 禁用；
  2) 真实学校邮箱注册（send-code → IMAP 取码 → 201）、系统账号/UID≥1000/家目录 750/P 状态/crypt 匹配/su 登录/无 sudo，
     同 IP 二次 409、已占用 IP 409；
  3) 忘记密码真实链路（reset-request → IMAP 取重置码 → 200 → 新密码 crypt 匹配；一次性/跨用途/弱密码不消耗/404），
     锁定账号重置 locked=true 且仍 L，管理员解锁后 P + su 可登录；
  4) 管理员：列表 email/os_status、重名预览 exampleuser2、reset-ip 后重新申请、重名后缀 exampleuser2、
     系统用户缺失时 reset-password/自助重置 409（v1.4 为 USER_MISSING；v1.5 自助侧统一为 USER_NOT_MANAGEABLE）、
     delete-user 200（F1；v1.5 已禁用 → 404）；
  5) 管理员失败锁定、日志无明文密码/SMTP 密码/完整邮箱、2 条历史真实注册保留未改动、测试数据全部清理。
- 线上验证覆盖了本机无法验证的真实 provisioner/TLS/SMTP+IMAP/systemd 权限/绑定地址/crypt+su 等；
  QA 未直接访问 star1（按 SPEC 权限约束），该结论来自 Lead 的 E2E 结果。

---

## 七、附录：验收清单对照（QA 覆盖）

| 验收项 | 测试/证据 |
|---|---|
| §18.8 全部条目（域名/冷却/日限/IP/一次性/错误/过期/5 次/同邮箱/ HMAC 无明文/真实邮件/sink 头注入/历史 null/后台 email） | `EmailSendCodeTest`、`EmailRegisterFlowTest`、`EmailUniquenessRegisterTest`、`EmailTtlTest`、`EmailPerEmailDailyTest`、`EmailGlobalDailyTest`、`EmailIpRateLimitTest`、`EmailAttemptsConcurrencyTest`、`SmtpDeliveryTest`、`LogHygieneTest`、`MigrationHistoricalDataTest`、`ApiContractTest.test_admin_list` |
| §19.7 query token/ADMIN_LOCKED 与恢复/admin CIDR/并发 503/安全头/邮件限流/日志脱敏/部署模板 | `AdminQueryTokenHardeningTest`、`AdminQueryTokenOptInTest`、`AdminLockoutTest`、`AdminLockoutConfigTest`、`AdminLockoutWindowTest`、`AdminCidrTest`、`ConcurrencyLimitTest`、`HardeningHeadersTest`、`EmailGlobalDailyTest`、`EmailPerEmailDailyTest`、`EmailIpRateLimitTest`、`LogHygieneTest`、`DeployConfigTemplateTest` |
| §21.6 reset-request 404/400/200/冷却/IP 限流/停用 | `PasswordResetRequestTest`、`PasswordResetIpRateLimitTest`、`EmailDisabledTest.test_reset_request_disabled` |
| §21.6 正确码重置成功（provisioner 收到 reset_password 且新密码通过策略） | `PasswordResetFlowTest.test_success_*`、`test_password_reset_prod.PasswordResetProductionPathTest.test_01_*` |
| §21.6 跨用途不可用（注册码↔重置码） | `PasswordResetFlowTest.test_cross_purpose_binding` |
| §21.6 错误/过期/一次性/5 次（含并发原子） | `PasswordResetFlowTest.test_wrong_code_* / test_too_many_attempts`、`PasswordResetTtlTest`、`PasswordResetAttemptsConcurrencyTest` |
| §21.6 弱新密码 400 / email.enabled=false 409 / USER_MISSING / 锁定不自动解锁 | `PasswordResetFlowTest.test_weak_* / test_user_missing_mapping / test_locked_account_not_auto_unlocked`、`EmailDisabledTest.test_reset_request_disabled` |
| §21.6 日志/响应无验证码与新密码；历史数据不受影响 | `PasswordResetFlowTest.test_success_locked_false_and_logs`、`test_password_reset_prod.test_01_*`、`MigrationV13ToV3Test`、`MigrationHistoricalDataTest` |
| L8：reset-request 枚举限流先于已注册检查 | `PasswordResetEnumerationRateLimitTest` |
| §22.7 绑定：错误密码 400 INVALID_CREDENTIALS / 非学校 400 / 邮箱占用 409 / 成功 200 + user_emails(portal 同步) | `test_bind_email.BindEmailFlowTest`（production + fake provisioner）、`test_api_mock.test_user_emails_sync_and_cross_table_uniqueness` |
| §22.7 已绑定重复绑定 409；一邮箱不能注册第二个账号 | `BindEmailFlowTest.test_email_already_bound_*`、`test_user_emails_sync_*`、迁移 §22 用例 |
| §22.7 绑定后忘记密码可重置 | `BindEmailFlowTest.test_bind_success_and_forgot_password`（真实 reset_password 捕获 + 新密码策略） |
| §22.7 管理列表含全部 uid≥1000 用户/字段/stats/特权标注/降级 | `test_bind_email.AdminUsersV15Test`（production），`test_api_mock.test_admin_users` |
| §22.7 管理员按 username 重置/锁定/绑定邮箱；特权 403 | `AdminUsersV15Test.test_03/04/07`、`test_api_mock.test_admin_*` |
| §22.7 删除禁用：路由 404/405、provisioner INVALID 不调 userdel、数据/家目录不受影响、前端无入口 | `test_api_mock.test_admin_delete_user_disabled`、`test_regression_prod_paths.DeleteUserDisabledRegressionTest`、`test_api_mock.test_static_v15_contract` |
| §22.7 v4 迁移回填/v1.2–v1.4 旧库升级 | `MigrationHistoricalDataTest`、`MigrationV13ToV4Test`、`MigrationV14ToV4Test` |
| §22.7 F11：bind 限流先于 verify_password、错误密码消耗额度、5 次失败锁定、verify 调用有界 | `test_bind_email.BindCredentialRateLimitTest`、`BindFailureLockTest` |
| §22.7 日志无密码/验证码、邮箱掩码 | `test_bind_email.*_never_logged`、`LogHygieneTest` |
| 部署模板 bind/CIDR/query token/lockout/email/reset 限流占位安全 | `DeployConfigTemplateTest` |
