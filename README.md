# SharkSSO — 统一认证体系（RADIUS + 802.1X + LDAP + 钉钉同步）

围绕统一账号的认证基础设施：**钉钉通讯录 → OpenLDAP（账号库）→ FreeRADIUS（认证判决 + 动态 VLAN）→ 华为 AC/AP（WiFi 802.1X）**，配套 Web 管理面板与访客 Portal 服务器。

> ⚠️ 本仓库所有密码 / 密钥 / 凭据均已替换为 `CHANGE_ME_*` 占位符或 `*Example1` 示例值，部署时必须全部改掉。
> ⚠️ 面板挂载 docker.sock，**不可暴露公网**。

## 架构与搭建顺序

```
【账号侧】                          【认证侧】
钉钉通讯录（唯一权威来源）           终端
   │ 第 3 步：同步                  │ 802.1X / Portal / MAC
   ▼                               ▼
第 1 步 OpenLDAP（账号库） ──▶ 第 4 步 FreeRADIUS（判决+VLAN）◀── 第 8 步 AC/交换机
   ▲ 每日自动同步                    ▲ UDP 1812，每台 NAS 一把独立密钥
第 6 步 Web 面板（8082，管理上面所有）   第 9 步 Portal（访客，可选）
```

**依赖关系决定了顺序**：账号库（LDAP）→ 同步（钉钉→LDAP）→ 认证判决（RADIUS）→ 管理入口（面板）→ 接入设备（AC）→ 访客（Portal，可选）。前一步不通，后面不用装。

## 第 0 步：部署前准备 —— 先填一张密码规划表

把 10 个值先定下来，后面每一步的 `CHANGE_ME_*` 都从这里取：

| # | 用途 | 占位符位置 | 示例格式 |
|---|---|---|---|
| 1 | LDAP admin 密码 | `ldap/docker-compose.yml` ×2、`radius/raddb/ldap-mod.conf` | 16 位随机 |
| 2 | MySQL root 密码 | `ldap/docker-compose.yml`、`ldap/scripts/reset-admin-pw.py` | 16 位随机 |
| 3 | go-ldap-admin 管理端密码 | `ldap/scripts/reset-admin-pw.py` | 16 位随机 |
| 4 | 面板登录密码 | `radius-web/docker-compose.yml` | 16 位随机 |
| 5 | Flask SECRET_KEY | `radius-web/docker-compose.yml` | 长随机串 |
| 6 | 钉钉 AppKey / AppSecret | `portal/config.yaml`（仅 Portal 需要） | 钉钉开放平台获取 |
| 7 | 每台 NAS 的独立密钥 | 面板「密钥管理」自动生成 | 24 位随机 |
| 8 | Portal 协议 / 管理密钥 | `portal/config.yaml` | 16 位随机 ×2 |
| 9 | CoA 密钥 | `portal/config.yaml`（= AC 侧 authorization 密钥） | 16 位随机 |
| 10 | 测试账号密码 | `radius/raddb/users` | 自定 |

---

## 第 1 步：装账号库（OpenLDAP + go-ldap-admin + MySQL）

**目的**：先有账号库，后面所有认证都从这里查人。

```bash
# 1.1 服务器装好 Docker（已有可跳过）
curl -fsSL https://get.docker.com | sh && docker compose version

# 1.2 建目录、把本仓库 ldap/ 目录上传到服务器 /opt/SharkSSO/ldap
mkdir -p /opt/SharkSSO/ldap && cd /opt/SharkSSO/ldap

# 1.3 改密码：编辑 docker-compose.yml，把 CHANGE_ME_LDAP_ADMIN_PW（2 处）、
#     CHANGE_ME_MYSQL_ROOT_PW 换成第 0 步定的值

# 1.4 启动
docker compose up -d
```

**验证**（三个容器都 Up 才算过）：
```bash
docker ps --format '{{.Names}} {{.Status}}' | grep sharksso
# 预期：sharksso-ldap / sharksso-ldap-mysql / sharksso-ldap-admin 均 Up
```

**LDAP 数据结构**（后面写过滤器的依据）：
- `ou=people`：扁平存人，`uid=姓名拼音`，密码 SSHA 哈希，mail 必须纯 ASCII
- `ou=dingtalkroot`：部门组 `groupOfUniqueNames` + `uniqueMember`，嵌套树，同名部门不同上级各存一份（DN 拼音、中文名在 description）
- `ou=disabled`：离职区

## 第 2 步：初始化 go-ldap-admin 管理端

**目的**：拿到网页管理端（8889），后面钉钉凭据从这里配。

```bash
# 2.1 改默认密码：reset-admin-pw.py 里的 CHANGE_ME_LDAPADMIN_UI_PW、
#     CHANGE_ME_MYSQL_ROOT_PW 替换后执行
docker exec sharksso-ldap python3 scripts/reset-admin-pw.py
```

**验证**：浏览器开 `http://<服务器IP>:8889`，用新密码登录成功。

## 第 3 步：配置钉钉同步

**目的**：让钉钉通讯录自动灌进 LDAP，人事变动不用手工维护。

1. 钉钉开放平台创建企业内部应用，拿到 **AppKey / AppSecret**，开通通讯录只读权限
2. go-ldap-admin 管理端 → 钉钉配置页，填入 AppKey/AppSecret，启用同步（enable-sync=true）
3. 部署离职守卫：服务器 crontab 加 `0 4 * * * docker exec sharksso-ldap python3 scripts/dingtalk-leave-guard.py --apply`（手机号+邮箱双维度判定，移入 ou=disabled）

**验证**：
```bash
docker exec sharksso-ldap python3 scripts/verify-sync.py
# 预期：人数、部门组数量与钉钉一致；手动触发可用 scripts/dingtalk-sync.py
```

已知坑：姓名/邮箱含全角括号等非 ASCII 字符 → 同步 `invalid per syntax` 停摆（补 ASCII 邮箱解决）；同步失败不回滚 DB 会卡死循环。

## 第 4 步：装 FreeRADIUS（先本地，后接 LDAP）

**目的**：认证判决引擎先跑起来，用本地测试账号打通，再接 LDAP。

```bash
# 4.1 把本仓库 radius/ 上传到 /opt/SharkSSO/radius，raddb 下
#     clients.conf.example → clients.conf、users.example → users（改测试账号密码）

# 4.2 启动
cd /opt/SharkSSO/radius && docker compose up -d
ss -ulnp | grep 1812     # 预期 0.0.0.0:1812

# 4.3 本机自测（localhost/testing123 是镜像自带自测条目，先验证服务活着）
docker compose exec radius radtest testuser '你的测试账号密码' 127.0.0.1 0 testing123
# 预期：Received Access-Accept
```

**此时先不要接 LDAP**——等面板装完、配置可视化后再接（第 6 步）。

## 第 5 步：装 Web 管理面板

**目的**：之后所有配置（账号/密钥/动态 VLAN）都在网页上做，不再手工编辑文件。

```bash
# 把本仓库 radius-web/ 上传到 /opt/SharkSSO/radius/web
# docker-compose.yml 里改 CHANGE_ME_PANEL_ADMIN_PW 和 SECRET_KEY
cd /opt/SharkSSO/radius/web && docker compose up -d --build
curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8082/login   # 预期 200
```

页面清单：总览 / 账号管理 / 密钥管理 / LDAP 对接 / 动态 VLAN / 认证测试 / 日志 / 配置文件 / 密码 / 对接指南。

## 第 6 步：RADIUS 接通 LDAP + 动态 VLAN 规则

**目的**：让员工 LDAP 账号能认证，并按部门下发 VLAN。

1. 面板「LDAP 对接」页：地址 `ldap://127.0.0.1:389`，bind 密码 = 第 1 步的 LDAP admin 密码，用页面上的连通性测试（TCP→bind→base_dn→拉组）通过后**一键启用**（失败自动回滚）
2. 面板「动态 VLAN」页：从 LDAP 读部门列表，逐行填 VLAN 号（**号必须是 AC/交换机上真实存在的**，RADIUS 只发数字不建 VLAN），保存自动生成 unlang 并重启

关键参数（已写进 `radius/raddb/` 里的配置，踩坑备注）：
- `base_dn` 写全（如 `dc=moying,dc=ai`），`${..base_dn}` 变量引用不展开
- 组查询 `membership_filter` 反查 `uniqueMember`（OpenLDAP 无 memberOf）；`cacheable_name = yes` 才有 `control:LDAP-Group`
- 客户端须 `require_message_authenticator = no`（FreeRADIUS 3.2 兼容华为）
- users 文件 check 属性行尾**不能有逗号**（否则容器重启循环）

**验证**：
- 面板「认证测试」页测本地账号 → Accept
- 测一个 LDAP 真实账号 → Accept + Tunnel 三元组（LDAP 密码是 SSHA，**只支持 PAP/TTLS-PAP，PEAP-MSCHAPv2 不可用**——SSHA 算不出 NT hash，这是密码存储形态决定的，不是 bug）

## 第 7 步：注册接入设备（NAS）

**目的**：告诉 RADIUS 允许哪些设备来认证。

- 面板「密钥管理」页 → 添加设备：**IP 填设备发认证报文的源 IP**（不是服务器 IP、不是网段；源 IP 不确定才用网段兜底），密钥留空自动生成 24 位随机值
- 把生成的密钥填到设备侧 `radius-server shared-key`（一台设备一把，换密钥只影响单台）
- 保存后 `cd /opt/SharkSSO/radius && docker compose restart radius`

## 第 8 步：AC / 交换机对接（802.1X）

**目的**：WiFi 用户弹账号密码框，认证通过按部门进 VLAN。

以华为 AC（V600R024C10）为例，面板「对接指南」页有按真机定制的可复制命令。骨架顺序：

| # | 动作 | 验证 |
|---|---|---|
| 0 | AC 上 `ping -a <AC源IP> <RADIUS IP>` | 通（不通先修路由） |
| 1 | radius-server template + aaa 域 + dot1x/authentication-profile + security-profile（wpa2 dot1x aes） | — |
| 2 | **试验 SSID**：业务 VLAN 设隔离兜底段 + `dynamic-vlan enable`，不动现有 SSID | AC 上 `test-aaa 测试账号 密码 radius-template 模板名` = OK |
| 3 | 真手机连试验 SSID 输测试账号 | 拿到 RADIUS 下发 VLAN 的 IP = 全链路通 |
| 4 | 逐个把生产 SSID 的 security-profile 换成 dot1x 模板 + 挂 authentication-profile | 员工正常上网进对 VLAN |

注意：打印机/IoT/机器人等不支持 802.1X 的设备**留 PSK** 或后续走 MAC 认证（账号 = MAC 地址）；AP 接入交换机 trunk 要放行动态 VLAN；有线接入端口动态 VLAN 需 `port link-type hybrid`。

## 第 9 步（可选）：Portal 访客认证

**目的**：访客连 WiFi 弹网页，钉钉扫码核验身份后放行，不用发 PSK。

1. `portal/config.yaml.example` → `config.yaml`，8 处 `CHANGE_ME_*` 全部填掉（含钉钉凭据、Portal/CoA 密钥）
2. `cd portal && docker compose up -d --build`（8085 + UDP 50100）
3. AC 上配 web-auth-server 指向 8085，共享密钥与 `shared_key` 一致
4. 钉钉回调域名需备案（内网 IP 不行），未就绪可用 `dev_mode: true` 联调
5. 动态 VLAN 走 CoA（UDP 3799）或 Portal 协议放行，`release_mode: both` 联调最稳

## 第 10 步：收尾检查清单

- [ ] 所有 `CHANGE_ME_*` 已替换（`grep -r CHANGE_ME /opt/SharkSSO/` 应无结果）
- [ ] 服务器 crontab：02:30/03:30 同步、04:00 离职守卫
- [ ] 全员初始密码策略（不要用 123456 裸奔）
- [ ] 8082/8889/8085 不暴露公网，仅内网访问
- [ ] 每台 NAS 独立密钥（不要共用大网段条目）
- [ ] raddb 定期备份（`raddb/` + `ldap/` 数据卷）

---

## 排障（从里往外分层）

| 层 | 方法 | 失败定位 |
|---|---|---|
| ① RADIUS+账号 | 面板「认证测试」 | users / LDAP / RADIUS 本身 |
| ② 网络连通 | NAS 上 `ping -a <源IP> <RADIUS IP>` | 路由 / 防火墙 |
| ③ NAS↔RADIUS | NAS 上 `test-aaa 用户 密码 radius-template 模板名` | 密钥 / 源接口 / 1812 被拦 |
| ④ 终端↔NAS | 真终端连 802.1X SSID | security/authentication-profile 绑定 |
| ⑤ VLAN 落位 | `display access-user username xxx verbose` | trunk 未放行 / DHCP / 未映射部门 |

常见故障：`test-aaa` 超时 → clients.conf IP 与设备源 IP 不一致 / 密钥不符 / 未配 source interface；Accept 但落兜底 VLAN → 账号没配 VLAN 或部门没映射（设计如此非故障）；Accept 但拿不到 IP → trunk 未放行；LDAP 同步停摆 → mail 含非 ASCII 或 DB 卡死循环；`${..base_dn}` 不展开 → 必须写全 DN。

## 目录结构

| 目录 | 内容 | 部署到 |
|---|---|---|
| `ldap/` | OpenLDAP + go-ldap-admin + MySQL compose、同步/守卫脚本 | `/opt/SharkSSO/ldap` |
| `radius/` | FreeRADIUS 3.2 compose 与 raddb 配置 | `/opt/SharkSSO/radius` |
| `radius-web/` | 管理面板（Flask，8082） | `/opt/SharkSSO/radius/web` |
| `portal/` | 访客 Portal 服务器（8085） | `/opt/SharkSSO/portal` |
| `docs/` | 802.1X + 动态 VLAN 全场景模拟文档 | — |

## License

内部项目，未附开源许可证。默认私有仓库。
