# SharkSSO — 统一认证体系（RADIUS + 802.1X + LDAP + 钉钉同步）

围绕统一账号的认证基础设施：**钉钉通讯录 → OpenLDAP（账号库）→ FreeRADIUS（认证判决 + 动态 VLAN）→ 华为 AC/AP（WiFi 802.1X）**，配套 Web 管理面板与访客 Portal 服务器。

> ⚠️ 本仓库所有密码 / 密钥 / 凭据均已替换为 `CHANGE_ME_*` 占位符或示例值，部署时必须全部改掉。
> ⚠️ 面板挂载 docker.sock，**不可暴露公网**。

## 架构与关联关系

```
钉钉通讯录（人 + 部门，唯一权威来源）
   │ 每日自动同步（go-ldap-admin，02:30 部门 / 03:30 人员，04:00 离职守卫）
   ▼
OpenLDAP（dc=moying,dc=ai）          ←—— 账号库：uid=拼音 / 部门组 uniqueMember / SSHA 密码
   ▲ bind 校验密码 + 查部门组（membership_filter 反查）
   │
FreeRADIUS 3.2（UDP 1812/1813，host 网络）
   ▲ RADIUS 协议（每台 NAS 一把独立共享密钥，clients.conf）
   │
华为 AC / 交换机（authenticator）     ←—— 收终端 EAPOL，转发给 RADIUS
   ▲ 802.1X / Portal / MAC 认证
终端
```

三层密钥（互不相干）：
| 密钥 | 存放 | 管理 |
|---|---|---|
| NAS 共享密钥（设备↔RADIUS） | `radius/raddb/clients.conf`，一台设备一把 | Web「密钥管理」页 |
| 用户密码 | LDAP（SSHA）或 users 文件（本地明文） | 「账号管理」页 / 钉钉同步 |
| 面板登录密码 | `.adminpw` | 「密码」页 |

## 仓库结构

| 目录 | 内容 | 部署到 |
|---|---|---|
| `ldap/` | OpenLDAP + go-ldap-admin + MySQL 的 compose、钉钉同步/离职守卫脚本 | `/opt/SharkSSO/ldap` |
| `radius/` | FreeRADIUS 3.2 compose 与 raddb 配置（clients/users/ldap/site-default/vlan-map） | `/opt/SharkSSO/radius` |
| `radius-web/` | 管理面板（Flask，8082）：账号/密钥/LDAP 对接/动态 VLAN/认证测试/真机对接指南 | `/opt/SharkSSO/radius/web` |
| `portal/` | 访客 Portal 服务器（钉钉扫码 + Portal 2.0 + CoA 动态 VLAN，8085） | `/opt/SharkSSO/portal` |
| `docs/` | 802.1X + 动态 VLAN 全场景模拟文档 | — |

## 快速部署

```bash
# 0) 前置：Linux + Docker + docker compose 插件
# 1) LDAP 三件套
cd ldap && docker compose up -d
# 2) FreeRADIUS
cd ../radius && docker compose up -d
# 3) 管理面板
cd ../radius-web && docker compose up -d --build
# 4) Portal（可选，需先填 config.yaml）
cd ../portal && docker compose up -d --build
```

### 必改清单（部署前逐项替换）

| 位置 | 占位符 | 说明 |
|---|---|---|
| `ldap/docker-compose.yml` | `CHANGE_ME_LDAP_ADMIN_PW` ×2、`CHANGE_ME_MYSQL_ROOT_PW` | LDAP admin / MySQL root |
| `ldap/scripts/reset-admin-pw.py` | `CHANGE_ME_LDAPADMIN_UI_PW`、`CHANGE_ME_MYSQL_ROOT_PW` | go-ldap-admin 管理端 |
| `radius/raddb/clients.conf.example` → `clients.conf` | `CHANGE_ME_DEVICE_SECRET` | 每台 NAS 一把独立密钥（面板可自动生成） |
| `radius/raddb/users.example` → `users` | `*Example1` 示例密码 | 本地测试账号 |
| `radius/raddb/ldap-mod.conf` | `CHANGE_ME_LDAP_ADMIN_PW` | RADIUS bind LDAP 的密码 |
| `radius-web/docker-compose.yml` | `CHANGE_ME_PANEL_ADMIN_PW`、`SECRET_KEY` | 面板初始密码 / Flask 密钥 |
| `portal/config.yaml.example` → `config.yaml` | 8 处 `CHANGE_ME_*`（含钉钉 AppKey/AppSecret、CoA 密钥） | 全部必改 |

### 关键配置要点（踩坑总结）

- LDAP 对接地址用 `ldap://127.0.0.1:389`（RADIUS 与 LDAP 同机，回环绕开跨网段 389 不通）
- `base_dn` 必须写全（`dc=moying,dc=ai`），`${..base_dn}` 变量引用在此部署形态下不展开
- 组查询用 `membership_filter` 反查 `uniqueMember`（OpenLDAP 默认无 memberOf）；`cacheable_name = yes` 才有 `control:LDAP-Group`
- FreeRADIUS 3.2 客户端须显式 `require_message_authenticator = no`（华为设备兼容）
- users 文件 check 属性行尾**不能有逗号**（否则容器重启循环）
- LDAP 密码是 SSHA → **PEAP-MSCHAPv2 不可用**（算不出 NT hash），本地 users 明文账号不受限；LDAP 账号走 PAP/TTLS-PAP
- 动态 VLAN：RADIUS 只下发 VLAN 号（Tunnel 三元组），**不创建 VLAN**；号必须真实存在于 AC/交换机；AC 侧需开 `dynamic-vlan enable`
- 未匹配到规则的账号落在 SSID 兜底业务 VLAN（建议设隔离段）

## 全链路认证时序

```
1 终端连 SSID → 802.1X 弹窗 → 输账号密码（EAPOL 只到 AC 为止）
2 AC 封装 EAP → Access-Request（源 IP = AC 源接口）→ RADIUS:1812
3 RADIUS：users 本地匹配 → 无则 LDAP bind 校验 → 通过后按部门组查 vlan-map
4 Access-Accept + Tunnel-Private-Group-Id=<VLAN> 回 AC
5 AC 划入下发 VLAN（dynamic-vlan enable）→ 用户在该 VLAN 拿 DHCP
```

## 排障（从里往外分层）

| 层 | 方法 | 失败定位 |
|---|---|---|
| ① RADIUS+账号 | 面板「认证测试」 | users / LDAP / RADIUS 本身 |
| ② 网络连通 | NAS 上 `ping -a <源IP> <RADIUS IP>` | 路由 / 防火墙 |
| ③ NAS↔RADIUS | NAS 上 `test-aaa 用户 密码 radius-template 模板名` | 密钥 / 源接口 / 1812 被拦 |
| ④ 终端↔NAS | 真终端连 802.1X SSID | security/authentication-profile 绑定 |
| ⑤ VLAN 落位 | `display access-user username xxx verbose` | trunk 未放行 / DHCP / 未映射部门 |

## License

内部项目，未附开源许可证。默认私有仓库。
