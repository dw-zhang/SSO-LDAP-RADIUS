# 802.1X + 动态 VLAN 端到端模拟场景

目标：新建一个测试 SSID，员工连上后输入账号密码，交换机/AC 自动把他划进对应 VLAN。
**不碰现有办公 Wi-Fi，不依赖 LDAP 密码策略**，用 RADIUS 本地账号先把链路验证通。

## 一、场景参数

| 项 | 值 |
|---|---|
| SSID | `Office-8021X` |
| 认证方式 | WPA2-Enterprise（即 802.1X） |
| RADIUS 服务器 | `10.10.0.41`，认证 `1812/udp`，计费 `1813/udp` |
| 共享密钥 | 先在面板「NAS 客户端」把 AC 的管理 IP 注册为独立条目，密钥留空自动生成，两边一致即可（旧的 10.10.0.0/16 大网段密钥已作废） |
| 未认证临时 VLAN | `100`（连上但没认证时落这里） |
| 测试账号 A | `sim8021x` / `SimUser@Example1` → **VLAN 20** |
| 测试账号 B | `simguest` / `GuestUser@Example1` → **VLAN 99** |

VLAN 与网段（示例，按你实际规划改）：

| VLAN | 网段 | 用途 |
|---|---|---|
| 100 | 10.10.100.0/24 | 未认证临时区，只能到认证服务器 |
| 20 | 10.10.20.0/24 | 员工办公网 |
| 99 | 10.10.99.0/24 | 隔离/访客网 |

账号已建好并实测：两个账号分别下发 20 和 99，密码错误则 Reject。

---

## 二、AC / 交换机侧准备（必做，漏了 VLAN 下发不生效）

### 1. 建 VLAN

华为 AC：
```
vlan batch 20 99 100
```

> **关键**：AC 本地必须先有这个 VLAN，否则收到 RADIUS 下发的 VLAN 号也会被忽略。

### 2. 上行口放通

如果 AC 是二层旁挂（网关在核心交换机），AC 到交换机的上行口必须是 trunk，放通 20/99/100：

```
interface GigabitEthernet 0/0/1
 port link-type trunk
 port trunk allow-pass vlan 20 99 100
```

### 3. DHCP

认证通过后客户端会在新 VLAN 里发 DHCP。地址池要加在新 VLAN 的网关设备上（核心交换机或 AC）：

```
ip pool vlan20
 gateway-list 10.10.20.1
 network 10.10.20.0 mask 255.255.255.0
 dns-list 223.5.5.5
```

---

## 三、AC 上创建 SSID（华为 V200R019 及以后，模板化写法）

```
# 1) RADIUS 服务器模板（密钥 = AC 在面板「NAS 客户端」里的独立密钥，先去面板注册 AC 再来填）
radius-server template RAD_SHARK
 radius-server shared-key cipher <AC的独立密钥>
 radius-server authentication 10.10.0.41 1812
 radius-server accounting 10.10.0.41 1813
 radius-server retransmit 3
 radius-server timeout 5
 quit

# 2) 认证方案 + 域（把用户指向 RADIUS）
aaa
 authentication-scheme SCH_8021X
  authentication-mode radius
 quit
 domain sharknet
  authentication-scheme SCH_8021X
  radius-server RAD_SHARK
 quit
 quit

# 3) 802.1X 接入模板
dot1x-access-profile name D1X_EAP
 dot1x authentication-method eap
 quit

# 4) 认证模板（把 802.1X 接入模板挂进来）
authentication-profile name AUTH_OFFICE
 dot1x-access-profile D1X_EAP
 quit

# 5) 安全模板：WPA2-Enterprise
security-profile name SEC_ENTERPRISE
 security wpa2 dot1x aes
 quit

# 6) SSID 模板
ssid-profile name SSID_OFFICE
 ssid Office-8021X
 quit

# 7) VAP 模板：把上面几个串起来
vap-profile name VAP_OFFICE
 service-vlan vlan-id 100
 ssid-profile SSID_OFFICE
 security-profile SEC_ENTERPRISE
 authentication-profile AUTH_OFFICE
 quit

# 8) 下发到 AP 组（default 组默认包含所有未分组的 AP）
ap-group name default
 vap-profile VAP_OFFICE wlan 1 radio all
 quit
```

> 老版本（V200R007 之前）没有模板机制，是在 WLAN 虚接口下直接配：
> `dot1x enable` + `dot1x authentication-method eap` + `dot1x port-control auto`。
> 你告诉我型号和版本，我给对应写法。

---

## 四、客户端怎么连

### Windows 10/11

1. 点右下角 Wi-Fi → 选 `Office-8021X` → 连接
2. 弹出「输入凭据」窗口：
   - 用户名：`sim8021x`
   - 密码：`SimUser@Example1`
   - 域：**留空**（不要填，填了会当成 `域\用户名`）
3. 若弹出证书警告 → 点「连接」（测试环境用自签证书）
4. 连上后 `ipconfig` 应该看到 `10.10.20.x`

### iOS / Android

1. 连 `Office-8021X`
2. 用户名 `sim8021x`、密码 `SimUser@Example1`
3. 证书页点「信任」
4. 看 Wi-Fi 详情里的 IP 是否为 `10.10.20.x`

### 想验证第二个 VLAN

断开，重新连，用 `simguest` / `GuestUser@Example1`，IP 应变成 `10.10.99.x`。

---

## 五、验证三处（缺一不可）

### 1. RADIUS 侧有没有发对属性

```bash
cd /opt/SharkSSO/radius
python3 scripts/radius-test.py sim8021x SimUser@Example1
```

预期：
```
sim8021x         Access-Accept ✓
  Tunnel-Type                VLAN(13)
  Tunnel-Medium-Type         IEEE-802(6)
  Tunnel-Private-Group-Id    20
```

Windows 场景还要确认 MSCHAP 能算响应（已实测通过）：
```bash
docker exec sharksso-radius /opt/bin/radtest -t mschap sim8021x SimUser@Example1 127.0.0.1 0 testing123
```

### 2. AC 有没有收到并应用

```
display station ssid Office-8021X
```
看 `VLAN` 列是不是 20。

```
display access-user
```
看用户状态和 VLAN。

### 3. 客户端实际在哪个网段

Windows：`ipconfig`，看 IPv4 是不是 10.10.20.x。
再看核心交换机 MAC 表：`display mac-address | include <客户端MAC>`，确认出现在 VLAN 20 里。

---

## 六、失败对照表

| 现象 | 原因 | 处理 |
|---|---|---|
| 客户端一直「正在验证身份」 | AC 到 RADIUS 不通 / 密钥错 | AC 上 `test-aaa` 或抓包看 1812 是否有回包 |
| 提示「身份验证失败」但 RADIUS 日志是 Accept | AC 域配错，用户没走对域 | 检查 `domain` 绑定和 SSID 用的认证模板 |
| 认证成功但 IP 还是 10.10.100.x | AC 本地没建 VLAN 20 | `vlan batch 20` 补上 |
| 认证成功但拿不到 IP | 新 VLAN 没有 DHCP 池 / 上行口没放通 | 查地址池和 trunk |
| 电脑提示「无法连接到此网络」 | 安全模板与客户端能力不匹配 | 改用 `security wpa-wpa2 dot1x aes` 兼容模式 |
| RADIUS 容器反复重启 | users 文件语法错 | `radiusd -XC` 检查，注意 check 属性行末尾不能多逗号 |

---

## 七、这条链路跑通后，下一步是换账号源

现在用的是 RADIUS 本地明文账号，好处是不受 LDAP 影响，能单独验证「AC ↔ RADIUS ↔ VLAN 下发」。
链路确认无误后，把账号源换成 LDAP 有两种做法：

| 做法 | 改动 | 代价 |
|---|---|---|
| LDAP 改存明文密码 | go-ldap-admin 改 `user-password-encryption-type: clear`，重置全部密码 | 员工要输一次密码；389 必须限内网 |
| LDAP 加 samba schema 存 NT Hash | 改 schema + 同步脚本 | 改造量大，但比明文安全 |

在换之前，`sim8021x` 这类本地账号可以一直留着做回归测试。
