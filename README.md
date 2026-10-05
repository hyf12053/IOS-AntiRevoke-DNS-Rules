# iOS-AntiRevoke-DNS-Rules

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Automatically discovers iOS anti-revoke domains and publishes DNS profiles plus rules for major network tools.

自动抓取 iOS 反撤销域名，并发布 DNS 描述文件及主流网络工具规则。

> **This is a fork.** Upstream is [RzMY/IOS-AntiRevoke-DNS-Rules](https://github.com/RzMY/IOS-AntiRevoke-DNS-Rules).
> It carries fixes for a regression that made app installation fail with
> *"An Internet connection is required to verify…"* — see
> [Why this fork exists](#why-this-fork-exists--为什么有这个分支).

## Why this fork exists | 为什么有这个分支

In early October 2026, installing a signed app while an upstream profile was
installed started failing with an app-verification error, even on devices whose
iOS version and profile had not changed. The cause was in the generated domain
list, not in iOS:

1. **The install-verification path was blocked.** iOS contacts PPQ
   (`ppq.apple.com`, listed by Apple as *Enterprise App validation*) and
   `*.appattest.apple.com` (*App validation*) while installing an app and on its
   first launch. An upstream source began advertising an explicit 27-domain list
   that included five PPQ hosts, so PPQ leaked into the **normal** profile — the
   one meant to be used *while installing*.
2. **The two profiles stopped differing.** The enhanced "extra" set is derived
   by subtracting the normal set, so once PPQ moved into normal the extra set
   became empty and both profiles blocked identical domains. Switching profiles
   no longer helped.
3. **`appattest.apple.com` was a suffix trap.** `SupplementalMatchDomains` is a
   suffix match, so listing the bare name also blocks the whole family. The bare
   name itself is NODATA; the hosts that actually serve are
   `register.appattest.apple.com` and `data.appattest.apple.com`. That single
   entry silently disabled the hosts that actually serve.
4. **Unrelated Apple services were blocked** (`mesu`, `gdmf`, `guzzoni-*`,
   `comm-*.ess`, `axm-app`), which affects software updates, Siri and
   communication registration without helping against revocation.

Because the backend is a catch-all resolver rather than a policy resolver with
an allowlist, every listed domain is blocked unconditionally. The fixes
therefore live in the generator:

- `ALWAYS_EXCLUDED_DOMAINS` — never blocked in any profile (install verification
  plus unrelated services).
- `INSTALL_TIME_EXCLUDED_DOMAINS` — withheld from the normal profile but
  **deferred into the enhanced profile**, so blocking PPQ after installation
  still works.
- The enhanced profile is forced to remain a strict superset of the normal one.
- A CI guard fails the run if an install-verification domain reaches a published
  profile.

Two further defects were fixed at the same time: profile identity was
randomised on every run (so re-installing accumulated duplicate profiles instead
of updating), and signing is now refused when the certificate is expired or not
yet valid — previously nothing checked this, because
`openssl smime -verify -noverify` skips exactly that check.

## Features | 特性

- Daily discovery based on [Apple's official host list](https://support.apple.com/zh-cn/101555). / 每日基于 [Apple 官方主机列表](https://support.apple.com/zh-cn/101555)更新候选域名。
- DNS behavior is compared across Khoindvn, AppleJr and Sideloading endpoints. / 对比 Khoindvn、AppleJr 与 Sideloading 的 DNS 查询结果。
- Publishes normal and enhanced configurations separately. / 分别发布正常配置与增强配置。
- Guarantees the app-verification path stays reachable while installing. / 保证安装期间 App 验证链路可达。
- Supports iOS/iPadOS, Quantumult X, Surge, Loon, Shadowrocket and Hosts. / 支持 iOS/iPadOS、Quantumult X、Surge、Loon、Shadowrocket 与 Hosts。
- GitHub Actions tests, verifies and commits all generated artifacts. / GitHub Actions 自动测试、验签并提交产物。
- Signing is optional: without `SSL_CERT` / `SSL_KEY` secrets the profiles are
  published unsigned, which installs and works normally (iOS shows an
  "Unsigned" label). / 签名为可选：未配置 `SSL_CERT` / `SSL_KEY` 时发布未签名描述文件，安装与使用均正常（iOS 仅显示"未签名"标记）。

## Downloads | 下载

Replace `hyf12053` with your own account if you renamed the fork. Raw links work
directly from a browser or a "Import remote file" field in Quantumult X / Surge /
Loon / Shadowrocket.

### Normal Configuration | 正常配置

Use the normal configuration for installation and daily sideloading.

正常配置用于安装证书、签名工具及日常侧载。

| Platform / 平台 | File / 文件 |
| --- | --- |
| iOS/iPadOS | **[RevokeGuard.mobileconfig](https://antirevoke-doh.dns-moat.workers.dev/download)** |
| Quantumult X | [RevokeGuard_QuantumultX.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/RevokeGuard_QuantumultX.txt) |
| Surge | [RevokeGuard_Surge.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/RevokeGuard_Surge.txt) |
| Loon | [RevokeGuard_Loon.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/RevokeGuard_Loon.txt) |
| Shadowrocket | [RevokeGuard_Shadowrocket.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/RevokeGuard_Shadowrocket.txt) |
| Hosts | [RevokeGuard_hosts.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/RevokeGuard_hosts.txt) |
| Domains / 域名 | [domains.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/domains.txt) |

> **Install on iOS/iPadOS from the short link above.** It answers with
> `Content-Type: application/x-apple-aspen-config`, the type iOS uses to
> recognise a configuration profile.
>
> `raw.githubusercontent.com` serves `.mobileconfig` as `text/plain` with
> `X-Content-Type-Options: nosniff`, so the real type cannot be sniffed. Safari
> tolerates that when you tap the file directly, but an in-app link, a redirect
> or a QR scan may refuse it — use the [raw
> URL](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/RevokeGuard_Auto-Sync.mobileconfig)
> only as a fallback.

### Enhanced Configuration | 增强配置

| Platform / 平台 | File / 文件 |
| --- | --- |
| iOS/iPadOS | **[RevokeGuard_Enhanced.mobileconfig](https://antirevoke-doh.dns-moat.workers.dev/download2)** |
| Quantumult X | [RevokeGuard_Enhanced_QuantumultX.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/enhanced/RevokeGuard_Enhanced_QuantumultX.txt) |
| Surge | [RevokeGuard_Enhanced_Surge.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/enhanced/RevokeGuard_Enhanced_Surge.txt) |
| Loon | [RevokeGuard_Enhanced_Loon.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/enhanced/RevokeGuard_Enhanced_Loon.txt) |
| Shadowrocket | [RevokeGuard_Enhanced_Shadowrocket.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/enhanced/RevokeGuard_Enhanced_Shadowrocket.txt) |
| Hosts | [RevokeGuard_Enhanced_hosts.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/enhanced/RevokeGuard_Enhanced_hosts.txt) |
| Extra domains / 增强域名 | [enhanced-domains.txt](https://raw.githubusercontent.com/hyf12053/IOS-AntiRevoke-DNS-Rules/main/output/enhanced/enhanced-domains.txt) |

## Usage | 使用说明

1. Install the normal anti-revoke DNS profile, or import the matching rule file into your network tool.
   安装正常反撤销 DNS 描述文件，或将对应规则导入网络工具。
2. Download KSign or ESign from [Khoindvn Bypass](https://khoindvn.io.vn/#bypass).
   前往 [Khoindvn Bypass](https://khoindvn.io.vn/#bypass) 下载 KSign 或 ESign。
3. Sideload your apps.
   侧载你的应用。

**Note 1:** If a normally working application becomes unable to open, remove all sideloaded apps and the trusted certificate, select a new certificate, then repeat the steps above.

**Note 1：** 如果已正常使用的应用无法打开，请卸载所有侧载应用并删除已信任证书，选择新证书后重新执行以上流程。

**Note 2:** If the above problems frequently occur, install or enable the enhanced configuration after the app opens successfully for the first time. Temporarily remove or disable the enhanced configuration whenever you need to sideload another app.

**Note 2：** 如果经常出现上述问题，请在应用第一次成功打开后安装或启用增强配置；之后每次需要侧载新应用时，先暂时移除或停用增强配置。

Do not enable the normal and enhanced iOS profiles at the same time. The enhanced profile already includes all normal domains. Network-tool users should keep the normal rules enabled and toggle the separate enhanced rule set as required.

请勿同时安装正常与增强 iOS 描述文件；增强描述文件已经包含全部正常域名。网络工具用户应保持正常规则启用，并按需单独开关增强规则组。

## Discovery | 规则发现

The daily workflow performs the following operations:

每日工作流执行以下操作：

1. Read candidate domains from Apple's official enterprise network page. / 从 Apple 官方企业网络页面读取候选域名。
2. Download and decode the three upstream DNS profiles. / 下载并解析三个上游 DNS 描述文件。
3. Use explicit `DNSSettings.SupplementalMatchDomains` lists directly as results; otherwise query the candidates through the normal endpoints below. / 若所选 payload 的 `DNSSettings.SupplementalMatchDomains` 包含域名列表，直接作为结果，不再探测该源；否则使用以下正常端点查询候选域名。
4. Process Sideloading `afterinstalling` separately using the same list-or-probe logic and calculate its additional domains. / 按相同的域名列表或探测逻辑单独处理 Sideloading `afterinstalling`，并计算新增域名。
5. Apply the exclusions to the normal list, then derive the enhanced set so that
   every deferred domain still reaches the enhanced outputs. / 对正常列表应用排除规则，再据此推导增强集合，确保被推迟的域名仍然进入增强产物。
6. Generate normal outputs and the isolated `output/enhanced/` set. / 生成正常产物及隔离的 `output/enhanced/` 增强产物。

| Source / 来源 | Mode / 模式 | Payload identifier |
| --- | --- | --- |
| Khoindvn | Normal / 正常 | First DNS payload with a domain list or HTTPS endpoint / 首个包含域名列表或 HTTPS 端点的 DNS payload |
| AppleJr | Normal / 正常 | First DNS payload with a domain list or HTTPS endpoint / 首个包含域名列表或 HTTPS 端点的 DNS payload |
| Sideloading | Normal / 正常 | `novadev.nexdns.whileinstalling` |
| Sideloading | Enhanced / 增强 | `novadev.nexdns.afterinstalling` |

### Exclusion rules | 排除规则

A domain is excluded from the normal profile when blocking it would break
installation. Excluded entries fall into two groups:

| Group | Behaviour | Examples |
| --- | --- | --- |
| Always excluded | Removed from **both** profiles | `appattest.apple.com` (suffix-matches the serving `register.` / `data.` hosts), `mesu`, `gdmf`, `guzzoni-*`, `comm-*.ess`, `axm-app` |
| Deferred to enhanced | Removed from normal, kept in enhanced | `ppq.apple.com` + 4 PPQ CNAME variants, `vpp.itunes.apple.com` |

Deferring rather than deleting matters: the enhanced rule files are generated
from the enhanced "extra" set, so dropping a deferred domain outright would
remove it from Quantumult X / Surge / Loon / Shadowrocket users' configs too.

`PPQ_EDGE_DOMAINS` pins the four PPQ edge hosts (`ppq-ext.v.aaplimg.com`,
`ppq-st-ext.itunes.apple.com`, `use1-ppq-ext-prod.apple.com`,
`usw2-ppq-ext-prod.apple.com`) into the enhanced profile unconditionally. Apple's
host table lists only `ppq.apple.com`, so these can never be found by probing the
candidate pool — they are learnable only from an upstream profile's explicit
list. Pinning them means a partial PPQ block cannot happen if every upstream
stops publishing them.

To adjust the behaviour, edit `ALWAYS_EXCLUDED_DOMAINS`,
`INSTALL_TIME_EXCLUDED_DOMAINS` and `PPQ_EDGE_DOMAINS` in `main.py`.
`tests/test_install_verification.py` fails if a published profile ever blocks an
install-verification domain, if the two profiles collapse into the same domain
set, or if the enhanced profile stops being a superset of the normal one.

## Configuration | 配置

| Variable | Default | Purpose |
| --- | --- | --- |
| `BACKEND_HOST` | `reject.rzmy.dpdns.org` | DoH backend the profiles point at. Accepts a bare host or a full `https://…` URL. Set a repository *variable* of the same name; an unset variable falls back to the default. |
| `SSL_CERT_PATH` / `SSL_KEY_PATH` | _(empty)_ | PEM certificate chain and key used to CMS-sign the profiles. Omit both to publish unsigned profiles. |

`BACKEND_HOST` also has a `--backend-host` CLI flag. A full URL is accepted
because self-hosted resolvers are usually not at the root of a domain — a
Cloudflare Worker lives at `https://<name>.<subdomain>.workers.dev`.

Keep in mind what the default backend does: it answers `NXDOMAIN` for **every**
name, so a listed domain is blocked unconditionally, and it has no allowlist.
That is exactly why the exclusion lists above must be maintained in the
generator rather than by adding "allow" entries to the profile.

### Running your own backend | 自建后端

The default backend is someone else's server on someone else's domain. This
repository includes a Cloudflare Worker that replaces it, deployable for free
without owning a domain:

```bash
npm install -g wrangler
wrangler login
cd worker && wrangler deploy
```

See [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) for the full walkthrough,
including why the Worker answers NXDOMAIN for everything and when that is the
wrong behaviour.

The same Worker serves short download links for the profiles. The ones this
repository uses:

```
https://antirevoke-doh.dns-moat.workers.dev/download    → normal profile
https://antirevoke-doh.dns-moat.workers.dev/download2   → enhanced profile
```

The names match upstream's `/download` and `/download2`. Beyond being shorter,
these send `Content-Type: application/x-apple-aspen-config`, which is the type
iOS uses to recognise a configuration profile.
`raw.githubusercontent.com` serves `.mobileconfig` as `text/plain` with
`nosniff`, so it only works when the user taps the file directly.

If a fetch from GitHub fails, these routes answer **502** rather than forwarding
an error body. The profile is retrieved at request time, so upstream can return
an HTML error page or a truncated body *with HTTP 200*; forwarding that would
make the device install a broken profile while looking like a successful
download.

## Credits | 致谢

- [Apple Support](https://support.apple.com/zh-cn/101555)
- [Khoindvn](https://khoindvn.io.vn/)
- [AppleJr](https://applejr.net/)
- [Sideloading / NexDNS](https://sideloading.net/dns/)
- Upstream: [RzMY/IOS-AntiRevoke-DNS-Rules](https://github.com/RzMY/IOS-AntiRevoke-DNS-Rules)

## License | 许可证

[MIT License](LICENSE)
