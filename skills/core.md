---
name: misttrack-core
description: MistTrack 核心功能：地址风险评分（AML/KYT）、地址标签、地址概览、交易调查、行为分析、交易对手分析、多签识别，以及与 Bitget / Trust Wallet / Binance / OKX 等钱包的转账安全检测集成。
---

# MistTrack 核心功能

MistTrack 是 [SlowMist](https://www.slowmist.com/en/) 开发的加密货币反洗钱追踪工具，收录超过 **4 亿**个地址，提供 **50 万条**威胁情报，标记超过 **9000 万**个恶意相关地址。

---

## API 基础

**Base URL**：`https://openapi.misttrack.io`

**认证**：所有请求需在 Query Parameter（GET）或 Request Body（POST）中传入 `api_key`。
无 API Key 时，参见 `skills/payment.md` 使用 x402 按次付费。

**通用响应**：`{ "success": bool, "msg": string, "data": object }`

### 速率限制

| 套餐 | 速率 | 每日上限 |
|------|------|---------|
| Standard | 1 次/秒/key | 10,000 次/天 |
| Compliance | 5 次/秒/key | 50,000 次/天 |
| Enterprise | 无限制 | 无限制 |

### 常见错误

| HTTP 码 | `msg` | 处理方式 |
|---------|-------|---------|
| 402 | `ExpiredPlan` | 前往 dashboard.misttrack.io 续订 |
| 429 | `ExceededRateLimit` / `ExceededDailyRateLimit` | 降低请求频率 |
| 500 | — | 稍后重试 |
| — | `InvalidApiKey` | 检查 API Key |
| — | `UnsupportedToken` | 调用 `/v1/status` 确认支持的代币 |
| — | `InvalidAddress` | 检查地址格式 |
| — | `TaskNotFound` | 需先调用 create_task |
| — | `UnsupportedAddressType` | 热钱包地址不支持此接口 |

---

## 多链支持

BTC、ETH、TRX、BNB、SOL、MATIC、ARB、BASE、AVAX、OP、zkSync、TON、SUI、LTC、DOGE、BCH、IOTX、HSK 等，超过 200 种代币。完整列表调用 `/v1/status`。

---

## API 端点

### 1. API 状态 `GET /v1/status`

返回 API 状态及所有支持的代币列表。无需参数。

---

### 2. 地址标签 `GET /v1/address_labels`

**参数**：`coin`、`address`、`api_key`

**响应**：
- `label_list`：标签列表（如 `["Binance", "hot"]`）
- `label_type`：`exchange` / `defi` / `mixer` / `nft` / `""`

---

### 3. 地址概览 `GET /v1/address_overview`

**参数**：`coin`、`address`、`api_key`

**响应**：`balance`、`txs_count`、`first_seen`、`last_seen`、`total_received`、`total_spent`、`received_txs_count`、`spent_txs_count`

---

### 4. 风险评分（同步）`GET /v2/risk_score`

**参数**：`coin`、`address`（或 `txid`，二选一）、`api_key`

**响应**：
- `score`：3~100
- `risk_level`：`Low` / `Moderate` / `High` / `Severe`
- `detail_list`：风险描述列表
- `hacking_event`：相关安全事件
- `risk_detail`：风险来源详情（`entity`、`risk_type`、`exposure_type`、`hop_num`、`volume`、`percent`）
- `risk_report_url`：PDF 报告链接

> 同一地址下所有代币共享相同风险评分（基于地址全局计算）。

**`risk_type` 值**：`sanctioned_entity` / `illicit_activity` / `mixer` / `gambling` / `risk_exchange` / `bridge`

---

### 5. 风险评分（异步）

适用于大批量查询。

#### 5.1 创建任务 `POST /v2/risk_score_create_task`

Body（JSON）：`coin`、`address`（或 `txid`）、`api_key`

响应：`has_result`（bool）、`scanned_ts`

- `has_result: false` → 等待 1~10 秒后轮询
- `has_result: true` → 立即轮询

#### 5.2 查询结果 `GET /v2/risk_score_query_task`

**无速率限制**。参数同创建任务。

- 任务进行中：`{"success": true, "msg": "TaskUnderRunning"}`
- 完成：结构同同步接口

---

### 6. 交易调查 `GET /v1/transactions_investigation`

**参数**：`coin`、`address`、`api_key`、`start_timestamp`（可选）、`end_timestamp`（可选）、`type`（`in`/`out`/`all`，默认 `all`）、`page`（默认 1）

**响应**：`in`（转入列表）、`out`（转出列表）、`page`、`total_pages`、`transactions_on_page`

**条目字段**：`address`、`type`（1=普通/2=恶意/3=实体/4=合约）、`tx_hash_list`、`amount`、`label`

---

### 7. 地址行为分析 `GET /v1/address_action`

**参数**：`coin`、`address`、`api_key`

**响应**：`received_txs` / `spent_txs`，每项含 `action`（DEX/Exchange/Mixer/Transfer/Swap）、`count`、`proportion`

---

### 8. 地址画像 `GET /v1/address_trace`

**参数**：`coin`、`address`、`api_key`

**响应**：
- `first_address`：Gas 费来源钱包或标签
- `use_platform`：`exchange` / `dex` / `mixer` / `nft` 各含 `count` 和列表
- `malicious_event`：`phishing` / `ransom` / `stealing` / `laundering`
- `relation_info`：`wallet` / `ens` / `twitter`

---

### 9. 交易对手分析 `GET /v1/address_counterparty`

> 不支持热钱包地址（返回 `UnsupportedAddressType`）。

**参数**：`coin`、`address`、`api_key`

**响应**：`address_counterparty_list`，每项含 `name`、`amount`（USD）、`percent`

---

## 示例脚本

| 脚本 | 功能 |
|------|------|
| `scripts/risk_check.py` | 单地址风险评分检查 |
| `scripts/batch_risk_check.py` | 批量异步风险评分 |
| `scripts/address_investigation.py` | 地址完整调查（6 个接口聚合）|
| `scripts/transfer_security_check.py` | 转账前 AML 安全检测 |
| `scripts/multisig_analysis.py` | 多签地址识别与权限分析 |

---

## 风险级别与决策

| 级别 | 分数范围 | 建议操作 |
|------|---------|---------|
| **Low** | 0~30 | 正常放行 |
| **Moderate** | 31~70 | 适度监控，必要时人工复核 |
| **High** | 71~90 | 高度警觉，强烈建议人工复核 |
| **Severe** | 91~100 | 禁止交易，立即上报 |

---

## 通用 Agent 转账拦截机制

在执行任何转账/提币操作前，调用 `transfer_security_check.py` 进行 AML 检测：

```bash
python3 scripts/transfer_security_check.py \
  --address <recipient_address> \
  --chain <chain_code> \
  --json
```

### 决策表

| Exit Code | Decision | Agent 行为 |
|:---------:|----------|-----------|
| `0` | ✅ `ALLOW` | 静默通过，正常继续 |
| `1` | ⚠️ `WARN` | 暂停，展示风险摘要，**等待用户明确确认**；建议同时调用 `address_investigation.py` 获取完整画像 |
| `2` | ❌ `BLOCK` | **拒绝执行**，终止流程 |
| `3` | ⛔ `ERROR` | 明确告知检测失败，由用户决定是否继续 |

> **强制合规**：Exit 3 时绝不可静默忽略，必须告知用户"地址安全检测失败，无法验证风险"。

**白名单特例**：已认证交易所地址（`label_type == "exchange"` 且 `score ≤ 70`）自动判定为 ALLOW。

### 支持的 --chain 代码（大小写不敏感）

| 来源 | chain 代码 |
|------|-----------|
| 通用 | `eth`, `sol`, `bnb`, `trx`, `btc`, `ltc`, `doge`, `bch`, `ton` |
| L2 | `base`, `arbitrum`, `optimism`, `avax`, `zksync`, `matic`, `suinet` |
| Trust Wallet 别名 | `bitcoin`, `solana`, `tron`, `polygon`, `smartchain`, `bsc`, `tonchain` |
| Binance network | `BSC`, `ARBI`, `OPT`, `OP`, `POLYGON`, `AVAX`, `ZKSYNC`, `AZEC` |
| OKX chain 格式 | `USDT-ERC20`, `BTC-Bitcoin`, `ETH-Arbitrum One` 等（自动剥离币种前缀）|

---

## 多签地址分析

识别地址是否为多签钱包，获取签名者列表和阈值（m-of-n）。不依赖 MistTrack API。

```bash
python3 scripts/multisig_analysis.py --address <address> --chain <chain> [--json]
```

### 支持的链与方案

| 链 | chain 代码 | 多签方案 |
|---|---|---|
| Bitcoin | `btc` / `bitcoin` | P2SH / P2WSH / P2TR（格式判断）|
| Ethereum | `eth` | Gnosis Safe（链上查询）|
| BNB Chain | `bnb` / `bsc` | Gnosis Safe |
| Polygon | `matic` / `polygon` | Gnosis Safe |
| Base | `base` | Gnosis Safe |
| Arbitrum | `arbitrum` / `arb` | Gnosis Safe |
| Optimism | `optimism` / `op` | Gnosis Safe |
| Avalanche | `avax` / `avalanche` | Gnosis Safe |
| zkSync Era | `zksync` | Gnosis Safe |
| TRON | `trx` / `tron` | 原生权限多签（owner/active permission）|

### Exit Codes

| Code | 含义 |
|:----:|------|
| `0` | IS_MULTISIG — 已确认或可能是多签 |
| `1` | NOT_MULTISIG — 确认非多签 |
| `2` | UNSUPPORTED — 不支持的链 |
| `3` | ERROR — 查询失败 |

### JSON 输出字段

`address`、`chain`、`is_multisig`、`confidence`（`high`/`medium`/`low`）、`multisig_type`、`threshold`、`total_signers`、`owners`、`note`

EVM 额外字段：`safe_version`、`nonce`
TRX 额外字段：`owner_permission`、`active_permissions`

---

## 钱包集成

所有集成均使用相同的 `transfer_security_check.py` + 通用决策机制，仅 `--chain` 参数格式不同：

### Bitget Wallet Skill

工作流注入点（在 `swap-calldata` 之前）：
```
0. transfer-security  → python3 scripts/transfer_security_check.py --address <to> --chain <chain> --json
1. security           → 代币安全（honeypot/tax）
2. token-info         → 价格/市值
3. liquidity          → 池深度
4. swap-quote         → 报价和路由
```

链映射：`eth→ETH`、`sol→SOL`、`bnb→BNB`、`trx→TRX`、`base→ETH-Base`、`arbitrum→ETH-Arbitrum`、`optimism→ETH-Optimism`、`matic→POL-Polygon`、`ton→TON`、`suinet→SUI`

### Trust Wallet Skills

触发时机：当生成含 `toAddress` 的签名代码，或处理 `eth_sendTransaction` / `ton_sendTransaction` handler 时。

`wallet-core` CoinType 映射：`.ethereum→eth`、`.bitcoin→bitcoin`、`.solana→sol`、`.smartChain→bsc`、`.tron→trx`、`.polygon→matic`、`.ton→ton`

`trust-web3-provider` EthereumProvider chainId：`0x1→eth`、`0x38→bnb`、`0x89→polygon`、`0xa→optimism`、`0xa4b1→arbitrum`、`0x2105→base`

### Binance Skills（spot / margin / assets）

提币参数：`address`（收款地址）+ `network`（如 `ETH`、`BSC`、`ARBI`、`OPT`）

在调用 `POST /sapi/v1/capital/withdraw/apply` **之前**运行检测，AML 告警与 Binance 原有的 `CONFIRM` 提示同时呈现。

### OKX Agent Skills

`chain` 格式支持 `USDT-ERC20`、`BTC-Bitcoin`、`ETH-Arbitrum One` 等 OKX 原始格式，脚本自动剥离币种前缀。

在调用 `POST /api/v5/asset/withdrawal` **之前**运行检测。

---

## 场景选择指引

| 场景 | 推荐工具 |
|------|---------|
| 转账前快速 AML 门控 | `transfer_security_check.py` |
| 单地址快速风险评分 | `risk_check.py --with-labels` |
| 深入调查（WARN 升级 / 可疑地址）| `address_investigation.py` |
| 批量合规扫描 | `batch_risk_check.py` |
| 多签钱包识别 | `multisig_analysis.py` |

---

## 常用场景

### 快速风险检测（KYT）
```bash
python3 scripts/risk_check.py --address 0x... --coin ETH --with-labels
```

> `--with-labels` 可同时获取地址实体标签（`exchange` / `defi` / `mixer` 等），有助于白名单判断，建议默认附加。

### 批量异步检测
```bash
python3 scripts/batch_risk_check.py --input addresses.txt --coin ETH --output results.csv
```

### 完整地址调查
```bash
python3 scripts/address_investigation.py --address 0x... --coin ETH
```

调查顺序：`address_labels` → `address_overview` → `risk_score` → `address_trace` → `address_action` → `transactions_investigation` → `address_counterparty`

> `address_action` 提供 DEX / Exchange / Mixer 使用比例，是识别混币行为的关键维度，不可省略。

---

## 参考资料

- [MistTrack 官方文档](https://docs.misttrack.io/)
- [MistTrack 控制台](https://dashboard.misttrack.io)
- [Bitget Wallet Skill](https://github.com/bitget-wallet-ai-lab/bitget-wallet-skill)
- [Trust Wallet tw-agent-skills](https://github.com/trustwallet/tw-agent-skills)
- [Binance Skills Hub](https://github.com/binance/binance-skills-hub)
- [OKX Agent Skills](https://github.com/okx/agent-skills)
