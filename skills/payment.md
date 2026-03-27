---
name: misttrack-payment
description: MistTrack x402 按次付费支付协议。当用户没有 MistTrack API Key 时，使用 x402 协议以 USDC 按次付费调用 MistTrack API。
---

# MistTrack x402 Payment 机制

> 当用户没有 MistTrack API Key 时，Agent 可使用 x402 协议按次付费调用 MistTrack API。支持通过 EVM（EIP-3009）或 Solana 部分签名方式使用 USDC 支付。
>
> 如果用户配置了私钥并指定了链，则默认自动使用用户配置的私钥和链进行支付（提醒一次）。默认使用 Base 链支付。

## 支持的 API 及费用（USDC/次）

| # | x402 API 路径 | 对应原始路径 | 单价 |
|---|---|---|---|
| 1 | `https://openapi.misttrack.io/x402/address_labels` | `v1/address_labels` | $0.1 |
| 2 | `https://openapi.misttrack.io/x402/address_overview` | `v1/address_overview` | $0.5 |
| 3 | `https://openapi.misttrack.io/x402/risk_score` | `v2/risk_score` | $1.0 |
| 4 | `https://openapi.misttrack.io/x402/risk_score_create_task` | `v2/risk_score_create_task` | $1.0 |
| 5 | `https://openapi.misttrack.io/v2/risk_score_query_task` | `v2/risk_score_query_task` | $0（免费轮询）|
| 6 | `https://openapi.misttrack.io/x402/transactions_investigation` | `v1/transactions_investigation` | $1.0 |
| 7 | `https://openapi.misttrack.io/x402/address_action` | `v1/address_action` | $0.5 |
| 8 | `https://openapi.misttrack.io/x402/address_trace` | `v1/address_trace` | $0.5 |
| 9 | `https://openapi.misttrack.io/x402/address_counterparty` | `v1/address_counterparty` | $0.5 |

## 支持的 EVM 链

| Chain ID | 网络 |
|:---:|:---|
| 1 | Ethereum Mainnet |
| 10 | Optimism |
| 137 | Polygon |
| 8453 | Base（默认）|
| 42161 | Arbitrum One |
| 43114 | Avalanche C-Chain |

---

## 使用方式

### 1. CLI 命令行调用

```bash
# 完整 x402 支付流程（请求 → 解析 402 → 签名 → 重试）
python3 scripts/pay.py pay \
  --url "https://openapi.misttrack.io/x402/address_labels?address=0x..." \
  --private-key <hex_private_key> \
  --chain-id 8453

# 手动签名 EIP-3009
python3 scripts/pay.py sign-eip3009 \
  --private-key <hex> \
  --token 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  --chain-id 8453 \
  --to 0x209693Bc6afc0C5328bA36FaF03C514EF312287C \
  --amount 10000

# 对 Solana 部分交易进行签名
python3 scripts/pay.py sign-solana \
  --private-key <hex_32byte_seed> \
  --transaction <base64_encoded_tx>
```

环境变量：`X402_PRIVATE_KEY` 可替代 `--private-key` 参数。

### 2. 代码内嵌调用

```python
from scripts.pay import request_with_x402

response = request_with_x402(
    url="https://openapi.misttrack.io/x402/address_labels?address=0x...",
    private_key="your_private_key_hex",
    chain_id=8453,
    auto_pay=True,  # True = 自动支付，无需确认
)
print(response.json())
```

---

## 安全限制

- 单次支付上限：**$1.00 USDC（1,000,000 最小单位）**。超出此金额自动拒绝签名，防止恶意服务器耗尽钱包。
- 私钥通过 `--private-key` 参数或 `X402_PRIVATE_KEY` 环境变量传入，建议使用环境变量。

---

## 所需依赖

```bash
pip install eth-account eth-abi eth-utils requests
# Solana 支付额外需要：
pip install solders base58
```
