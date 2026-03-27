---
name: misttrack-skills
description: 使用 MistTrack OpenAPI 进行加密货币地址风险分析、AML 合规检测和交易追踪。MistTrack 是由 SlowMist 开发的反洗钱追踪工具，支持 BTC、ETH、TRX、BNB 等主流链上地址与交易的风险评分、标签查询、交易调查等功能。
---

# MistTrack Skills

## 子技能索引

本技能包含两个功能模块，分别定义在 `skills/` 目录下：

| 文件 | 功能 | 适用场景 |
|------|------|---------|
| [skills/core.md](skills/core.md) | **核心功能** | 风险评分、地址调查、多签分析、转账安全检测、钱包集成（Bitget/Trust/Binance/OKX）|
| [skills/payment.md](skills/payment.md) | **x402 支付** | 无 API Key 时按次付费调用 MistTrack API |

---

## 快速指引

### 转账安全检测（最常用）

在执行任何转账/提币操作前，调用以下脚本检测收款地址 AML 风险：

```bash
python3 scripts/transfer_security_check.py \
  --address <recipient_address> \
  --chain <chain_code> \
  --json
```

Exit Code：`0=ALLOW` / `1=WARN` / `2=BLOCK` / `3=ERROR`
详细决策机制见 [skills/core.md](skills/core.md)。

### 地址完整调查

```bash
python3 scripts/address_investigation.py --address 0x... --coin ETH
```

### x402 按次付费

无 API Key 时，使用 `scripts/pay.py` 以 USDC 按次付费。
详见 [skills/payment.md](skills/payment.md)。

---

## 环境变量

| 变量 | 说明 |
|------|------|
| `MISTTRACK_API_KEY` | MistTrack API 密钥（所有脚本优先读取此变量）|
| `X402_PRIVATE_KEY` | x402 支付使用的 EVM/Solana 私钥（十六进制）|

> 设置了 `MISTTRACK_API_KEY` 时，所有脚本自动使用 API Key 模式。
> 未设置时，可配置 `X402_PRIVATE_KEY` 通过 `scripts/pay.py` 按次付费，详见 [skills/payment.md](skills/payment.md)。

---

## 脚本列表

| 脚本 | 功能 |
|------|------|
| `scripts/transfer_security_check.py` | 转账前 AML 地址检测（主入口）|
| `scripts/risk_check.py` | 单地址风险评分 |
| `scripts/batch_risk_check.py` | 批量异步风险评分 |
| `scripts/address_investigation.py` | 地址完整调查（6 接口聚合）|
| `scripts/multisig_analysis.py` | 多签地址识别与权限分析 |
| `scripts/pay.py` | x402 支付协议客户端 |
