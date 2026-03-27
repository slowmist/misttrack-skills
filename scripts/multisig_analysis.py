#!/usr/bin/env python3
"""
multisig_analysis.py — 多签地址识别与权限关系分析

识别并解析多签地址，分析签名参与者与权限关系。
支持 BTC、ETH/EVM 兼容链（Gnosis Safe）以及 TRX 原生权限多签。

用法：
  python3 scripts/multisig_analysis.py --address <address> --chain <chain>
  python3 scripts/multisig_analysis.py --address <address> --chain eth --json

支持的 chain 代码：
  btc, bitcoin                             — Bitcoin（P2SH / P2WSH / P2TR 格式判断）
  eth                                      — Ethereum（Gnosis Safe）
  bnb, bsc, smartchain                     — BNB Smart Chain（Gnosis Safe）
  matic, polygon                           — Polygon（Gnosis Safe）
  base                                     — Base（Gnosis Safe）
  arbitrum, arb                            — Arbitrum One（Gnosis Safe）
  optimism, op                             — OP Mainnet（Gnosis Safe）
  avax, avalanche                          — Avalanche（Gnosis Safe）
  zksync                                   — zkSync Era（Gnosis Safe）
  trx, tron                                — TRON（原生权限结构多签）

不支持的链（返回 exit 2）：
  sol, ton, ltc, doge, bch, aptos, cosmos

Exit codes：
  0  IS_MULTISIG      — 已确认或可能是多签地址
  1  NOT_MULTISIG     — 确认非多签（普通地址）
  2  UNSUPPORTED      — 不支持的链
  3  ERROR            — API 调用失败或查询错误

示例：
  # BTC P2SH 多签
  python3 scripts/multisig_analysis.py --address 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy --chain btc

  # ETH Gnosis Safe
  python3 scripts/multisig_analysis.py --address 0x849D52316331967b6fF1198e5E32A0eB168D039d --chain eth

  # TRX 原生多签
  python3 scripts/multisig_analysis.py --address TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW --chain trx

  # JSON 输出（机器可读）
  python3 scripts/multisig_analysis.py --address 0x... --chain eth --json
"""

import argparse
import json
import re
import sys
from typing import Optional

import requests

# ─── Constants ───────────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 20  # seconds

# Exit codes
EXIT_IS_MULTISIG = 0
EXIT_NOT_MULTISIG = 1
EXIT_UNSUPPORTED = 2
EXIT_ERROR = 3

# ANSI colours (disabled in JSON mode)
COLOUR = {
    "cyan":   "\033[36m",
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "red":    "\033[31m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

# Gnosis Safe Transaction Service base URLs per network
# ref: https://docs.safe.global/core-api/transaction-service-supported-networks
SAFE_API_URLS: dict[str, str] = {
    "eth":       "https://safe-transaction-mainnet.safe.global",
    "bnb":       "https://safe-transaction-bsc.safe.global",
    "bsc":       "https://safe-transaction-bsc.safe.global",
    "smartchain":"https://safe-transaction-bsc.safe.global",
    "matic":     "https://safe-transaction-polygon.safe.global",
    "polygon":   "https://safe-transaction-polygon.safe.global",
    "base":      "https://safe-transaction-base.safe.global",
    "arbitrum":  "https://safe-transaction-arbitrum.safe.global",
    "arb":       "https://safe-transaction-arbitrum.safe.global",
    "optimism":  "https://safe-transaction-optimism.safe.global",
    "op":        "https://safe-transaction-optimism.safe.global",
    "avax":      "https://safe-transaction-avalanche.safe.global",
    "avalanche": "https://safe-transaction-avalanche.safe.global",
    "zksync":    "https://safe-transaction-zksync.safe.global",
}

# Tron API public endpoint
TRON_API_URL = "https://api.trongrid.io"

# BTC chain identifiers
BTC_CHAINS = {"btc", "bitcoin"}

# TRX chain identifiers
TRX_CHAINS = {"trx", "tron"}

# All supported chains
SUPPORTED_CHAINS = set(SAFE_API_URLS.keys()) | BTC_CHAINS | TRX_CHAINS

# Chains we explicitly know are not supported
UNSUPPORTED_CHAINS: dict[str, str] = {
    "sol":     "Solana 链暂不支持多签链上查询（无公开标准接口）。",
    "solana":  "Solana 链暂不支持多签链上查询（无公开标准接口）。",
    "ton":     "TON 链暂不支持多签链上查询。",
    "tonchain":"TON 链暂不支持多签链上查询。",
    "ltc":     "LTC 地址多签需通过区块链浏览器确认脚本内容，暂不支持自动查询。",
    "doge":    "DOGE 地址多签需通过区块链浏览器确认脚本内容，暂不支持自动查询。",
    "bch":     "BCH 地址多签需通过区块链浏览器确认脚本内容，暂不支持自动查询。",
    "aptos":   "Aptos 链暂不支持多签链上查询。",
    "cosmos":  "Cosmos 链暂不支持多签链上查询。",
    "atom":    "Cosmos 链暂不支持多签链上查询。",
    "sui":     "Sui 链暂不支持多签链上查询。",
    "suinet":  "Sui 链暂不支持多签链上查询。",
}


# ─── BTC Analysis ────────────────────────────────────────────────────────────

def analyze_btc(address: str) -> dict:
    """
    Analyze a Bitcoin address for potential multisig based on address format.

    - P2SH  (starts with '3')       : May be multisig (also used for single-sig P2SH-P2WPKH)
    - P2WSH (bc1q, 62 chars)        : Likely multisig (Pay-to-Witness-Script-Hash)
    - P2TR  (bc1p)                  : Taproot, may use MuSig2/Tapscript multisig
    - P2PKH (starts with '1')       : Single-sig, not multisig
    - P2WPKH (bc1q, ~42 chars)      : Single-sig SegWit
    """
    address = address.strip()

    # P2PKH — definitely single sig
    if re.match(r"^1[1-9A-HJ-NP-Za-km-z]{25,34}$", address):
        return {
            "is_multisig":   False,
            "confidence":    "high",
            "multisig_type": None,
            "address_type":  "P2PKH",
            "threshold":     None,
            "total_signers": None,
            "owners":        [],
            "note": "P2PKH 地址（以 '1' 开头）是单签地址格式，不是多签。",
        }

    # P2SH — may be multisig
    if re.match(r"^3[1-9A-HJ-NP-Za-km-z]{25,34}$", address):
        return {
            "is_multisig":   True,
            "confidence":    "medium",
            "multisig_type": "P2SH",
            "address_type":  "P2SH",
            "threshold":     None,
            "total_signers": None,
            "owners":        [],
            "note": (
                "P2SH 地址（以 '3' 开头）可能是多签地址，也可能是 P2SH-P2WPKH 单签地址。"
                "如需确认多签参与者与阈值，请在区块链浏览器（如 mempool.space）查看"
                "该地址的赎回脚本（Redeem Script）。"
            ),
        }

    # Bech32/Bech32m addresses
    addr_lower = address.lower()

    # P2WSH — mainnet bc1q with 62 chars (SHA-256 witness program = 32 bytes → 62 bech32 chars)
    if addr_lower.startswith("bc1q") and len(address) == 62:
        return {
            "is_multisig":   True,
            "confidence":    "high",
            "multisig_type": "P2WSH",
            "address_type":  "P2WSH",
            "threshold":     None,
            "total_signers": None,
            "owners":        [],
            "note": (
                "P2WSH 地址（bc1q，62 字符）是 SegWit 多签地址格式。"
                "如需获取签名者列表和阈值（m-of-n），请在区块链浏览器"
                "（如 mempool.space）查看赎回脚本或见证脚本（Witness Script）。"
            ),
        }

    # P2WPKH — bc1q with ~42 chars — single sig
    if addr_lower.startswith("bc1q") and len(address) <= 45:
        return {
            "is_multisig":   False,
            "confidence":    "high",
            "multisig_type": None,
            "address_type":  "P2WPKH",
            "threshold":     None,
            "total_signers": None,
            "owners":        [],
            "note": "P2WPKH 地址（bc1q，约 42 字符）是单签 SegWit 地址格式，不是多签。",
        }

    # P2TR — Taproot (bc1p) — may use MuSig2 or Tapscript multisig
    if addr_lower.startswith("bc1p"):
        return {
            "is_multisig":   True,
            "confidence":    "low",
            "multisig_type": "P2TR",
            "address_type":  "P2TR",
            "threshold":     None,
            "total_signers": None,
            "owners":        [],
            "note": (
                "P2TR 地址（bc1p，Taproot）可能使用 MuSig2 聚合签名或 Tapscript 多签。"
                "由于 MuSig2 签名在链上看起来与单签相同，无法仅凭地址格式确认是否为多签。"
                "请通过区块链浏览器（如 mempool.space）查看其支出交易的见证数据以确认。"
            ),
        }

    # Testnet / unknown format
    return {
        "is_multisig":   None,
        "confidence":    "unknown",
        "multisig_type": None,
        "address_type":  "unknown",
        "threshold":     None,
        "total_signers": None,
        "owners":        [],
        "note": f"无法识别的 BTC 地址格式：{address}",
    }


# ─── ETH/EVM Analysis (Gnosis Safe) ─────────────────────────────────────────

def analyze_evm(address: str, chain: str) -> dict:
    """
    Query the Safe Transaction Service API to determine if the address is a
    Gnosis Safe multisig wallet and retrieve its owners/threshold.
    """
    base_url = SAFE_API_URLS[chain]
    url = f"{base_url}/api/v1/safes/{address}/"

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        raise RuntimeError("Safe API 请求超时（20s），请检查网络连接后重试。")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"网络请求错误：{e}")

    if resp.status_code == 404:
        # Address is not a Gnosis Safe
        return {
            "is_multisig":   False,
            "confidence":    "high",
            "multisig_type": None,
            "address_type":  "EOA_or_other_contract",
            "threshold":     None,
            "total_signers": None,
            "owners":        [],
            "note": "该地址不是 Gnosis Safe 合约（Safe API 返回 404）。",
        }

    if resp.status_code != 200:
        raise RuntimeError(
            f"Safe API 返回异常状态码 {resp.status_code}：{resp.text[:200]}"
        )

    data = resp.json()
    owners: list[str] = data.get("owners", [])
    threshold: int = data.get("threshold", 0)
    nonce: int = data.get("nonce", 0)
    version: str = data.get("version", "")
    master_copy: str = data.get("masterCopy", "") or data.get("singleton", "")

    is_multisig = threshold > 1 or len(owners) > 1

    return {
        "is_multisig":   is_multisig,
        "confidence":    "high",
        "multisig_type": "gnosis_safe",
        "address_type":  "gnosis_safe",
        "threshold":     threshold,
        "total_signers": len(owners),
        "owners":        owners,
        "safe_version":  version,
        "master_copy":   master_copy,
        "nonce":         nonce,
        "note": (
            f"Gnosis Safe {version} 合约，"
            f"需要 {threshold}/{len(owners)} 签名执行交易，"
            f"已执行 {nonce} 笔交易。"
        ) if is_multisig else (
            f"该地址是 Gnosis Safe {version} 合约，"
            f"但阈值为 {threshold}，签名者 {len(owners)} 人（单签或 1-of-1）。"
        ),
    }


# ─── TRX Analysis ────────────────────────────────────────────────────────────

def _parse_permission(perm: dict) -> dict:
    """Parse a single Tron permission object into a structured dict."""
    keys = perm.get("keys", [])
    return {
        "permission_name": perm.get("permission_name", ""),
        "threshold":       perm.get("threshold", 1),
        "keys": [
            {
                "address": k.get("address", ""),
                "weight":  k.get("weight", 1),
            }
            for k in keys
        ],
    }


def analyze_trx(address: str) -> dict:
    """
    Call Tron's public API to get account details and parse multisig permission structure.
    A TRX account is considered multisig if:
      - owner_permission.threshold > 1, OR
      - owner_permission has more than one key, OR
      - any active_permission has threshold > 1 or multiple keys
    """
    url = f"{TRON_API_URL}/v1/accounts/{address}"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        raise RuntimeError("Tron API 请求超时（20s），请检查网络连接后重试。")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"网络请求错误：{e}")

    if resp.status_code != 200:
        raise RuntimeError(
            f"Tron API 返回异常状态码 {resp.status_code}：{resp.text[:200]}"
        )

    body = resp.json()
    accounts = body.get("data", [])
    if not accounts:
        raise RuntimeError(
            f"未找到 TRX 地址 {address}（账户不存在或尚未激活）。"
        )

    account = accounts[0]

    # Parse owner permission
    owner_perm_raw = account.get("owner_permission", {})
    owner_perm = _parse_permission(owner_perm_raw) if owner_perm_raw else None

    # Parse active permissions (list)
    active_perms_raw = account.get("active_permission", [])
    active_perms = [_parse_permission(p) for p in active_perms_raw]

    # Determine if multisig
    owner_is_multisig = False
    if owner_perm:
        owner_is_multisig = (
            owner_perm["threshold"] > 1 or len(owner_perm["keys"]) > 1
        )

    active_is_multisig = any(
        p["threshold"] > 1 or len(p["keys"]) > 1
        for p in active_perms
    )

    is_multisig = owner_is_multisig or active_is_multisig

    # Collect all unique signer addresses across all permissions
    all_signers: set[str] = set()
    if owner_perm:
        for k in owner_perm["keys"]:
            if k["address"]:
                all_signers.add(k["address"])
    for p in active_perms:
        for k in p["keys"]:
            if k["address"]:
                all_signers.add(k["address"])

    # Build summary note
    if is_multisig:
        details = []
        if owner_perm and owner_is_multisig:
            details.append(
                f"owner_permission: 阈值 {owner_perm['threshold']}，"
                f"共 {len(owner_perm['keys'])} 个授权密钥"
            )
        for p in active_perms:
            if p["threshold"] > 1 or len(p["keys"]) > 1:
                details.append(
                    f"active_permission '{p['permission_name']}': "
                    f"阈值 {p['threshold']}，共 {len(p['keys'])} 个授权密钥"
                )
        note = "TRX 原生多签账户。权限结构：" + "；".join(details) + "。"
    else:
        note = "该 TRX 地址权限阈值为 1 且只有 1 个密钥，是普通单签账户。"

    return {
        "is_multisig":        is_multisig,
        "confidence":         "high",
        "multisig_type":      "tron_native" if is_multisig else None,
        "address_type":       "tron_account",
        "threshold":          owner_perm["threshold"] if owner_perm else None,
        "total_signers":      len(all_signers),
        "owners":             sorted(all_signers),
        "owner_permission":   owner_perm,
        "active_permissions": active_perms,
        "note":               note,
    }


# ─── Output helpers ───────────────────────────────────────────────────────────

def print_result(result: dict, address: str, chain: str, json_output: bool) -> None:
    output = {
        "address": address,
        "chain":   chain,
        **result,
    }

    if json_output:
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return

    c = COLOUR
    is_multisig = result.get("is_multisig")
    confidence  = result.get("confidence", "unknown")
    multisig_type = result.get("multisig_type") or "—"
    address_type  = result.get("address_type") or "—"
    threshold     = result.get("threshold")
    total_signers = result.get("total_signers")
    owners        = result.get("owners", [])

    # Confidence badge
    conf_badge = {
        "high":    f"{c['green']}高{c['reset']}",
        "medium":  f"{c['yellow']}中{c['reset']}",
        "low":     f"{c['yellow']}低{c['reset']}",
        "unknown": f"{c['red']}未知{c['reset']}",
    }.get(confidence, confidence)

    if is_multisig is True:
        status_icon = f"{c['cyan']}✅ 多签地址{c['reset']}"
    elif is_multisig is False:
        status_icon = f"{c['yellow']}— 非多签地址{c['reset']}"
    else:
        status_icon = f"{c['red']}❓ 无法确认{c['reset']}"

    print(f"\n{c['bold']}多签地址分析报告{c['reset']}")
    print("─" * 52)
    print(f"地址：          {address}")
    print(f"链：            {chain}")
    print(f"地址类型：      {address_type}")
    print(f"分析结论：      {status_icon}  （置信度：{conf_badge}）")

    if multisig_type and multisig_type != "—":
        print(f"多签方案：      {multisig_type}")

    if threshold is not None:
        print(f"签名阈值：      {threshold} / {total_signers}（至少需要 {threshold} 个签名者）")

    if owners:
        print(f"签名参与者：    共 {len(owners)} 人")
        for i, owner in enumerate(owners, 1):
            print(f"  [{i:02d}] {owner}")

    # TRX advanced detail
    owner_perm   = result.get("owner_permission")
    active_perms = result.get("active_permissions", [])
    safe_version = result.get("safe_version")
    nonce        = result.get("nonce")

    if owner_perm and (
        owner_perm["threshold"] > 1 or len(owner_perm["keys"]) > 1
    ):
        print(f"\n{c['bold']}Owner 权限（阈值 {owner_perm['threshold']}）：{c['reset']}")
        for k in owner_perm["keys"]:
            print(f"  地址 {k['address']}  权重 {k['weight']}")

    if active_perms:
        for ap in active_perms:
            if ap["threshold"] > 1 or len(ap["keys"]) > 1:
                print(
                    f"{c['bold']}Active 权限 "
                    f"'{ap['permission_name']}' "
                    f"（阈值 {ap['threshold']}）：{c['reset']}"
                )
                for k in ap["keys"]:
                    print(f"  地址 {k['address']}  权重 {k['weight']}")

    if safe_version:
        print(f"Safe 版本：     {safe_version}")
    if nonce is not None:
        print(f"历史交易数：    {nonce} 笔")

    print("─" * 52)
    note = result.get("note", "")
    if note:
        print(f"说明：{note}")
    print()


def print_error(message: str, json_output: bool) -> None:
    if json_output:
        print(json.dumps(
            {"is_multisig": None, "error": message},
            ensure_ascii=False, indent=2
        ))
    else:
        print(f"\n❌  多签地址分析失败\n错误原因：{message}\n", file=sys.stderr)


# ─── Argument parsing ────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    all_chains = sorted(SUPPORTED_CHAINS | set(UNSUPPORTED_CHAINS.keys()))
    parser = argparse.ArgumentParser(
        description=(
            "多签地址识别与权限分析工具\n"
            "支持 BTC（P2SH/P2WSH/P2TR）、ETH/EVM（Gnosis Safe）、TRX（原生权限多签）"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--address", "-a",
        required=True,
        help="待分析的区块链地址",
    )
    parser.add_argument(
        "--chain", "-c",
        required=True,
        choices=all_chains,
        help=(
            f"链标识符\n"
            f"支持：{', '.join(sorted(SUPPORTED_CHAINS))}\n"
            f"不支持（exit 2）：{', '.join(sorted(UNSUPPORTED_CHAINS.keys()))}"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="以 JSON 格式输出结果（适合 Agent 机器解析）",
    )
    return parser.parse_args()


# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()
    chain   = args.chain.lower()
    address = args.address.strip()

    # 1. Handle explicitly unsupported chains
    if chain in UNSUPPORTED_CHAINS:
        print_error(UNSUPPORTED_CHAINS[chain], args.json_output)
        sys.exit(EXIT_UNSUPPORTED)

    # 2. Route to the correct analyzer
    try:
        if chain in BTC_CHAINS:
            result = analyze_btc(address)
        elif chain in TRX_CHAINS:
            result = analyze_trx(address)
        else:
            result = analyze_evm(address, chain)
    except RuntimeError as e:
        print_error(str(e), args.json_output)
        sys.exit(EXIT_ERROR)

    # 3. Print result
    print_result(result, address, chain, args.json_output)

    # 4. Exit code
    is_multisig = result.get("is_multisig")
    if is_multisig is True or is_multisig is None:
        sys.exit(EXIT_IS_MULTISIG)
    else:
        sys.exit(EXIT_NOT_MULTISIG)


if __name__ == "__main__":
    main()
