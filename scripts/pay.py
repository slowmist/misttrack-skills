#!/usr/bin/env python3
"""
x402 支付

处理 HTTP 402 支付流程:
- 默认使用 EIP-3009 (transferWithAuthorization) 支付 USDC
- Solana 部分签名
- Permit2 (通用 ERC-20 备用方案)

用法:

  # 完整的 HTTP 402 流程 (请求 + 支付 + 重试)
  python3 pay.py pay \
    --url https://openapi.misttrack.io/x402/address_labels \
    --private-key <hex> \
    --chain-id 8453

  # 对 402 响应中的 EIP-3009 支付进行签名
  python3 pay.py sign-eip3009 \
    --private-key <hex> \
    --token 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
    --chain-id 8453 \
    --to 0x209693Bc6afc0C5328bA36FaF03C514EF312287C \
    --amount 10000 \
    --token-name "USD Coin" \
    --token-version "2" \
    --max-timeout 60

  # 对 Solana 部分交易进行签名
  python3 pay.py sign-solana \
    --private-key <hex> \
    --transaction <base64-encoded-tx>

"""

import argparse
import base64
import json
import os
import sys
import time


def _keccak256(data: bytes) -> bytes:
    """计算 keccak256 哈希。"""
    from eth_utils import keccak
    return keccak(data)


def _eip712_hash(token_name, token_version, chain_id, token_address,
                 from_addr, to_addr, value, valid_after, valid_before,
                 nonce_bytes):
    """计算用于 TransferWithAuthorization (EIP-3009) 的 EIP-712 哈希。

    这是手动实现，以匹配 x402 接收方的验证标准。
    eth_account.encode_typed_data 对 bytes32 的编码方式不同，
    这会产生接收方拒绝的哈希值。
    """
    from eth_abi import encode

    # EIP712Domain 类型哈希
    domain_type_hash = _keccak256(
        b"EIP712Domain(string name,string version,"
        b"uint256 chainId,address verifyingContract)")
    domain_separator = _keccak256(
        domain_type_hash
        + _keccak256(token_name.encode())
        + _keccak256(token_version.encode())
        + encode(["uint256"], [chain_id])
        + encode(["address"], [token_address]))

    # TransferWithAuthorization 类型哈希
    auth_type_hash = _keccak256(
        b"TransferWithAuthorization(address from,address to,"
        b"uint256 value,uint256 validAfter,uint256 validBefore,"
        b"bytes32 nonce)")
    struct_hash = _keccak256(
        auth_type_hash
        + encode(["address"], [from_addr])
        + encode(["address"], [to_addr])
        + encode(["uint256"], [value])
        + encode(["uint256"], [valid_after])
        + encode(["uint256"], [valid_before])
        + nonce_bytes)  # 原始 32 字节，不要进行 abi 编码

    return _keccak256(b"\x19\x01" + domain_separator + struct_hash)


def sign_eip3009(private_key, token_address, chain_id, to, amount,
                 token_name="USD Coin", token_version="2", max_timeout=60):
    """为 x402 的 EIP-3009 支付签名 transferWithAuthorization。

    返回包含 'signature' 和 'authorization' 字段的字典。
    """
    from eth_account import Account

    now = int(time.time())
    nonce_bytes = os.urandom(32)
    nonce_hex = "0x" + nonce_bytes.hex()
    acct = Account.from_key(private_key)

    valid_after = now - 600  # 允许 10 分钟时钟偏差（与官方 SDK 一致）
    valid_before = now + max_timeout

    msg_hash = _eip712_hash(
        token_name, token_version, chain_id, token_address,
        acct.address, to, int(amount), valid_after, valid_before, nonce_bytes)

    signed = acct.unsafe_sign_hash(msg_hash)

    return {
        "signature": "0x" + signed.signature.hex(),
        "authorization": {
            "from": acct.address,
            "to": to,
            "value": str(int(amount)),
            "validAfter": str(valid_after),
            "validBefore": str(valid_before),
            "nonce": nonce_hex,
        }
    }


def sign_solana_partial(private_key_hex, serialized_tx_b64):
    """部分签名一个 Solana x402 支付交易。

    返回 base64 编码的包含部分签名的交易。
    """
    import base58
    from solders.keypair import Keypair
    from solders.transaction import VersionedTransaction

    kp = Keypair.from_seed(bytes.fromhex(private_key_hex))
    tx_bytes = base64.b64decode(serialized_tx_b64)
    vtx = VersionedTransaction.from_bytes(tx_bytes)

    # 通过匹配公钥找到我们的签名者索引
    our_index = -1
    for i, key in enumerate(vtx.message.account_keys):
        if key == kp.pubkey():
            our_index = i
            break

    if our_index == -1:
        raise ValueError(f"钱包 {kp.pubkey()} 不在交易签名者中")

    # 解码 shortvec 以找到签名数组边界
    original_bytes = bytes(vtx)
    idx = 0
    result = 0
    shift = 0
    while True:
        byte = original_bytes[idx]
        result |= (byte & 0x7F) << shift
        idx += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
    sig_count = result
    sig_array_start = idx

    # 提取消息字节 (位于所有签名之后)
    msg_bytes = original_bytes[sig_array_start + sig_count * 64:]

    # 签名消息
    sig = kp.sign_message(msg_bytes)

    # 拼接到正确的槽位
    new_tx = bytearray(original_bytes)
    offset = sig_array_start + our_index * 64
    new_tx[offset:offset + 64] = bytes(sig)

    return base64.b64encode(bytes(new_tx)).decode()


def build_payment_payload(payment_required, private_key, chain_id=None):
    """从 402 PaymentRequired 响应构建 PaymentPayload。

    接受完整的 PaymentRequired（包含 accepts[]）和单个 PaymentRequirements 对象。
    根据网络自动选择 EIP-3009 或 Solana。
    返回已准备好填入 PAYMENT-SIGNATURE 请求头的字典 PaymentPayload。
    """
    # 处理完整的 PaymentRequired 和单项 requirements
    # 硬性上限：拒绝超过 $1 USDC (1_000_000 单位，6 位小数) 的支付
    # 借此防止恶意服务器通过抬高 402 费用耗尽钱包
    # 如确定需要更高支付金额，可通过 max_amount 参数覆盖
    MAX_AMOUNT = 1_000_000  # $1.00 USDC

    if "accepts" in payment_required:
        req = payment_required["accepts"][0]
    else:
        req = payment_required

    amount = int(req.get("amount", 0))
    if amount > MAX_AMOUNT:
        raise ValueError(
            f"支付金额 {amount} 超过了硬性上限 {MAX_AMOUNT} "
            f"(${amount / 1_000_000:.2f} > ${MAX_AMOUNT / 1_000_000:.2f} USDC)。 "
            f"拒绝签名 —— 可能是恶意服务器。"
        )

    scheme = req.get("scheme", "exact")
    network = req.get("network", "")

    payload = {
        "x402Version": 2,
        "accepted": req,
    }

    if network.startswith("eip155:"):
        # EVM 支付
        cid = int(network.split(":")[1]) if not chain_id else chain_id
        extra = req.get("extra", {})
        method = extra.get("assetTransferMethod", "eip3009")

        if method == "eip3009":
            result = sign_eip3009(
                private_key=private_key,
                token_address=req["asset"],
                chain_id=cid,
                to=req["payTo"],
                amount=req["amount"],
                token_name=extra.get("name", "USD Coin"),
                token_version=extra.get("version", "2"),
                max_timeout=req.get("maxTimeoutSeconds", 60),
            )
            payload["payload"] = result
        else:
            raise NotImplementedError(f"尚未实现 Permit2 签名")

    elif network.startswith("solana:"):
        raise NotImplementedError(
            "Solana x402 需要先构建交易。"
            "请对提前构建好的交易使用 sign-solana 子命令。"
        )
    else:
        raise ValueError(f"不支持的网络: {network}")

    return payload


def cmd_sign_eip3009(args):
    """签名 EIP-3009 transferWithAuthorization。"""
    result = sign_eip3009(
        private_key=args.private_key,
        token_address=args.token,
        chain_id=args.chain_id,
        to=args.to,
        amount=args.amount,
        token_name=args.token_name,
        token_version=args.token_version,
        max_timeout=args.max_timeout,
    )
    print(json.dumps(result, indent=2))


def cmd_sign_solana(args):
    """部分签名 Solana x402 交易。"""
    result = sign_solana_partial(args.private_key, args.transaction)
    print(result)


def request_with_x402(url, private_key, chain_id=None, method="GET", data=None, headers=None, auto_pay=False):
    """
    程序化 HTTP 402 支付流程。
    如果响应为 HTTP 402，它将处理解析 402 支付要求，
    提示确认或自动签名支付，并携带 PAYMENT-SIGNATURE 重新尝试该请求。
    """
    import requests as req_lib

    if headers is None:
        headers = {}
    if data:
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
    body = data.encode() if isinstance(data, str) else data

    # 步骤 1: 初始请求
    resp = req_lib.request(method, url, headers=headers, data=body)

    if resp.status_code != 402:
        return resp

    # 步骤 2: 解析支付要求
    pr_header = (resp.headers.get("payment-required")
                 or resp.headers.get("PAYMENT-REQUIRED", ""))
    if not pr_header:
        print(f"错误: 402 响应缺失 payment-required 请求头\nHeaders: {dict(resp.headers)}")
        return resp

    payment_required = json.loads(base64.b64decode(pr_header))
    accepts = payment_required.get("accepts", [{}])
    req_info = accepts[0] if accepts else {}
    amount = int(req_info.get("amount", 0))
    decimals = 6  # USDC 默认
    usd = amount / (10 ** decimals)
    print(f"要求支付: ${usd:.6f} USDC 网络 {req_info.get('network', '?')}")
    print(f"  收款方: {req_info.get('payTo', '?')}")
    print(json.dumps(payment_required, indent=2))

    if not auto_pay:
        confirm = input("\n确认支付? [y/N] ")
        if confirm.lower() != "y":
            print("已取消。")
            return None

    # 步骤 3: 构建并签名支付
    payload = build_payment_payload(payment_required, private_key, chain_id)
    payment_sig = base64.b64encode(json.dumps(payload).encode()).decode()

    # 步骤 4: 携带支付重试
    headers["PAYMENT-SIGNATURE"] = payment_sig
    resp2 = req_lib.request(method, url, headers=headers, data=body)

    return resp2


def cmd_pay(args):
    """完整的 HTTP 402 支付流程: 请求 → 解析 402 → 签名 → 重试。"""
    headers = {}
    if args.header:
        for h in args.header:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    resp2 = request_with_x402(
        url=args.url,
        private_key=args.private_key,
        chain_id=args.chain_id,
        method=args.method.upper(),
        data=args.data,
        headers=headers,
        auto_pay=args.auto
    )

    if not resp2:
        return

    print(f"\n响应状态码: {resp2.status_code}")
    for hdr in ["payment-response", "PAYMENT-RESPONSE"]:
        if hdr in resp2.headers:
            pr = json.loads(base64.b64decode(resp2.headers[hdr]))
            print("结算结果:", json.dumps(pr, indent=2))
            break
    print(resp2.text[:5000])


def main():
    parser = argparse.ArgumentParser(description="x402 支付客户端")
    sub = parser.add_subparsers(dest="command")

    # sign-eip3009
    p = sub.add_parser("sign-eip3009", help="签名 EIP-3009 transferWithAuthorization")
    p.add_argument("--private-key", default=os.environ.get("X402_PRIVATE_KEY"),
                   help="Hex 私钥 (或者设置 X402_PRIVATE_KEY 环境变量)")
    p.add_argument("--token", required=True, help="Token 合约地址")
    p.add_argument("--chain-id", type=int, required=True, help="EVM 链 ID")
    p.add_argument("--to", required=True, help="支付接收方 (payTo)")
    p.add_argument("--amount", type=int, required=True, help="金额的最小单位 (例如 10000 即 $0.01 USDC)")
    p.add_argument("--token-name", default="USD Coin", help="EIP-712 domain Token 名称")
    p.add_argument("--token-version", default="2", help="EIP-712 domain Token 版本")
    p.add_argument("--max-timeout", type=int, default=60, help="最大超时秒数")
    p.set_defaults(func=cmd_sign_eip3009)

    # sign-solana
    p = sub.add_parser("sign-solana", help="部分签名 Solana x402 交易")
    p.add_argument("--private-key", default=os.environ.get("X402_PRIVATE_KEY"),
                   help="Hex 私钥, 32 字节 seed (或者设置 X402_PRIVATE_KEY 环境变量)")
    p.add_argument("--transaction", required=True, help="Base64 编码后的序列化交易")
    p.set_defaults(func=cmd_sign_solana)

    # pay
    p = sub.add_parser("pay", help="完整的 HTTP 402 支付流程")
    p.add_argument("--url", required=True, help="要访问的 URL")
    p.add_argument("--private-key", default=os.environ.get("X402_PRIVATE_KEY"),
                   help="Hex 私钥 (或者设置 X402_PRIVATE_KEY 环境变量)")
    p.add_argument("--chain-id", type=int, help="首选项 链 ID")
    p.add_argument("--method", default="GET", help="HTTP 请求方法 (默认: GET)")
    p.add_argument("--data", help="请求体 (JSON 字符串)")
    p.add_argument("--header", nargs="*", help="额外请求头 (key: value)")
    p.add_argument("--auto", action="store_true",
                   help="自动静默支付并跳过确认 (仅限测试, 请勿在生产环境的 Agent 中使用)")
    p.set_defaults(func=cmd_pay)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    if hasattr(args, "private_key") and not args.private_key:
        print("错误: 需要设置 --private-key 请求参数 (或者设置 X402_PRIVATE_KEY 环境变量)")
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()