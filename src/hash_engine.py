"""
hash_engine.py — 简化版Hash算法 SimpleHash-128

设计原理：
  采用 Merkle-Damgård 迭代结构，将任意长度消息压缩为 128-bit 摘要。
  与 SHA-1 结构类似，但压缩轮数减半（40轮），作为教学级简化实现。

核心参数：
  - 输出长度：128 bit (16 bytes)
  - 分组长度：512 bit (64 bytes)
  - 字长：32 bit
  - 状态：4 个 32-bit 字 (A, B, C, D)
  - 压缩轮数：40 轮

安全特性：
  - 雪崩效应：输入 1-bit 变化导致输出约 50% 位翻转
  - 抗原像性：计算上不可行从 hash 值反推原文
  - 抗碰撞性：找到两个不同消息生成相同 hash 计算上困难
"""

import struct


# ============================================================
# 常量定义
# ============================================================

# 初始向量 IV (与 SHA-1 初始值一致)
IV_A = 0x67452301
IV_B = 0xEFCDAB89
IV_C = 0x98BADCFE
IV_D = 0x10325476

# 轮常量 K (截取自 SHA-1 的四个阶段常量)
K_CONSTANTS = [
    0x5A827999,  # t = 0..9
    0x6ED9EBA1,  # t = 10..19
    0x8F1BBCDC,  # t = 20..29
    0xCA62C1D6,  # t = 30..39
]


# ============================================================
# 辅助函数
# ============================================================

def _rotl32(x: int, n: int) -> int:
    """32-bit 循环左移"""
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f_ch(x: int, y: int, z: int) -> int:
    """选择函数 Ch: (x & y) ^ (~x & z)"""
    return (x & y) ^ ((~x & 0xFFFFFFFF) & z)


def _f_parity(x: int, y: int, z: int) -> int:
    """奇偶函数 Parity: x ^ y ^ z"""
    return x ^ y ^ z


def _f_maj(x: int, y: int, z: int) -> int:
    """多数函数 Maj: (x & y) ^ (x & z) ^ (y & z)"""
    return (x & y) ^ (x & z) ^ (y & z)


def _get_f(t: int, b: int, c: int, d: int) -> int:
    """根据轮次 t 选择对应的非线性函数"""
    if t < 10:
        return _f_ch(b, c, d)
    elif t < 20:
        return _f_parity(b, c, d)
    elif t < 30:
        return _f_maj(b, c, d)
    else:
        return _f_parity(b, c, d)


def _get_k(t: int) -> int:
    """根据轮次 t 返回对应的轮常量"""
    return K_CONSTANTS[t // 10]


# ============================================================
# 消息填充 (Padding)
# ============================================================

def _pad_message(message: bytes) -> bytes:
    """
    SHA-1 风格的消息填充：
    1. 追加 0x80 (bit '1')
    2. 追加 0x00 直到 (原始长度 + padding) ≡ 448 (mod 512) ——即 56 (mod 64) 字节
    3. 最后 8 字节填入原始消息位数 (big-endian)
    """
    msg_len_bits = len(message) * 8

    # 追加 '1' bit (0x80)
    message += b'\x80'

    # 追加 '0' bits 直到长度 ≡ 56 (mod 64)
    while (len(message) % 64) != 56:
        message += b'\x00'

    # 追加 64-bit 原始消息位数 (big-endian)
    message += struct.pack('>Q', msg_len_bits)

    return message


# ============================================================
# 核心：分组压缩函数
# ============================================================

def _compress_block(block: bytes, state: list) -> list:
    """
    处理单个 512-bit 消息分组，更新 4-word 状态。

    参数:
        block: 64 字节消息分组
        state: [A, B, C, D] 4 个 32-bit 字列表

    返回:
        更新后的 [A, B, C, D]
    """
    # 1. 将 64 字节分组拆分为 16 个 32-bit 大端字
    W = list(struct.unpack('>16I', block))

    # 2. 消息扩展：扩展到 40 个字
    for t in range(16, 40):
        w = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]
        W.append(_rotl32(w, 1))

    # 3. 初始化工作变量
    a, b, c, d = state

    # 4. 40 轮压缩
    for t in range(40):
        temp = (_rotl32(a, 5) +
                _get_f(t, b, c, d) +
                d +
                W[t] +
                _get_k(t))
        temp &= 0xFFFFFFFF
        d = c
        c = _rotl32(b, 30)
        b = a
        a = temp

    # 5. 状态累加
    state[0] = (state[0] + a) & 0xFFFFFFFF
    state[1] = (state[1] + b) & 0xFFFFFFFF
    state[2] = (state[2] + c) & 0xFFFFFFFF
    state[3] = (state[3] + d) & 0xFFFFFFFF

    return state


# ============================================================
# 公开接口
# ============================================================

def simple_hash_128(data: bytes) -> bytes:
    """
    计算 SimpleHash-128 摘要。

    参数:
        data: 任意长度的字节串

    返回:
        16 字节 (128-bit) hash 值
    """
    # 初始化状态
    state = [IV_A, IV_B, IV_C, IV_D]

    # 消息填充
    padded = _pad_message(data)

    # 逐分组压缩
    for i in range(0, len(padded), 64):
        block = padded[i:i + 64]
        state = _compress_block(block, state)

    # 输出：4 个 32-bit 字按大端序拼接为 16 字节
    return struct.pack('>4I', state[0], state[1], state[2], state[3])


def simple_hash_hex(data: bytes) -> str:
    """返回十六进制表示的 hash 值"""
    return simple_hash_128(data).hex()


def simple_hash_str(text: str) -> str:
    """对 UTF-8 字符串计算 hash，返回十六进制"""
    return simple_hash_hex(text.encode('utf-8'))


# ============================================================
# 消息认证码 MAC
# ============================================================

def compute_mac(key: bytes, message: bytes) -> bytes:
    """
    基于 SimpleHash-128 的简单 MAC：MAC = Hash(key || message)

    用于挑战应答协议中的应答生成，绑定密钥与挑战数据。
    """
    return simple_hash_128(key + message)


def compute_mac_hex(key: bytes, message: bytes) -> str:
    """返回十六进制 MAC 值"""
    return compute_mac(key, message).hex()


def verify_mac(key: bytes, message: bytes, expected: bytes) -> bool:
    """验证 MAC 值是否匹配"""
    return compute_mac(key, message) == expected


# ============================================================
# 自测（雪崩效应验证）
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("SimpleHash-128 自测")
    print("=" * 60)

    # 测试 1: 基本 hash
    msg = b"Hello, IoT Security!"
    h1 = simple_hash_hex(msg)
    print(f"\n[测试1] 消息: {msg.decode()}")
    print(f"  Hash: {h1}")
    print(f"  长度: {len(h1)} 个十六进制字符 ({len(h1)//2} 字节)")

    # 测试 2: 1-bit 翻转 → 雪崩效应
    msg2 = b"Hello, IoT Security#"
    h2 = simple_hash_hex(msg2)
    diff_bits = 0
    for i in range(32):  # 128 bits = 32 hex chars
        if h1[i] != h2[i]:
            nibble1 = int(h1[i], 16)
            nibble2 = int(h2[i], 16)
            diff_bits += bin(nibble1 ^ nibble2).count('1')
    print(f"\n[测试2] 消息末字节 0x21→0x23 (1-bit 翻转)")
    print(f"  原 Hash: {h1}")
    print(f"  新 Hash: {h2}")
    print(f"  翻转比特数: {diff_bits}/128 ({diff_bits/128*100:.1f}%)")

    # 测试 3: 空消息
    print(f"\n[测试3] 空消息 Hash: {simple_hash_hex(b'')}")

    # 测试 4: 长消息
    long_msg = b"Internet of Things Security" * 100
    print(f"\n[测试4] 长消息 ({len(long_msg)} 字节) Hash: {simple_hash_hex(long_msg)[:32]}...")

    # 测试 5: MAC 正确性
    key = b"secret-key-12345"
    message = b"card-uid-001|challenge-nonce-abc|timestamp-1234"
    mac = compute_mac(key, message)
    print(f"\n[测试5] MAC 计算")
    print(f"  密钥: {key.decode()}")
    print(f"  消息: {message.decode()}")
    print(f"  MAC:  {mac.hex()}")
    print(f"  验证: {'通过' if verify_mac(key, message, mac) else '失败'}")

    print("\n" + "=" * 60)
    print("自测完成")
