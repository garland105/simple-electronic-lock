"""
key.py — 安全电子钥匙

选题三：安全电子锁
模拟电子钥匙的安全凭据存储和密码学运算功能。

核心功能：
  1. 安全存储 UID 和预共享密钥 (PSK)
  2. 响应锁发来的挑战（计算应答 MAC）
  3. 接收锁闭确认信息并验证锁身份
  4. 声音/视觉提示模拟
"""

import sys
from hash_engine import compute_mac, verify_mac


class SecurityKey:
    """
    安全电子钥匙。

    持有卡片唯一标识符（UID）和预共享密钥（PSK）。
    在认证协议中作为被验证方，根据挑战计算应答。
    在锁闭确认中作为验证方，验证锁发来的确认信息。
    """

    def __init__(self, uid: str, psk: bytes):
        """
        初始化钥匙。

        参数:
            uid:  钥匙唯一标识符（模拟硬件 ROM 中的序列号）
            psk:  预共享密钥（模拟安全芯片中存储的密钥）
        """
        self.uid = uid
        self._psk = psk  # 私密，不可外部直接访问

    def get_uid(self) -> str:
        """返回钥匙 UID（公开可读）"""
        return self.uid

    # ---- 挑战-应答 ----

    def respond_to_challenge(self, nonce: bytes, timestamp: int) -> bytes:
        """
        响应锁发来的挑战。

        计算: MAC = SimpleHash-128(PSK || UID || nonce || timestamp)

        参数:
            nonce:     16 字节随机数
            timestamp: Unix 时间戳

        返回:
            16 字节 MAC 应答值
        """
        uid_bytes = self.uid.encode("utf-8")
        ts_bytes = timestamp.to_bytes(8, "big")
        message = self._psk + uid_bytes + nonce + ts_bytes
        return compute_mac(self._psk, message)

    # ---- 锁闭确认 ----

    def verify_lock_confirmation(self, lock_id: str, nonce: bytes,
                                  timestamp: int, mac: bytes) -> bool:
        """
        验证锁发来的关闭确认信息。

        锁关闭后发送 (lock_id, nonce, timestamp, MAC)，
        钥匙重新计算预期 MAC 并比对，同时发出声音提示。

        参数:
            lock_id:   锁编号
            nonce:     16 字节随机数（锁生成）
            timestamp: Unix 时间戳
            mac:       锁发送的 MAC

        返回:
            True = 锁身份验证通过，False = 验证失败
        """
        lock_bytes = lock_id.encode("utf-8")
        ts_bytes = timestamp.to_bytes(8, "big")
        message = self._psk + lock_bytes + nonce + ts_bytes
        expected_mac = compute_mac(self._psk, message)

        if mac == expected_mac:
            self._beep_ok()
            return True
        else:
            self._beep_fail()
            return False

    # ---- 声音提示模拟 ----

    def _beep_ok(self):
        """认证成功提示音"""
        print(f"  [Key-{self.uid}] 🔊 嘀——认证通过！锁已安全关闭。")
        try:
            sys.stdout.write("\a")
            sys.stdout.flush()
        except Exception:
            pass

    def _beep_fail(self):
        """认证失败提示音"""
        print(f"  [Key-{self.uid}] 🔇 嘀嘀嘀——验证失败！锁身份存疑。")
        try:
            sys.stdout.write("\a\a\a")
            sys.stdout.flush()
        except Exception:
            pass
