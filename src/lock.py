"""
lock.py — 安全电子锁

选题三：安全电子锁
模拟安全电子锁的认证决策与门禁控制功能。

核心功能：
  1. 生成挑战（随机 nonce + 时间戳）
  2. 验证钥匙的应答 MAC
  3. 防重放攻击（Nonce 缓存 + 时间窗口）
  4. 锁闭后发送确认信息
  5. 门禁日志记录
"""

import time
import secrets
from typing import Optional, Set, Tuple
from hash_engine import compute_mac, verify_mac
from key import SecurityKey


# ============================================================
# 防重放模块
# ============================================================

class ReplayProtection:
    """
    防重放攻击模块。

    双重防御：
      1. Nonce 缓存：维护最近使用 nonce 集合，拒绝重复 nonce
      2. 时间窗口：挑战有效期为 ±30 秒，超时拒绝
    """

    MAX_NONCE_CACHE = 1000
    WINDOW_SECONDS = 30

    def __init__(self):
        self._used_nonces: Set[bytes] = set()

    def validate(self, nonce: bytes, challenge_ts: int) -> bool:
        """
        验证挑战的防重放属性。

        返回:
            True = 有效，False = 重放/过期
        """
        # Nonce 去重
        if nonce in self._used_nonces:
            print("  [防重放] 警告：检测到重复 nonce！可能是重放攻击。")
            return False

        # 时间窗口
        now = int(time.time())
        if abs(now - challenge_ts) > self.WINDOW_SECONDS:
            print(f"  [防重放] 警告：挑战已过期 "
                  f"(偏差 {abs(now - challenge_ts)}s > {self.WINDOW_SECONDS}s)")
            return False

        # 缓存 nonce
        self._used_nonces.add(nonce)
        if len(self._used_nonces) > self.MAX_NONCE_CACHE:
            items = list(self._used_nonces)
            self._used_nonces = set(items[len(items)//2:])

        return True


# ============================================================
# 安全电子锁
# ============================================================

class SecurityLock:
    """
    安全电子锁 — 认证决策与访问控制节点。

    通过安全信道连接至密钥服务器 (KeyServer)，执行挑战-应答协议
    验证钥匙身份，并控制电锁状态。锁闭后发送确认信息。
    """

    def __init__(self, lock_id: str, key_server):
        """
        初始化电子锁。

        参数:
            lock_id:    锁编号（如 "DOOR-A1"）
            key_server: KeyServer 实例
        """
        self.lock_id = lock_id
        self.key_server = key_server
        self.replay_protector = ReplayProtection()
        self.is_locked = True          # 默认锁定状态
        self.access_log: list = []

    # ---- 开锁认证 ----

    def authenticate(self, key: SecurityKey) -> Tuple[bool, str]:
        """
        执行钥匙认证，通过则开锁。

        流程：
          1. 读取钥匙 UID → 向 KeyServer 查询 PSK
          2. 生成挑战 (nonce, timestamp) → 发送给钥匙
          3. 钥匙返回 MAC → 锁独立计算预期 MAC → 比对
          4. 防重放检查
          5. 通过则解锁，失败则保持锁定

        参数:
            key: 待认证的钥匙

        返回:
            (是否通过, 消息说明)
        """
        uid = key.get_uid()

        # Step 1: 查询 PSK
        psk = self.key_server.get_psk(uid)
        if psk is None:
            self._log(uid, False, "PSK 不存在或已吊销")
            self.is_locked = True
            return False, f"认证失败：钥匙 {uid} 未注册或已被吊销"

        # Step 2: 生成挑战
        nonce = secrets.token_bytes(16)
        timestamp = int(time.time())

        # Step 3: 发送挑战，收到应答
        mac_received = key.respond_to_challenge(nonce, timestamp)

        # Step 4: 锁端独立计算预期 MAC
        uid_bytes = uid.encode("utf-8")
        ts_bytes = timestamp.to_bytes(8, "big")
        expected_message = psk + uid_bytes + nonce + ts_bytes
        mac_expected = compute_mac(psk, expected_message)

        # Step 5: 比对 MAC
        if mac_received != mac_expected:
            self._log(uid, False, "MAC 不匹配")
            self.is_locked = True
            return False, "认证失败：MAC 验证不通过"

        # Step 6: 防重放
        if not self.replay_protector.validate(nonce, timestamp):
            self._log(uid, False, "防重放拦截")
            self.is_locked = True
            return False, "认证失败：重放攻击或挑战过期"

        # Step 7: 开锁
        self.is_locked = False
        self._log(uid, True, f"nonce={nonce.hex()[:12]}...")
        return True, f"认证通过：锁已开启，欢迎 {uid}"

    # ---- 锁闭确认 ----

    def confirm_lock_closed(self, key: SecurityKey) -> Tuple[bool, str]:
        """
        锁关闭后向钥匙发送确认信息，钥匙验证锁身份并发出声音提示。

        流程：
          1. 锁生成确认挑战 (nonce, timestamp)
          2. 锁计算 MAC = Hash(PSK || lock_id || nonce || timestamp)
          3. 发送 (lock_id, nonce, timestamp, MAC) 给钥匙
          4. 钥匙验证 MAC → 通过则发出提示音

        参数:
            key: 对应的钥匙

        返回:
            (钥匙是否确认, 消息)
        """
        uid = key.get_uid()

        # 获取 PSK
        psk = self.key_server.get_psk(uid)
        if psk is None:
            return False, f"确认失败：钥匙 {uid} 未注册"

        # 生成确认挑战
        nonce = secrets.token_bytes(16)
        timestamp = int(time.time())

        # 锁计算确认 MAC
        lock_bytes = self.lock_id.encode("utf-8")
        ts_bytes = timestamp.to_bytes(8, "big")
        message = psk + lock_bytes + nonce + ts_bytes
        confirm_mac = compute_mac(psk, message)

        # 发送给钥匙验证
        print(f"  [Lock-{self.lock_id}] 锁已关闭，发送确认信息...")
        print(f"    → lock_id={self.lock_id}, nonce={nonce.hex()[:12]}...")

        verified = key.verify_lock_confirmation(
            self.lock_id, nonce, timestamp, confirm_mac
        )

        if verified:
            self.is_locked = True
            self._log(uid, True, "锁闭确认通过")
            return True, "锁闭确认成功：钥匙已确认锁身份"
        else:
            self._log(uid, False, "锁闭确认失败")
            return False, "锁闭确认失败：钥匙无法验证锁身份"

    # ---- 日志 ----

    def _log(self, uid: str, granted: bool, detail: str):
        """记录操作日志"""
        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "lock": self.lock_id,
            "uid": uid,
            "result": "OPEN" if granted else "DENY",
            "detail": detail
        }
        self.access_log.append(entry)

    def print_log(self, limit: int = 20):
        """打印日志"""
        entries = self.access_log[-limit:]
        if not entries:
            print("  (暂无记录)")
            return
        for e in entries:
            status = "[OPEN]" if e["result"] == "OPEN" else "[DENY]"
            print(f"  {e['time']} | {status} | {e['uid']} | {e['detail']}")
