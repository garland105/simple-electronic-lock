"""
key_server.py — 密钥管理服务器

功能：
  1. 主密钥生成与安全存储
  2. 基于 HKDF 风格的每卡预共享密钥 (PSK) 派生
  3. 密钥查询接口（供读卡器认证时使用）
  4. 密钥轮换（主密钥更新 + 全部卡片密钥重新派生）

密钥派生策略：
  PSK = SimpleHash-128(master_key || uid || salt)
  其中 salt 为随机 16 字节，与 PSK 一起存储便于验证。
"""

import json
import os
import secrets
import base64
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional

from hash_engine import simple_hash_128, simple_hash_hex


# ============================================================
# 数据结构
# ============================================================

@dataclass
class CardKeyEntry:
    """单张卡片的密钥记录"""
    uid: str                    # 卡片唯一标识
    psk: bytes                  # 预共享密钥 (16 bytes)
    salt: bytes                 # 密钥派生盐值 (16 bytes)
    created_at: str             # 创建时间 (ISO format)
    status: str = "active"      # active | revoked


@dataclass
class KeyStore:
    """密钥库"""
    master_key_hash: str        # 主密钥的 hash 值（仅用于完整性校验，不泄露主密钥本身）
    master_key: bytes           # 主密钥 (32 bytes) — 实际部署中应在 HSM/TEE 中保护
    cards: Dict[str, CardKeyEntry] = field(default_factory=dict)


# ============================================================
# 密钥管理服务器
# ============================================================

class KeyServer:
    """
    密钥管理服务器核心类。

    采用 主密钥 → 卡片密钥 的二级派生架构：
    - 主密钥：系统初始化时随机生成，用于派生所有卡片密钥
    - 卡片密钥 PSK：由 主密钥 + 卡UID + 盐值 通过 SimpleHash-128 派生
    """

    STORAGE_FILE = "keystore.json"

    def __init__(self, storage_dir: str = "."):
        """
        初始化密钥服务器。

        参数:
            storage_dir: 密钥库 JSON 文件存储目录
        """
        self.storage_dir = storage_dir
        self.storage_path = os.path.join(storage_dir, self.STORAGE_FILE)
        self.keystore: Optional[KeyStore] = None

    # ---- 初始化与持久化 ----

    def initialize(self, force: bool = False) -> bool:
        """
        系统初始化：生成主密钥，创建空白密钥库。

        参数:
            force: 是否强制覆盖已有密钥库
        返回:
            是否成功初始化
        """
        if os.path.exists(self.storage_path) and not force:
            print("[KeyServer] 密钥库已存在，使用 load() 加载或 force=True 重新初始化。")
            return False

        # 生成 32 字节主密钥 (256-bit，使用安全随机数)
        master_key = secrets.token_bytes(32)

        # 计算主密钥 hash (仅用于完整性校验)
        master_key_hash = simple_hash_hex(master_key)

        self.keystore = KeyStore(
            master_key_hash=master_key_hash,
            master_key=master_key,
            cards={}
        )

        self._save()
        print(f"[KeyServer] 系统初始化完成。主密钥 Hash: {master_key_hash[:16]}...")
        return True

    def load(self) -> bool:
        """从磁盘加载密钥库"""
        if not os.path.exists(self.storage_path):
            print("[KeyServer] 密钥库文件不存在，请先调用 initialize()。")
            return False

        with open(self.storage_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        # 恢复主密钥
        master_key = base64.b64decode(raw["master_key"])

        # 恢复卡片密钥
        cards = {}
        for uid, entry in raw["cards"].items():
            cards[uid] = CardKeyEntry(
                uid=entry["uid"],
                psk=base64.b64decode(entry["psk"]),
                salt=base64.b64decode(entry["salt"]),
                created_at=entry["created_at"],
                status=entry.get("status", "active")
            )

        self.keystore = KeyStore(
            master_key_hash=raw["master_key_hash"],
            master_key=master_key,
            cards=cards
        )

        # 完整性校验
        computed_hash = simple_hash_hex(master_key)
        if computed_hash != raw["master_key_hash"]:
            print("[KeyServer] [WARN] 主密钥完整性校验失败！可能已被篡改。")
            return False

        print(f"[KeyServer] 密钥库加载成功。已注册 {len(cards)} 张卡片。")
        return True

    def _save(self):
        """将密钥库序列化并持久化到磁盘"""
        serializable = {
            "master_key_hash": self.keystore.master_key_hash,
            "master_key": base64.b64encode(self.keystore.master_key).decode("ascii"),
            "cards": {}
        }

        for uid, entry in self.keystore.cards.items():
            serializable["cards"][uid] = {
                "uid": entry.uid,
                "psk": base64.b64encode(entry.psk).decode("ascii"),
                "salt": base64.b64encode(entry.salt).decode("ascii"),
                "created_at": entry.created_at,
                "status": entry.status
            }

        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2, ensure_ascii=False)

    # ---- 卡片密钥管理 ----

    def register_card(self, uid: str) -> Optional[bytes]:
        """
        为指定 UID 的卡片派发预共享密钥 (PSK)。

        PSK = SimpleHash-128(master_key || UID || salt)

        参数:
            uid: 卡片唯一标识
        返回:
            16 字节 PSK，失败返回 None
        """
        if self.keystore is None:
            print("[KeyServer] 错误：密钥库未初始化。")
            return None

        if uid in self.keystore.cards:
            print(f"[KeyServer] 卡片 {uid} 已注册，返回已有 PSK。")
            return self.keystore.cards[uid].psk

        # 生成随机盐值
        salt = secrets.token_bytes(16)

        # 派生 PSK: PSK = Hash(master_key || uid || salt)
        derivation_material = self.keystore.master_key + uid.encode("utf-8") + salt
        psk = simple_hash_128(derivation_material)

        # 记录入库
        from datetime import datetime
        entry = CardKeyEntry(
            uid=uid,
            psk=psk,
            salt=salt,
            created_at=datetime.now().isoformat()
        )
        self.keystore.cards[uid] = entry
        self._save()

        print(f"[KeyServer] 卡片 {uid} 注册成功。PSK: {psk.hex()[:16]}...")
        return psk

    def get_psk(self, uid: str) -> Optional[bytes]:
        """查询指定 UID 的预共享密钥"""
        if self.keystore is None or uid not in self.keystore.cards:
            return None
        entry = self.keystore.cards[uid]
        if entry.status != "active":
            return None
        return entry.psk

    def revoke_card(self, uid: str) -> bool:
        """吊销指定卡片"""
        if self.keystore is None or uid not in self.keystore.cards:
            return False
        self.keystore.cards[uid].status = "revoked"
        self._save()
        print(f"[KeyServer] 卡片 {uid} 已吊销。")
        return True

    def list_cards(self) -> list:
        """列出所有注册卡片"""
        if self.keystore is None:
            return []
        return [
            {"uid": uid, "status": e.status, "created_at": e.created_at}
            for uid, e in self.keystore.cards.items()
        ]

    def rotate_master_key(self) -> bool:
        """
        主密钥轮换：
        1. 生成新的主密钥
        2. 为所有 active 卡片重新派生 PSK
        """
        if self.keystore is None:
            return False

        new_master = secrets.token_bytes(32)
        new_hash = simple_hash_hex(new_master)

        # 为每张 active 卡片重新派生 PSK
        for uid, entry in self.keystore.cards.items():
            if entry.status != "active":
                continue
            new_salt = secrets.token_bytes(16)
            derivation = new_master + uid.encode("utf-8") + new_salt
            entry.psk = simple_hash_128(derivation)
            entry.salt = new_salt

        self.keystore.master_key = new_master
        self.keystore.master_key_hash = new_hash
        self._save()

        print(f"[KeyServer] 主密钥轮换完成。新主密钥 Hash: {new_hash[:16]}...")
        return True


# ============================================================
# 自测
# ============================================================

if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        print("=" * 60)
        print("KeyServer 自测")
        print("=" * 60)

        # 初始化 & 注册卡片
        ks = KeyServer(tmpdir)
        assert ks.initialize(), "初始化失败"

        psk1 = ks.register_card("CARD-001")
        psk2 = ks.register_card("CARD-002")
        psk3 = ks.register_card("CARD-003")

        assert psk1 is not None and psk2 is not None, "注册失败"
        assert len(psk1) == 16, f"PSK 长度错误: {len(psk1)}"

        print(f"\n[测试] 三张卡片注册成功，PSK 均不同: "
              f"{psk1 != psk2 and psk2 != psk3 and psk1 != psk3}")

        # 查询 PSK
        retrieved = ks.get_psk("CARD-001")
        assert retrieved == psk1, "PSK 查询不一致"

        # 吊销
        ks.revoke_card("CARD-003")
        assert ks.get_psk("CARD-003") is None, "吊销后仍可获取 PSK"

        print(f"\n[测试] 卡片列表: {ks.list_cards()}")

        # 持久化 & 重新加载
        ks2 = KeyServer(tmpdir)
        assert ks2.load(), "重新加载失败"
        assert ks2.get_psk("CARD-001") == psk1, "重新加载后 PSK 不一致"

        # 主密钥轮换
        old_psk = ks2.get_psk("CARD-001")
        ks2.rotate_master_key()
        new_psk = ks2.get_psk("CARD-001")
        assert old_psk != new_psk, "密钥轮换后 PSK 未变化"
        print(f"\n[测试] 密钥轮换后 PSK 已更新")

        print("\n" + "=" * 60)
        print("KeyServer 自测全部通过")
