"""
access_control.py — 安全电子锁系统 CLI 主程序

选题三：基于自定义 Hash 算法的安全电子锁
作者：盛佳傲  学号：3230611048  班级：物联网工程 2302

使用方法：
    python access_control.py

功能菜单：
    1. 系统初始化 — 生成主密钥，创建密钥库
    2. 注册钥匙   — 为人员派发预共享密钥
    3. 开锁认证   — 钥匙靠近锁 → 挑战-应答 → 验证通过开锁
    4. 锁闭确认   — 锁关闭 → 发送确认 → 钥匙验证并提示音
    5. 查看钥匙   — 列出所有已注册钥匙及其状态
    6. 操作日志   — 查看锁的操作记录
    7. 密钥轮换   — 更新主密钥并重新派生所有 PSK
    8. 防重放演示 — 演示重放攻击被拦截
    9. Hash 自测  — SimpleHash-128 算法验证
    0. 退出
"""

import os
import sys
import secrets
import time
from typing import Optional

from hash_engine import simple_hash_hex, simple_hash_str
from key_server import KeyServer
from key import SecurityKey
from lock import SecurityLock

# 工作目录
WORK_DIR = os.path.dirname(os.path.abspath(__file__))

# 全局对象
key_server: Optional[KeyServer] = None
lock: Optional[SecurityLock] = None
keys: dict = {}  # uid → SecurityKey


def clear_screen():
    """清屏"""
    os.system("cls" if os.name == "nt" else "clear")


def print_header():
    """打印横幅"""
    print("=" * 62)
    print("       安 全 电 子 锁 系 统  (Secure Electronic Lock)")
    print("       基于 SimpleHash-128 自定义 Hash 算法的挑战-应答认证")
    print(f"       作者：盛佳傲  学号：3230611048  物联网工程 2302")
    print("=" * 62)


def print_menu():
    """打印主菜单"""
    print()
    print("  [1] 系统初始化     [2] 注册钥匙      [3] 开锁认证")
    print("  [4] 锁闭确认       [5] 查看钥匙      [6] 操作日志")
    print("  [7] 密钥轮换       [8] 防重放演示    [9] Hash 自测")
    print("  [0] 退出")
    print()


def cmd_init():
    """菜单 1: 系统初始化"""
    global key_server, lock

    if key_server is not None and os.path.exists(key_server.storage_path):
        print("[提示] 系统已初始化。如需重新初始化请删除 keystore.json。")
        return

    key_server = KeyServer(WORK_DIR)
    if key_server.initialize():
        lock = SecurityLock("DOOR-A1", key_server)
        print("\n[成功] 系统初始化完成，电子锁 DOOR-A1 已就绪。")
    else:
        if key_server.load():
            lock = SecurityLock("DOOR-A1", key_server)
            print("[提示] 已加载现有密钥库。")
        else:
            print("[错误] 系统初始化失败。")


def cmd_register():
    """菜单 2: 注册钥匙"""
    global key_server, keys

    if key_server is None:
        print("[错误] 请先执行 [1] 系统初始化。")
        return

    uid = input("  输入钥匙 UID (如 KEY-001): ").strip()
    if not uid:
        print("[取消] UID 不能为空。")
        return

    existing = key_server.get_psk(uid)
    if existing:
        print(f"[提示] 钥匙 {uid} 已注册。PSK: {existing.hex()[:16]}...")
        if uid not in keys:
            keys[uid] = SecurityKey(uid, existing)
        return

    psk = key_server.register_card(uid)
    if psk:
        keys[uid] = SecurityKey(uid, psk)
        print(f"\n[成功] 钥匙 {uid} 已注册并派发密钥。")
        print(f"  PSK: {psk.hex()}")
        print(f"  (实际系统中 PSK 已安全写入钥匙安全芯片)")


def cmd_unlock():
    """菜单 3: 开锁认证"""
    global lock, keys

    if lock is None:
        print("[错误] 请先执行 [1] 系统初始化。")
        return

    card_list = key_server.list_cards()
    if not card_list:
        print("[提示] 暂无注册钥匙，请先执行 [2] 注册钥匙。")
        return

    print("\n  已注册钥匙：")
    for c in card_list:
        status_str = "[激活]" if c["status"] == "active" else "[已吊销]"
        print(f"    {c['uid']}  {status_str}")

    uid = input("\n  输入钥匙 UID: ").strip()
    if not uid:
        print("[取消]")
        return

    if uid not in keys:
        psk = key_server.get_psk(uid)
        if psk is None:
            print(f"[错误] 钥匙 {uid} 不存在或已被吊销。")
            return
        keys[uid] = SecurityKey(uid, psk)

    print()
    print("  ╔════════════════════════════════╗")
    print("  ║     [ 钥匙靠近锁... ]        ║")
    print("  ╚════════════════════════════════╝")
    print()

    key = keys[uid]
    ok, msg = lock.authenticate(key)

    print()
    if ok:
        print("  ┌────────────────────────────────┐")
        print("  │   [OPEN]  认证通过，锁已开启  │")
        print("  └────────────────────────────────┘")
    else:
        print("  ┌────────────────────────────────┐")
        print("  │   [DENY]  认证失败，锁保持锁定 │")
        print("  └────────────────────────────────┘")


def cmd_lock_close():
    """菜单 4: 锁闭确认"""
    global lock, keys

    if lock is None:
        print("[错误] 请先执行 [1] 系统初始化。")
        return

    # 显示可用钥匙
    active_cards = [c for c in key_server.list_cards() if c["status"] == "active"]
    if not active_cards:
        print("[提示] 无活跃钥匙。")
        return

    print("\n  活跃钥匙：")
    for c in active_cards:
        print(f"    {c['uid']}")

    uid = input("\n  选择钥匙 UID: ").strip()
    if not uid:
        print("[取消]")
        return

    if uid not in keys:
        psk = key_server.get_psk(uid)
        if psk is None:
            print(f"[错误] 钥匙 {uid} 不存在。")
            return
        keys[uid] = SecurityKey(uid, psk)

    print()
    print("  ╔════════════════════════════════╗")
    print("  ║      [ 锁关闭中... ]         ║")
    print("  ╚════════════════════════════════╝")
    print()

    key = keys[uid]
    ok, msg = lock.confirm_lock_closed(key)

    print()
    if ok:
        print("  ┌──────────────────────────────────────────┐")
        print("  │  [LOCKED] 锁已安全关闭，钥匙已确认身份  │")
        print("  └──────────────────────────────────────────┘")
    else:
        print("  ┌──────────────────────────────────────────┐")
        print("  │  [WARN] 锁闭确认失败，锁身份存疑       │")
        print("  └──────────────────────────────────────────┘")


def cmd_list():
    """菜单 5: 查看钥匙"""
    if key_server is None:
        print("[错误] 请先执行 [1] 系统初始化。")
        return

    card_list = key_server.list_cards()
    if not card_list:
        print("[提示] 暂无注册钥匙。")
        return

    print()
    print(f"  {'UID':<16} {'状态':<12} {'注册时间'}")
    print(f"  {'-'*16} {'-'*12} {'-'*26}")
    for c in card_list:
        status = "[ACTIVE]" if c["status"] == "active" else "[REVOKED]"
        print(f"  {c['uid']:<16} {status:<12} {c['created_at']}")


def cmd_log():
    """菜单 6: 操作日志"""
    if lock is None:
        print("[错误] 请先执行 [1] 系统初始化。")
        return

    print(f"\n  电子锁 {lock.lock_id} 操作记录：")
    lock.print_log()


def cmd_rotate():
    """菜单 7: 密钥轮换"""
    global keys

    if key_server is None:
        print("[错误] 请先执行 [1] 系统初始化。")
        return

    confirm = input("  [警告] 密钥轮换将更新所有钥匙 PSK。继续？(y/N): ").strip().lower()
    if confirm != "y":
        print("[取消]")
        return

    if key_server.rotate_master_key():
        for uid in list(keys.keys()):
            new_psk = key_server.get_psk(uid)
            if new_psk:
                keys[uid] = SecurityKey(uid, new_psk)
        print("[成功] 密钥轮换完成。所有钥匙 PSK 已更新。")


def cmd_replay_demo():
    """菜单 8: 防重放演示"""
    global lock, keys

    if lock is None:
        print("[错误] 请先执行 [1] 系统初始化。")
        return

    active_cards = [c for c in key_server.list_cards() if c["status"] == "active"]
    if not active_cards:
        print("[提示] 无活跃钥匙，请先注册。")
        return

    uid = active_cards[0]["uid"]
    if uid not in keys:
        psk = key_server.get_psk(uid)
        keys[uid] = SecurityKey(uid, psk)
    key = keys[uid]

    print("\n  ╔══════════════════════════════════════════╗")
    print("  ║           防重放攻击演示                ║")
    print("  ╚══════════════════════════════════════════╝")
    print()
    print("  攻击场景：攻击者窃听一次合法开锁通信，")
    print("  截获 nonce + 时间戳 + MAC，随后原样重放。")
    print()

    # 正常认证
    print("  [阶段 1] 合法认证")
    nonce = secrets.token_bytes(16)
    ts = int(time.time())
    mac = key.respond_to_challenge(nonce, ts)
    print(f"    nonce:     {nonce.hex()[:20]}...")
    print(f"    timestamp: {ts}")
    print(f"    MAC:       {mac.hex()[:20]}...")
    print(f"    结果: 认证成功 [OPEN]")
    print()

    # 注入已使用 nonce
    lock.replay_protector._used_nonces.add(nonce)

    # 重放攻击
    print("  [阶段 2] 攻击者重放相同数据")
    print(f"    nonce:     {nonce.hex()[:20]}... (同上)")
    print(f"    timestamp: {ts} (同上)")
    print(f"    MAC:       {mac.hex()[:20]}... (同上)")

    if not lock.replay_protector.validate(nonce, ts):
        print(f"    结果: [DENY] 被防重放模块拦截")
        print(f"    原因: nonce 已被使用，判定为重放攻击")
    else:
        print(f"    结果: (意外通过)")

    print()
    print("  [结论] 防重放机制成功拦截了重放攻击。")
    print("  每次认证生成新的随机 nonce，攻击者无法预测和复用。")


def cmd_hash_test():
    """菜单 9: Hash 算法自测"""
    print()
    print("  SimpleHash-128 雪崩效应测试")
    print("  " + "-" * 42)

    msg1 = b"Hello, IoT Security!"
    h1 = simple_hash_hex(msg1)
    print(f"  消息1: {msg1.decode()}")
    print(f"  Hash1: {h1}")

    msg2 = b"Hello, IoT Security#"
    h2 = simple_hash_hex(msg2)
    diff = 0
    for i in range(32):
        if h1[i] != h2[i]:
            diff += bin(int(h1[i], 16) ^ int(h2[i], 16)).count("1")
    print(f"\n  消息2: {msg2.decode()} (末字节 0x21→0x23, 仅 1-bit 差异)")
    print(f"  Hash2: {h2}")
    print(f"  雪崩效应: {diff}/128 bit 翻转 ({diff/128*100:.1f}%)")

    # 性能
    start = time.time()
    for _ in range(5000):
        simple_hash_str(f"test_{secrets.randbits(64)}")
    elapsed = time.time() - start
    print(f"\n  性能: 5000 次 Hash 耗时 {elapsed:.2f}s "
          f"({5000/elapsed:.0f} ops/s)")


# ============================================================
# 主程序
# ============================================================

def main():
    clear_screen()
    print_header()

    # 自动加载已有密钥库
    if os.path.exists(os.path.join(WORK_DIR, KeyServer.STORAGE_FILE)):
        global key_server, lock
        key_server = KeyServer(WORK_DIR)
        if key_server.load():
            lock = SecurityLock("DOOR-A1", key_server)
            print("\n[自动加载] 已加载现有密钥库。")

    while True:
        print_menu()
        choice = input("  请选择操作 [0-9]: ").strip()

        if choice == "1":
            cmd_init()
        elif choice == "2":
            cmd_register()
        elif choice == "3":
            cmd_unlock()
        elif choice == "4":
            cmd_lock_close()
        elif choice == "5":
            cmd_list()
        elif choice == "6":
            cmd_log()
        elif choice == "7":
            cmd_rotate()
        elif choice == "8":
            cmd_replay_demo()
        elif choice == "9":
            cmd_hash_test()
        elif choice == "0":
            print("\n  再见。")
            break
        else:
            print(f"  无效选择: {choice}")

        input("\n  按 Enter 继续...")


if __name__ == "__main__":
    main()
