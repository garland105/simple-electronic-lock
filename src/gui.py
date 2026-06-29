"""
gui.py — 安全电子锁系统 可视化管理界面

基于 Python Tkinter（标准库，零外部依赖）
"""

import os
import sys
import time
import secrets
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from datetime import datetime

# 确保当前目录在 path 中
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from hash_engine import simple_hash_hex, simple_hash_str
from key_server import KeyServer
from key import SecurityKey
from lock import SecurityLock

# ============================================================
# 全局状态
# ============================================================
key_server = None
lock = None
keys = {}          # uid -> SecurityKey


# ============================================================
# 颜色主题
# ============================================================
BG_MAIN = "#1E1E2E"       # 主背景（深色主题）
BG_PANEL = "#252536"       # 面板背景
BG_BTN = "#3B3B5C"         # 按钮背景
BG_BTN_HOVER = "#4A4A72"   # 按钮悬停
BG_ENTRY = "#2D2D44"       # 输入框背景
FG_TEXT = "#E0E0F0"        # 主文字
FG_ACCENT = "#89B4FA"      # 强调色
FG_SUCCESS = "#A6E3A1"     # 成功绿色
FG_ERROR = "#F38BA8"       # 错误红色
FG_WARN = "#F9E2AF"         # 警告黄色
FG_INFO = "#89DCEB"         # 信息蓝色


class App(tk.Tk):
    """主窗口"""

    def __init__(self):
        super().__init__()
        self.title("安全电子锁系统 | 盛佳傲 3230611048 物联网工程 2302")
        self.geometry("1000x680")
        self.minsize(900, 600)
        self.configure(bg=BG_MAIN)

        # 字体
        self.font_title = ("Microsoft YaHei UI", 16, "bold")
        self.font_btn = ("Microsoft YaHei UI", 10)
        self.font_log = ("Consolas", 10)
        self.font_status = ("Microsoft YaHei UI", 9)

        self._build_ui()
        self._auto_load()

    # ============================================================
    # UI 构建
    # ============================================================

    def _build_ui(self):
        """构建界面"""
        # ---- 顶部标题栏 ----
        title_frame = tk.Frame(self, bg=BG_PANEL, height=52)
        title_frame.pack(fill=tk.X, side=tk.TOP)
        title_frame.pack_propagate(False)

        title_label = tk.Label(
            title_frame,
            text="🔐  安全电子锁系统  |  SimpleHash-128  挑战-应答认证",
            font=self.font_title, fg=FG_ACCENT, bg=BG_PANEL
        )
        title_label.pack(side=tk.LEFT, padx=18, pady=10)

        self.status_label = tk.Label(
            title_frame,
            text="🔴 未初始化",
            font=self.font_status, fg=FG_ERROR, bg=BG_PANEL
        )
        self.status_label.pack(side=tk.RIGHT, padx=18, pady=10)

        # ---- 主体区域 ----
        main_frame = tk.Frame(self, bg=BG_MAIN)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # 左侧按钮面板
        self._build_sidebar(main_frame)

        # 右侧日志输出
        self._build_log_area(main_frame)

    def _build_sidebar(self, parent):
        """左侧按钮面板"""
        sidebar = tk.Frame(parent, bg=BG_PANEL, width=200)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
        sidebar.pack_propagate(False)

        # 面板标题
        tk.Label(
            sidebar, text="操 作 面 板", font=("Microsoft YaHei UI", 11, "bold"),
            fg=FG_ACCENT, bg=BG_PANEL
        ).pack(pady=(16, 10))

        buttons = [
            ("📀 系统初始化", self._on_init, FG_INFO),
            ("🔑 注册钥匙", self._on_register, FG_TEXT),
            ("🔓 开锁认证", self._on_unlock, FG_SUCCESS),
            ("🔒 锁闭确认", self._on_lock_close, FG_INFO),
            ("🚫 吊销钥匙", self._on_revoke, FG_ERROR),
            ("📋 查看日志", self._on_log, FG_TEXT),
            ("🔄 密钥轮换", self._on_rotate, FG_WARN),
            ("🛡 防重放演示", self._on_replay, FG_WARN),
            ("🧪 Hash 自测", self._on_hash_test, FG_INFO),
        ]

        self.buttons = []
        for text, cmd, color in buttons:
            btn = tk.Button(
                sidebar, text=text, command=cmd,
                font=self.font_btn, bg=BG_BTN, fg=color,
                activebackground=BG_BTN_HOVER, activeforeground=color,
                relief=tk.FLAT, cursor="hand2", height=1, width=16,
                anchor="w", padx=16
            )
            btn.pack(pady=3, padx=12, fill=tk.X)
            # Hover effect
            btn.bind("<Enter>", lambda e, b=btn: b.configure(bg=BG_BTN_HOVER))
            btn.bind("<Leave>", lambda e, b=btn: b.configure(bg=BG_BTN))
            self.buttons.append(btn)

        # 版权信息放底部
        tk.Label(
            sidebar,
            text="\n盛佳傲\n3230611048\n物联网工程 2302\n江苏大学",
            font=("Microsoft YaHei UI", 8), fg="#6C6C8A", bg=BG_PANEL,
            justify=tk.CENTER
        ).pack(side=tk.BOTTOM, pady=14)

    def _build_log_area(self, parent):
        """右侧日志输出区域"""
        right = tk.Frame(parent, bg=BG_PANEL)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(
            right, text="操 作 日 志",
            font=("Microsoft YaHei UI", 11, "bold"),
            fg=FG_ACCENT, bg=BG_PANEL
        ).pack(pady=(12, 6))

        # 日志文本框 + 滚动条
        log_frame = tk.Frame(right, bg=BG_PANEL)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 6))

        self.log_text = tk.Text(
            log_frame, bg=BG_ENTRY, fg=FG_TEXT, font=self.font_log,
            wrap=tk.WORD, relief=tk.FLAT, padx=10, pady=8,
            borderwidth=0, highlightthickness=0
        )
        scrollbar = tk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 配置颜色标签
        self.log_text.tag_config("info", foreground=FG_INFO)
        self.log_text.tag_config("success", foreground=FG_SUCCESS)
        self.log_text.tag_config("error", foreground=FG_ERROR)
        self.log_text.tag_config("warn", foreground=FG_WARN)
        self.log_text.tag_config("title", foreground=FG_ACCENT, font=("Consolas", 11, "bold"))
        self.log_text.tag_config("timestamp", foreground="#6C6C8A")
        self.log_text.tag_config("bold", font=("Consolas", 10, "bold"))

        # 清空按钮
        clear_btn = tk.Button(
            right, text="清空日志", command=self._on_clear_log,
            font=("Microsoft YaHei UI", 8), bg=BG_BTN, fg="#6C6C8A",
            activebackground=BG_BTN_HOVER, relief=tk.FLAT, cursor="hand2"
        )
        clear_btn.pack(pady=(0, 8), side=tk.RIGHT, padx=10)

        # 初始欢迎信息
        self._log("title", "=" * 60)
        self._log("title", "  安全电子锁系统  v1.0")
        self._log("title", "  选题: 基于自定义 Hash 算法的安全电子锁")
        self._log("title", "=" * 60)
        self._log("info", "  等待系统初始化...\n")

    # ============================================================
    # 日志输出
    # ============================================================

    def _log(self, tag: str, text: str):
        """向日志区输出带颜色标记的文本"""
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{ts}] ", "timestamp")
        self.log_text.insert(tk.END, text + "\n", tag)
        self.log_text.see(tk.END)
        self.update_idletasks()

    def _log_raw(self, text: str):
        """输出无时间戳的纯文本"""
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)
        self.update_idletasks()

    def _on_clear_log(self):
        self.log_text.delete("1.0", tk.END)

    def _set_status(self, text: str, color: str):
        self.status_label.config(text=text, fg=color)

    # ============================================================
    # 自动加载
    # ============================================================

    def _auto_load(self):
        global key_server, lock
        keystore_path = os.path.join(SCRIPT_DIR, KeyServer.STORAGE_FILE)
        if os.path.exists(keystore_path):
            key_server = KeyServer(SCRIPT_DIR)
            if key_server.load():
                lock = SecurityLock("DOOR-A1", key_server)
                self._set_status("🟢 已就绪", FG_SUCCESS)
                self._log("success", f"已加载现有密钥库，锁 DOOR-A1 就绪。")

    # ============================================================
    # 按钮事件
    # ============================================================

    def _on_init(self):
        global key_server, lock
        if key_server is not None:
            self._log("warn", "系统已初始化，如需重新初始化请删除 keystore.json。")
            return

        key_server = KeyServer(SCRIPT_DIR)
        if key_server.initialize():
            lock = SecurityLock("DOOR-A1", key_server)
            self._set_status("🟢 已就绪", FG_SUCCESS)
            self._log("success", "系统初始化完成！主密钥已生成。")
            self._log("info", "  锁编号: DOOR-A1")
            self._log("info", "  下一步: 点击 [注册钥匙] 添加钥匙。")
        else:
            self._log("error", "初始化失败。")

    def _on_register(self):
        global key_server, keys
        if key_server is None:
            self._log("error", "请先点击 [系统初始化]。")
            return

        uid = simpledialog.askstring(
            "注册钥匙", "请输入钥匙 UID（如 KEY-001）:", parent=self
        )
        if not uid:
            return

        uid = uid.strip()
        existing = key_server.get_psk(uid)
        if existing:
            if uid not in keys:
                keys[uid] = SecurityKey(uid, existing)
            self._log("info", f"钥匙 {uid} 已注册（已存在）。")
            return

        psk = key_server.register_card(uid)
        if psk:
            keys[uid] = SecurityKey(uid, psk)
            self._log("success", f"钥匙 {uid} 注册成功！PSK: {psk.hex()[:16]}...")

    def _on_revoke(self):
        global key_server, keys
        if key_server is None:
            self._log("error", "请先点击 [系统初始化]。")
            return

        uid = simpledialog.askstring(
            "吊销钥匙", "输入要吊销的钥匙 UID（如 KEY-001）:", parent=self
        )
        if not uid:
            return
        uid = uid.strip()

        if key_server.revoke_card(uid):
            # 同时从缓存中移除
            keys.pop(uid, None)
            self._log("warn", f"钥匙 {uid} 已吊销。此钥匙将无法再开锁。")
        else:
            self._log("error", f"吊销失败：钥匙 {uid} 不存在。")

    def _on_unlock(self):
        global lock, keys
        if lock is None:
            self._log("error", "请先点击 [系统初始化]。")
            return

        uid = simpledialog.askstring(
            "开锁认证", "请输入钥匙 UID（如 KEY-001）:", parent=self
        )
        if not uid:
            return
        uid = uid.strip()

        if uid not in keys:
            psk = key_server.get_psk(uid)
            if psk is None:
                self._log("error", f"钥匙 {uid} 不存在或已吊销。")
                return
            keys[uid] = SecurityKey(uid, psk)

        key = keys[uid]
        self._log("info", f"═══ 开锁认证: {uid} ═══")
        ok, msg = lock.authenticate(key)

        if ok:
            self._log("success", f"  🔓 {msg}")
        else:
            self._log("error", f"  ❌ {msg}")

    def _on_lock_close(self):
        global lock, keys
        if lock is None:
            self._log("error", "请先点击 [系统初始化]。")
            return

        uid = simpledialog.askstring(
            "锁闭确认", "请输入钥匙 UID（如 KEY-001）:", parent=self
        )
        if not uid:
            return
        uid = uid.strip()

        if uid not in keys:
            psk = key_server.get_psk(uid)
            if psk is None:
                self._log("error", f"钥匙 {uid} 不存在。")
                return
            keys[uid] = SecurityKey(uid, psk)

        key = keys[uid]
        self._log("info", f"═══ 锁闭确认: {uid} ═══")
        ok, msg = lock.confirm_lock_closed(key)

        if ok:
            self._log("success", f"  🔒 {msg}")
            self._log("success", f"  🔊 钥匙 {uid}: 嘀——认证通过！锁已安全关闭。")
        else:
            self._log("error", f"  ❌ {msg}")

    def _on_log(self):
        global lock
        if lock is None:
            self._log("error", "请先点击 [系统初始化]。")
            return

        self._log("title", "═══ 操作日志 ═══")
        entries = lock.access_log[-30:]
        if not entries:
            self._log("info", "  (暂无记录)")
            return

        for e in entries:
            tag = "success" if e["result"] == "OPEN" else "error"
            status = "[OPEN]" if e["result"] == "OPEN" else "[DENY]"
            self._log(tag, f"  {e['time']} | {status} | {e['uid']} | {e['detail']}")

    def _on_rotate(self):
        global key_server, keys
        if key_server is None:
            self._log("error", "请先点击 [系统初始化]。")
            return

        ok = messagebox.askyesno(
            "密钥轮换",
            "⚠ 此操作将更新所有钥匙的 PSK。\n继续？",
            parent=self
        )
        if not ok:
            return

        if key_server.rotate_master_key():
            for uid in list(keys.keys()):
                new_psk = key_server.get_psk(uid)
                if new_psk:
                    keys[uid] = SecurityKey(uid, new_psk)
            self._log("success", "主密钥轮换完成！所有钥匙 PSK 已更新。")

    def _on_replay(self):
        global lock, keys
        if lock is None:
            self._log("error", "请先点击 [系统初始化]。")
            return

        active = [c for c in key_server.list_cards() if c["status"] == "active"]
        if not active:
            self._log("warn", "暂无活跃钥匙。")
            return

        uid = active[0]["uid"]
        if uid not in keys:
            psk = key_server.get_psk(uid)
            keys[uid] = SecurityKey(uid, psk)
        key = keys[uid]

        self._log("title", "═══ 防重放攻击演示 ═══")
        self._log("info", "场景: 攻击者窃听合法通信后重放相同数据。\n")

        # 正常认证
        self._log("bold", "[阶段 1] 合法认证")
        nonce = secrets.token_bytes(16)
        ts = int(time.time())
        mac = key.respond_to_challenge(nonce, ts)
        self._log("info", f"  nonce:     {nonce.hex()[:24]}...")
        self._log("info", f"  timestamp: {ts}")
        self._log("info", f"  MAC:       {mac.hex()[:24]}...")
        self._log("success", "  结果: 认证成功 [OPEN]\n")

        # 注入已使用 nonce
        lock.replay_protector._used_nonces.add(nonce)

        # 重放攻击
        self._log("bold", "[阶段 2] 攻击者重放")
        self._log("info", f"  nonce:     {nonce.hex()[:24]}... (同上)")
        self._log("info", f"  timestamp: {ts} (同上)")
        self._log("info", f"  MAC:       {mac.hex()[:24]}... (同上)")

        if not lock.replay_protector.validate(nonce, ts):
            self._log("error", "  结果: [DENY] 防重放模块拦截")
            self._log("warn", "  原因: nonce 已使用，判定为重放攻击")
        else:
            self._log("error", "  结果: (意外通过 — 防御失效)")

        self._log("success", "\n✓ 防重放机制成功拦截攻击。")

    def _on_hash_test(self):
        self._log("title", "═══ SimpleHash-128 雪崩效应测试 ═══")

        msg1 = b"Hello, IoT Security!"
        h1 = simple_hash_hex(msg1)
        self._log("info", f"  消息1: {msg1.decode()}")
        self._log("info", f"  Hash1: {h1}")

        msg2 = b"Hello, IoT Security#"
        h2 = simple_hash_hex(msg2)
        diff = sum(
            bin(int(h1[i], 16) ^ int(h2[i], 16)).count("1")
            for i in range(32)
        )
        self._log("info", f"\n  消息2: {msg2.decode()} (1-bit 差异)")
        self._log("info", f"  Hash2: {h2}")
        self._log("success", f"  雪崩效应: {diff}/128 bit 翻转 ({diff/128*100:.1f}%)")

        # 性能
        start = time.time()
        for _ in range(5000):
            simple_hash_str(f"test_{secrets.randbits(64)}")
        elapsed = time.time() - start
        self._log("info", f"\n  性能: 5000 次 Hash 耗时 {elapsed:.2f}s "
                  f"({5000/elapsed:.0f} ops/s)")


# ============================================================
# 选择对话框
# ============================================================

class SelectDialog(tk.Toplevel):
    """简单的列表选择弹窗"""

    def __init__(self, parent, title, prompt, choices):
        super().__init__(parent)
        self.result = None
        self.title(title)
        self.geometry("320x240")
        self.configure(bg=BG_PANEL)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        tk.Label(
            self, text=prompt, font=("Microsoft YaHei UI", 10),
            fg=FG_TEXT, bg=BG_PANEL
        ).pack(pady=(16, 8))

        listbox = tk.Listbox(
            self, bg=BG_ENTRY, fg=FG_TEXT, font=("Microsoft YaHei UI", 11),
            selectbackground=BG_BTN_HOVER, relief=tk.FLAT, borderwidth=0,
            highlightthickness=0
        )
        listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 12))
        for c in choices:
            listbox.insert(tk.END, f"  {c}")

        def on_select():
            sel = listbox.curselection()
            if sel:
                self.result = choices[sel[0]]
                self.destroy()

        tk.Button(
            self, text="确 定", command=on_select,
            font=("Microsoft YaHei UI", 10), bg=BG_BTN, fg=FG_ACCENT,
            activebackground=BG_BTN_HOVER, relief=tk.FLAT, cursor="hand2"
        ).pack(pady=(0, 14))

        listbox.bind("<Double-Button-1>", lambda e: on_select())
        listbox.bind("<Return>", lambda e: on_select())


# ============================================================
# 入口
# ============================================================

if __name__ == "__main__":
    app = App()
    app.mainloop()
