# -*- coding: utf-8 -*-
"""
智策学校局域网配置软件 (zc-IPFreeScanner)
版本: v1.2
功能: ① 自动检测当前电脑连接的路由器(网关)地址,点击可打开管理页面
      ② 网段切换: 192.168.168.x / 192.168.200.x
      ③ 扫描所选网段空闲 IP (Ping + ARP 双重检测)
      ④ 展示列表 -> 随机抽取 -> 用户确认后写入 Windows 静态 IP(DNS 预设可选)
"""

import ctypes
import random
import re
import subprocess
import sys
import threading
import queue
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox
from concurrent.futures import ThreadPoolExecutor

# ---------------- 版本信息 ----------------
APP_NAME = "智策学校局域网配置软件"
APP_NAME_EN = "zc-IPFreeScanner"
APP_VERSION = "v1.2"
SUBNET_MASK = "255.255.255.0"
# 可切换网段: (显示名, 网段前缀, 兜底网关)
SUBNETS = [
    ("192.168.168.x", "192.168.168", "192.168.168.1"),
    ("192.168.200.x", "192.168.200", "192.168.200.1"),
]

# 国内主流 DNS 预设:(名称, 主 DNS, 备 DNS)
DNS_PRESETS = [
    ("阿里 AliDNS",      "223.5.5.5",      "223.6.6.6"),
    ("腾讯 DNSPod",      "119.29.29.29",   "182.254.116.116"),
    ("114DNS",           "114.114.114.114", "114.114.115.115"),
    ("百度 DNS",         "180.76.76.76",   "180.76.76.76"),
    ("360 DNS",          "101.226.4.6",    "123.125.81.6"),
    ("火山引擎",         "180.184.1.1",    "180.184.2.2"),
    ("CNNIC SDNS",       "1.2.4.8",        "210.2.4.8"),
]
PING_TIMEOUT_MS = 600
WORKERS = 64

IS_FROZEN = getattr(sys, "frozen", False)


# ---------------- 管理员权限 ----------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate():
    """尝试以管理员身份重新启动自己;返回 True 表示已发起提权。"""
    try:
        if IS_FROZEN:
            exe = sys.executable
            params = ""
        else:
            exe = sys.executable
            params = f'"{__file__}"'
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return ret > 32
    except Exception:
        return False


# ---------------- 网络工具函数 ----------------
def run_cmd(args, timeout=15):
    """执行命令,返回 (returncode, stdout)。GBK 解码兼容中文 Windows。"""
    try:
        r = subprocess.run(
            args, capture_output=True, text=True,
            encoding="gbk", errors="ignore",
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return r.returncode, (r.stdout or "")
    except Exception as e:
        return -1, str(e)


def get_gateway():
    """检测当前电脑所连路由器地址(默认网关的下一跳)。失败返回 None。"""
    rc, out = run_cmd([
        "powershell", "-NoProfile", "-Command",
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue "
        "| Sort-Object RouteMetric | Select-Object -First 1).NextHop",
    ], timeout=20)
    gw = out.strip()
    if rc == 0 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", gw):
        return gw
    return None


def get_active_adapter():
    """返回 (网卡名, 当前IP) —— 优先取有默认网关的网卡,否则取第一块 Up 的物理网卡。"""
    # 1) 默认路由所在网卡
    rc, out = run_cmd([
        "powershell", "-NoProfile", "-Command",
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue "
        "| Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias",
    ], timeout=20)
    nic = out.strip().strip("\r\n")
    # 2) 兜底: 第一块 Up 状态网卡
    if not nic or rc != 0:
        rc, out = run_cmd([
            "powershell", "-NoProfile", "-Command",
            "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} "
            "| Select-Object -First 1).Name",
        ], timeout=20)
        nic = out.strip()
    if not nic:
        return None, None
    # 当前 IP
    rc, out = run_cmd([
        "powershell", "-NoProfile", "-Command",
        f"(Get-NetIPAddress -InterfaceAlias '{nic}' -AddressFamily IPv4 "
        f"-ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress",
    ], timeout=20)
    ip = out.strip()
    return nic, (ip if ip else None)


def get_arp_ips(prefix):
    """从系统 ARP 表解析指定网段已占用 IP(排除广播/空 MAC)。"""
    _, out = run_cmd(["arp", "-a"], timeout=10)
    ips = set()
    pat = re.compile(
        r"^(" + re.escape(prefix) + r"\.\d+)\s+"
        r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}", re.M
    )
    for m in pat.finditer(out):
        mac = out[m.start():].split()[1].lower()
        if mac not in ("ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00"):
            ips.add(m.group(1))
    return ips


def ping_ip(ip):
    """ping 单个 IP,通则返回 True。"""
    rc, _ = run_cmd(
        ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip],
        timeout=PING_TIMEOUT_MS / 1000 + 3,
    )
    return rc == 0


def scan_subnet(prefix, progress_cb=None, cancel_event=None):
    """
    扫描指定网段,返回 (free_ips, occupied_ips)。
    检测逻辑: ping 响应 或 出现在 ARP 表 => 占用。
    """
    all_ips = [f"{prefix}.{i}" for i in range(1, 255)]
    arp_before = get_arp_ips(prefix)

    occupied = set(arp_before)
    done = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(ping_ip, ip): ip for ip in all_ips}
        for fut in futures:
            pass
        # 按完成顺序收集
        pending = set(futures)
        while pending:
            if cancel_event and cancel_event.is_set():
                pool.shutdown(wait=False, cancel_futures=True)
                return None, None
            for fut in list(pending):
                if fut.done():
                    ip = futures[fut]
                    if fut.result():
                        occupied.add(ip)
                    pending.discard(fut)
                    done += 1
                    if progress_cb:
                        progress_cb(done, len(all_ips))

    own_ip = getattr(scan_subnet, "_own_ip", None)
    if own_ip:
        occupied.add(own_ip)
    occupied.add(f"{prefix}.1")   # 保留给网关,避免冲突
    occupied.add(f"{prefix}.255")

    free = [ip for ip in all_ips if ip not in occupied]
    return free, sorted(occupied, key=lambda x: int(x.rsplit(".", 1)[1]))


# ---------------- GUI ----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("560x640")
        self.minsize(520, 600)
        self.resizable(True, True)

        self.free_ips = []
        self.chosen_ip = None
        self.nic_name = None
        self.gateway = None          # 自动检测到的路由器地址
        self.msg_q = queue.Queue()
        self.cancel_event = threading.Event()
        self.scanning = False

        self._build_ui()
        self.after(100, self._poll_queue)
        self.after(200, self._init_adapter_info)

    # ---------- UI 构建 ----------
    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}
        frm_top = ttk.Frame(self)
        frm_top.pack(fill="x", **pad)

        self.lbl_adapter = ttk.Label(frm_top, text="网卡: 检测中…")
        self.lbl_adapter.pack(anchor="w")

        frm_net = ttk.Frame(frm_top)
        frm_net.pack(fill="x", pady=(4, 0))
        ttk.Label(frm_net, text="目标网段:").pack(side="left")
        self.subnet_var = tk.StringVar(value=SUBNETS[0][0])
        self.cmb_subnet = ttk.Combobox(frm_net, textvariable=self.subnet_var,
                                       values=[s[0] for s in SUBNETS],
                                       state="readonly", width=16)
        self.cmb_subnet.pack(side="left", padx=6)
        self.cmb_subnet.bind("<<ComboboxSelected>>", self.on_subnet_change)
        self.lbl_router = ttk.Label(frm_top, text="路由器(网关): 检测中…",
                                    foreground="#0a7d32")
        self.lbl_router.pack(anchor="w", pady=(4, 0))

        frm_dns = ttk.Frame(frm_top)
        frm_dns.pack(fill="x", pady=(4, 0))
        ttk.Label(frm_dns, text="DNS 预设:").pack(side="left")
        self.dns_var = tk.StringVar(value=DNS_PRESETS[0][0])
        self.cmb_dns = ttk.Combobox(frm_dns, textvariable=self.dns_var,
                                    values=[p[0] for p in DNS_PRESETS],
                                    state="readonly", width=16)
        self.cmb_dns.pack(side="left", padx=6)
        self.lbl_dns_detail = ttk.Label(
            frm_dns, foreground="#666",
            text=f"主 {DNS_PRESETS[0][1]}  备 {DNS_PRESETS[0][2]}")
        self.lbl_dns_detail.pack(side="left", padx=6)
        self.cmb_dns.bind("<<ComboboxSelected>>", self.on_dns_change)

        self.btn_scan = ttk.Button(frm_top, text="开始扫描所选网段",
                                   command=self.start_scan)
        self.btn_scan.pack(fill="x", pady=(6, 0))

        self.progress = ttk.Progressbar(self, maximum=254, mode="determinate")
        self.progress.pack(fill="x", **pad)
        self.lbl_status = ttk.Label(self, text="状态: 就绪")
        self.lbl_status.pack(anchor="w", padx=10)

        frm_list = ttk.LabelFrame(self, text=" 空闲 IP 列表 ")
        frm_list.pack(fill="both", expand=True, **pad)
        self.listbox = tk.Listbox(frm_list, activestyle="dotbox",
                                  font=("Consolas", 11), selectbackground="#7a4fd0")
        sb = ttk.Scrollbar(frm_list, command=self.listbox.yview)
        self.listbox.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.listbox.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        self.listbox.bind("<<ListboxSelect>>", self.on_list_select)

        self.lbl_count = ttk.Label(self, text="共 0 个空闲 IP")
        self.lbl_count.pack(anchor="w", padx=10)

        frm_pick = ttk.LabelFrame(self, text=" 抽取 ")
        frm_pick.pack(fill="x", **pad)
        self.btn_pick = ttk.Button(frm_pick, text="🎲 随机抽取一个",
                                   command=self.random_pick, state="disabled")
        self.btn_pick.pack(side="left", padx=6, pady=6)
        self.lbl_chosen = ttk.Label(frm_pick, text="未选择", font=("微软雅黑", 13, "bold"),
                                    foreground="#7a4fd0")
        self.lbl_chosen.pack(side="left", padx=12)

        self.btn_apply = ttk.Button(self, text="✔ 确定写入静态 IP",
                                    command=self.apply_static, state="disabled")
        self.btn_apply.pack(fill="x", **pad)

        self.lbl_info = ttk.Label(
            self, foreground="#666", justify="left",
            text=(f"{APP_NAME} {APP_VERSION} ({APP_NAME_EN})\n"
                  f"写入内容: IP + 掩码 {SUBNET_MASK} + 自动检测到的网关 + 所选 DNS\n"
                  f"提示: 路由器地址显示后,点击它可直接打开路由器管理页面。"))
        self.lbl_info.pack(anchor="w", padx=10, pady=(0, 8))

    # ---------- 初始化 ----------
    def _init_adapter_info(self):
        def work():
            nic, ip = get_active_adapter()
            scan_subnet._own_ip = ip
            gw = get_gateway()
            gw_ok = None
            if gw:
                rc, _ = run_cmd(["ping", "-n", "1", "-w", "1000", gw], timeout=5)
                gw_ok = (rc == 0)
            self.msg_q.put(("adapter", nic, ip, gw, gw_ok))
        threading.Thread(target=work, daemon=True).start()

    # ---------- 扫描 ----------
    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.cancel_event.clear()
        self.btn_scan.config(state="disabled", text="扫描中…请稍候")
        self.btn_pick.config(state="disabled")
        self.btn_apply.config(state="disabled")
        self.cmb_subnet.config(state="disabled")
        self.listbox.delete(0, "end")
        self.free_ips = []
        self.chosen_ip = None
        self.lbl_chosen.config(text="未选择")
        self.lbl_status.config(text="状态: 正在扫描(并发 Ping + ARP 双重检测)…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        prefix = self._current_subnet()[1]

        def cb(done, total):
            self.msg_q.put(("progress", done, total))
        free, occupied = scan_subnet(prefix, progress_cb=cb,
                                     cancel_event=self.cancel_event)
        self.msg_q.put(("scan_done", free, occupied))

    # ---------- 队列轮询 ----------
    def _poll_queue(self):
        try:
            while True:
                msg = self.msg_q.get_nowait()
                kind = msg[0]
                if kind == "adapter":
                    nic, ip, gw, gw_ok = msg[1], msg[2], msg[3], msg[4]
                    self.nic_name = nic
                    self.gateway = gw
                    self.lbl_adapter.config(
                        text=f"网卡: {nic or '未检测到'}   (当前 IP: {ip or '无'})")
                    if gw:
                        state = "✅ 可达" if gw_ok else "⚠️ 暂不可达"
                        self.lbl_router.config(
                            text=f"路由器(网关): {gw}   {state}"
                                 f"   🔗 点击打开管理页面",
                            foreground="#0a7d32" if gw_ok else "#b45309",
                            cursor="hand2")
                        self.lbl_router.bind("<Button-1>",
                                             lambda e: self.open_router_page())
                    else:
                        self.lbl_router.config(
                            text="路由器(网关): 未检测到(写入时将使用 "
                                 f"{self.default_gw()})",
                            foreground="#b45309")
                elif kind == "progress":
                    done, total = msg[1], msg[2]
                    self.progress.config(maximum=total, value=done)
                    self.lbl_status.config(text=f"状态: 扫描中… {done}/{total}")
                elif kind == "scan_done":
                    free, occupied = msg[1], msg[2]
                    self.scanning = False
                    self.btn_scan.config(state="normal", text="重新扫描")
                    self.cmb_subnet.config(state="readonly")
                    if free is None:
                        self.lbl_status.config(text="状态: 已取消")
                        return
                    self.free_ips = free
                    self.listbox.delete(0, "end")
                    for ip in free:
                        self.listbox.insert("end", f"  {ip}")
                    self.lbl_count.config(text=f"共 {len(free)} 个空闲 IP")
                    self.lbl_status.config(
                        text=f"状态: 扫描完成 ✅  (占用 {len(occupied)} 个)")
                    if free:
                        self.btn_pick.config(state="normal")
                    else:
                        messagebox.showinfo("结果", "未发现空闲 IP,请检查网段或网络。")
                elif kind == "apply_done":
                    self._handle_apply_done(msg[1], msg[2])
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    # ---------- 路由器管理页 / DNS 切换 ----------
    def open_router_page(self):
        """用默认浏览器打开路由器管理页面。"""
        gw = self.gateway or self.default_gw()
        url = f"http://{gw}"
        try:
            webbrowser.open(url)
            self.lbl_status.config(text=f"状态: 已在浏览器打开 {url}")
        except Exception as e:
            messagebox.showerror("打开失败", f"无法打开 {url}\n\n{e}")

    def get_selected_dns(self):
        """返回当前所选 DNS 预设 (名称, 主, 备)。"""
        name = self.dns_var.get()
        for p in DNS_PRESETS:
            if p[0] == name:
                return p
        return DNS_PRESETS[0]

    def on_dns_change(self, _evt=None):
        p = self.get_selected_dns()
        self.lbl_dns_detail.config(text=f"主 {p[1]}  备 {p[2]}")

    # ---------- 网段切换 ----------
    def _current_subnet(self):
        """返回当前所选网段 (显示名, 前缀, 兜底网关)。"""
        name = self.subnet_var.get()
        for s in SUBNETS:
            if s[0] == name:
                return s
        return SUBNETS[0]

    def default_gw(self):
        """当前网段的兜底网关(自动检测失败时使用)。"""
        return self._current_subnet()[2]

    def on_subnet_change(self, _evt=None):
        """切换网段后清空旧结果,提示重新扫描。"""
        if self.scanning:
            return
        self.listbox.delete(0, "end")
        self.free_ips = []
        self.chosen_ip = None
        self.lbl_chosen.config(text="未选择")
        self.lbl_count.config(text="共 0 个空闲 IP")
        self.btn_pick.config(state="disabled")
        self.btn_apply.config(state="disabled")
        self.lbl_status.config(
            text=f"状态: 已切换到 {self._current_subnet()[0]},请重新扫描 ✅")

    # ---------- 选择 ----------
    def on_list_select(self, _evt=None):
        sel = self.listbox.curselection()
        if sel:
            self.chosen_ip = self.listbox.get(sel[0]).strip()
            self.lbl_chosen.config(text=self.chosen_ip)
            self.btn_apply.config(state="normal")

    def random_pick(self):
        if not self.free_ips:
            return
        ip = random.choice(self.free_ips)
        idx = self.free_ips.index(ip)
        self.listbox.selection_clear(0, "end")
        self.listbox.selection_set(idx)
        self.listbox.see(idx)
        self.chosen_ip = ip
        self.lbl_chosen.config(text=ip)
        self.btn_apply.config(state="normal")

    # ---------- 写入 ----------
    def apply_static(self):
        if not self.chosen_ip:
            return
        if not is_admin():
            messagebox.showerror("权限不足",
                                 "写入静态 IP 需要管理员权限。\n请右键以管理员身份运行本程序。")
            return
        nic = self.nic_name or get_active_adapter()[0]
        if not nic:
            messagebox.showerror("错误", "未检测到活动网卡,无法写入。")
            return
        gw = self.gateway or self.default_gw()
        dns = self.get_selected_dns()
        ok = messagebox.askyesno(
            "确认写入",
            f"即将把网卡【{nic}】设置为静态 IP:\n\n"
            f"  IP 地址:  {self.chosen_ip}\n"
            f"  子网掩码: {SUBNET_MASK}\n"
            f"  默认网关: {gw} (自动检测到的路由器)\n"
            f"  DNS:      {dns[0]}  {dns[1]} / {dns[2]}\n\n"
            f"⚠ 写入过程中网络会短暂中断,确认继续?",
        )
        if not ok:
            return

        self.btn_apply.config(state="disabled")
        self.lbl_status.config(text="状态: 正在写入静态 IP…")

        def work():
            results = []
            results.append(run_cmd([
                "netsh", "interface", "ip", "set", "address",
                f"name={nic}", "static", self.chosen_ip, SUBNET_MASK, gw,
            ], timeout=30))
            results.append(run_cmd([
                "netsh", "interface", "ip", "set", "dns",
                f"name={nic}", "static", dns[1], "primary",
            ], timeout=30))
            results.append(run_cmd([
                "netsh", "interface", "ip", "add", "dns",
                f"name={nic}", dns[2], "index=2",
            ], timeout=30))
            self.msg_q.put(("apply_done", results, dns))

        threading.Thread(target=work, daemon=True).start()

    def _handle_apply_done(self, results, dns):
        failed = [(i, r) for i, r in enumerate(results) if r[0] != 0]
        if not failed:
            self.lbl_status.config(text="状态: 写入成功 ✅")
            messagebox.showinfo(
                "写入成功",
                f"静态 IP 已写入:\n{self.chosen_ip} / {SUBNET_MASK}\n"
                f"网关 {self.gateway or self.default_gw()}  "
                f"DNS {dns[0]} {dns[1]} / {dns[2]}")
        else:
            detail = "\n".join(f"步骤{i+1} rc={r[0]}: {r[1][:120]}" for i, r in failed)
            self.lbl_status.config(text="状态: 写入失败 ❌")
            messagebox.showerror("写入失败", f"以下步骤出错:\n\n{detail}")
        self.btn_apply.config(state="normal")


def main():
    if not is_admin():
        # PyInstaller --uac-admin 正常情况下已提权;这里是脚本直跑的兜底
        if elevate():
            sys.exit(0)
        # 提权被拒绝 -> 仍允许扫描,写入时再提示
        pass
    App().mainloop()


if __name__ == "__main__":
    main()
