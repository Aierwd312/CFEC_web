import tkinter as tk
from tkinter import messagebox, ttk
import json
import requests
import threading
import time
import os
import winreg as reg
import sys

# 本地存储文件路径
STORAGE_FILE = 'schoolweb.json'

# 加载本地存储数据
def load_storage():
    if not os.path.exists(STORAGE_FILE):
        return {'auto_connect': False, 'auto_start': False}
    with open(STORAGE_FILE, 'r') as f:
        return json.load(f)

# 保存本地存储数据
def save_storage(data):
    with open(STORAGE_FILE, 'w') as f:
        json.dump(data, f)

# 添加或删除开机自启动
def set_auto_start(enable=True):
    key = reg.HKEY_CURRENT_USER
    key_value = r'Software\Microsoft\Windows\CurrentVersion\Run'
    key_open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
    script_path = os.path.abspath(__file__).replace("main_program.py", "startup_script.py")  # 更改为启动脚本的路径
    command = f'"{sys.executable}" "{script_path}"'
    if enable:
        reg.SetValueEx(key_open, 'CampusNetHelper', 0, reg.REG_SZ, command)
    else:
        try:
            reg.DeleteValue(key_open, 'CampusNetHelper')
        except FileNotFoundError:
            pass
    reg.CloseKey(key_open)

# 修改后的开机自启动开关回调函数
def toggle_auto_start():
    current_state = auto_start_var.get()
    set_auto_start(current_state)
    save_storage({
        'username': entry_username.get().strip(),
        'password': entry_password.get().strip(),
        'auto_connect': auto_connect_var.get(),
        'auto_start': current_state
    })

# 创建窗口
root = tk.Tk()
root.title('校园网连接助手')
root.geometry('350x350')

# 标题
tk.Label(root, text='校园网连接助手', font=('宋体', 20)).pack(pady=10)

# 账号输入框
tk.Label(root, text='账号：').pack(anchor='w', padx=10)
entry_username = tk.Entry(root, width=30)
entry_username.pack(padx=10, pady=5)

# 密码输入框
tk.Label(root, text='密码：').pack(anchor='w', padx=10)
entry_password = tk.Entry(root, show='*', width=30)
entry_password.pack(padx=10, pady=5)

# 加载数据
data = load_storage()

# 自动连接开关
auto_connect_var = tk.BooleanVar(value=data.get('auto_connect', False))
auto_connect_switch = ttk.Checkbutton(root, text="自动连接", variable=auto_connect_var, command=lambda: save_storage({
    'username': entry_username.get().strip(),
    'password': entry_password.get().strip(),
    'auto_connect': auto_connect_var.get(),
    'auto_start': auto_start_var.get()
}))
auto_connect_switch.pack(pady=5)

# 开机自启动开关
auto_start_var = tk.BooleanVar(value=data.get('auto_start', False))
auto_start_switch = ttk.Checkbutton(root, text="开机自启动", variable=auto_start_var, command=toggle_auto_start)
auto_start_switch.pack(pady=5)

# 连接按钮
btn_connect = tk.Button(root, text='点击连接', command=lambda: on_connect(), height=2, width=20)
btn_connect.pack(pady=10)

# 注销按钮
btn_logout = tk.Button(root, text='点击注销', command=lambda: on_logout(), height=2, width=20)
btn_logout.pack()

# 填充输入框
entry_username.insert(0, data.get('username', ''))
entry_password.insert(0, data.get('password', ''))

# 登录状态标志
login_success_shown = False
monitor_thread = None
monitor_running = threading.Event()

# 登录URL
LOGIN_URL = 'http://10.149.255.240/0.htm'
USER_INFO_URL = 'http://10.149.255.240/'

# 模拟登录校园网
def login(username, password, show_success_message=True):
    global login_success_shown
    data = {'DDDDD': username, 'upass': password, '0MKKey': '登录', 'v6ip': ''}
    try:
        response = requests.post(LOGIN_URL, data=data)
        if '登录成功' in response.text:
            if show_success_message and not login_success_shown:
                login_success_shown = True
                messagebox.showinfo('提示', f'{username} 登录成功')
            return True
        else:
            messagebox.showerror('错误', '登录失败')
            return False
    except Exception as e:
        messagebox.showerror('错误', f'登录请求失败: {e}')
        return False

# 检测网络是否正常
def is_network_ready():
    try:
        response = requests.get(USER_INFO_URL, headers={'Cache-Control': 'no-cache', 'Pragma': 'no-cache'})
        return 'flow=' in response.text or 'Dr.COMWebLoginID_3.htm' in response.text
    except Exception as e:
        return False

# 主函数
def main(username, password):
    global monitor_thread, monitor_running
    btn_connect.config(state=tk.DISABLED)
    if login(username, password):  # 第一次登录时显示提示
        if auto_connect_var.get():  # 如果自动连接被开启，启动网络监控
            monitor_running.set()
            if monitor_thread is None or not monitor_thread.is_alive():
                monitor_thread = threading.Thread(target=lambda: monitor_connection(username, password))
                monitor_thread.start()
    btn_connect.config(state=tk.NORMAL)

# 网络监控
def monitor_connection(username, password):
    global login_success_shown
    while monitor_running.is_set():
        if not is_network_ready():
            if not login(username, password, show_success_message=False):  # 不重复显示登录成功消息
                monitor_running.clear()
                break
        else:
            login_success_shown = False  # 网络恢复后允许下次提示登录成功
        time.sleep(60)

# 注销功能
def on_logout():
    global monitor_running
    monitor_running.clear()
    try:
        response = requests.get('http://10.149.255.240/F.htm')
        entry_username.delete(0, tk.END)
        entry_password.delete(0, tk.END)
        messagebox.showinfo('提示', '已成功注销')
    except Exception as e:
        messagebox.showerror('错误', f'注销失败: {e}')
    finally:
        btn_logout.config(state=tk.NORMAL)
        btn_connect.config(state=tk.NORMAL)

# 连接按钮事件
def on_connect():
    username = entry_username.get().strip()
    password = entry_password.get().strip()
    if not username or not password:
        messagebox.showerror('错误', '账号或密码不能为空！')
        return
    save_storage({
        'username': username,
        'password': password,
        'auto_connect': auto_connect_var.get(),
        'auto_start': auto_start_var.get()
    })
    threading.Thread(target=lambda: main(username, password)).start()

# 启动时检查自动连接状态
def check_auto_connect():
    if auto_connect_var.get():
        username = data.get('username', '')
        password = data.get('password', '')
        if username and password:
            on_connect()

# 设置开机自启动状态
set_auto_start(auto_start_var.get())

# 运行程序
check_auto_connect()  # 检查自动连接状态
root.mainloop()