import os
import sys
import time
import subprocess

def startup():
    print("启动中...")
    # 获取主程序的真实路径
    path = os.path.dirname(sys.argv[0])
    # 主程序的路径
    main_program_path = os.path.join(path, "main_program.py")  # 替换为您的主程序名
    python_executable = sys.executable  # 获取当前使用的Python解释器路径
    try:
        # 使用Python解释器启动主程序
        subprocess.Popen([python_executable, main_program_path])
    except Exception as e:
        print(f"自启动失败，请手动操作... 错误信息：{e}")
        time.sleep(10)
    print("启动完成...")
    time.sleep(3)

startup()