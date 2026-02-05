#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
MaiQRTool - 舞萌/中二 登录二维码获取工具
Copyright (C) 2026 TesterNaN
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from flask import Flask, render_template, jsonify, send_from_directory, Response, request, make_response, abort
import threading
import win32gui
import win32con
import win32process
import ctypes
import win32api
import time
from PIL import ImageGrab
import psutil
from pyzbar.pyzbar import decode
import os
import requests
import uuid
import json
import base64
import secrets
import string
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import logging
import sys
from datetime import datetime

app = Flask(__name__)
# 设置一个安全的密钥用于session/cookie
app.secret_key = secrets.token_bytes(24)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# 设置DPI感知
ctypes.windll.user32.SetProcessDPIAware()

# 配置文件路径
CONFIG_FILE = "config.json"

# 配置参数（从配置文件加载）
CONFIG = None

# 常量定义
SESSION_EXPIRY_DAYS = 30  # Session有效期（天），固定30天
RENEW_THRESHOLD_DAYS = 7  # 续期阈值（天）
DEFAULT_PORT = 5000  # 默认端口

# 创建安全日志记录器
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# 创建控制台处理器
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

# 设置日志格式
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

console_handler.setFormatter(formatter)
security_logger.addHandler(console_handler)
security_logger.propagate = False

class SharedRequestPool:
    """共享请求池，/getcode 和 /img 共用同一个自动化流程"""
    
    def __init__(self):
        self.is_running = False  # 是否正在执行自动化流程
        self.raw_result = None   # 自动化流程的原始结果
        self.event = threading.Event()  # 事件，用于通知等待的请求
        self.lock = threading.Lock()    # 锁，保护状态
        self.waiting_requests = {}      # 等待的请求 {request_id: {'route': 'getcode'/'img', 'event': threading.Event, 'result': None}}
        self.next_request_id = 0
    
    def acquire_for_execution(self, route_name):
        """获取执行权，返回 (是否需要执行, 请求ID, 事件)"""
        with self.lock:
            request_id = self.next_request_id
            self.next_request_id = (self.next_request_id + 1) & 0xFFFFFFFF  # 防止整数溢出
            
            # 如果正在执行，则成为消费者
            if self.is_running:
                event = threading.Event()
                self.waiting_requests[request_id] = {
                    'route': route_name,
                    'event': event,
                    'result': None
                }
                return False, request_id, event  # 不需要执行，等待结果
            
            # 否则成为生产者
            self.is_running = True
            self.event.clear()  # 清除事件，等待新结果
            self.waiting_requests.clear()
            return True, request_id, None  # 需要执行
    
    def wait_for_result(self, request_id, event, timeout=35):
        """等待结果（消费者调用）"""
        # 等待事件，最多等待35秒
        if event.wait(timeout):
            with self.lock:
                if request_id in self.waiting_requests:
                    return self.waiting_requests[request_id]['result']
        return None  # 超时
    
    def set_raw_result(self, raw_result):
        """设置原始结果并处理所有等待的请求"""
        # 处理所有等待的请求
        events_to_set = []
        
        with self.lock:
            self.raw_result = raw_result
            
            # 收集需要设置的事件和结果
            for req_id, req_data in self.waiting_requests.items():
                route = req_data['route']
                
                if raw_result["success"]:
                    if route == 'getcode':
                        # 对于 /getcode，返回JSON
                        result = jsonify({
                            "success": True,
                            "qr_results": raw_result["qr_results"]
                        })
                    else:  # 'img'
                        # 对于 /img，下载图片
                        try:
                            meid = raw_result["qr_results"][0][4:]
                            qr_url = f"https://wq.wahlap.net/qrcode/img/{meid}.png?v"
                            img_response = requests.get(qr_url, timeout=10)
                            
                            if img_response.status_code == 200:
                                result = Response(
                                    img_response.content,
                                    mimetype='image/png',
                                    headers={
                                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                                        'Pragma': 'no-cache',
                                        'Expires': '0'
                                    }
                                )
                            else:
                                result = jsonify({
                                    "success": False,
                                    "error": f"图片下载失败，状态码: {img_response.status_code}"
                                }), 400
                        except requests.exceptions.RequestException as e:
                            result = jsonify({
                                "success": False,
                                "error": f"网络请求失败: {str(e)}"
                            }), 500
                        except Exception as e:
                            result = jsonify({
                                "success": False,
                                "error": f"图片处理失败: {str(e)}"
                            }), 500
                else:
                    # 自动化流程失败
                    result = jsonify({
                        "success": False,
                        "error": raw_result.get("error", "未知错误")
                    }), 400
                
                # 保存处理后的结果
                req_data['result'] = result
                events_to_set.append(req_data['event'])
            
            # 在执行结果处理后，但在通知消费者之前，重置状态
            # 这样新的请求不会干扰当前这批消费者
            self.is_running = False
        
        # 在锁外设置事件，避免死锁
        for event in events_to_set:
            event.set()
    
    def release_consumer(self, request_id):
        """消费者释放"""
        with self.lock:
            if request_id in self.waiting_requests:
                del self.waiting_requests[request_id]

# 全局共享请求池
shared_pool = SharedRequestPool()

def get_client_ip():
    """获取客户端真实IP地址"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip

def is_port_in_use(port, host='0.0.0.0'):
    """检查端口是否已被占用"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True

def load_or_create_config():
    """加载或创建配置文件"""
    global CONFIG
    
    if os.path.exists(CONFIG_FILE):
        # 加载现有配置
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                CONFIG = json.load(f)
            print(f"已加载配置文件: {CONFIG_FILE}")
            
            # 确保配置中包含所有必要字段
            required_fields = ['login_password', 'aes_key', 'aes_iv', 'port']
            for field in required_fields:
                if field not in CONFIG:
                    print(f"警告：配置文件中缺少 {field} 字段，将使用默认值")
                    if field == 'port':
                        CONFIG[field] = DEFAULT_PORT
                    else:
                        # 对于其他字段，需要重新生成配置文件
                        return create_new_config()
            
            return True
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            return False
    else:
        # 创建新配置
        return create_new_config()

def create_new_config():
    """创建新的配置文件"""
    global CONFIG
    try:
        # 生成随机登录密码（16个字符）
        login_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        
        # 生成AES密钥（32字节 = 256位）
        aes_key = secrets.token_bytes(32)
        
        # 生成AES偏移量（16字节）
        aes_iv = secrets.token_bytes(16)
        
        # 使用默认端口
        port = DEFAULT_PORT
        
        CONFIG = {
            'login_password': login_password,
            'aes_key': base64.b64encode(aes_key).decode('utf-8'),
            'aes_iv': base64.b64encode(aes_iv).decode('utf-8'),
            'port': port,
            'created_at': int(time.time())
        }
        
        # 保存到文件
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(CONFIG, f, indent=2, ensure_ascii=False)
        
        print(f"已创建配置文件: {CONFIG_FILE}")
        print(f"登录密码: {login_password}")
        print(f"服务端口: {port}")
        print(f"AES密钥和偏移量已生成并保存")
        return True
    except Exception as e:
        print(f"创建配置文件失败: {e}")
        return False

def get_aes_key():
    """获取AES密钥"""
    if not CONFIG or 'aes_key' not in CONFIG:
        raise ValueError("AES密钥未配置")
    return base64.b64decode(CONFIG['aes_key'])

def get_aes_iv():
    """获取AES偏移量"""
    if not CONFIG or 'aes_iv' not in CONFIG:
        raise ValueError("AES偏移量未配置")
    return base64.b64decode(CONFIG['aes_iv'])

def get_login_password():
    """获取登录密码"""
    if not CONFIG or 'login_password' not in CONFIG:
        raise ValueError("登录密码未配置")
    return CONFIG['login_password']

def get_port():
    """获取服务端口"""
    if not CONFIG or 'port' not in CONFIG:
        return DEFAULT_PORT
    return CONFIG['port']

# 加载白名单
def load_whitelist():
    """加载白名单从JSON文件"""
    whitelist_file = "whitelist.json"
    if os.path.exists(whitelist_file):
        try:
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return set(data.get('uuids', []))
        except Exception as e:
            print(f"加载白名单失败: {e}")
            return set()
    return set()

# 保存白名单
def save_whitelist(whitelist):
    """保存白名单到JSON文件"""
    whitelist_file = "whitelist.json"
    try:
        with open(whitelist_file, 'w', encoding='utf-8') as f:
            json.dump({'uuids': list(whitelist)}, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"保存白名单失败: {e}")
        return False

# AES加密函数
def aes_encrypt(data):
    """AES加密数据"""
    try:
        cipher = AES.new(get_aes_key(), AES.MODE_CBC, get_aes_iv())
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        print(f"AES加密失败: {e}")
        return None

# AES解密函数
def aes_decrypt(encrypted_data):
    """AES解密数据"""
    try:
        cipher = AES.new(get_aes_key(), AES.MODE_CBC, get_aes_iv())
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        decrypted_data = unpad(decrypted_padded, AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"AES解密失败: {e}")
        return None

def generate_session_data(user_uuid):
    """生成会话数据，格式：UUID|timestamp"""
    timestamp = int(time.time())
    return f"{user_uuid}|{timestamp}"

def parse_session_data(encrypted_session):
    """解析会话数据"""
    try:
        # 解密会话数据
        session_data = aes_decrypt(encrypted_session)
        if not session_data:
            return None
        
        # 解析数据
        parts = session_data.split('|')
        if len(parts) != 2:
            return None
            
        user_uuid, timestamp_str = parts
        
        try:
            session_timestamp = int(timestamp_str)
        except ValueError:
            return None
        
        # 计算过期时间戳（固定30天）
        expiry_timestamp = session_timestamp + (SESSION_EXPIRY_DAYS * 24 * 3600)
        
        return {
            'uuid': user_uuid,
            'timestamp': session_timestamp,
            'expiry_timestamp': expiry_timestamp
        }
        
    except Exception as e:
        print(f"解析会话数据失败: {e}")
        return None

def is_session_valid(session_info):
    """检查会话是否有效"""
    if not session_info:
        return False
    
    current_time = int(time.time())
    
    # 检查是否已过期
    if current_time > session_info['expiry_timestamp']:
        return False
    
    # 检查UUID是否在白名单中
    whitelist = load_whitelist()
    if session_info['uuid'] not in whitelist:
        return False
    
    return True

def needs_session_renewal(session_info):
    """检查是否需要续期"""
    if not session_info:
        return False
    
    current_time = int(time.time())
    
    # 计算距离过期还有多少秒
    seconds_until_expiry = session_info['expiry_timestamp'] - current_time
    
    # 转换为天数
    days_until_expiry = seconds_until_expiry / (24 * 3600)
    
    # 如果距离过期小于等于续期阈值，需要续期
    return days_until_expiry <= RENEW_THRESHOLD_DAYS

def renew_session(session_info):
    """续期会话，生成新的会话数据"""
    if not session_info:
        return None
    
    # 使用相同的UUID，但更新时间戳
    new_session_data = generate_session_data(session_info['uuid'])
    new_encrypted_session = aes_encrypt(new_session_data)
    
    return new_encrypted_session

# 鉴权装饰器
def auth_required(f):
    """需要鉴权的装饰器"""
    def decorated_function(*args, **kwargs):
        # 获取客户端IP
        client_ip = get_client_ip()
        
        # 获取cookie中的加密会话
        encrypted_session = request.cookies.get('session_token')
        
        if not encrypted_session:
            # 记录无授权访问尝试
            security_logger.warning(f"IP: {client_ip} 尝试无授权访问 {request.path}")
            abort(404)
        
        # 解析会话数据
        session_info = parse_session_data(encrypted_session)
        
        # 检查会话是否有效
        if not is_session_valid(session_info):
            # 记录无效会话访问
            security_logger.warning(f"IP: {client_ip} 使用无效会话访问 {request.path}")
            abort(404)
        
        # 检查是否需要续期
        response = None
        if needs_session_renewal(session_info):
            new_session = renew_session(session_info)
            if new_session:
                # 创建响应
                response = make_response()
                
                # 计算新的过期时间
                expires_timestamp = int(time.time()) + (SESSION_EXPIRY_DAYS * 24 * 3600)
                expires_datetime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(expires_timestamp))
                
                # 设置新的cookie
                response.headers.add(
                    'Set-Cookie',
                    f'session_token={new_session}; Expires={expires_datetime}; HttpOnly; Path=/; SameSite=Lax'
                )
        
        # 调用原始函数
        func_result = f(*args, **kwargs)
        
        # 如果已经有响应（续期的情况），合并响应
        if response:
            if isinstance(func_result, Response):
                response.set_data(func_result.get_data())
                response.headers.update(func_result.headers)
            elif isinstance(func_result, tuple):
                if len(func_result) >= 1:
                    response.set_data(func_result[0].get_data() if hasattr(func_result[0], 'get_data') else func_result[0])
                if len(func_result) >= 2:
                    response.status_code = func_result[1]
                if len(func_result) >= 3:
                    response.headers.update(func_result[2])
            else:
                response.set_data(str(func_result))
            
            return response
        
        return func_result
    
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/login')
def login():
    """登录页面，验证密码并生成加密的会话token"""
    # 获取客户端IP
    client_ip = get_client_ip()
    
    # 首先检查是否已经登录（有有效的session_token）
    encrypted_session = request.cookies.get('session_token')
    
    if encrypted_session:
        # 尝试解析和验证会话
        session_info = parse_session_data(encrypted_session)
        if session_info and is_session_valid(session_info):
            # 已经登录，返回提示信息
            security_logger.info(f"IP: {client_ip} 尝试重复登录（已登录状态）")
            return "您已经登录，无需重复登录"
    
    # 如果没有有效的session，继续正常的登录流程
    password = request.args.get('password')
    
    # 如果没有password参数，直接返回404
    if not password:
        security_logger.warning(f"IP: {client_ip} 尝试无密码登录")
        abort(404)
    
    # 密码不正确，返回404
    if password != get_login_password():
        security_logger.warning(f"IP: {client_ip} 登录失败（密码错误）")
        abort(404)
    
    # 生成新的UUID
    new_uuid = str(uuid.uuid4())
    
    # 加载白名单并添加新UUID
    whitelist = load_whitelist()
    whitelist.add(new_uuid)
    
    # 保存白名单
    if not save_whitelist(whitelist):
        security_logger.error(f"IP: {client_ip} 登录成功但保存白名单失败")
        abort(404)
    
    # 生成加密的会话数据
    session_data = generate_session_data(new_uuid)
    encrypted_session = aes_encrypt(session_data)
    
    if not encrypted_session:
        security_logger.error(f"IP: {client_ip} 登录成功但会话加密失败")
        abort(404)
    
    # 计算过期时间戳（固定30天）
    expires_timestamp = int(time.time()) + (SESSION_EXPIRY_DAYS * 24 * 3600)
    expires_datetime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(expires_timestamp))
    
    # 创建响应并设置cookie，不返回UUID给客户端
    response = make_response("登陆成功")
    
    # 设置cookie，直接使用Expires头
    response.headers.add(
        'Set-Cookie',
        f'session_token={encrypted_session}; Expires={expires_datetime}; HttpOnly; Path=/; SameSite=Lax'
    )
    
    # 记录登录成功
    security_logger.info(f"IP: {client_ip} 登录成功")
    
    return response

@app.route('/logout')
@auth_required
def logout():
    """登出，从白名单中移除UUID"""
    # 获取客户端IP
    client_ip = get_client_ip()
    
    # 获取cookie中的加密会话
    encrypted_session = request.cookies.get('session_token')
    
    if encrypted_session:
        # 解析会话获取UUID
        session_info = parse_session_data(encrypted_session)
        if session_info:
            user_uuid = session_info['uuid']
            
            # 从白名单中移除
            whitelist = load_whitelist()
            if user_uuid in whitelist:
                whitelist.discard(user_uuid)
                if save_whitelist(whitelist):
                    # 记录登出成功
                    security_logger.info(f"IP: {client_ip} 登出成功")
                else:
                    security_logger.error(f"IP: {client_ip} 登出成功但保存白名单失败")
    
    # 清除cookie
    response = make_response("登出成功")
    response.headers.add(
        'Set-Cookie',
        'session_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/; SameSite=Lax'
    )
    
    return response

def execute_automation_workflow():
    """执行完整的自动化工作流程并返回二维码结果"""
    result = {"success": False, "qr_results": [], "error": None}
    
    maimai_hwnd = None
    wechat_hwnd = None
    
    try:
        maimai_hwnd = win32gui.FindWindow(None, "舞萌丨中二")
        if not maimai_hwnd:
            result["error"] = "未找到舞萌窗口"
            return result
        
        placement = win32gui.GetWindowPlacement(maimai_hwnd)
        if placement[1] == win32con.SW_SHOWMINIMIZED:
            win32gui.ShowWindow(maimai_hwnd, win32con.SW_RESTORE)

        # 设置窗口为最顶层并激活
        win32gui.SetWindowPos(
            maimai_hwnd,
            win32con.HWND_TOPMOST,
            0, 0, 0, 0,
            win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW
        )
        
        # 等待一下确保窗口已激活
        time.sleep(0.2)
        
        # 取消置顶状态，但保持窗口在前台
        win32gui.SetWindowPos(
            maimai_hwnd,
            win32con.HWND_NOTOPMOST,
            0, 0, 0, 0,
            win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW
        )

        time.sleep(0.1)
        
        left, top = win32gui.ClientToScreen(maimai_hwnd, (0, 0))
        client_rect = win32gui.GetClientRect(maimai_hwnd)
        right = left + client_rect[2]
        bottom = top + client_rect[3]
        
        point1 = (left + (right - left) // 2, bottom - 39)
        point2 = (left + 270, bottom - 210)
        
        win32api.SetCursorPos(point1)
        time.sleep(0.05)
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, point1[0], point1[1], 0, 0)
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, point1[0], point1[1], 0, 0)
        time.sleep(3)
        
        win32api.SetCursorPos(point2)
        time.sleep(0.05)
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, point2[0], point2[1], 0, 0)
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, point2[0], point2[1], 0, 0)
        
        # 等待微信窗口出现
        wechat_hwnd = None
        start_time = time.time()
        timeout = 30  # 等待微信窗口出现的总时间
        
        while time.time() - start_time < timeout:
            def enum_callback(hwnd, window_list):
                if win32gui.IsWindowVisible(hwnd):
                    title = win32gui.GetWindowText(hwnd)
                    if title == "微信":
                        try:
                            _, pid = win32process.GetWindowThreadProcessId(hwnd)
                            process = psutil.Process(pid)
                            if process.name().lower() == "wechatappex.exe":
                                window_list.append(hwnd)
                        except:
                            pass
                return True
            
            windows = []
            win32gui.EnumWindows(enum_callback, windows)
            
            if windows:
                wechat_hwnd = windows[0]
                win32gui.ShowWindow(wechat_hwnd, win32con.SW_RESTORE)
                win32gui.SetForegroundWindow(wechat_hwnd)
                break
            
            time.sleep(0.5)  # 每0.5秒检查一次
        
        if not wechat_hwnd:
            result["error"] = "未找到微信窗口"
            return result
        
        # 轮询截图并尝试扫码
        qr_found = False
        max_attempts = 10
        attempt_interval = 0.5
        
        for attempt in range(max_attempts):
            # 确保窗口仍然在前台
            try:
                win32gui.SetForegroundWindow(wechat_hwnd)
            except:
                pass
            
            # 截图
            rect = win32gui.GetWindowRect(wechat_hwnd)
            screenshot = ImageGrab.grab(bbox=rect)
            
            # 尝试扫码
            try:
                decoded_objects = decode(screenshot)
                if decoded_objects:
                    result["qr_results"] = [obj.data.decode('utf-8') for obj in decoded_objects]
                    qr_found = True
                    break  # 成功找到二维码，退出轮询
            except Exception as e:
                # 扫码失败，继续下一次尝试
                pass
            
            # 如果不是最后一次尝试，则等待
            if attempt < max_attempts - 1:
                time.sleep(attempt_interval)
        
        # 无论扫码成功与否，都执行清理
        # 关闭微信窗口
        if wechat_hwnd:
            win32gui.PostMessage(wechat_hwnd, win32con.WM_CLOSE, 0, 0)
            time.sleep(0.5)
        
        # 最小化舞萌窗口
        if maimai_hwnd:
            ctypes.windll.user32.ShowWindow(maimai_hwnd, 6)
        
        # 设置最终结果
        if qr_found:
            result["success"] = True
        else:
            result["error"] = "二维码识别失败"
        
    except Exception as e:
        result["error"] = f"执行过程中发生异常: {str(e)}"
        # 异常时尝试清理
        try:
            if 'wechat_hwnd' in locals() and wechat_hwnd:
                win32gui.PostMessage(wechat_hwnd, win32con.WM_CLOSE, 0, 0)
            if 'maimai_hwnd' in locals() and maimai_hwnd:
                ctypes.windll.user32.ShowWindow(maimai_hwnd, 6)
        except:
            pass
    
    return result

@app.route('/')
@auth_required
def index():
    """返回主页面，自动执行流程并显示二维码"""
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/getcode')
@auth_required
def get_code():
    """执行自动化流程并返回结果（JSON格式）"""
    # 获取客户端IP
    client_ip = get_client_ip()
    
    # 尝试获取执行权
    should_execute, request_id, wait_event = shared_pool.acquire_for_execution('getcode')
    
    if should_execute:
        # 我是生产者
        try:
            # 记录开始获取二维码
            security_logger.info(f"IP: {client_ip} 开始获取登录二维码JSON")
            
            # 执行自动化流程
            result = execute_automation_workflow()
            
            # 设置原始结果，这会自动处理所有等待的请求
            shared_pool.set_raw_result(result)
            
            # 返回处理后的结果
            if result["success"]:
                # 记录成功获取
                security_logger.info(f"IP: {client_ip} 成功获取登录二维码JSON")
                return jsonify({
                    "success": True,
                    "qr_results": result["qr_results"]
                })
            else:
                # 记录获取失败
                error_msg = result.get("error", "未知错误")
                security_logger.error(f"IP: {client_ip} 获取登录二维码JSON失败: {error_msg}")
                return jsonify({
                    "success": False,
                    "error": error_msg
                }), 400
                
        except Exception as e:
            # 记录异常
            error_msg = f"API调用失败: {str(e)}"
            security_logger.error(f"IP: {client_ip} 获取登录二维码JSON时发生异常: {error_msg}")
            
            # 设置错误结果
            shared_pool.set_raw_result({"success": False, "error": error_msg})
            
            return jsonify({
                "success": False,
                "error": error_msg
            }), 500
    else:
        # 我是消费者，等待结果
        security_logger.info(f"IP: {client_ip} 等待获取登录二维码JSON结果")
        
        # 等待结果（最多35秒）
        result = shared_pool.wait_for_result(request_id, wait_event, 35)
        
        if result:
            # 成功获取到结果
            shared_pool.release_consumer(request_id)
            return result
        else:
            # 超时
            shared_pool.release_consumer(request_id)
            security_logger.error(f"IP: {client_ip} 等待二维码JSON结果超时")
            
            return jsonify({
                "success": False,
                "error": "请求超时"
            }), 504


@app.route('/img')
@auth_required
def get_img_code():
    """执行自动化流程并返回结果（图片格式）"""
    # 获取客户端IP
    client_ip = get_client_ip()
    
    # 尝试获取执行权
    should_execute, request_id, wait_event = shared_pool.acquire_for_execution('img')
    
    if should_execute:
        # 我是生产者
        try:
            # 记录开始获取二维码图片
            security_logger.info(f"IP: {client_ip} 开始获取登录二维码图片")
            
            # 执行自动化流程
            result = execute_automation_workflow()
            
            # 设置原始结果，这会自动处理所有等待的请求
            shared_pool.set_raw_result(result)
            
            # 返回处理后的结果
            if result["success"]:
                meid = result["qr_results"][0][4:]
                qr_url = f"https://wq.wahlap.net/qrcode/img/{meid}.png?v"
                
                img_response = requests.get(qr_url, timeout=10)
                
                if img_response.status_code == 200:
                    # 记录图片下载成功
                    security_logger.info(f"IP: {client_ip} 成功获取登录二维码图片")
                    
                    # 直接返回图片数据
                    return Response(
                        img_response.content,
                        mimetype='image/png',
                        headers={
                            'Cache-Control': 'no-cache, no-store, must-revalidate',
                            'Pragma': 'no-cache',
                            'Expires': '0'
                        }
                    )
                else:
                    # 记录图片下载失败
                    error_msg = f"图片下载失败，状态码: {img_response.status_code}"
                    security_logger.error(f"IP: {client_ip} {error_msg}")
                    
                    return jsonify({
                        "success": False,
                        "error": error_msg
                    }), 400
            else:
                # 记录二维码获取失败
                error_msg = result.get("error", "未知错误")
                security_logger.error(f"IP: {client_ip} 获取二维码数据失败: {error_msg}")
                
                return jsonify({
                    "success": False,
                    "error": error_msg
                }), 400
                
        except requests.exceptions.RequestException as e:
            # 记录网络请求异常
            security_logger.error(f"IP: {client_ip} 网络请求失败: {str(e)}")
            
            error_msg = f"网络请求失败: {str(e)}"
            shared_pool.set_raw_result({"success": False, "error": error_msg})
            
            return jsonify({
                "success": False,
                "error": error_msg
            }), 500
        except Exception as e:
            # 记录其他异常
            security_logger.error(f"IP: {client_ip} API调用失败: {str(e)}")
            
            error_msg = f"API调用失败: {str(e)}"
            shared_pool.set_raw_result({"success": False, "error": error_msg})
            
            return jsonify({
                "success": False,
                "error": error_msg
            }), 500
    else:
        # 我是消费者，等待结果
        security_logger.info(f"IP: {client_ip} 等待获取登录二维码图片结果")
        
        # 等待结果（最多35秒）
        result = shared_pool.wait_for_result(request_id, wait_event, 35)
        
        if result:
            # 成功获取到结果
            shared_pool.release_consumer(request_id)
            return result
        else:
            # 超时
            shared_pool.release_consumer(request_id)
            security_logger.error(f"IP: {client_ip} 等待二维码图片结果超时")
            
            return jsonify({
                "success": False,
                "error": "请求超时"
            }), 504

if __name__ == '__main__':
    # 安装必要的库
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
    except ImportError:
        print("需要安装pycryptodome库，请运行: pip install pycryptodome")
        exit(1)
    
    # 加载或创建配置文件
    if not load_or_create_config():
        print("配置加载失败，程序退出")
        exit(1)
    
    # 获取配置的端口
    PORT = get_port()
    
    # 检查端口是否被占用
    if is_port_in_use(PORT):
        print(f"错误：端口 {PORT} 已被占用！")
        print("请确保没有其他实例正在运行，或修改配置文件中的端口号。")
        exit(1)
    
    # 启动日志
    security_logger.info("=" * 50)
    security_logger.info(f"服务启动 - 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    security_logger.info(f"监听地址: 0.0.0.0:{PORT}")
    security_logger.info(f"本地访问: http://localhost:{PORT}")
    security_logger.info(f"登录密码: {get_login_password()}")
    security_logger.info("=" * 50)
    
    # 记录启动信息到控制台
    print(f"\n服务启动成功!")
    print(f"服务地址: http://localhost:{PORT}")
    print(f"访问 /login?password={get_login_password()} 进行登录")
    print(f"访问 /logout 进行登出")
    
    app.run(host='0.0.0.0', port=PORT)