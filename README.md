# OpenClaw

自动化 SQLmap 扫描队列，Web 界面管理注入任务。

## 环境要求

- Python 3.9+
- sqlmap（已安装在系统）

---

## 快速部署

### 1. 克隆 / 上传代码

```bash
git clone <your-repo> openclaw
cd openclaw
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 确认 sqlmap 路径

默认路径是 `/usr/bin/sqlmap`，可以先检查：

```bash
which sqlmap
sqlmap --version
```

如果路径不同，启动后在页面右上角「设置」里改，或直接改 `config.py`：

```python
DEFAULT_SQLMAP_PATH = "/usr/bin/sqlmap"
```

### 4. 启动

```bash
python app.py
```

浏览器访问 `http://127.0.0.1:5000`

数据库和扫描目录会自动创建，无需手动初始化。

---

## 生产部署（推荐）

直接用 `python app.py` 跑的是 Flask 开发服务器，不适合长期运行。推荐用 Gunicorn。

### 安装 Gunicorn

```bash
pip install gunicorn
```

### 启动

```bash
gunicorn -w 1 -b 0.0.0.0:5000 "app:app" --preload
```

**必须 `-w 1`（单 worker）**，因为扫描任务队列和子进程状态保存在内存里，多 worker 会导致状态不一致。

---

## Systemd 服务（开机自启）

创建 `/etc/systemd/system/openclaw.service`：

```ini
[Unit]
Description=OpenClaw SQLmap Scanner
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/openclaw
ExecStart=/usr/local/bin/gunicorn -w 1 -b 0.0.0.0:5000 "app:app" --preload
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
systemctl daemon-reload
systemctl enable openclaw
systemctl start openclaw
systemctl status openclaw
```

---

## Nginx 反向代理（可选）

如果需要绑定域名或 HTTPS，在 Nginx 里加一个 location：

```nginx
server {
    listen 80;
    server_name scan.example.com;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

HTTPS 用 certbot 申请证书即可：

```bash
certbot --nginx -d scan.example.com
```

---

## 目录结构

```
openclaw/
├── app.py            # Flask 路由
├── scanner.py        # 扫描队列 & sqlmap 调用
├── db.py             # SQLite 数据库操作
├── config.py         # 路径 & 默认参数配置
├── requirements.txt
├── openclaw.db       # 自动创建
├── scans/            # 自动创建，每个任务一个子目录
│   └── <task_id>/
│       ├── request.txt
│       └── output/   # sqlmap 输出
└── templates/
    └── index.html
```

---

## 使用说明

1. 用 Burp / 浏览器抓到 HTTP 请求报文
2. 在注入点处打上 `*` 标记（sqlmap `-r` 模式识别）
3. 粘贴到「新建任务」，填好 Level / Risk / 超时，提交
4. 任务进入队列，自动串行执行，页面每 3 秒刷新一次

**三个扫描阶段：**

| 阶段 | 命令 | 目的 |
|------|------|------|
| 注入探测 | sqlmap -r ... | 是否存在 SQL 注入 |
| UPDATE 测试 | --sql-query=UPDATE ... | 是否支持堆叠查询写操作 |
| DBA 检测 | --is-dba | 当前数据库用户是否有 root 权限 |

后两个阶段只在注入探测成功后才执行。

---

## 常见问题

**sqlmap 找不到**

页面右上角「设置」里修改 sqlmap 路径，或 `which sqlmap` 确认。

**任务一直 pending**

检查 worker 线程是否正常。重启服务即可，重启时会自动把卡住的 running 任务标记为 killed。

**端口被占用**

```bash
# 改端口
gunicorn -w 1 -b 0.0.0.0:8080 "app:app" --preload
```

**磁盘空间**

sqlmap 的 `--output-dir` 输出会积累在 `scans/<task_id>/output/`，可以定期清理已完成任务。
