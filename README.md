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

## 宝塔面板（aaPanel）部署

宝塔支持直接托管 Python 项目，全程图形化，不需要手写 systemd。

### 第一步：安装 sqlmap

宝塔终端执行：

```bash
pip3 install sqlmap
which sqlmap        # 记下路径，通常是 /usr/local/bin/sqlmap 或 /usr/bin/sqlmap
```

### 第二步：安装 Python 项目管理器

宝塔面板 → **软件商店** → 搜索 **Python项目管理器** → 安装。

同时确认已安装 **Python 3.9+**（软件商店 → 运行环境 → Python 管理器，选版本安装）。

### 第三步：上传代码

在宝塔「文件」里把代码上传到服务器，例如 `/www/wwwroot/openclaw/`。

或者在终端 git clone：

```bash
cd /www/wwwroot
git clone <your-repo> openclaw
```

### 第四步：安装依赖

宝塔终端：

```bash
cd /www/wwwroot/openclaw
pip3 install -r requirements.txt
pip3 install gunicorn
```

### 第五步：添加 Python 项目

宝塔面板 → **Python项目管理器** → **添加项目**，按下表填写：

| 字段 | 填写内容 |
|------|----------|
| 项目名称 | openclaw |
| 项目路径 | `/www/wwwroot/openclaw` |
| Python版本 | 选你安装的 3.9+ 版本 |
| 启动方式 | **gunicorn** |
| 启动文件 | `app:app` |
| 端口 | `5000`（或其他空闲端口） |
| 启动参数 | `-w 1 --preload` |

> **`-w 1` 必须填**，任务队列状态保存在内存，多 worker 会导致任务状态混乱。

点击「确定」，项目管理器会自动启动并设置开机自启。

### 第六步：配置反向代理（绑定域名）

宝塔面板 → **网站** → **添加站点**，填入域名。

站点建好后 → 点击站点 → **反向代理** → 添加反向代理：

| 字段 | 填写内容 |
|------|----------|
| 代理名称 | openclaw |
| 目标URL | `http://127.0.0.1:5000` |
| 发送域名 | `$host` |

保存后即可通过域名访问。

### 第七步：开启 HTTPS（可选）

宝塔面板 → 网站 → 点击站点 → **SSL** → 选「Let's Encrypt」，一键申请证书并开启强制 HTTPS。

### 第八步：修改 sqlmap 路径

首次访问页面，点右上角「设置」，把 sqlmap 路径改成第一步 `which sqlmap` 查到的实际路径。

---

### 宝塔常见问题

**项目启动失败**

Python项目管理器 → 点击项目 → 查看「运行日志」，通常是依赖没装或路径写错。

**5000 端口被占用**

改用其他端口（如 5001、8888），在项目管理器里修改端口，反向代理目标 URL 也同步修改。

**宝塔防火墙拦截**

如果只走 Nginx 反向代理，5000 端口不需要对外开放，不用在宝塔防火墙里放行。

**sqlmap 执行没权限**

```bash
chmod +x /usr/local/bin/sqlmap
```

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
