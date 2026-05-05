# OpenClaw

自动化 SQLmap 扫描队列，Web 界面管理注入任务。

---

## 环境要求

| 依赖 | 版本要求 |
|------|----------|
| Python | 3.9 及以上 |
| sqlmap | 任意版本（推荐最新） |
| Flask | 3.0.0（requirements.txt 自动安装） |
| Gunicorn | 生产环境需要（pip 安装） |

---

## 一、直接运行（测试用）

适合本地测试，不建议生产环境使用。

```bash
# 1. 克隆代码
git clone <your-repo> openclaw
cd openclaw

# 2. 安装依赖
pip3 install -r requirements.txt

# 3. 确认 sqlmap 已安装
which sqlmap
sqlmap --version

# 4. 启动
python3 app.py
```

访问 `http://127.0.0.1:5000`

数据库和扫描目录会**自动创建**，无需手动初始化。

---

## 二、生产环境（Gunicorn）

Flask 自带的开发服务器不适合长期运行，生产环境必须用 Gunicorn。

```bash
pip3 install gunicorn

gunicorn -w 1 -b 0.0.0.0:5000 "app:app" --preload
```

> **`-w 1` 必须保留**：任务队列和子进程状态保存在内存中，多 worker 会导致状态混乱。

---

## 三、宝塔面板（aaPanel）部署

### 第一步：安装 sqlmap

在宝塔终端执行：

```bash
pip3 install sqlmap

# 记下实际路径，后面要用
which sqlmap
# 通常是 /usr/local/bin/sqlmap 或 /usr/bin/sqlmap
```

如果系统 sqlmap 是 .py 文件（如 `/www/wwwroot/sqlmap/sqlmap-master/sqlmap.py`），直接填该路径即可，程序会自动加 `python3` 前缀执行。

### 第二步：安装 Python 管理器

宝塔面板 → **软件商店** → 搜索 **Python项目管理器** → 安装

同时安装 **Python 3.9+**（软件商店 → 运行环境 → Python 管理器，选版本安装）

### 第三步：上传代码

方式一：宝塔「文件」里直接上传并解压到 `/www/wwwroot/openclaw/`

方式二：在终端 git clone：

```bash
cd /www/wwwroot
git clone <your-repo> openclaw
```

### 第四步：安装依赖

```bash
cd /www/wwwroot/openclaw
pip3 install -r requirements.txt
pip3 install gunicorn
```

### 第五步：添加 Python 项目

宝塔面板 → **Python项目管理器** → **添加项目**，按以下对照填写：

| 界面字段 | 填写内容 | 备注 |
|----------|----------|------|
| Python项目名称 | `openclaw` | 随意起名 |
| 项目端口 | `5000` | 或其他空闲端口 |
| Python环境 | 选已安装的 3.9+ 版本 | 在「环境管理」里安装 |
| 启动方式 | `gunicorn` | 下拉选择 |
| 项目路径 | `/www/wwwroot/openclaw` | 代码所在目录 |
| 入口文件 | 自动检测为 `app.py` | 无需修改 |
| 通信协议 | **WSGI** | Flask 是 WSGI，选这个 |
| 应用程序名称 | `app` | 自动检测，无需修改 |
| 启动命令 | `-w 1 --preload` | 只填额外参数 |
| 启动用户 | `root` 或 `www` | 默认即可 |
| 安装依赖 | 自动检测 requirements.txt | 无需修改 |
| 项目初始化命令 | 留空 | |

> **`-w 1` 必须填入启动命令**，多 worker 会导致任务队列状态混乱。

点击「确认」后宝塔会自动安装依赖、启动服务并设置开机自启。

### 第六步：配置反向代理（绑定域名）

宝塔面板 → **网站** → **添加站点** → 填入域名

站点建好后 → 点击站点 → **反向代理** → 添加：

| 字段 | 填写内容 |
|------|----------|
| 代理名称 | openclaw |
| 目标URL | `http://127.0.0.1:5000` |
| 发送域名 | `$host` |

### 第七步：开启 HTTPS（可选）

宝塔面板 → 网站 → 点击站点 → **SSL** → Let's Encrypt → 一键申请证书

### 第八步：设置 sqlmap 路径

首次访问页面，在左侧底部「SQLMAP 路径」输入框填入第一步查到的实际路径，点「保存配置」。

---

### 宝塔常见问题

**任务一直排队，不运行**

Python项目管理器 → 查看「运行日志」，确认 worker 线程有无报错。重启项目后，卡住的 running 任务会自动标记为 killed，可以重新提交。

**sqlmap 无权限**

```bash
chmod +x /usr/local/bin/sqlmap
# 或者
chmod +x /www/wwwroot/sqlmap/sqlmap-master/sqlmap.py
```

**5000 端口被占用**

Python项目管理器里把端口改为其他空闲端口（如 5001、8888），反向代理目标 URL 同步修改。

**5000 端口不需要对外开放**，走 Nginx 反向代理，宝塔防火墙不用放行 5000。

**重新部署后任务记录还在**

数据库文件是 `openclaw.db`，扫描文件在 `scans/` 目录，删掉这两个即可清空数据。

---

## 四、Systemd 服务（纯命令行服务器）

不用宝塔的情况下，用 systemd 管理进程和开机自启。

创建 `/etc/systemd/system/openclaw.service`：

```ini
[Unit]
Description=OpenClaw SQLmap Scanner
After=network.target

[Service]
User=www-data
WorkingDirectory=/www/wwwroot/openclaw
ExecStart=/usr/local/bin/gunicorn -w 1 -b 0.0.0.0:5000 "app:app" --preload
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> `User=www-data` 按实际情况修改，`WorkingDirectory` 填代码实际路径。

启用并启动：

```bash
systemctl daemon-reload
systemctl enable openclaw
systemctl start openclaw
systemctl status openclaw
```

查看日志：

```bash
journalctl -u openclaw -f
```

---

## 五、Nginx 反向代理（绑定域名 / HTTPS）

```nginx
server {
    listen 80;
    server_name scan.example.com;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 300s;
    }
}
```

HTTPS 证书：

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
├── config.py         # 路径 & 默认参数
├── requirements.txt
├── openclaw.db       # 运行时自动创建
├── scans/            # 运行时自动创建
│   └── <task_id>/
│       ├── request.txt
│       └── output/   # sqlmap 输出文件
└── templates/
    └── index.html
```

---

## 使用说明

### 基本流程

1. 用 Burp Suite 或浏览器开发者工具抓到 HTTP 请求报文
2. 在注入点处打上 `*` 标记，例如：
   ```
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=admin*&password=123456
   ```
3. 点击「新建扫描」，粘贴请求包，填好 Level / Risk / 超时，提交
4. 任务进入队列，串行自动执行，页面每 3 秒刷新

### 扫描阶段

每个任务分三个阶段，后两个阶段只在注入探测成功后才执行：

| 阶段 | 目的 |
|------|------|
| 注入探测 | 检测是否存在 SQL 注入点 |
| UPDATE 测试 | 检测是否支持堆叠查询（可写入操作） |
| DBA 检测 | 检测当前数据库用户是否有 root/DBA 权限 |

### Level / Risk 说明

| 参数 | 范围 | 说明 |
|------|------|------|
| Level | 1–5 | 测试深度，越高测试越多参数（Headers、Cookies 等），但越慢 |
| Risk | 1–3 | 风险等级，越高使用越激进的 payload（可能影响数据库数据） |

默认 Level=2、Risk=2，适合大多数场景。

### CSRF Token 说明

请求包里带有 CSRF Token 的目标，sqlmap 扫描时会自动识别并询问是否自动更新 Token，程序已配置为自动选 Y。如果 Token 是每次请求动态生成的，建议在请求包里保留最新的 Token 值。

---

## 常见问题

**sqlmap 找不到 / 路径错误**

页面左侧底部「SQLMAP 路径」输入框修改路径，或直接编辑 `config.py` 里的 `DEFAULT_SQLMAP_PATH`。

**任务一直 pending 不执行**

重启服务。重启会自动将卡住的 running 任务标记为 killed，重新提交即可。

**sqlmap 版本问题（using STDIN for parsing targets list）**

部分 sqlmap dev 版本在非交互模式下有此 bug，程序已通过 `--ignore-stdin` 参数规避。

**磁盘占用增长**

sqlmap 输出积累在 `scans/<task_id>/output/`，可在页面上删除已完成的任务，或直接 `rm -rf scans/`（会清空扫描文件，数据库记录保留）。
