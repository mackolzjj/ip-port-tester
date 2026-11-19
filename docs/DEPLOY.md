# 部署到服务器

这个工具本质是一个**要求出站访问任意 `IP:端口` 的探测程序**。放到公网服务器上能跑，但有三件事必须先想清楚：

1. **它会被当成扫描器**。探测行为是 TCP 握手，很多 VPS 商家的 AUP 明确禁止端口扫描，被投诉会直接停机。别拿它对整个互联网扫端口。
2. **界面必须加口令**。`--host 0.0.0.0` 会自动生成口令，但如果你反代出去，还得再套一层（见下文）。
3. **必须加 `--keep-alive`**。默认逻辑是「最后一个页面关掉就退出」，服务器上没人开页面就会被自己关掉。

---

## 方式一：直接跑（systemd，推荐给有 SSH 的 VPS）

### 1. 建用户和目录

```bash
sudo useradd -r -s /usr/sbin/nologin -d /opt/iptester iptester
sudo mkdir -p /opt/iptester
sudo chown -R iptester:iptester /opt/iptester
```

### 2. 放代码

```bash
# 任选其一
sudo -u iptester git clone https://github.com/mackolzjj/ip-port-tester.git /opt/iptester
# 或者从本地上传（只需要一个文件）
scp ip_tester.py user@server:/tmp/ && sudo mv /tmp/ip_tester.py /opt/iptester/
sudo chown iptester:iptester /opt/iptester/ip_tester.py
```

只需要 `ip_tester.py` 一个文件，其余都会自动生成。

### 3. 配口令

```bash
sudo tee /etc/iptester.env >/dev/null <<'EOF'
IPTESTER_TOKEN=换成你自己的长口令
EOF
sudo chmod 600 /etc/iptester.env
```

不设也行——程序会自动生成一个并写到 `/opt/iptester/token.txt`，用 `sudo cat` 看一眼即可。

### 4. 装 service

```bash
sudo cp /opt/iptester/deploy/iptester.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now iptester
sudo systemctl status iptester --no-pager
```

开机自启已包含（`enable`）。日志：

```bash
sudo journalctl -u iptester -f
```

### 5. 放行端口

```bash
sudo ufw allow 8765/tcp            # Ubuntu/Debian
sudo firewall-cmd --add-port=8765/tcp --permanent && sudo firewall-cmd --reload   # CentOS
```

云服务器还要在**控制台安全组**里放行同样的端口，这一步最容易漏。

浏览器打开 `http://服务器IP:8765`，用户名随便填（或留空），口令填上面那个。

### 更新

```bash
cd /opt/iptester && sudo -u iptester git pull
sudo systemctl restart iptester
```

### 内网免认证

只在家里 / 办公室内网用，嫌登录框麻烦：

```ini
ExecStart=/usr/bin/python3 /opt/iptester/ip_tester.py --host 0.0.0.0 --port 8765 --keep-alive --no-auth --no-browser
```

Docker 里追加一个 command 即可（ENTRYPOINT 已带其余参数）：

```yaml
    command: ["--no-auth"]
```

> `--no-auth` 意味着任何能连到这个端口的人都能用，也能借它测任意目标的端口。
> 只在可信内网开；公网或半开放网络请保留口令。

---

## 方式二：Docker

```bash
docker build -t ip-port-tester .

docker run -d --name iptester \
  --restart unless-stopped \
  -p 8765:8765 \
  -e IPTESTER_TOKEN=换成你自己的长口令 \
  -v /srv/iptester/output:/app/output \
  ip-port-tester
```

或者用 compose：

```yaml
services:
  iptester:
    build: .
    restart: unless-stopped
    ports: ["8765:8765"]
    environment:
      IPTESTER_TOKEN: 换成你自己的长口令
    volumes:
      - ./output:/app/output
```

> 容器里必须保留 `--keep-alive`（Dockerfile 的 ENTRYPOINT 已带），否则最后一个页面关掉容器就会退出。

---

## 方式三：Nginx 反代 + HTTPS（对外暴露时用）

不加密的话口令是明文传输，公网上等于没有。前面挂一层 Nginx：

```nginx
server {
    listen 443 ssl http2;
    server_name speed.example.com;

    ssl_certificate     /etc/letsencrypt/live/speed.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/speed.example.com/privkey.pem;

    # 只允许自己的 IP（强烈建议打开）
    allow 1.2.3.4;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;

        # WebSocket 升级：必须带上，否则「关页面即退出」失效
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 3600s;   # 测速可能很久，别被反代掐断
        proxy_send_timeout 3600s;
    }
}
```

配套把服务只监听本地：

```ini
ExecStart=/usr/bin/python3 /opt/iptester/ip_tester.py --host 127.0.0.1 --port 8765 --keep-alive --no-browser
```

证书用 certbot：

```bash
sudo certbot --nginx -d speed.example.com
```

---

## 常见问题

**打开是空白 / 401 反复弹框**
口令错了。`sudo cat /opt/iptester/token.txt` 看真实口令；`IPTESTER_TOKEN` 环境变量优先级高于 `token.txt`。

**页面能开，但一刷新服务就退出**
没加 `--keep-alive`。服务器上必须加，否则「关页面退出」的逻辑会把服务带走。

**测速全是 0ms / 全部可用**
本机有代理 TUN 在替你回 SYN。界面上会有橙色提示，先关代理的 TUN 模式再测。

**测速很慢或大面积失败**
看服务器自己的出站是否正常：`curl -sI https://www.baidu.com`。再确认 `--workers`（默认 32）没有被系统 `ulimit -n` 卡住。

**端口连不上但服务在跑**
先 `ss -lntp | grep 8765` 确认监听，再查云控制台安全组——90% 是这一步漏了。

**想让多个同事同时用**
直接把地址发给他们即可，同一实例支持多标签/多人同时测；结果在各自浏览器里，不会串。

**结果文件在哪**
`/opt/iptester/output/ip_speed.txt`（可用节点）和 `ip_speed_detail.csv`（全量明细）。下载按钮也走的是同一份。

---

## 安全清单

- [ ] 设了 `IPTESTER_TOKEN`，且长度 ≥ 16
- [ ] 加了 `--keep-alive`
- [ ] 对外开放时走 HTTPS（Nginx + 证书）
- [ ] Nginx 里 `allow` 限定来源 IP
- [ ] 不在公网机器上做大规模扫描（违反 VPS 商家 AUP 会被停机）
- [ ] `/etc/iptester.env` 权限 600，不进 git
