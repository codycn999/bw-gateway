# bw-gateway 管理员速查（给网关所有者）

以下命令都用你自己的账号在 VM 上执行，不要交给 muse。配置文件是 `/etc/bw-gateway/env`（root:root，600）。

## 查看配置

只看每行的名字，值全部隐藏（可以放心截图）：
```
sudo sed -E 's/=.*/=****/' /etc/bw-gateway/env
```

列出所有 agent key 及其权限（隐藏哈希）：
```
sudo grep '^GATEWAY_KEY_' /etc/bw-gateway/env | sed -E 's/=[0-9a-f]{64}:/  ->  /'
```
输出示例：`GATEWAY_KEY_MUSE_CODYCN999  ->  by-uuid`

查看完整内容（含 Bitwarden token 等明文，只在自己终端看，不要截图或粘贴）：
```
sudo cat /etc/bw-gateway/env
```

网关当前实际加载了哪些 key（以日志为准）：
```
sudo journalctl -u bw-gateway --no-pager | grep 'agent key' | tail -1
```

> 文件里只存 key 的哈希，**无法从中还原 key**。key 丢了就生成一把新的，删掉旧行。

## 新增 agent key

一条命令生成 key 并写入配置（屏幕上的 `bwg_...` 就是 key，只显示这一次）：
```
python3 /opt/bw-gateway/scripts/new-agent-key.py <名字> by-uuid | tee /dev/tty | grep '^GATEWAY_KEY_' | sudo tee -a /etc/bw-gateway/env >/dev/null
sudo systemctl restart bw-gateway
```
权限部分可换成：`by-uuid`（给了 UUID 才能读）、`project:<项目UUID>`、`<机密UUID>,<机密UUID>`、机密名或通配符 `OPENAI_*`，多个用逗号分隔。

## 吊销 / 更换 agent key

吊销（把 `<名字>` 换成大写名字，例如 `MUSE_CODYCN999`）：
```
sudo sed -i '/^GATEWAY_KEY_<名字>=/d' /etc/bw-gateway/env
sudo systemctl restart bw-gateway
```
更换：先吊销，再用同一个名字新增。

修改某把 key 的权限：
```
sudo nano /etc/bw-gateway/env     # 只改冒号后面的部分，Ctrl+O 回车保存，Ctrl+X 退出
sudo systemctl restart bw-gateway
```

删除旧的共享 key（确认没人再用后）：
```
sudo sed -i '/^GATEWAY_API_KEY=/d' /etc/bw-gateway/env
sudo systemctl restart bw-gateway
```

## 检查与测试

```
sleep 5; curl -s http://127.0.0.1:8080/health; echo        # agents 数应等于 key 数
```

用某把 key 测试（`read -s` 单独执行，粘贴 key 后回车，不回显）：
```
read -s K
curl -s -H "Authorization: Bearer $K" http://127.0.0.1:8080/v1/whoami; echo
curl -s -H "Authorization: Bearer $K" http://127.0.0.1:8080/v1/value/<机密UUID>; echo
unset K
```

外网（在自己电脑上）：
```
curl -s https://bw-gateway.hoot.dpdns.org/health
```

## 日志与审计

谁在什么时候读了哪些机密（不含值）：
```
sudo journalctl -u bw-gateway --no-pager | grep audit | tail -50
```
认证失败和封禁：
```
sudo journalctl -u bw-gateway --no-pager | grep -E 'auth failed|lockout' | tail -50
```

## 服务

```
sudo systemctl restart bw-gateway                     # 改配置后必须重启
systemctl status bw-gateway --no-pager | head -5
systemctl status cloudflared --no-pager | head -5     # Cloudflare Tunnel
```

## 部署新代码

让 muse 连一次 VM 即可（会自动执行 `bw-gateway-deploy`），或你自己执行：
```
sudo /usr/local/bin/bw-gateway-deploy
```
部署不会改动 `/etc/bw-gateway/env`。

## 更换 Bitwarden 机器账户 token

```
sudo nano /etc/bw-gateway/env      # 替换 BWS_ACCESS_TOKEN 的值
sudo systemctl restart bw-gateway
```
然后在 Bitwarden 里吊销旧 token。

## 用完清理

```
history -c      # 退出终端前清掉本次会话的命令历史
```
