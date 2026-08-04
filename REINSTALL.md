# KADA 重装 / 全新部署步骤清单

> 适用系统：Linux（Debian / Ubuntu / CentOS 等）。本项目只能在 Linux 运行，Windows 只能看代码、跑不了。
> 项目已从旧名 `aimili-vpngate` / `AimiliVPN` 全面更名为 **kada / KADA**，下面全部用新名字。

---

## 一、准备环境
1. 一台 Linux 服务器（VPS），有 `root` 或 `sudo` 权限。
2. 在防火墙放行要用到的端口（默认：管理网页 **8787**、双效代理 **7928**，可按需改）。
3. 装好 `git` 和 `python3`：
   - Debian / Ubuntu：`sudo apt update && sudo apt install -y git python3`
   - CentOS / Rocky：`sudo yum install -y git python3`

## 二、获取代码（全新、干净、无旧名）
在任意目录执行：
```bash
git clone https://github.com/kadiswang/kada.git
cd kada
```
> 如果你本地还有旧的 `aimili-vpngate` 文件夹，直接删掉即可，不影响任何东西。

## 三、一键安装
```bash
bash install.sh
```
脚本会自动完成：
- 把程序装到 `/opt/kada`
- 创建系统服务 `kada.service`（systemd）或 `kada`（OpenRC）
- 设为开机自启并启动

## 四、常用操作
```bash
sudo systemctl start   kada    # 启动
sudo systemctl stop    kada    # 停止
sudo systemctl restart kada     # 重启
sudo systemctl status  kada    # 查看状态
sudo journalctl -u kada -f     # 看实时日志
```
> 用 OpenRC 的机器把 `systemctl` 换成 `rc-service kada start/stop/restart`。

## 五、打开管理网页
浏览器访问：`http://<你的服务器IP>:8787`
- 首次启动会自动拉取节点、建立加密通道（约 5–30 秒）。
- 登录账号在 `install.sh` 顶部变量 / 配置文件里设置，详见 README。

## 六、卸载（如需要）
```bash
bash install.sh uninstall
```
或运行安装脚本后选择卸载，会停止服务、删除 `/opt/kada`、清理 systemd / OpenRC 配置。

## 七、改默认配置（可选）
想改安装目录、服务名、端口等，编辑 `install.sh` 顶部变量后重跑安装即可：
- 安装目录：`/opt/kada`
- 服务名：`kada.service`
- 管理网页端口：`8787`
- 双效代理端口：`7928`

## 八、常见问题
- **网页打不开**：检查防火墙是否放行 8787；`sudo systemctl status kada` 是否 `active`。
- **代理连不上**：双效代理默认只绑 `127.0.0.1`（本机使用）；要对外需在防火墙 / 反代里另行配置。
- **节点一直为空**：确认服务器能访问外网拉取节点；看日志 `sudo journalctl -u kada -f`。

---

### 新旧名字对照（备查）
| 项目 | 旧名 | 新名 |
| --- | --- | --- |
| 仓库 / 项目 | aimili-vpngate | **kada** |
| 界面产品名 | AimiliVPN | **KADA** |
| 安装目录 | /opt/aimilivpn | **/opt/kada** |
| 系统服务 | aimilivpn.service | **kada.service** |
| 网页主题键 | aimili_theme | **kada_theme** |
