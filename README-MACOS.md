# agy-tool · macOS 移植说明

原项目（justhil/agy-tool）只支持 Windows：PE 解析、`%LOCALAPPDATA%` 路径、`.exe`
进程管理。本移植在**不改动 Windows 行为**的前提下增加 macOS 支持，分支 `macos-port`。

## 改了什么

| 模块 | Windows（原版） | macOS（移植） |
|---|---|---|
| 二进制格式 | PE64 节表 + ImageBase 映射 | 新增 Mach-O 64 解析（`LC_SEGMENT_64` 的 vmaddr/fileoff 映射），含 Fat/Universal 双架构切片逐个打补丁 |
| 桌面端内核 | `%LOCALAPPDATA%\Programs\antigravity\resources\bin\language_server.exe` | `/Applications/Antigravity.app/Contents/Resources/bin/language_server`（也识别 `~/Applications` 安装） |
| 独立 CLI | `%LOCALAPPDATA%\agy\bin\agy.exe` / `where.exe` | `~/.local/bin/agy`（官方安装脚本默认位置），找不到时用 `which agy`；可用环境变量 `AGY_TOOL_AGY_PATH` 指向自定义安装路径 |
| IDE 内核 | `language_server_windows_x64.exe` | `/Applications/Antigravity IDE.app/Contents/Resources/app/extensions/antigravity/bin/language_server_macos_arm`（Intel 为 `language_server_macos_x64`） |
| HUD 的 app.asar | `%LOCALAPPDATA%\Programs\antigravity\resources\app.asar` | `/Applications/Antigravity.app/Contents/Resources/app.asar` |
| CDP 端口文件 | `%APPDATA%\Antigravity\DevToolsActivePort` | `~/Library/Application Support/Antigravity/DevToolsActivePort` |
| 进程检测/终止 | `tasklist` / `taskkill` + `CREATE_NO_WINDOW` | `ps` 匹配进程名 / `pkill -x` |
| 写入运行中二进制 | 改名替换（Windows 特性） | 同样走改名替换，并恢复 Unix 可执行权限位 |
| 代码签名 | 无此概念 | **写后自动 ad-hoc 重签**：Mach-O 本体 `codesign --force --sign -`；位于 `.app` 内时再重签整个 bundle（覆盖 app.asar 资源封印） |

提示词补丁逻辑、presets、上下文门禁的字节签名、applyEdits 绕过、HUD 的 JS 注入
与 CDP 热注入逻辑全部与原版共用，未改语义。

## 使用（macOS）

```bash
cargo build --release
mkdir -p ~/agy-tool && cp target/release/agy-tool ~/agy-tool/
cp -r presets ~/agy-tool/          # presets 必须与可执行文件同目录
cd ~/agy-tool
./agy-tool --status                # 只读扫描：先看模板/门禁识别情况
./agy-tool --full --prompt tier4-guardrails   # 推荐档：提示词精简 + 900K + HUD
./agy-tool --restore               # 一键全部还原（从 backup/ 恢复）
```

首次修改会在可执行文件同级 `backup/` 下保存原版备份；请把 `agy-tool` 放在
可写目录（如 `~/agy-tool`），不要放进 `/Applications`。

## 已知限制与注意事项（重要）

1. **上下文解锁在 Apple Silicon 上暂未命中**。门禁签名是 x86_64 指令字节，
   来自 Windows 版 Go 二进制；同一份 Go 源码编译的 darwin/amd64 大概率同构，
   但 **arm64 的指令编码完全不同，需要拿到 arm64 真机二进制重新定位签名**。
   在 arm64 上 `--context` 会自动跳过（日志无命中条目），提示词精简不受影响。
   CLI 版可先用官方环境变量 `AGY_CLI_AUTO_COMPACT_OVERRIDE=840000` 解锁压缩阈值。
2. **重签会改变程序的代码身份**。ad-hoc 签名后 Antigravity 失去公证身份：
   首次启动可能需要在「系统设置 → 隐私与安全性」放行，或被钥匙串询问是否
   允许访问登录项（agy 的登录凭证）——选允许即可，严重时重新登录一次。
   这是修改任何已签名 Mac 应用的固有效果，不是本工具的 bug。
3. **自动更新会覆盖补丁**。agy / Antigravity 更新后二进制恢复原版，
   重新运行本工具即可；`--status` 可确认当前状态。
4. **指针格式假设待真机确认**。Mach-O 解析假设 embed.FS 条目里存的是
   首选基址下的绝对 VA（Go 内部链接器的经典 rebase 模型，与 PE 版假设一致）。
   若新版 agy 改用 chained fixups 等指针编码，`--status` 会报解析失败而非
   乱打补丁——先跑 `--status` 确认能识别出模板槽位再动手。
5. **验证状态**：Mach-O/Fat 解析与补丁往返已通过合成二进制单元测试，
   darwin 目标交叉 `cargo check` 通过；GitHub Actions 提供 macos-14（arm64）
   与 macos-13（Intel）真实构建+测试，并有可选 job 在 runner 上装官方 agy
   跑 `--status` 验证真实二进制。**真机（真实 Antigravity 安装）端到端验证
   仍待在 Mac 上完成**——先跑 `--status` 看模板槽位是否被正确识别，再打补丁。
5. 修改官方客户端二进制本身的风险（账号风控等）与原版 Windows 相同，
   与本移植无关，见原 README。
