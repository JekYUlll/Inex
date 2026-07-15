# VS Code 持久 Profile 验收协议（Linux）

这是一份针对候选 VSIX 的人工验收协议，不是发布批准或“无残留”
证明。它补足自动化 Extension Host 不能可靠驱动的真实 folder picker、任务
终端口令输入、用户持久 profile、WorkBench 选项卡焦点和 Source Control 路径。

只使用一次性的测试内容。不要把真实日记、真实 Umbra 口令、真实 Git remote
或任何可识别个人信息用于本协议。

## 前提

1. 使用候选 VSIX 所绑定的 Linux x64 主机；不得将不同 revision 的 `inex`、
   `inexd` 与 VSIX 混用。
2. 建立一个新的、专用的 VS Code profile，除 Inex 外不安装扩展，也不要登录
   Settings Sync。
3. 使用新的临时目录，例如：

   ```sh
   ROOT="$(mktemp -d /tmp/inex-vscode-profile-check.XXXXXX)"
   SOURCE="$ROOT/source"
   VAULT_PARENT="$ROOT/vault-parent"
   PROFILE="$ROOT/profile"
   EXTENSIONS="$ROOT/extensions"
   mkdir -p "$SOURCE" "$VAULT_PARENT" "$PROFILE" "$EXTENSIONS"
   git -C "$SOURCE" init -q --initial-branch=main
   printf '# Heading A\r\n\r\nDisposable profile canary\r\n\r\n## Heading B\r\n\r\nBody\r\n' > "$SOURCE/note.md"
   git -C "$SOURCE" add note.md
   git -C "$SOURCE" -c user.name=Inex -c user.email=inex@example.invalid \
     commit -q -m fixture
   ```

   该文件刻意使用 CRLF，且 canary 必须是本次运行独有的可丢弃字符串。
   可以在 `Disposable profile canary` 后追加随机后缀，但不要把它写入 shell
   history、截图、issue 或共享日志。
4. 安装候选包到该 profile：

   ```sh
   code --install-extension /absolute/path/to/inex-vscode-0.1.0-linux-x64.vsix \
     --user-data-dir "$PROFILE" --extensions-dir "$EXTENSIONS"
   ```

   然后以相同 profile 启动 VS Code，打开 `$SOURCE`。不要使用开发 Extension
   Host，也不要复用日常 profile。

## 首次导入与无操作 Git 回归

1. 在 Explorer 中右键 `$SOURCE`，选择 **Inex: Initialize from Existing
   Markdown Repository**。在真实 folder picker 中选择 `$VAULT_PARENT`，并输入
   新的临时 vault 名称和两次临时密码。
2. 接受 **Open New Vault**，确认新工作区是刚生成的密文 vault。终端外再执行：

   ```sh
   git -C "$VAULT_PARENT/<chosen-vault-name>" status --porcelain=v1 -z | od -An -t x1
   ```

   预期没有任何输出。此时磁盘中只应有 `note.md.enc`，不应有普通 `note.md`。
3. 在 Inex tree 中打开 `note.md`；反复点击 Heading A、Heading B 和 Heading A。
   每次应正确定位，不应只在第一次跳转时生效。隐藏并再次显示编辑器，然后关闭
   标签页；不要键入、保存或执行任何编辑命令。
4. 再次执行上面的 `git status`。预期仍为空。若出现 `M note.md.enc`，保留该
   vault，不要通过保存、重置或重新导入掩盖问题；记录 VS Code 版本、VSIX SHA-256、
   `git status --porcelain=v1 -z | od -An -t x1`、以及复现的确切点击顺序。

## Markdown 呈现、SCM 与受控比较

1. 确认 custom editor 的 display layer 显示 heading、列表、链接、代码和普通
   Markdown emphasis；这不是 Markdown TextDocument、语言服务器或原生 Markdown
   preview。普通 VS Code Markdown 扩展不应获得 Inex plaintext TextDocument。
2. 只对临时 fixture 做一次可见编辑并保存。Source Control 应只报告
   `note.md.enc` 的密文变化；原生 diff 无法阅读是预期安全行为。
3. 在 Source Control 的 `note.md.enc` 上执行 **Inex: Compare Saved Working
   Copy with HEAD (Outer)**。结果必须是 Inex 的只读比较面板，而不是原生 diff
   或普通明文编辑器。关闭该面板后执行 **Inex: Compare HEAD with Parent (Outer)**
   （fixture 至少需要两个密文 commit；可先创建一个空的密文 commit）。
4. 在完成截图/记录后，仅对该临时 vault 使用普通 Git 命令恢复测试改动；不要将
   `git reset`、明文导出或复原步骤应用于真实 vault。

## 锁定、关闭与持久 profile 观察

1. 解锁、打开 document，作一次编辑但不要保存，然后尝试关闭标签页；确认 Inex
   的 dirty/recovery 交互，而不是 VS Code 把明文写为普通文件。
2. 保存后执行 **Inex: Lock Vault**，确认已打开的 Inex editor 被清理为锁定状态。
   关闭窗口、重新以同一 `$PROFILE` 启动、再解锁并确认保存的内容来自密文 vault。
3. 若要覆盖 Hot Exit 或崩溃情形，只能使用该一次性 profile 和 canary。分别记录
   正常退出、dirty close、强制终止后的行为；不要把单次没有命中当作完整 release
   residue matrix 的替代。

## 清理与报告

完成后，先关闭所有使用 `$PROFILE` 的 VS Code 进程，再以可丢弃 canary 扫描
`$ROOT`、系统临时目录中本次产生的根，以及 VS Code 日志目录。扫描前不要把 canary
复制进终端历史或报告。若发现命中，保留证据根供诊断；若无命中，仍只报告为一次
人工诊断结果。

成功记录至少包含：候选 VSIX 的绝对路径与 SHA-256、VS Code 版本、OS、测试开始和
结束时的密文 Git status、Heading 重复跳转结果、SCM/受控比较观察、锁定/重启观察，
以及是否检测到 canary。不得记录测试口令、明文内容或 canary 本身。

完成诊断后可删除 `$ROOT`。真实 source、真实 vault 和常用 VS Code profile 都不应
参与或被本协议删除。
