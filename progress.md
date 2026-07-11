# Inex Progress Log

## Session: 2026-07-10

### Phase 1: 需求、格式与工程基线冻结

- **Status:** complete
- **Started:** 2026-07-10 (Asia/Shanghai)
- Actions taken:
  - 建立用户要求的持续 goal。
  - 完整读取 planning-with-files 技能并执行 session catchup；没有旧上下文需要恢复。
  - 检查 Git 工作树与仓库文件，确认项目为绿地仓库且用户的 `.agent/` 内容保持未改动。
  - 完整读取 347 行 `.agent/init_plan.md`，提取安全边界、架构、客户端差异、Git/迁移要求与实施顺序。
  - 创建七阶段持久化开发计划、发现库和进度日志。
  - 核对本机 Rust/Node/Python/Git、libsodium、VS Code 与 Sublime 工具链，确认本地具备实现和 smoke-test 条件。
  - 检查初始提交、GPL-3.0 许可证与现有 Rust `.gitignore`，确认没有需要保留的遗留代码。
  - 创建 README、threat model、P0/P1/P2 验收矩阵、组件架构、EDRY v1 与 JSON-RPC v1 实现草案。
  - 修正上位草案的 key-slot/file 绑定矛盾：文件使用 master-key epoch，口令 KDF/wrap 参数逐 slot 保存。
  - 记录 stdio sidecar 与非交互 Git merge driver 的会话鸿沟，并冻结“不具备解锁通道时不修改 `%A`”的失败安全行为。
  - 冻结 Rust 密码学/格式依赖并生成 `Cargo.lock`；vendored libsodium 基线在本机完成首次 workspace check。
  - 根据实际 transitive build dependency 将声明 MSRV 从 1.85 修正为 1.88。
  - 根据当前 VS Code backup tracker 将写入面改为真实 `*.md.enc` 上的 CustomEditorProvider，并规定 backup 只能写 EDRY encrypted draft。
  - 根据 Sublime API 限制将第二客户端改为 hard-gated scratch/self-dirty/encrypted-draft 模式，并设为残留测试通过前 experimental。
  - 建立可编译的 VS Code TypeScript custom-editor placeholder 与 Sublime Python security-gate skeleton。
  - 完成 Rust fmt/check/test/clippy、TypeScript typecheck/build、Python syntax 与 Sublime JSON 验证。
- Files created/modified:
  - `task_plan.md` (created)
  - `findings.md` (created)
  - `progress.md` (created)
  - `README.md` (created)
  - `SECURITY.md` (created)
  - `docs/PRD.md` (created)
  - `docs/architecture.md` (created)
  - `docs/spec/edry-v1.md` (created)
  - `docs/spec/json-rpc-v1.md` (created)
  - `docs/spec/vault-v1.md` (created)
  - `docs/acceptance-matrix.md` (created)
  - `docs/dependencies.md` (created)
  - `fixtures/README.md` (created)
  - `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml` (created)
  - `crates/inex-core`, `crates/inex-daemon`, `crates/inex-cli` (created)
  - `editors/vscode` TypeScript/package/pnpm skeleton (created)
  - `editors/sublime` Python/package skeleton (created)
- **Completed:** 2026-07-10 (Asia/Shanghai)

### Phase 2: Rust 密码学核心与 vault 生命周期

- **Status:** in_progress
- **Started:** 2026-07-10 (Asia/Shanghai)
- Actions taken:
  - None.
- Files created/modified:
  - `crates/inex-core/src/vault_config.rs` (created)

## Session: 2026-07-11

### Phase 2 continuation

- **Status:** complete
- Actions taken:
  - 按 planning-with-files session catchup 核对工作树、计划/发现/进度文件与 Phase 2 源码，确认中断前的三个并行模块未落盘。
  - 重新启动 logical path、EDRY codec、libsodium/secure-memory 三个互不重叠的实现任务。
  - 实现 `vault.json` v1 数据模型、canonical unpadded base64url fixed bytes、逐 slot KDF/wrap schema 与不可信输入资源上限。
  - 实现 deterministic wrap AAD、metadata key context 和覆盖完整 slot/features 的 deterministic metadata-MAC payload。
  - 添加并通过 JSON round-trip、非 canonical base64、weak KDF warning、resource ceiling、duplicate slot、slot-order independence、AAD binding 和 exact-password 8 个测试。
  - 接入并审查跨平台 logical path、EDRY deterministic codec 和 libsodium secure-memory 三个模块。
  - 独立校正 EDRY golden header 时间戳，补充 nil UUID/时间逆序拒绝；core 44/44 测试通过。
  - 补齐 `vault_config` 公共错误契约；pedantic clippy 与 warnings-as-errors rustdoc 通过。
  - 实现 master key secure-memory、Argon2id slot create/unlock/add/remove、metadata MAC 验证与完整 EDRY committed/draft 加解密组合层。
  - 通过 7 个高层 crypto 定向测试（错误密码、metadata tamper、slot change 不重写正文、UTF-8 精确往返、context/tamper/draft）。
  - 调研原子写入后端：确认 std file lock 的 MSRV 缺口、Windows ReplaceFileW 失败风险与 same-directory rename 的可承诺边界。
  - 实现只读 vault 树扫描：拒绝明文 Markdown、非 canonical 密文路径、symlink/reparse/special file 与 Unicode case-fold 冲突，并提供稳定 RPC tree shape。
  - 实现 bounded in-memory search：Zeroizing 正文/查询/snippet、Unicode case fold 原文坐标映射、UTF-16 列号与 CRLF 处理；无任何持久化路径。
  - 实现跨进程原子密文写：同目录随机 staging、写入后 sync、Linux flock/Windows LockFileEx、锁内 etag 重查、replace-before-never-delete 与失败清理。
  - 完成 Phase 2 primitives 的统一质量门：81/81 core tests、fmt、pedantic clippy、warnings-as-errors rustdoc 全部通过；atomic 另通过 Rust 1.88 与 Windows GNU 交叉检查。
  - 在冻结 Unicode 17 路径语义后重新审计 MSRV：Rust 1.88 的 std case table 不匹配，声明/CI 基线提升为已固定的 Rust 1.97。
  - 会话恢复后验收中断代理留下的 RPC framing checkpoint；修复 `Interrupted` 重试、malformed/truncated header 分类和 body buffer 擦除，15/15 tests、clippy、rustdoc 全部通过。
  - 完成 repository-level `Vault`：create/unlock/read/create/save/mkdir/list/draft/search/password-slot/rename/delete 全生命周期，所有 plaintext 返回值使用 zeroizing ownership。
  - 冻结并写入 `fixtures/v1-fixed` 的完整 vault/slot/EDRY compatibility vector，确定性重建、解锁和正文解密逐字节通过。
  - 把原子层扩展为 `VaultMutationGuard`，将 collision scan、etag recheck、metadata transaction、conditional delete 与 journaled rebind 串在同一个 OS lock 域内。
  - 实现 crash-recoverable rename：先同步 journal，再提交并复验 destination，最后退休 source；恢复前重新验证 ancestor、mount、identity 与 exact etag，拒绝 symlink/mount escape。
  - Windows namespace mutation 改用 extended-length `MoveFileExW(MOVEFILE_WRITE_THROUGH)`；删除/rename cleanup 先移入 `.vault-local` 密文 tombstone，并在 Win32 error 后重查完整目标状态。
  - 修复官方 MinGW libsodium static archive 的 `memset_explicit`/`SystemFunction036` link gap；兼容代码限制在 Windows-GNU audited FFI cfg，完成测试二进制链接。
  - Windows 文件 identity 使用 nonzero `FILE_ID_INFO`，全零时退回 volume serial + nonzero legacy file index，避免 FAT/exFAT 上把两个 zero-id 文件误判为同一对象。
  - 路径 profile 补齐 251-byte final component、leading ASCII space、CONIN$/CONOUT$、superscript COM/LPT、DOS `~digit`、空 child join 与 Unicode 17 compile-time table gate。
  - Tree scan 加入累计 path-byte budget、wrong-case reserved alias 拒绝、Linux `st_dev` + mount-id boundary；direct read/save/delete 同样要求每级唯一 portable-casefold exact child。
  - Search 改为 streaming fold KMP/增量位置计算与 query-sized work memory；每次 query 重算完整 ciphertext fingerprint，等长篡改并恢复时间戳也会先失效索引。
  - Phase 2 Linux 最终 119/119；Windows GNU cross-check/clippy/link 均通过，Wine 116/116（含 >260-char write/rebind/delete、Win32 identity、exact casing 与 draft alias）。Wine 仅为 API/ABI 冒烟，原生 NTFS/ReFS/MSVC 仍保留为 Phase 7 blocking evidence。
  - 独立只读安全审查在最后一轮未发现可复现的 Phase 2 代码阻断；原生 MSVC/NTFS/ReFS/FAT/exFAT、Hyper-V 掉电、ARM64 与 Git for Windows 长路径被明确保留到 Phase 6/7 release gate。
- Files created/modified:
  - `crates/inex-core/src/vault_config.rs` (created)
  - `crates/inex-core/src/lib.rs` (exported module)
  - `crates/inex-core/src/path.rs` (created)
  - `crates/inex-core/src/format.rs` (created)
  - `crates/inex-core/src/sodium.rs` (created)
  - `crates/inex-core/src/crypto.rs` (created)
  - `crates/inex-core/src/atomic.rs` (created)
  - `crates/inex-core/src/search.rs` (created)
  - `crates/inex-core/src/tree.rs` (created)
  - `crates/inex-core/src/vault.rs` (created)
  - `fixtures/v1-fixed/*` (created)
  - `docs/spec/edry-v1.md`, `docs/spec/vault-v1.md`, `docs/acceptance-matrix.md` (hardened)
- **Completed:** 2026-07-11 (Asia/Shanghai)

### Phase 3: `inexd`、CLI 与本地协议

- **Status:** in_progress
- **Started:** 2026-07-11 (Asia/Shanghai)
- Actions taken:
  - 已完成 strict Content-Length JSON-RPC framing checkpoint（15/15），下一步接入协议验证、session store、handler/server 与 CLI。
  - 按用户补充要求启用 Git checkpoint 工作流；在暂停并行写入、确认无 partial edit、执行 staged whitespace/secret audit 后，将 Phase 1/2 稳定基线提交为 `075f8fd`（`feat: establish encrypted vault core and project baseline`），并创建 annotated tag `checkpoint-phase-2` 作为明确回滚点。
  - 接入 session/sensitive 模块后的首轮 daemon 门禁在 rustfmt 检查处停止；已先记录失败，尚未把未执行的 tests/clippy/rustdoc 误记为通过。
  - 格式修复后首次真实编译暴露 sensitive helper 测试的引用类型不匹配；该编译门禁已记录并按最小范围修正。
  - daemon 25/25 tests 通过后，clippy 在 sensitive base64 decoder 的所有权意图处停止；保留“转移并清零输入”契约并显式消费 owner 后重新执行全门禁。
  - 完成 256-bit session capability、15 分钟 monotonic idle、128 个随机 document handle 上限、lock/expiry/shutdown 清理，以及敏感 JSON 字段的 zeroizing ownership 转移；集成 daemon 25/25 tests、clippy、rustdoc 通过。
  - 完成 20 个冻结 RPC method 的严格 request parser、复杂度预算、可关联 request id 的拒绝响应与固定错误模型；集成 daemon 35/35 tests、clippy、rustdoc 通过。
  - CLI 完成 init/locked verify/password add-remove-change/search/serve：口令和查询均不进入 argv/env value，查询通过隐藏 TTY 或显式有界 stdin；独立 18/18 tests 后又通过 workspace 162/162 tests、clippy 与 rustdoc。
  - 并行安全审计发现两个集成前 hardening 项：阻塞 stdio 不能让 idle session 无限驻留，server 必须定时唤醒并触发 expiry；`inex serve` 缺少 sibling daemon 时必须 fail closed，禁止隐式 PATH 回退。
  - 修复 `inex serve` PATH 劫持面：仅接受同目录 daemon 或显式非空 `INEXD_PATH`；最终基础增量 workspace gate 为 CLI 20/20 + core 119/119 + daemon 35/35，fmt、clippy `-D warnings`、rustdoc `-D warnings` 与 diff whitespace 全通过。
  - 将上述可独立回滚的 Phase 3 基础增量提交为 `99044dc`（`feat: add secure RPC and CLI foundations`）；handler/watchdog/E2E 未混入该稳定 checkpoint。
  - 首次把 20-method handler 接入真实 crate 后，编译在一个 zeroizing string 匹配类型、未使用 import 和漏映射的 plaintext-size variant 处停止；已按 planning-with-files 先记录再做最小修复。
  - handler 编译修复后的重跑先被 rustfmt 门禁拦截；按门禁顺序记录并格式化后从 tests 重新开始。
  - handler/params 接入后 daemon 48/48 tests 通过；随后的 pedantic clippy 在机械 match/ownership 风格和一个完整生命周期测试长度处停止，已记录后按不改变行为的最小范围修正。
  - 处理 CLI 审计项：解锁凭据尽早 drop、snippet 流式转义、密码元数据 durability/弱 KDF 逐槽告警、search limit 前置拒绝、verify mutation/recovery 披露；22/22 tests、完整 clippy/rustdoc 通过并提交为 `7128a8b`（`fix: harden CLI secret and durability handling`）。
  - 核对 `rpassword 7.5.4` 源码确认其 hidden-TTY 公共 API 无调用方输入硬上限；显式 stdin 仍为读取期硬上限，TTY 只能 Enter 后检查，已在 CLI help/module docs 明示并保留为后续依赖修补项。
  - handler 对抗审计确认 session 错误同码、shutdown 终态、active-vault unlock、listTree 输出预算和 TreeError 分类五个语义缺口；在 server checkpoint 前全部按冻结协议收敛并补回归测试。
  - 五项 handler 审计回归加入后的首轮门禁仅在两处 rustfmt 差异停止；已记录并从格式化后重启完整 daemon 门禁。
  - audit-hardened daemon 57/57 tests 通过后，clippy 要求合并 terminal/pre-hello 的同结果分支；保持错误语义不变并重跑全门禁。
  - shipped `inexd` 进程级 framed RPC E2E 首次通过；随后 clippy 仅对完整生命周期场景的 108 行长度停止，采用窄 test-only 说明后重跑。
  - 完成 production `inexd`：zero-capacity reader backpressure、1 秒 idle watchdog、aligned-body error continuation、desync termination、response/request scrub、clean EOF/shutdown wipe；Linux daemon 57/57 + process E2E 1/1 通过。
  - 通过最终 workspace gate：CLI 22/22、core 119/119、daemon 57/57、process E2E 1/1，fmt、pedantic clippy `-D warnings`、rustdoc `-D warnings` 与 whitespace check 全部通过。
  - 通过 Windows GNU workspace clippy 与全 target no-run link；Wine 实跑 CLI 21/21、daemon 57/57、`inexd` process E2E 1/1。原生 NTFS/ReFS 与 MSVC 仍保留为 Phase 7 发布门禁。
  - daemon runtime 终审无阻断项；将 handler/params/watchdog server/binary/E2E/spec 作为独立 checkpoint 提交为 `815f216`（`feat: ship watchdog-backed stdio daemon`）。
  - 在 Phase 3 import 并行实现期间启动 Phase 4 foundation：严格 Node framing/sidecar、fail-closed bundled binary resolution、vault tree、可写 CustomEditor 与 encrypted draft backup；首轮 typecheck 的两个 exact-type 错误已先记录再修复。
  - VS Code foundation 修复后通过 `pnpm check`、6/6 Node 单测与 production bundle；并行安全审计已启动，尚未把该基础门禁误记为 Extension Host/残留审计完成。
  - VS Code 安全审计后闭合 session失效/stdio/EPIPE、dirty lock、open-vs-lock/dual-unlock 竞态、authenticated keepalive + 本地 idle deadline、bounded encrypted restore、stale-draft 双确认、portable path 与大帧队列边界；导航新增 heading/link/backlink，spellcheck 默认关闭，编辑消息改为 debounce + save-time snapshot。
  - 将 daemon `system.ping` 的可选 session 续期语义、能力协商与回归测试作为独立 Git checkpoint 提交为 `cb8e17c`（`feat: add authenticated session keepalive`）；未混入正在重构的 import 或未完成的编辑器包。
  - 完成 copy-only `inex import <plaintext-source> <new-vault> [--dry-run]`：dry-run 不取口令/不写盘，真实导入只写 sibling encrypted staging，完整重开验证后以 no-replace 原子发布；源明文始终只读，破坏性 in-place 明确拒绝。
  - import 的最终安全审阅闭合 publication marker 清理失败分类、seal 后最终 exact allowlist、Windows `as_encoded_bytes` 路径预算，以及 Linux `openat2`/P-S-L descriptor identity 四项问题；独立终审给出 GO。
  - Phase 3 最终本机 workspace 221/221 tests、fmt、pedantic clippy `-D warnings`、rustdoc `-D warnings`、whitespace gate 全部通过；Windows GNU workspace no-run/clippy 与 Wine 215/215 通过，原生 Windows/NTFS 证据保留到 Phase 7。
  - 将 failure-safe staged import 独立提交为 `2f287e3`（`feat: add failure-safe staged vault import`），未混入 VS Code/Sublime/planning 工作树。
- **Completed:** 2026-07-11 (Asia/Shanghai)

### Phase 4: VS Code 主客户端

- **Status:** complete
- **Started:** 2026-07-11 (Asia/Shanghai)
- Actions taken:
  - 实现 strict Content-Length RPC client 与 explicit/bundled-only sidecar resolution；不存在 PATH fallback，child exit、stdio/protocol fault、session expiry 均进入一次性 fail-closed lock。
  - 实现真实 `*.md.enc` `CustomEditorProvider`、Tree View、搜索、heading/link/wiki-link/backlink 导航，以及 generation-bound document handles；plaintext 不注册为 `TextDocument`。
  - 实现 EDRY encrypted backup/recovery、stale draft 二次确认、save-time webview snapshot、etag conflict、dirty save/discard/cancel 和 lock 时 script-free locked page 替换。
  - 对 framing、sidecar、路径、bounded file、Markdown 与 residue scanner 建立 20 个 Node 测试；`pnpm check`、20/20 tests、100.6 KiB production bundle 与 integration bundle 全部通过。
  - 在本机 VS Code 与最低支持的 1.125.0 上分别运行真实 Extension Host backup/recovery + isolated-root canary 扫描，均 exit 0；runner 同时检查并清理残留进程/目录。
  - 最终只读安全审阅给出 GO；打包 VSIX + bundled platform `inexd` 安装 smoke，以及 Windows/Linux 持久 profile 的跨进程 Hot Exit/Local History/crash restore 继续作为 Phase 7 发布证据，不扩大 Phase 4 的自动化结论。
  - 将 hardened VS Code client、安全文档与测试 harness 独立提交为 `f51d4e9`（`feat: add hardened VS Code encrypted editor`），未混入 Sublime 工作树。
  - 补齐 P1-04 文件管理：新建空 Markdown、mkdir、etag 条件 rename/delete；脏文档、tab-close 拒绝、handle-close/RPC 失败均失败关闭并通过认证树对账恢复。
  - 主线程复验 `pnpm check`、23/23 unit、production/integration bundle，以及当前 VS Code 与最低 1.125.0 的真实 Extension Host CRUD + encrypted backup/recovery + residue audit；独立提交为 `b3bad32`（`feat: add authenticated editor file management`）。
- **Completed:** 2026-07-11 (Asia/Shanghai)

### Phase 5: Sublime 轻量客户端

- **Status:** complete (experimental platform boundary retained)
- **Started:** 2026-07-11 (Asia/Shanghai)
- Actions taken:
  - 完成 strict framed RPC、bundled/explicit sidecar、vault unlock/tree/search/navigation、scratch managed buffer、自管 dirty/etag、encrypted draft、save/close/lock 与安全设置 hard gate。
  - 增加 New Folder/New Markdown/active clean rename/etag-delete，使用 generation/path/etag/draft epoch 与 per-document lock 阻断 UI 切换、编辑和 draft/CRUD 竞态。
  - 在首次明文插入前设置固定 marker；所有 lock/open/delete 先固定 scrub 再释放 owner，逐 view 异常隔离且 sidecar shutdown 有同步兜底；draft 删除拒绝 symlink/reparse 并在 POSIX 用 verified dirfd 锚定。
  - 61/61 pure-Python tests（含 Python 3.8 AST）通过；真实 Build 4200 normal 通过注册 WindowCommand 与 InputPanel/QuickPanel 完成 open/edit/save/close + mkdir/create/rename/delete，`crud_complete=true`、`root_scan_hits=0`。
  - 真实 Build 4200 plugin-host SIGKILL 得到 `PASS_WITH_DOCUMENTED_BOUNDARY`：host-dead plaintext 可复制、宿主不在同进程重启、必须重启 Sublime，应用退出后 `root_scan_hits=0`；因此继续标 experimental，不宣称 crash-time erasure。
  - 独立只读审计复跑 pure、normal CRUD 与 SIGKILL 场景；Sublime 增量提交为 `b124170`（`feat: complete experimental Sublime client`）。
- **Completed:** 2026-07-11 (Asia/Shanghai)

### Phase 6: Git 合并、迁移与恢复工具

- **Status:** complete
- **Started:** 2026-07-11 (Asia/Shanghai)
- Actions taken:
  - 新增 `inex-git` crate 与 `inex merge-driver`、`inex git install-driver/merge/recover`；locked driver 安装为 canonical absolute `inex` + 零 placeholders，不读取 Git 临时路径且固定返回冲突。
  - 实现 local-only `.gitattributes`/`.gitignore` 安装、有效属性复核、Git ≥2.36、清空环境、禁用 fsmonitor/lazy fetch、bounded plumbing 与动态 Windows argv 预算。
  - 实现 stage AEAD 认证、内存 diff3、clean/unresolved EDRY 标志、全局 file-id 预检、密文 worktree/index transaction journal 与认证恢复；split-index、非 `100644` 与当时未支持的跨路径 rename/modify 失败关闭，并行 Git porcelain 明确不受支持。
  - 独立审计闭合 file-id late-write、Windows batch、split-index durability、fsmonitor/lazy-fetch 四项 blocker，最终判定 Checkpoint GO；GA 的原生 Windows 与 rename/modify 证据留给 Phase 7。
  - 主线程复验 workspace 239/239 tests、fmt、pedantic clippy、rustdoc、Windows GNU workspace check 与 diff-check 全部通过。
  - 将 Rust/CLI/spec 增量独立提交为 `02260d8`（`feat: add encrypted Git merge and recovery`），未混入 planning 或 Sublime E2E harness。
- **Completed:** 2026-07-11 (Asia/Shanghai)

### Phase 7: 跨平台验证、打包与发布准备

- **Status:** in_progress
- **Started:** 2026-07-11 (Asia/Shanghai)
- Actions taken:
  - 新增四平台 CI/package workflow、确定性 Rust/VSIX/unpacked-Sublime ZIP、SHA256SUMS、package provenance、77-component/147-text license inventory、严格 artifact/native dependency audit 与 executable/VSIX smoke。
  - 闭合两轮独立发布审计：严格 VSIX XML/content-types/package identity、TOML/tag version、PE32+、ELF interpreter/RPATH、Win32 portable paths、特殊成员/权限、member/size ceiling、canonical origin 与 tag-bound native gates；最终代码审计 GO。
  - 发布工具 19/19、actionlint、pedantic/all-features Clippy、239/239 Rust workspace tests 与 rustdoc 均通过；system-GCC Linux x64 repackage/audit/VSIX CLI smoke 已有本地 checkpoint 证据。
  - 完成安装、用户、操作/恢复、排错、editor security、dependency/license 与 release checklist 文档；仍保留 native Windows/ARM、持久 editor profile、签名/私密报告、独立法律审查和最终 clean-source 双构建门禁。
  - 使用 system GCC 重建可移植 ELF；precommit 两轮 Rust ZIP/VSIX/Sublime ZIP/SHA256SUMS 逐字节一致，严格 artifact/native-dependency audit、三个 executable smoke 与 VS Code 1.125.0 CLI 安装均通过（manifest 如实标记 dirty，不能替代最终 clean-source 证据）。
  - 独立文档审计修复过度安全声明、`.vault-local`/CustomEditor 事实、绝对 CLI 路径、Python/pnpm/build 前提与可执行发布命令；复审为零 blocker、零 major。
  - 将发布流水线、24 个代码/配置/文档文件独立提交为 `d042360`（`feat: add audited cross-platform release pipeline`）；planning 与后续 completion 证据未混入该功能提交。
  - 在 `feature/git-rename-modify` 分支闭合 binding rename/modify：同时支持 Git detected 三阶段 destination 与 no-renames split source/destination，使用唯一 merge-base + 固定 `HEAD`/`MERGE_HEAD` tree entry 证明 rename，不把相同 file-id 或密文相似度当 provenance。
  - 引入稳定 journal 文件内的 v2 split/v3 detected 严格 schema、source-aware forward recovery、固定 commit provenance、repository-aware SHA-1/SHA-256 全宽 OID 与 tracked/untracked third-owner 预变更复核；rename/rename、历史 destination、multiple merge-base 与歧义均失败关闭。
  - 独立安全审计发现并闭合 detected source 遗留、历史副本误判、SHA-256 OID prefix、stage-zero/unmerged overlap、recovery owner 顺序与 final-after-commit recovery 等 major；最新定向门禁为 `inex-git` 30/30、真实 CLI Git 9/9、pedantic Clippy 与 diff-check 全通过。外部 Git 在最后检查至 `update-index` 的无 CAS 窗口保留为明确 non-GA 边界。
  - 将经终审 GO 的 rename/modify 源码与真实 Git 测试独立提交为 `862d28c`（`feat: merge encrypted rename-modify conflicts`）；文档/planning 与后续 clean-source 证据另行提交。

## Test Results

| Test | Input | Expected | Actual | Status |
|------|-------|----------|--------|--------|
| planning session catchup | repository path | no stale state or actionable recovery report | no output; clean start | PASS |
| repository baseline | `git status --short --branch`, `rg --files` | identify tracked/untracked starting state | `master`, only `LICENSE` tracked, `.agent/` untracked | PASS |
| local toolchain probe | version/pkg-config/command checks | Rust, Node, Python and editor tooling available | all required local toolchains found; libsodium 1.0.22 available | PASS |
| pinned dependency build | `cargo check --workspace --all-targets` | pinned libsodium/minicbor/zeroize graph compiles | compiled successfully; lockfile generated | PASS |
| Rust skeleton gate | fmt/check/test/clippy with warnings denied | all workspace targets clean | all passed | PASS |
| VS Code skeleton gate | `pnpm run check`, `pnpm run build` | strict TypeScript compiles and bundles | passed; 3.1 KiB placeholder bundle | PASS |
| Sublime skeleton gate | in-memory Python compile + JSON parsing | Python 3.8-compatible syntax/config shape | passed on Python 3.12 parser; Build 4200 runtime smoke remains Phase 5 | PASS |
| vault metadata pre-auth layer | `cargo test -p inex-core vault_config` | reject unsafe metadata before KDF; deterministic AAD/MAC payload | 8/8 tests passed | PASS |
| integrated core primitives | `cargo test -p inex-core --all-targets -- --test-threads=1` | path/format/sodium/config tests all pass | 44/44 passed | PASS |
| core static quality | pedantic clippy + rustdoc `-D warnings` | no warnings/errors | passed | PASS |
| high-level vault crypto | `cargo test -p inex-core crypto -- --test-threads=1` | slot/auth/file/draft lifecycle works and fails closed | 7 targeted tests passed | PASS |
| integrated Phase 2 primitives | `cargo test -p inex-core --all-targets -- --test-threads=1` | atomic/path/format/crypto/search/tree/config all fail closed | 81/81 passed | PASS |
| integrated Phase 2 static quality | fmt + pedantic clippy + rustdoc `-D warnings` | no formatting, lint or documentation warnings | all passed | PASS |
| atomic MSRV/cross-platform compile | Rust 1.88 targeted tests + Windows GNU library check | lock backend and API compile at declared MSRV on both OS families | passed | PASS |
| strict RPC framing checkpoint | daemon tests + pedantic clippy + rustdoc | partial/coalesced/interrupt/invalid/oversize/body-free errors and zeroized byte buffers | 15/15 and static gates passed | PASS |
| final Linux Phase 2 core | `cargo test -p inex-core --all-targets -- --test-threads=1` | full crypto/vault/atomic/path/tree/search lifecycle and adversarial cases | 119/119 passed | PASS |
| final core static gates | fmt + native/Windows pedantic clippy + rustdoc `-D warnings` | no formatting/lint/documentation warnings | all passed | PASS |
| Windows GNU link gate | `cargo test -p inex-core --target x86_64-pc-windows-gnu --no-run` | bundled libsodium and Win32 FFI produce executable | passed | PASS |
| Windows API/ABI smoke | linked core test exe under Wine | Win32 lock/identity/write-through move, aliases and >260-char paths work | 116/116 passed; exe SHA-256 `a41b8fcd…1328` | PASS (non-native) |
| search freshness adversary | same-size ciphertext tamper + restore accessed/modified timestamps | query invalidates plaintext index before returning stale hit | `SearchIndexNotReady` regression passes | PASS |
| rebind recovery escape adversary | valid journal then replace source ancestor with symlink | recovery conflicts and leaves redirected ciphertext untouched | regression passes | PASS |
| VS Code Phase 4 foundation | `pnpm check && pnpm test && pnpm build` | strict TypeScript, framing/sidecar unit tests, and production bundle all pass | passed; 6/6 Node tests; 43.5 KiB bundle | PASS |
| VS Code hardened client/navigation | `pnpm check && pnpm test && pnpm build && pnpm test:extension:build` | strict TypeScript, bounded protocol/path/file/Markdown/EPIPE/residue tests, production and integration bundles pass | passed; 20/20 Node tests; 100.6 KiB production bundle | PASS |
| authenticated keepalive daemon | daemon 57 tests + process E2E + pedantic clippy + rustdoc | optional-session ping renews idle deadline without weakening session errors | all passed; committed as `cb8e17c` | PASS |
| Phase 3 staged import | `cargo test --workspace --all-targets` | dry-run/copy import, verified staging, source preservation, no-replace publication and failure classification pass | 221/221 passed | PASS |
| Phase 3 import static gates | fmt + pedantic clippy + rustdoc `-D warnings` + diff check | no formatting, lint, documentation or whitespace failures | all passed | PASS |
| Phase 3 import Windows smoke | Windows GNU no-run/clippy + Wine tests | cross-platform API/link behavior compiles and Wine suite passes | no-run/clippy passed; Wine 215/215 | PASS (non-native) |
| VS Code current Extension Host | isolated user/extensions/temp/vault roots on local VS Code | encrypted backup/recovery succeeds and dynamic canary leaves no detected residue | exit 0; residue audit passed | PASS |
| VS Code minimum Extension Host | same harness on VS Code 1.125.0 | minimum supported engine follows the same encrypted recovery contract | exit 0; residue audit passed | PASS |
| post-Phase-6 full Rust regression | `cargo test --workspace --all-targets --locked` | CLI/core/daemon/process/Git suites remain green while editor/release work proceeds | 239/239 passed (43 CLI, 128 core, 58 daemon/process, 10 Git) | PASS |
| VS Code authenticated CRUD unit gate | `pnpm check && pnpm test && pnpm build && pnpm test:extension:build` | strict RPC/path/model mutations and bundles pass | 23/23 tests; 127.1 KiB production bundle; 13.7 KiB integration bundle | PASS |
| VS Code authenticated CRUD Extension Host | current VS Code and 1.125.0 isolated runners | real daemon create/mkdir/rename/delete, close/RPC failure recovery, encrypted backup, and residue scan pass | both runners exit 0 | PASS |
| Sublime final pure gate | `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=editors/sublime python3 -W error::ResourceWarning -m unittest discover ...` | Python 3.8-compatible client/model/RPC/draft/CRUD/scrub invariants pass without cache residue | 61/61; no ResourceWarning or `__pycache__` | PASS |
| Sublime Build 4200 real CRUD | isolated XDG/Xvfb/DBus profile with registered commands and real panels | unlock/open/edit/save/close, mkdir/create/rename/etag-delete and authenticated tree checks leave no plaintext disk residue | `crud_complete=true`, four CRUD events, `root_scan_hits=0`, EDRY | PASS |
| Sublime Build 4200 host SIGKILL | kill only isolated `plugin_host-3.8` with marked managed plaintext open | reproduce and report platform boundary, then terminate app and scan roots | plaintext copyable; host not restarted; `PASS_WITH_DOCUMENTED_BOUNDARY`; `root_scan_hits=0` | PASS (boundary, not crash erasure) |
| hardened release-tool gate | 19 negative/determinism/provenance tests + actionlint + pedantic/all-features Clippy | reject forged VSIX/ZIP/PE/tag/origin inputs and keep workflows syntactically valid | 19/19; actionlint 0; Clippy pass | PASS |
| release-tool independent re-review | replay both audit rounds against current scripts/workflow | every reported bypass is rejected; no code blocker/major remains | final code-audit verdict GO | PASS |
| precommit deterministic Linux package | system-GCC release build + two package directories + strict audits/smoke | all four outputs are byte-identical and install/run while dirty provenance remains explicit | two `cmp` chains pass; artifact/native audits and VS Code 1.125.0 CLI smoke pass | PASS (precommit only) |
| documentation consistency audit | README/security/PRD/architecture/install/operations/release commands vs implementation | no overclaim or non-runnable binding command remains | independent rereview reports 0 blocker, 0 major; noted minors repaired | PASS |
| Git rename/modify security gate | detected/split real Git shapes, exact merge-tree provenance, SHA-256 prefix/E2E, stage-zero overlap, third owners, v1/v2/v3 fault states and post-commit recovery | supported shapes merge ciphertext-only; ambiguity/tamper/drift fail before mutation | `inex-git` 30/30, CLI Git 9/9, independent review GO with no blocker/major | PASS (Linux source checkpoint) |
| post-rename full Rust gate | fmt + workspace tests + all-features pedantic Clippy + rustdoc `-D warnings` + diff-check | no regression or static warning across all crates | 261/261 tests; all static gates pass | PASS |
| post-rename Windows GNU gate | workspace all-targets no-run + all-features pedantic Clippy | every crate/test executable links and cfg-specific lints pass | 9 Windows test executables produced; Clippy pass | PASS (cross-only, non-native) |

## Error Log

| Timestamp | Error | Attempt | Resolution |
|-----------|-------|---------|------------|
| 2026-07-10 | `cargo fmt --check` found trailing blank lines in the new Rust skeleton | 1 | Resolved with canonical `cargo fmt --all`; fmt/check/test/clippy then passed |
| 2026-07-10 | Combined PRD/architecture patch context mismatch | 1 | No partial change; inspect exact sections and apply smaller targeted patches |
| 2026-07-11 | `format::fixed_header_vector_is_stable` expected timestamp bytes differed from encoded fixture value | 1 | Independently corrected timestamp bytes; 44/44 core tests pass |
| 2026-07-11 | Combined planning/rustdoc patch context mismatch after rustfmt wrapping | 1 | No partial change; inspect exact source and apply smaller patches |
| 2026-07-11 | 8 `vault_config` public Result APIs lacked clippy-required `# Errors` rustdoc | 1 | Added docs; clippy and rustdoc pass |
| 2026-07-11 | Rust rejects non-ASCII characters inside `b"..."` test literal | 1 | Replace with UTF-8 `str.as_bytes()` and rerun |
| 2026-07-11 | Combined clippy/source patch missed rustfmt-compressed context | 1 | No partial change; apply exact smaller patch |
| 2026-07-11 | Pedantic clippy flagged redundant success pattern in crypto test | 1 | Replace with `.is_ok()` and rerun |
| 2026-07-11 | Pedantic clippy flagged a 64 KiB stack array in atomic streaming hash | 1 | Reduce buffer to 16 KiB; Rust 1.97/MSRV/Windows checks and all quality gates pass |
| 2026-07-11 | Interrupted RPC framing checkpoint had 2 failing tests (`Interrupted` retry and malformed/truncated classification) | 1 | Retry interrupted header reads, distinguish partial EOF from malformed terminated lines, and pass 15/15 tests |
| 2026-07-11 | RPC framing tests passed after repair, then clippy flagged `manual_let_else` | 1 | Apply the idiomatic `let...else`; full daemon tests/clippy/rustdoc pass |
| 2026-07-11 | Rust 1.88 failed the compile-time Unicode 17 path semantics assertion | 1 | Raise declared MSRV to pinned Rust 1.97 and document the format-compatibility reason; future Unicode drift remains a compile error |
| 2026-07-11 | Core 110/110 passed but clippy flagged `hash_file_metadata` as an unnecessary `Result` | 1 | Logged before repair; remove the infallible wrapper and rerun tests/clippy/rustdoc |
| 2026-07-11 | Full gate found rustfmt drift in new streaming-search differential tests | 1 | Logged before repair; apply canonical `cargo fmt --all` and restart the complete gate |
| 2026-07-11 | Core 111/111 passed but clippy rejected two truncating LCG index casts | 1 | Logged before repair; replace with modulo plus checked conversion and restart the complete gate |
| 2026-07-11 | Windows GNU test link missed `memset_explicit` and `SystemFunction036` from bundled libsodium | 2 | Add Windows-GNU-only volatile symbol plus forced advapi32 import; no-run link and Wine tests pass |
| 2026-07-11 | First Wine run passed 105/106 but case-only rename test did not actually recase `vault.json` | 1 | Recreate the wrong-case entry after removing canonical metadata; final Wine suite passes |
| 2026-07-11 | Portability hardening introduced rustfmt drift, one unused wrapper and cfg-specific clippy warnings | 1 each | Log each gate, apply canonical formatting/narrow cfg fixes, then rerun native and Windows gates |
| 2026-07-11 | Combined Windows long-path test patch missed shifted context | 1 | No partial edit; inspect exact locations and apply two smaller patches |
| 2026-07-11 | Combined VS Code icon/ignore patch missed current `.vscodeignore` context | 1 | No partial edit; add the icon separately after verifying existing `src/**` packaging exclusion |
| 2026-07-11 | Combined planning update missed the timestamped error-row context | 1 | No partial edit; inspect exact rows and apply smaller planning-file patches |
| 2026-07-11 | Node strip-only test loader rejected the new `sidecar.ts` constructor parameter property | 1 | Replace it with an explicit field assignment and restart the complete VS Code gate |
| 2026-07-11 | Combined VS Code session-epoch patch missed current controller context | 1 | No partial edit; inspect the exact file and split the open-vs-lock race fix into smaller patches |
| 2026-07-11 | VS Code post-race-fix gate used a duplicated relative path from the package directory | 1 | Treat all chained gates as not executed, correct `rg` to `src`, and restart check/test/build |
| 2026-07-11 | VS Code typecheck rejected nonexistent `CancellationToken.None` | 1 | Use a scoped `CancellationTokenSource` for pre-lock snapshots and restart check/test/build |
| 2026-07-11 | Main-thread Sublime unittest discovery could not import package modules because `PYTHONPATH` was omitted | 1 | Record the harness invocation error and rerun with `PYTHONPATH=editors/sublime`; no product code was changed |
| 2026-07-11 | Strict `json.tool` rejected comments in `Inex.sublime-settings` after all 42 tests passed | 1 | Do not misclassify Sublime's comment-bearing settings syntax; validate the strict commands file separately |
| 2026-07-11 | Sublime final audit found unblocked `open_context_url`, macro recording/save persistence, and UI-delay idle-deadline drift | 1 | Keep Phase 5 NO-GO; repair exact Build 4200 command surfaces and carry authenticated response monotonic timestamps into main-thread deadline updates |
| 2026-07-11 | Sublime macro re-review showed JSON fingerprints cannot prove exact `[]`, and `res://Packages/Default` is overrideable | 1 | Check the returned Python type/value directly and fail closed on all macro files while a managed buffer exists |
| 2026-07-11 | Sublime staged diff check rejected three redundant EOF blank lines | 1 | No commit was created; apply a three-file formatting-only fix and restart the final test/staged gate |
| 2026-07-11 | Initial Build 4200 E2E harness blocked on a foreground `--wait` launch | 1 | Treat as a harness failure, stop only its isolated process tree, and redesign the runner around background launch plus explicit timeouts |
| 2026-07-11 | Build 4200 Safe Mode did not auto-load Inex/InexQA packages copied after startup | 1 | Use an explicit fixed plugin reload through the isolated UI; if Safe Mode forbids it, run the same matrix in a pre-populated ordinary isolated XDG profile and report that evidence boundary |
| 2026-07-11 | Phase 6 review found file-id uniqueness could fail after an earlier result write and Windows `check-attr` batches could exceed argv limits | 1 | Keep the Git increment uncommitted; perform whole-plan identity preflight and use encoded-byte-budgeted batches with boundary tests |
| 2026-07-11 | Normal isolated Build 4200 loaded Inex but the test helper never reported because it defaulted to Python 3.3 | 1 | Add a test-only `.python-version` selecting 3.8 and rerun; product package loading was already evidenced by its Python 3.8 bytecode |
| 2026-07-11 | Phase 6 durability audit found `sharedindex.*` was outside the journal/index fsync model | 1 | Reject Git split-index repositories before any merge/recovery write and add a real-repository regression |
| 2026-07-11 | Build 4200 reached real unlock but Python RPC stdout blocked on `BufferedReader.read(65536)` for a short hello frame | 1 | Pause the editor matrix, switch to a bounded read-once pipe primitive, add a real subprocess regression, and rerun from hello |
| 2026-07-11 | Git residual audit exposed fsmonitor helper execution and promisor lazy-fetch subprocess risk | 1 | Override fsmonitor off in every invocation, disable lazy fetch, and add an external-helper non-execution regression |
| 2026-07-11 | Build 4200 E2E completed real unlock but the harness pressed Enter before selecting a Quick Panel row | 1 | Treat as UI-driver error; send Down then Enter for the single `qa.md` item and restart the isolated run |
| 2026-07-11 | Build 4200 created an initial untitled window beside the bootstrap window and generic class search focused the wrong top-level | 1 | Select the bootstrap-title X11 window explicitly before driving its Quick Panel |
| 2026-07-11 | Build 4200 hello/unlock/tree passed but `document.open` rejected the daemon's 22-character handle as if it were a 43-character session | 1 | Introduce exact session/document capability validators and rerun against a real daemon response |
| 2026-07-11 | Build 4200 opened and edited correctly, but the QA helper sent Save/Close as TextCommands rather than their real WindowCommand dispatch | 1 | Fix only the helper to call the owning window and rerun the same bounded flow |
| 2026-07-11 | Generic programmatic WindowCommand Save also remained a no-op without a product error | 1 | Use explicit `inex_save`/`inex_close_active` for the minimal encrypted lifecycle; reserve native command interception for an X11-driven subtest |
| 2026-07-11 | Build 4200 removed the saved tab but retained a Python wrapper reporting `is_valid()` | 1 | Make the harness assert live-window membership and registry removal instead of stale wrapper validity |
| 2026-07-11 | Build 4200 post-flow cleanup raced reparented plugin-host/crash-handler exit | 1 | Quiesce the complete isolated process tree before scanning, printing PASS, and deleting the root |
| 2026-07-11 | Crash runner treated empty `xclip` as fatal, then attempted an unsupported same-process plugin-host restart | 2 | Use explicit clipboard/PRIMARY states, late-host checks and `PASS_WITH_DOCUMENTED_BOUNDARY`; always terminate the isolated app and require zero root hits |
| 2026-07-11 | First real CRUD E2E pressed Down on a preselected delete row and chose Cancel | 1 | Preserve the file, select the first row with Home, and rerun the complete real-panel flow to `crud_complete=true` |
| 2026-07-11 | Independent Sublime audit found lock-loop API exceptions could bypass sidecar shutdown and draft removal could follow a symlinked directory | 1 | Isolate every view operation with shutdown fallback; use reparse checks/dirfd-anchored removal and regress redirected-target preservation |
| 2026-07-11 | First release unit invocation omitted `PYTHONPATH=scripts`; the retry reused zsh's special `path` array and erased PATH | 2 | Discard both incomplete chains, clear generated cache, enable fail-fast, use a safe variable name and rerun 19/19 plus all static gates |
| 2026-07-11 | Two independent release audits exposed permissive VSIX/ZIP/version/PE checks and later Win32-name/mode/tag/native/provenance bypasses | 2 | Add strict negative tests and exact workflow bindings; final 19/19/actionlint/pedantic/native-smoke re-review is GO |
| 2026-07-11 | Default xlings release binary used a build-home ELF interpreter/RUNPATH | 1 | Reject it as non-portable, rebuild with `/usr/bin/gcc`, and require strict ELF/native-dependency audit before packaging |
| 2026-07-11 | Documentation audit found overbroad encryption/support claims and release/CLI examples that were not self-contained | 1 | Correct the threat/resource model and exact commands, then obtain a zero-blocker/zero-major independent rereview |
| 2026-07-11 | Rename/modify audit found detected source omission, copy-vs-rename ambiguity, SHA-256 abbreviated OID acceptance, recovery owner ordering, and final-ref recovery gaps | 1 | Bind exact merge trees/full OID width, introduce source-aware v2/v3 journals and owner prechecks, then add the full negative/crash-state suite |
| 2026-07-11 | Provenance-aware detected CLI fixture lacked `MERGE_HEAD`, and a broad patch inserted v3 validation into legacy v1 recovery | 1 each | Start a real merge before stage normalization, patch the exact version block, and restart all targeted gates |
| 2026-07-11 | First global worktree owner pass skipped all non-active unmerged paths | 1 | Validate their current digest against authenticated stage objects and reject target identity reuse before any earlier conflict result is written |
| 2026-07-11 | Final Git audit proved one path can carry stage zero and unmerged stages simultaneously | 1 | Reject the intersection from one full-index snapshot plus local original-state rechecks; use a valid different-identity source-bound stage-zero regression to avoid false coverage |

## 5-Question Reboot Check

| Question | Answer |
|----------|--------|
| Where am I? | Phase 7 — 跨平台验证、打包与发布准备 |
| Where am I going? | Final clean-source deterministic build/audit/smoke → completion audit |
| What's the goal? | 交付 init plan 定义的跨平台密文仓库与编辑器虚拟明文系统 |
| What have I learned? | 见 `findings.md`：冻结格式、依赖、编辑器备份风险与失败安全边界 |
| What have I done? | Phase 1–6、发布流水线与 Git rename/modify 源码契约已闭合并固化为 Git checkpoint；正在生成最终 clean-source 证据 |
