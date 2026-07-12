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
  - 将 rename 合同、安全/运维/release scope 与 261/261 全量门禁同步提交为 `9d27250`（`docs: record audited rename merge contract`），随后 fast-forward 合并回 `master` 并删除功能分支，未推送远端。
  - 在 clean `9d27250` 与最终 evidence-only successor 上分别执行 system-GCC release build；每个提交均双打包，Rust ZIP、VSIX、unpacked Sublime ZIP 与 SHA256SUMS 逐字节一致，严格 artifact/native-dependency audit 和两轮 VS Code 1.125.0 package smoke 全通过，manifest 为 canonical origin、exact commit、`dirtySourceTree=false`。

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
| final clean-source Linux package | system-GCC release build + two independent package directories + byte comparison + strict artifact/native/smoke | all outputs deterministic, clean provenance, portable ELF, installable VSIX and runnable bundled sidecars | both four-file sets byte-identical; both audits/smokes pass; `dirtySourceTree=false` | PASS (Linux x64 checkpoint) |
| clean standalone Linux artifact lifecycle | committed harness in standalone clone + final Linux x64 artifacts | import/password/current-old rejection/historical metadata, exact RPC bodies, single-commit Git bundle, clean tree-copy restore, driver relocation, frozen-v1 and residue checks all bind | harness `1e01842`, artifact `76ac04a`, 5/5 bodies, 3 artifact + 5 harness + 4 fixture hashes, outside-source sensitive hits 0 | PASS (lifecycle-only Linux x64 checkpoint) |

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
| 2026-07-12 | Final provenance review reproduced replacement-object, external-worktree, executable-mode and unbounded-Git-output attack surfaces | 1 | Sanitize Git environment/config, reject replacement refs, bind canonical root/gitdir/index and exact HEAD tree modes/blob bytes, use bounded concurrent Git capture, and cover every probe in the existing release test |
| 2026-07-12 | The expanded provenance test ran mode/race/worktree probes before deleting its synthetic replacement ref | 1 | Move the replacement assertion and cleanup to the end of that probe, keep the product checks strict, and rerun the complete suite to 49/49 with `ResourceWarning=error` |
| 2026-07-12 | Final probes hid a case-alias untracked file and altered effective origin through include/worktree/rewrite/empty URL configuration | 1 | Freeze Git case/Unicode/fileMode behavior, require direct standalone administration paths, reject ambiguous config scopes and require one identical raw/effective canonical origin |
| 2026-07-12 | Syntax-only `py_compile` omitted the no-bytecode environment and created three local cache files | 1 | Remove only those generated cache directories, record the mistake, and rerun later Python gates with `PYTHONDONTWRITEBYTECODE=1` |
| 2026-07-12 | Targeted Rust gate used nonexistent inex-cli test target `git_workflow` after inex-git 31/31 had passed | 1 | Preserve the valid crate result, use the discovered target `git_cli`, and confirm its 9/9 tests pass |
| 2026-07-12 | Final Git probes found portable file/directory prefix collisions, self-hiding untracked `.gitignore`, clean-filter helper execution, split index and object-alternate dependencies | 1 | Add portable prefix sets, bounded ignored-file parent checks, a narrow local-config allowlist with non-execution marker, and direct standalone object/index rejection with real-Git regressions |
| 2026-07-12 | Initial provenance allowlist omitted actions/checkout's retained `gc.auto=0`, while forcing POSIX fileMode on Windows risked a false dirty result | 1 | Allow only exact `gc.auto=0`, branch fileMode by native semantics, require `core.autocrlf=false`, add a CI-shaped regression and set the policy in the package workflow |
| 2026-07-12 | A small attribute-isolation patch used the wrong f-string context and was rejected before writing | 1 | Inspect the exact runner/environment lines and apply `GIT_ATTR_NOSYSTEM` plus `core.attributesFile` as two precise hunks; no partial edit existed |
| 2026-07-12 | Manifest audit omitted installFormat and parser exactness, accepting unknown fields, duplicate keys, UTF-16/32 and bool/float schema version aliases | 1 | Enforce strict UTF-8, recursive duplicate rejection, exact top/source/file keys, integer schema 1 and kind/platform install format; add negative tests and re-audit the final artifact |
| 2026-07-12 | Two release-test invocations omitted the repository `PYTHONPATH`, and default Conda Python 3.12 lacked required Linux pidfd APIs | 2 | Treat import/pidfd errors as invalid harness evidence; rerun with `PYTHONPATH=scripts`, fixed Python 3.13.14 and `ResourceWarning=error` to 59/59 |
| 2026-07-12 | A combined runtime/smoke patch used stale smoke-function context | 1 | `apply_patch` made no partial write; inspect current lines and land Rust, tests and Python smoke as separate patches |
| 2026-07-12 | First strict Clippy pass rejected two test `expect()` calls and one single-branch daemon `match` | 1 | Use the repository's panic-on-error test pattern plus `let...else`; rerun workspace pedantic Clippy with warnings denied |

## 5-Question Reboot Check

| Question | Answer |
|----------|--------|
| Where am I? | Phase 7 — 跨平台验证、打包与发布准备 |
| Where am I going? | Completion audit and external/native gate handoff |
| What's the goal? | 交付 init plan 定义的跨平台密文仓库与编辑器虚拟明文系统 |
| What have I learned? | 见 `findings.md`：冻结格式、依赖、编辑器备份风险与失败安全边界 |
| What have I done? | Phase 1–6、发布流水线、Git rename/modify 与最终 clean-source Linux x64 双构建证据均已固化；未完成项均为明确外部/native gate |

## 2026-07-12 — Phase 7 continuation

- 重新读取 `planning-with-files`、`.agent/init_plan.md`、三份持久化计划文件并运行 session catch-up；未发现未同步上下文。
- Git 基线为干净 `master`，HEAD `76ac04aa594001c9259a3117cbd933436357e0ce`，领先 `origin/master` 20 个提交；继续以独立、经验证提交作为容错边界，不改写历史、不擅自推送。
- 本轮先审计 Phase 7 尚未关闭的发布/残留/恢复矩阵，优先完成无需外部平台或新权限即可形成绑定证据的项目；原生 Windows/ARM、hosted CI、签名与法务仍按外部门禁处理。
- 记录一次无副作用的计划补丁失败：首次补丁包含空的 `findings.md` 更新 hunk，`apply_patch` 在写入前拒绝；拆分为有实际内容的独立补丁。
- 完成未勾选项初筛：活动计划仅余三个聚合门禁，发布清单中的本机候选为最终产物导入/备份/恢复、秘密与磁盘残留扫描、依赖许可/发行物清单；已并行委派发布门禁、index CAS 与恢复演练的只读设计审计。
- 复核绑定 acceptance matrix 与 CLI/运维契约：决定优先构建最终产物 lifecycle drill，使 copy import、Git 本地配置、备份/恢复、认证读取、字节比对和 canary 残留检查成为可重复的 Linux checkpoint，而不是仅保留人工说明。
- 确认实现路径：安全解包 Rust ZIP，构造含 Unicode/混合换行/空文件/边界文件的 disposable source，最终 CLI dry-run/real import/password 变更，最终 daemon 认证逐字节读取，Git commit+bundle+clone+driver 重装，v1 fixture 不改写验证，并扫描 vault/Git/bundle/进程输出中的动态秘密 canary。
- 复核发布工具边界：复用严格 artifact audit 与 archive 解析；演练必须在创建任何敏感测试数据前先验证 clean provenance，且所有子进程输出保持内存中并纳入 canary/password 扫描。
- 新增 `scripts/drill_release_lifecycle.py` 与 `scripts/tests/test_release_lifecycle.py`；5/5 定向测试及包含既有发布审计的 24/24 Python 3.13 测试通过，覆盖 canonical base64url、RPC framing、跨 chunk/UTF-16 秘密扫描、symlink 拒绝、源哈希和 Unicode/最大尺寸 fixture 构造。
- `python3.13 -m py_compile` 通过，但生成了本地 `__pycache__`；它不是源码变更，进入 Git 门禁前只清理由本命令产生的缓存并复验工作树。
- 根据独立恢复审计补强演练：新增完整 regular-file filesystem snapshot/restore、空目录保留、Git fsck、历史 `vault.json`+旧密码仍可读且当前 metadata 拒绝旧密码、密码变更不改 EDRY 哈希等证明。首次顺序补丁把 restore `git fsck` 放在 clone 前，编号检查在执行前发现并修正，未触碰任何测试 vault。
- 首次最终 artifact 整链运行在固定输出断言处安全停止（exit 1，临时根自动删除）；源码复核确认产品输出为 `ParentSyncStatus::Synced`，而 harness 误期望简写 `synced`。修正精确契约，并为后续失败增加只含固定阶段/固定预期行的诊断。
- 第二次整链已通过 import、密码变更/历史 metadata、Git bundle、完整 filesystem snapshot、两种 restore 与认证 byte compare，最后在 frozen-v1 全树哈希检查停止；产品按设计保留 `.vault-local/mutation.lock`。调整为原始 `vault.json`/EDRY 哈希必须逐项不变，只允许新增 `.vault-local/` runtime 文件，其他新增路径仍失败。
- 修正后发布工具测试 26/26 通过，最终 clean artifact `target/release-final-76ac04a-a/linux-x64` 的完整 lifecycle drill PASS：3 个 artifact 先审计，5 个 Markdown（最大 16,777,216 bytes）认证逐字节一致，source hashes unchanged，当前 metadata 拒绝旧密码但历史 metadata+旧密码仍可读，Git bundle/fsck/clone 与 full filesystem snapshot/restore 均成功，driver 显式重装，frozen-v1 product bytes unchanged，动态 canary/两组密码在审计磁盘根与子进程日志中 0 命中。
- 已委派三路只读复审：安全/秘密与 TOCTOU、发布清单证据边界、Git/跨平台 snapshot 顺序；主线程继续执行静态质量和差异检查。
- 当前差异通过 `git diff --check`、26/26 Python 3.13 发布测试与零 `__pycache__` 检查；本机未发现可用 `ruff`，因此后续以解释器测试、独立代码审计和仓库既有质量门作为绑定静态证据。
- 主动安全加固 lifecycle harness：子进程 argv+environment+stdout+stderr 均扫 raw/base64/base64url/hex/UTF-16 动态秘密；扫描和哈希使用 no-follow/single-link/identity+时间戳复验；RPC response 加 60 秒硬超时并并发排空 shutdown；所有 disposable 根除 plaintext source 外整体扫描，并以文件名拒绝空 `.md` 泄漏。27/27 发布测试与真实最终 artifact drill 再次 PASS。
- 发布证据复审提出两个 blocker：artifact audit 与执行未绑定同一 ZIP snapshot，最终 JSON 缺 artifact/harness provenance；另有隔离 cwd/TMPDIR、精确 `AUTH_FAILED`、frozen-v1 命名和失败证据保留等 major。保持增量未提交，先修复并重跑，当前 PASS 只视为开发证据。
- 三路复审已全部返回；新增 fixture path escape blocker，以及 bundle verify cwd、driver 模糊匹配、restore 后 clean status、verify/tree 判据、stderr drain/output bound、Windows reparse/可信静止树边界等问题。下一修订将先私有快照 artifact、固定 fixture identity/O_EXCL，再补精确协议/Git/report 判据；未修复前暂不接受 checklist 的 `[x]` 为最终证据。
- 一次组合 hardening 补丁因当前函数顺序与上下文不匹配而在写入前整体拒绝；改为按 environment/process、RPC、Git、fixture/report 四组小补丁推进，避免误插入顺序。
- 完成私有 artifact snapshot/内存 entries 复审、固定 fixture/O_EXCL、精确 verify/tree/AUTH_FAILED/driver/Git 判据、隔离 TMPDIR/cwd、bounded pipe/RPC stderr drain、失败证据保留与 provenance 报告；34/34 测试通过。首次 hardened real run 在报告 Linux fstype `ext2/ext3` 时因斜杠白名单过窄停止，合成根按设计保留；只检查固定 stat bytes 后扩展标准表示并准备删除该根重跑。
- 删除上述已定位的合成失败根后，34/34 测试与 hardened real drill PASS。报告绑定三项 artifact SHA-256、artifact source `76ac04a` clean provenance、四项 fixture SHA-256、三项 harness file hash、Git 2.43.0、Linux 6.8.0-124 x86_64 与 `ext2/ext3`；执行期间 artifact/harness hashes 稳定，driver relocation、exact tree/body compare 和全部秘密扫描通过。该中间运行的 harness source 当时仍为 `dirtySourceTree=true`，故只作为后续 clean rerun 前的开发证据。
- 稳定差异通过完整 Rust source-quality gate：workspace 261/261、`cargo fmt --check`、all-target/all-feature pedantic Clippy（warnings denied）、rustdoc `-D warnings`、actionlint 与 `git diff --check` 全绿。新增 release tooling 未回归 core/daemon/CLI/Git。
- 编辑器回归门同步通过：VS Code TypeScript check、23/23 Node tests 与 production build 全绿；Sublime 61/61 Python tests 在 ResourceWarning-as-error 下通过且无 `__pycache__`。本轮 release harness 变更未影响两个客户端。
- Git index CAS 审计确认官方 porcelain 没有 expected-old index CAS；真正闭合需 alternate `GIT_INDEX_FILE` candidate、Inex 自持 `.git/index.lock`、old/candidate digest 与 journal v4、跨平台原子替换和完整 fault matrix。该项保持独立 GA checkpoint，本轮不以长驻 `update-index` 子进程伪装闭合。
- 新增 artifact snapshot 超大输入预检测试后 release tooling 35/35 通过；在提交 clean-harness checkpoint 前，独立安全复审发现 frozen-v1 fixture 仍有摘要后重开路径的换包 blocker，并指出 RPC secret/schema、Git 隐藏历史、物理密文 allowlist、进程树有界清理与残留路径/Base64 对齐等 Linux major。真实制品演练暂停，先修复并重新复审。
- 独立 Git driver 复核确认 native Windows 的 `\\?\` canonical path 与 Python `Path.resolve()` 可能不一致，且 canonical executable path 中 `%O/%A/%B/%L/%P` 会被 Git 在 shell 前展开。Windows verifier 保持未覆盖；installer 的 `%` 路径拒绝需作为产品 hardening 修复并加回归。
- 完成第二轮 lifecycle 安全闭环：frozen fixture 固定四文件限长单次捕获；RPC 拒绝重复键/额外字段/密码与 session 回显并逐 method 精确验 schema；POSIX leader 退出后仍清理进程组；导入前后要求 exact ciphertext physical allowlist；Git 仅允许一个 `main` ref/commit、比较恢复 HEAD 并拒绝 unreachable object；残留扫描覆盖路径组件与 Base64 三种流对齐，报告明确排除 `plaintext-source`。Native Windows 因 Job Object/ADS 未实现而 fail-closed，dirty harness 也在 artifact 使用前 fail-closed。
- Git driver 产品层已在任何仓库写入前拒绝 canonical executable path 中任意 `%`，防止 Git placeholder 预展开；inex-git 31/31、CLI Git 9/9、fmt 与 pedantic Clippy 通过。发布工具新增 adversarial 回归后 45/45 在 `ResourceWarning=error` 下通过；首次普通运行暴露的 reader 管道未显式关闭 warning 已修复并由严格重跑证实。
- 提交前完整 Rust 门禁通过 workspace 262/262、`cargo fmt --check`、all-target/all-feature pedantic Clippy（warnings denied）与 rustdoc（warnings denied）；组合命令只在末尾因 `actionlint` 不在当前 `PATH` 中断，按发布清单改用仓库内固定的 `target/tools/actionlint` v1.7.12 单独复验，不把工具发现错误误记为源码回归。
- 最新双路攻击复审继续否决提交前 GO：可控探针证明后代 `setsid()` 能逃出单一 PGID，另一路复现 artifact 预检后膨胀仍被无界 tree copy 捕获；还发现 plaintext source 只比文件未比空目录、结束时未重验 HEAD/dirty/origin、driver 重装后未重验 refs/unreachable object。所有探针逃逸进程均由审查代理立即 SIGKILL，真实演练继续暂停。
- 对上述问题实施 fail-closed 修复：Linux 每次 spawn 前启用 child-subreaper并要求零既有子进程，结束后递归读取有界 `/proc` census、以 pidfd SIGKILL 并回收包括 `setsid()`/double-fork 在内的后代；artifact 实际 capture 流式重验单文件/总量/identity；source 同时绑定 file hashes、directory manifest 和非 canary 敏感路径；结尾最后重验 harness files+source revision；每次 Git driver 重装后再验单 main ref/commit、HEAD 与 unreachable objects。RPC body 另收紧为 strict UTF-8。
- 新增竞态/空目录/provenance/UTF-16/32/`setsid()` 回归后，发布工具 49/49 在 `ResourceWarning=error` 下通过；`setsid()` 探针的 `/proc/<pid>` 在 command 返回前已消失。固定 `target/tools/actionlint` v1.7.12、workflow lint、diff whitespace 与零 Python cache 检查同步通过。
- 一次补充 untracked whitespace 探针误用 zsh 只读特殊变量 `status`，在任何写入前停止；tracked `git diff --check` 已通过，改用非特殊变量重跑两份新文件后再形成提交门禁。
- 最终 provenance 复审用临时 canonical-origin repo 证明 `assume-unchanged` 可让实际 tracked bytes 改变而 `git status` 仍为空；当前真实 repo 无特殊 flag，但门禁可被稳定绕过。共享 `source_revision()` 已改为拒绝 `assume-unchanged`/`skip-worktree` 等非普通 index 状态，并在 clean 树上以 SHA-1/SHA-256 Git blob 规则流式绑定每个单链接 regular tracked file 到固定 HEAD tree，再复核 HEAD/origin/index/status 未漂移；既有 origin 测试扩展覆盖两类 flag，严格发布测试仍为 49/49。
- 后续 provenance 攻击复审继续闭合 replacement refs、继承 `GIT_*`、`core.worktree` 重定向、index/gitdir/root 替换、POSIX executable-mode 漂移与 Git 子进程无界输出/挂起：共享 runner 现在并发限长读取 stdout/stderr、60 秒超时并清理进程组，`source_revision()` 首尾各做一次完整 HEAD-tree blob 重算。测试编排曾让 replacement ref 掩盖后续断言，清理顺序修正后严格发布套件在 `ResourceWarning=error` 下恢复 49/49。
- 最后一次 blob 读取后的同用户改写仍是 live checkout 的固有尾窗；当前 checkpoint 明确要求受信任的独占、静止 release checkout，不把双重重验表述为抗并发原子 snapshot。真正的敌对并发绑定需让构建和 provenance 共用一份私有固定字节捕获。
- 最终定向 provenance 轮次补齐 `core.ignoreCase` 大小写别名、owner-execute Git mode、annotated-tag peel、direct index、linked/sibling worktree、include/worktree config、URL rewrite、重复/空 origin 与 global config 隔离。实现现固定 Git 语义、绝对绑定 Git binary/root/`.git`/common-dir/index/config/HEAD，拒绝非 standalone checkout，并要求 local/effective canonical origin 唯一一致；同一 49 项套件在全部探针加入后仍以 `ResourceWarning=error` 通过。
- Lifecycle JSON 与 SECURITY/operations/release checklist 已明确列出 binding trust assumptions 和 not-covered：从解释器启动到 artifact/report 捕获必须无同主体写者，工具链、生成输入与 artifact directory 可信不变；installation 与同一组文档另明确 source commit 不是独立 build attestation。
- 提交前低成本门禁复验：`cargo fmt --all --check`、inex-git 31/31、修正目标名后的 CLI `git_cli` 9/9、固定 actionlint、tracked/untracked whitespace 与零 Python cache 均通过；一次不存在的 `git_workflow` 测试目标调用已单独记录，不影响随后有效结果。
- 最后一轮真实 Git 负测把 portable `foo`/`FOO/bar` 前缀碰撞、root/nested self-ignored `.gitignore`、filter helper marker、linked/split/symlink index、object alternates、annotated tag、global/local/worktree config、CI `gc.auto=0` 与 autocrlf policy 纳入同一 provenance 测试；完整发布工具 49/49 在 `ResourceWarning=error` 下用时 21.904s 通过。
- 根 `.gitattributes` 在 checkout 前固定 `* -text`，package workflow 再 pin `core.autocrlf=false`；manifest audit 同步升级为 strict UTF-8/duplicate-free/exact-key/exact-install-format。原 final Linux artifact 在新审计器下通过，最终完整发布测试 49/49（22.914s）、actionlint、whitespace、零 cache 通过；三路冻结快照复核均为 blocker/major/minor 0/0/0。
- 创建 Git checkpoint `1e01842fc26ec24183f911ca38a9eb32924db579` 后，原 repo 与 `git clone --no-hardlinks` 的独立 standalone checkout 都由 `source_revision()` 报告 clean canonical provenance，提交后严格发布测试 49/49 通过。真实 final artifact lifecycle 随后 PASS：artifact source `76ac04aa…`、harness source `1e01842f…`，三 artifact 哈希 `d551f3ca…`/`590dcd14…`/`34d61157…`，5/5 认证正文、Git bundle/fsck、clean tree-copy restore、driver relocation、frozen-v1 unchanged、Linux subreaper/procfs/pidfd cleanup 全部成立，`plaintext-source` 外敏感命中为 0；一次性 clone 在验证 clean 后删除。
- 完成下一阶段 Git CAS 源码审计：现有 v1/v2/v3 三条 commit/recovery 状态机均在最后一次 index/owner/provenance 检查后直接调真实 index 的 `git update-index`，因而 Inex 不持有跨越 worktree 前滚和 index 发布的同一 `.git/index.lock`。已冻结最小 v4 方向：alternate index 生成与语义验证 candidate，随机完整 marker 以 no-replace move 争用真 lock，lock 内重验 old digest/owner/provenance，create-only v4 绑定 old/candidate digest+size 和内层 payload，再以 `candidate -> index.lock -> index` 发布。
- 两路独立审计同意 create-only v4 可由真实 namespace 状态推断，不需要可变 phase；实现保留 v1/v2/v3 旧 journal 的严格读取/恢复兼容，新事务只写 v4。本轮先在 Linux 临时真实仓库完成 foreign lock、并行 porcelain、marker/candidate/final-index 崩溃矩阵与 SHA-1/SHA-256 回归；原生 Windows 掉电证据依然独立未完成。
- 完成 Git index CAS v4 主实现：真实 index 的完整 bytes/size/SHA-256 snapshot 经 alternate `GIT_INDEX_FILE` 生成并语义验证候选，随机完整 marker 以 no-replace move 争用 `.git/index.lock`，锁内重验 index/owner/provenance，create-only v4 journal 原子发布后才允许 worktree 前滚，最后执行 `candidate -> index.lock -> index` 两次可恢复 namespace move；旧 v1/v2/v3 仍只读兼容。
- 补齐 bounded Git runner、candidate/marker/journal staging 的 RAII 清理和错误后态协调；恢复矩阵覆盖 foreign/pre-lock winner、lock-held porcelain、marker、candidate-in-lock、published、later unrelated index update、target drift、tamper、foreign replacement lock 与 truncated pre-journal staging。v4 严格 schema 现把 outer object format 同时绑定 stage/result OID 与 rename provenance 三个 commit OID。
- 新增跨平台 verified-file no-replace/replace primitive：要求绝对、词法规范、全祖先非 link/reparse、同一本地 mount、single-link regular file 与路径/句柄 identity；成功后分别报告两侧 parent sync。Wine 暴露目的句柄保持打开会导致 `MoveFileExW` code 5，调整为最终重验后消费句柄再替换，并明确同一 OS 用户直接 namespace rebind 不在 handle-bound CAS 承诺内。
- 当前定向证据：inex-core verified-file 7/7、inex-git 47/47、CLI Git 9/9、Git pedantic Clippy、Windows GNU check 与 `git diff --check` 已通过；复审代理在 Wine 默认路径复验 verified-file 5/5。原生 MSVC/NTFS/ReFS abrupt-kill/power-loss、ref-only 并发与 legacy recovery CAS 继续保留为 Phase 7 外部门禁。
- CAS v4 最终三路独立复核均给出当前 Linux 源码 checkpoint GO：安全、测试/文档与跨平台契约合计 blocker/confirmed-major/required-minor 为 0/0/0；一致判定 GA/native Windows 仍 NO-GO。全 workspace 本机测试、fmt、pedantic Clippy、rustdoc warnings-as-errors，以及 Windows GNU 全 workspace check/pedantic Clippy 和固定 actionlint 已通过；最终差异另从头复跑完整 workspace 与仓库卫生门禁。
- 最终差异通过 285/285 workspace tests 与全部既定静态/交叉门禁后创建 Git checkpoint `7f05d79dc1290851c0b51f1f54e96f3a65ead42a`（`feat: add held-lock Git index CAS`）。从该 clean HEAD 再次复验 verified-file 7/7、inex-git 47/47、CLI Git 9/9、fmt、whitespace 与 clean status 全绿；未推送远端，原生 Windows/GA 门禁不因该源码 checkpoint 改变。
- Phase 7 后续三路只读审计冻结 “Strict release-set evidence v1” 顺序：先修 native target 未传入许可 metadata、宽松 inventory JSON/schema/source/checksum/license policy、三包 inventory/sidecar 不一致与 lifecycle report 无 schema/秘密自扫描，再从新 clean HEAD 重建 Linux x64 证据；随后才扩展 RPC/CLI/Git 负路径秘密 drill。法务、签名、hosted CI、原生 Windows/ARM 与持久 editor profile 均不因本地自动化而关闭。
- 完成 Strict release-set evidence v1 源码实现：许可生成按四平台固定 Rust triple 解析 locked/offline graph，只信任四个精确 workspace manifest，拒绝自动 member/path/git/非 crates.io/缺 checksum/未知表达式；工程 policy 的 12 个表达式与 libsodium ISC 摘要在生成器/审计器中固定，Cargo/native 许可文本逐项带 SHA-256。
- 三包 artifact audit 现要求 canonical strict JSON、精确 schema/target/policy、完整 license text 集、完全相同 inventory bytes 与 `inexd` bytes；package report 绑定 canonical SHA256SUMS，release-set/lifecycle report 绑定 source/artifact/manifest/inventory/sidecar，lifecycle 将 Unicode JSON escape 纳入动态秘密 variants 并原样输出已扫描 bytes。
- `inex runtime-info`/`inexd --runtime-info` 报告编译 Rust target、debug assertions 与 exact libsodium 1.0.22/ABI 26.4/non-minimal；所有 sodium 初始化都先强制该 runtime。Package smoke 要求平台固定 triple 与 release profile。Windows GNU no-run link 和 Wine 实跑确认其输出 `x86_64-pc-windows-gnu`/`true`，不能冒充 MSVC/release package。
- CI release-tooling 与 package quality-gate 在 offline 许可测试前显式安装固定 Rust/预取 locked Cargo graph；Rust ZIP 的根 README 重写到随包 `DEPENDENCY_LICENSE_POLICY.json`，避免离线 Markdown link audit 指向不存在的源码目录。
- 最终源码门禁：Python 3.13.14 严格发布工具 59/59、Rust workspace 287/287、fmt、all-target/all-feature pedantic Clippy、rustdoc warnings-as-errors、固定 actionlint、Windows GNU check/clippy/no-run link 与 `git diff --check` 全绿。三路最终复审为 blocker/major/required-minor 0/0/0；下一步必须从新 clean Git checkpoint 重建 Linux x64 artifacts，旧 49-test artifacts 仅保留历史证据。
- 创建源码 checkpoint `40ff7288879b27cc2e3b956b029fdb10e99ab25c` 后，严格 provenance 报告 clean。两份隔离 system-GCC release build 的 `inex`/`inexd` 分别逐字节一致（SHA-256 `3c7c4813…`/`5bacbda4…`），runtime-info 固定 GNU x64、debug assertions false、libsodium 1.0.22/ABI 26.4/non-minimal；VS Code 23/23、check/build 同步通过。
- 两套 strict-v1 artifact 四文件逐字节一致：Rust ZIP `b6b69bd9…`、Sublime ZIP `aaf2cd8f…`、VSIX `468886d4…`、SHA256SUMS `2059268a…`。两轮 release-set audit、native audit和 VS Code 1.125.0 install/smoke 全绿；共同 inventory `228bfeb7…` 绑定 77 个 Cargo component/147 份 hashed texts，共同 sidecar `5bacbda4…`，artifact source clean `40ff728`。
- 初次 strict lifecycle 在 harness `40ff728` 上通过正常 import/password/Git/frozen/residue 全链。随后持久化 CLI wrong-password+secret-query、RPC auth failure 和 locked merge-driver canary-content 三条负路径，创建 clean harness checkpoint `7f83dd63c2cbe890e014bcb6df9a91286091e566` 并对同一 artifacts 重跑 PASS：三项 nondisclosure 均 true，5/5 正文、两类 restore、driver relocation、frozen-v1、process cleanup 成立，`plaintext-source` 外敏感命中 0。独立复审 blocker/major/required-minor 0/0/0。
- 从 `git clone --no-hardlinks` 创建一次性独立 checkout，恢复 canonical origin 后由 `source_revision()` 绑定 clean harness `d44ead9bff35252577118441f8f575ed7e7b8d12`；同一 strict-v1 artifacts 的完整含负路径 lifecycle 再次 PASS。clone 复验 clean/零 cache 后已删除，未依赖原仓库 Git objects 或 worktree 状态。
- 重新审计 Phase 7 未闭合项：确认原生 Windows fault/lifecycle、持久 editor profile、exact packaged Sublime、two-version、签名/法务/发布仍未绑定；Phase 7 保持 `in_progress`，不把本地源码或 hosted 预备代码冒充外部结果。
- VS Code persistent-profile X11 原型在 exact 1.125.0/VSIX/Extension Host 上两次无法可靠触发 Command Palette activation；按 fail-closed 证据标准撤销全部未验证 VS Code runner/package 入口，清理所有含秘密隔离根，保留门禁未完成状态。
- Sublime Build 4200 runner 移除明文口令 fake helper，改用真实 `/usr/bin/zenity` masked prompt 与 stdin-only xdotool 输入，并把动态随机口令加入 residue tokens。61/61 pure tests、正常 CRUD E2E `PASS`、plugin-host kill `PASS_WITH_DOCUMENTED_BOUNDARY` 均通过；两条 E2E 的 `root_scan_hits=0`，失败诊断根已删除。源码/runner checkpoint 为 `d00de886aec59d1b8988f71e82516303460bc285`。
- Core atomic 新增 native force-kill 子进程门禁并通过 137/137 `inex-core` tests 及 all-target/all-feature pedantic Clippy；本机覆盖 Linux 四个 commit 边界，Windows GNU/native 执行仍待后续交叉/hosted 门禁。
- Git pre-lock reservation 初版通过 52/52 `inex-git`、Linux/Windows-GNU check+pedantic Clippy，但独立严格复审为 NO-GO（1 blocker/2 major/2 minor）：orphan reservation staging 未发现、同-token foreign regular ownership、Windows wrong-case alias、dangling staging及负测矩阵。已进入返修，未创建 Git checkpoint。
- 修正 `SECURITY.md` 中 strict release tests/harness 的旧证据，新增 draft `docs/release-notes-0.1.0-pre-alpha.md` 并从 README 链接；release notes 明确不构成发布批准。
- Argon2 只读审计确认 production creation 未实现 init plan 声称的 250–750 ms calibration，且 `docs/dependencies.md` 原表述超前、现已修正；已把 bounded ops-only calibration、RPC creation cap 与 password rewrap no-downgrade 加入 Phase 7 未完成项，尚未误标为实现。
- Git pre-lock 返修完成：canonical orphan staging、initial/final ownership receipts、RAII monotonic phase、wrong-case reserved-name inventory、foreign regular/hardlink/link/reparse preservation、stable-journal reentry 与 SHA-1/SHA-256 负测均落地。最终 `inex-git` 65/65、workspace 307/307、Linux/Windows-GNU check+pedantic Clippy/no-run、fmt/rustdoc/diff 全绿；冻结独立复审 0 blocker/0 major/0 required minor。Superseding checkpoint 为 `26c1ae1501104ae5207aced0a1501bf0bf92b580`；默认 Myers 的夸大统计经 minimal/patience/histogram 一致还原为 `1765+/72-`，仓库本地 diff algorithm 已设为 histogram。
- 本 checkpoint 仅宣称 fail-closed：receipt 发布间的 SIGKILL 状态会可见且保留为 `RecoveryConflict`，尚不能自动回收；原生 NTFS/ReFS write-through/power-loss 与总 Phase 7/GA 仍为 NO-GO。
- 独立文档复核纠正三类 release-decision 漂移：`40ff728` 仅为历史 artifact、receipt-gap 是人工处置 blocker、Argon2 calibration/RPC cap/rewrap no-downgrade 尚未实现；最终复核 GO，文档 checkpoint 为 `c3f9864bb1692fada8aeeaa5c33a8b9abe2a5da3`。
- 实现 production Argon2id ops-only calibration：默认固定 64 MiB/parallelism 1，在 ops 3..20 内以公开 dummy 输入搜索 250–750 ms 单次 KDF 窗口并缓存每进程结果/失败；custom policy、fast/slow/interior-gap fallback 与 invalid bounds 由假计时器确定性覆盖，冻结 fixture 继续走显式参数。
- 新增独立 new-vault creation ceiling（默认 ops 20/64 MiB）并保留 reader 20/1 GiB；core、RPC explicit/absent、CLI init/import 都在 root/staging 前完成校准或策略拒绝。RPC 精确区分 `KDF_POLICY`、`INVALID_PARAMS` 与 host `INTERNAL_ERROR`，stdio 负测证明超 cap 不创建 root。
- CLI password add/change 在旧口令释放、新口令读取前取得 calibrated baseline；Vault 公共入口以 authenticated slot 为 componentwise floor，允许保留 creation cap 以上但 reader-safe 的强参数。组合返修闭合二次 creation-cap 误拒绝，并把可绕过绑定的低层 `crypto::add_password_slot` 收窄为 `pub(crate)`。
- 新增真实 CLI process tests：`init` 创建的 slot 为 ops 3..20/64 MiB 且可解锁；从 ops4/64 MiB+8 KiB authenticated slot 执行 `password add` 后新 slot 不降级且新密码可解锁，密码不进入 argv/stdout/stderr。独立复审另跑 6 次 init，均选 ops3/64 MiB，完整命令 1256–1287 ms。
- Argon2 冻结复审：安全与文档均 GO，0 blocker/0 major/0 required minor。全 workspace 325/325、fmt、all-target/all-feature pedantic Clippy、rustdoc、Windows-GNU check/clippy/no-run、release tooling 59/59、Sublime 61/61、VS Code 23/23/check/build 与 actionlint 均通过；原生 Windows/arm64 的实际计时/资源证据仍未闭合。
- Argon2 实现 checkpoint 为 `e8b64e75e0aa2321657b170215c612709159d7be`，绑定策略与发布边界的文档 checkpoint 为 `61d59ee77083b6f282ec988c3313a62666f810b7`；二者均位于 `master`，未推送远端。
- 从 clean `cb6ccbb` 的首次重建被 strict audit 正确拒绝：README 链接的 pre-alpha release notes 未进入包。最小修复将其同时加入 producer allowlist/auditor required set，并新增真实 packaged-document closure 回归；Python 3.13.14 严格发布工具 60/60 与双路独立复审 0/0/0 GO 后创建 checkpoint `fd543f494669b8e82e9b7c6dabf071b17954be28`。
- 从三个独立 standalone clone 绑定 clean `fd543f4`：A/B system-GCC offline release binary 与三包逐字节一致，native runtime 固定 GNU x64/release/libsodium 1.0.22 ABI 26.4 non-minimal，strict release-set/native audit 与隔离 VS Code 1.125.0 smoke 双路通过。SHA-256：`inex` `392ab0ed319577440b32f322ef73cd39f088f9aa2a7173941f81fe5dc531d095`，`inexd` `e210525b741769ba2df8192956701307025e4925232c21f19e4ff102bdcd7d79`，Rust ZIP `4479350f49c124225832fc838af7ac06bc9e8f68f0f587551a6ab7e7d39b137e`，Sublime ZIP `411944bb3a8838da300bad2882ccca82b799ace313a3062969d95db3f860571c`，VSIX `f573721d3e9b0036f444978cabf6a641445756c6be1359eec736b61e6b1b2785`。
- 第三个 clean harness clone 对只读 A artifacts 连续两次 lifecycle PASS：artifact/harness source 都是 clean `fd543f4`，5/5 正文与 16 MiB 边界、password historical scope、CLI/RPC/locked-Git nondisclosure、bundle/tree restore、driver relocation、frozen-v1、allowlist、descendant cleanup 与零 outside-source secret hit 全部成立。第二次 canonical JSON 已保存到 `target/strict-release-fd543f4-lifecycle/evidence/linux-x64-fd543f4.json` 并通过 schema validation，report SHA-256 `989cff808665de168fa5f76b3ca47107cae9879fc96b916b72e65d91c1c49d11`。
- 当前只升级 Linux x64 本地工程 checkpoint；Argon2 原生 timing/resource matrix、Git receipt-gap/NTFS-ReFS power-loss、packaged persistent-profile residue、其他原生目标、两版本/故障态、签名/发布/法务与独立 build attestation 均未因本轮关闭。
- `fd543f4` artifacts 的 bundled docs 是构建时快照，仍 underclaim 为旧 `40ff728` 证据；当前 evidence/docs 属于 artifact 构建后的 successor 变更。已在计划中新增发布候选重建门，禁止把本轮工程包称为 successor HEAD 产物或直接发布。
- 依据文档复审继续推进 non-self-attesting package docs：移除所有会随包分发文档中的 exact artifact commit/hash/pass 自声明，改为要求外部 evidence 精确匹配 `PACKAGE-MANIFEST.json`/`SHA256SUMS`；planning ledger 保留 `fd543f4` 历史证据。该 generic-doc source checkpoint 提交后必须重新做 A/B/lifecycle，才可闭合最终本地 Linux x64 工程包。
- 包内 evidence contract 经两轮全输入扫描返修并冻结：移除 installation/troubleshooting/user-guide/dependencies/checklist 残余的 unnamed artifact PASS 与 77/147 自声明，只保留候选必须满足的条件。发布工具 60/60、packaged-doc closure 与独立复审 0/0/0 GO 后，superseding clean package source 为 `5aa0b8c773a018f23082ffeca853e971e47064bc`。
- `5aa0b8c` A/B standalone system-GCC offline builds 再次逐字节一致并双路通过 strict release-set/native audit 与隔离 VS Code 1.125.0 smoke。SHA-256：`inex` `392ab0ed319577440b32f322ef73cd39f088f9aa2a7173941f81fe5dc531d095`，`inexd` `e210525b741769ba2df8192956701307025e4925232c21f19e4ff102bdcd7d79`，Rust ZIP `a0be5e6f1612a74f82009648d1bff6f06352ee89aa698ec4a7d95594c22b71b4`，Sublime ZIP `bb504221a29ebebff17d8c87087a264f9ff2a1e228fc3ea45f67f82e7d5063ed`，VSIX `dcfde351dfa170c69d94a3f4f4fd8b9295bbb236729327ab5041456cb1a4123d`，SHA256SUMS `14c14b9cb96a8f85b9c12adf18a1950fdca31efe0749c5e850bbc92fa81a3b09`。
- 第三个 clean `5aa0b8c` harness lifecycle PASS 并持久化 canonical external report：三项 nondisclosure、5/5 bodies/16 MiB、bundle/tree restore、driver relocation、frozen-v1、physical allowlist、descendant cleanup 和零 outside-source hit 全部成立。报告路径 `target/strict-release-5aa0b8c-lifecycle/evidence/linux-x64-5aa0b8c.json`，权限 0600，SHA-256 `22916a1f95ade1bb5a04a568db27c850022d710a2d9ab4c1f87aefd734ca10b4`；本 planning successor 不参与 package contents，artifact source 不变。
- 最终独立安全与实际归档文档复审均 GO，合计 0 blocker/0 major/0 required minor：A/B 三套 clone provenance/fsck、六份 manifest、26 个 Markdown/包、release-notes presence、零 exact identity、自外部 evidence 契约、报告内 artifact/harness/fixture hashes 与现存文件全部复核一致。结论严格限于 Linux x64 本地 artifact checkpoint；GA/跨平台发布继续 NO-GO。

## 2026-07-12 — Native Argon2id calibration evidence

- 创建 Rust checkpoint `f495211`：新增无参数、CLI-only 的 `inex kdf-calibration-info`，将默认 creation path 与诊断统一投影到同一进程 `OnceLock` 中的选中参数、决策观测、测量数和 outcome；命令在 password/query input 初始化前执行，不接受 vault、口令或策略覆盖。
- 确定性选择器测试覆盖 inclusive target window、`target-window` 与四类 fallback、最大六次测量、原始耗时噪声以及未测候选可落入窗口的非单调反例；因此 fallback 只描述 production selector 返回的分支，不证明所有 ops 都无法命中。
- 真实 CLI 进程测试固定 20 行 ASCII `inex-kdf-calibration-v1` 契约，验证 invalid password/query 环境仍被忽略、stdin 为 null、stderr 为空、额外参数在工作前拒绝，并证明隔离 HOME/XDG/USERPROFILE/APPDATA/TEMP/cwd 不产生持久 product state。当前 Rust workspace 333/333、fmt、all-target/all-feature pedantic Clippy 与 rustdoc warnings-as-errors 全绿。
- 新增 `scripts/drill_kdf_calibration.py`：对 strict 四文件 artifact 做 no-follow/single-link/限长 snapshot 与 release-set audit，绑定 `inex`/`inexd` 物理身份、digest 和两次 exact runtime-info probe，再固定执行三次 ordinal fresh-process calibration attempt，不重试或挑选；报告记录 Linux `/proc` VmHWM/VmPeak、host/runtime、零普通文件残留与 canonical external JSON，POSIX 输出为 create-new 0600。
- 独立终审复现了 executable 自改后仍可引用旧 digest 的 major；修复后四 artifact snapshot 与两个 executable 均以 dev/inode/mode/size/mtime/ctime/SHA-256 seal 绑定，POSIX executable 先去 write bits，并在每次 probe/attempt 前后及最终 report 前复验。新增 CLI/daemon 自改和 artifact snapshot mutation 负测后，release tooling 76/76 在 `ResourceWarning=error` 下通过。
- 两路 Windows 专项审计发现当前 `Popen -> AssignProcessToJobObject` 有抢跑窗口，且普通 tree snapshot 看不到文件或目录 NTFS ADS；因此 Windows run/main/report validator 在任何 artifact 使用前固定 fail closed，package workflow 仅在 Linux x64/arm64 生成并独立上传 KDF evidence。Windows x64/arm64 仍需 suspended-before-Job、Job-empty barrier、ADS enumeration 与原生回归后才能开放，不以现有 ctypes schema helper 形成 PASS。
- 文档与计划同步冻结：selected observation 包含 validation、可能的 libsodium init、secure allocation 与 Argon2id，结束于 derived key drop 前；它不是纯 KDF 或完整命令 SLA。外部 evidence topology 明确为两次 runtime probe 加三次 calibration attempt，CPython 固定 3.13.14，artifact directory snapshot 窗口与同主体 writer/host/clock/kernel/harness 信任边界均显式记录。
- KDF 证据实现拆为三个 Git checkpoint：`1675ff9` 仅提交 Linux harness/测试/workflow，`aeaaaa9` 仅冻结面向用户与发布的边界文档，`eeca0bc` 仅记录 planning checkpoint；主工作树随后保持 clean，未推送远端。
- 两个 standalone `--no-local --no-hardlinks` clone 从 clean `eeca0bcb0c683cbe5bb0806e3e16d57bf490b248` 独立构建。两者都使用官方 SHA256 清单校验的 Node 22.23.1、pnpm 10.32.1 offline/frozen、Rust 1.97.0、`/usr/bin/gcc` 13.3.0 与外置 target/artifact/TMP；VS Code 23/23/check/build、strict release-set/native audit 和 exact VS Code 1.125.0 packaged smoke 双路通过。
- A/B 的两个原生二进制与四文件 artifact 逐字节一致：`inex` `3f439a0aa13a64216eb2721572cf0d4f1550dc18c1939306458f7ca0217fa86d`，`inexd` `ec27ba2cd45268762c7760eada331f4116324c73c7b24a5c9ef70c316777158d`，Rust ZIP `a74c5f616a43d396e7e696879acdce3a93fd5572a821a4c7375f3cf666d4530e`，Sublime ZIP `654dbef7befdd1e68a3d2c229397ac5bfef4805b594ca24efc5faebea4abc918`，VSIX `8d6ed43840fbf57e9fade0e65cc074935b59aae3aa1e15dd0d5a91c09ae3f4f0`，SHA256SUMS `640e33269af4ef79aa9adc208df78ab0570b7df55dc982ec89a3c5bc554cd816`。
- 对 A artifact 执行一次无重试 harness run：两次 runtime probe 加三次 ordinal fresh calibration attempt 均 PASS，三次都返回 `target-window`、ops 16、64 MiB、parallelism 1、measurement count 3，selected observation 分别为 277259503/290942597/286955199 ns；VmHWM 为 70066176–70107136 bytes。外部 canonical report 为 mode 0600、11200 bytes，SHA-256 `8d8a9adfe6bc86bcb4448333c09bc90668fc73762d1de67bb5a7af1d59f2e989`。
- 计划复核确认既有 lifecycle 只绑定 `5aa0b8c`，不能继承到新增 CLI 与 package source `eeca0bc`；第三个 standalone clean clone 已对当前 A artifact 完整 PASS：14 个 required boolean、5/5 expected bodies/16 MiB、三项 nondisclosure、single-ref/single-commit bundle、clean tree restore、driver relocation、frozen-v1、physical allowlist、descendant cleanup 均成立，sensitive residue hits 为 0。外部 report 为 create-new 0600、6396 bytes，canonical validator/re-encode 通过，SHA-256 `30904006c1aa2c406a613978777ac534f910a0b39b1121c1c2341d4f2caddf85`。

## 2026-07-13 — Exact packaged Sublime Build 4200 baseline

- 将原 Build 4200 source/debug runner 升级为显式双模式：无 artifact 参数仍是 developer smoke；`--artifact-directory` 必须与外部 `--output` 配对，后者只接受 artifact/source/root 之外的 0700 parent 和 absent portable basename，并以 create-new 0600 写 canonical JSON。
- Artifact mode 在私有根封存严格四文件 release set，绑定 regular/nonlink/singlelink dev/inode/mode/size/mtime/ctime/SHA-256；audit 后只从 captured in-memory archive entries 以 O_EXCL 物化 Rust `inex` 和完整 Sublime `Inex/` tree，包内 `inexd` 去 write bits，并让空 `sidecar_path` 走 production package-owned resolution。运行前后复验 artifact、package tree、CLI/daemon、全部宿主工具与 clean harness seals；Sublime 打开后还以 `/proc/<pid>/exe` 证明唯一 sidecar PID 对应 sealed daemon。
- Binding scanner 增加 UTF-8/UTF-16LE/UTF-16BE、hex、standard/base64url padded/unpadded、随机 filename canary 与 16 字符 entropy fragments；目录读取、文件读取、link/special entry 与 helper partial/malformed/oversized JSON 均 fail closed。Packaged import 改用 2 MiB bounded process capture，动态 variants 不得进入 stdout/stderr，并验证固定成功行。
- 报告 validator 对 artifact/audit/member/installed tree/executable/shared sidecar/tool/helper/import/environment/X11/residue/scenario 做 exact schema、排序、计数与 digest 交叉绑定；normal/crash helper JSONL 去除 monotonic time 后以 normalized digest 保存。独立复核进一步发现 checksum seal、完整 package inventory、Rust CLI manifest 与 crash-ready fingerprint 的交叉绑定缺口；`ba35a80` 嵌入 canonical Rust/Sublime manifests、从三包 audit 重建 `SHA256SUMS`，并拒绝 omitted product member、任意 CLI digest 与 crash-ready 自证。`5967c8f` 再把不兼容的 hardened 外层报告明确升为 schema v2 并拒绝 v1 降级；嵌套 release-set/package manifests 保持其各自 v1。11 项 harness 测试连同 61 项产品纯测试共 72/72 通过。
- 保留旧 `50b84b8` 及中间 `ba35a80` v1 报告作为不可改写 predecessor；它们不能继续冒充 current-validator v2 证据。Clean `5967c8fa1305f539cdbcecf833b1d57b0805b650` harness clone 已对同一 clean `eeca0bcb0c683cbe5bb0806e3e16d57bf490b248` Linux x64 artifact 重跑两路 exact-package v2 E2E。Normal 为 `PASS`、16 helper records、179 materialized members、178 installed files、7 tools，report 204580 bytes/SHA-256 `be158e8220a79a06d7bcff34856141081c3784808e8fe438f91ee1d0df79e5c7`；plugin-host SIGKILL 为 `PASS_WITH_DOCUMENTED_BOUNDARY`、9 records、唯一 packaged sidecar、8 tools，report 204792 bytes/SHA-256 `1242090095767ef022cc1bfdb1bdda9536deff4fe686e1f9cb3b4612e2d9e968`。两份 mode 0600、single-link、canonical validator/re-encode 通过，Rust manifest 170 项、Sublime manifest 177 项均与 audit/materialization 交叉绑定，隔离根删除且 harness clone 保持 clean。
- Crash 路只在 clipboard/PRIMARY 读取成功且长度/SHA 与本轮已观测 opened/saved managed plaintext 指纹之一完全相同时通过；本机读取到完整 earlier-opened plaintext，证明 host-dead copy 边界而不是 crash-time erase。结果继续要求完整 Sublime restart，产品仍 experimental。
- 当前用户文档已在 `721cea0` 同步为 72/72 与 exact packaged Linux 单场景基线，但未写入自证 commit/hash；same-profile restart 与完整 persistent-profile/full-platform matrix 继续明确保持 pending。
- 审计同时发现并清理 28 个 2026-07-11 legacy fake-zenity 失败根；清理前逐项确认 owner/mode/固定结构且无 live process，只删除含旧随机测试口令的 proven roots，保留不匹配结构的 `pidprobe` 根未动。
- Git receipt-gap 只读状态矩阵确认 v4 无法靠 recovery classifier 小修安全闭合：无 initial receipt 的 candidate、Git mutation 后无 final receipt 及 partial receipt 都缺持久归属证据。首选后续为 v5 immutable candidate bundle，在非 active scratch 完成 mutation/final digest/payload 后原子发布整个目录；partial scratch 保留但不阻塞，新 active namespace 不再出现多文件 receipt 窗。

## 2026-07-13 — Current artifact and portal-safe Sublime restart successor

- Build 4200 隐藏但实际生效的 `remember_open_files` 被纳入精确安全门禁并要求 `false`；产品与文档 checkpoint 为 `86285ce9480c06306bbec702166b29c7a243ed99`。两个 standalone clean build 固定 Node 22.23.1、Rust 1.97.0、offline Cargo 与 `/usr/bin/gcc`，四文件产物逐字节一致：Rust ZIP `863add927d0d9e7ed8f4d7db453fd2ee4c1930fc61fce407c8a68abaf09fb106`、Sublime ZIP `34b2490a20cfb9c7982ea3e13f8db799e5a2a3d50d2bd531561d43de1ea3c356`、VSIX `93043a0fa1fbfd3f83c0570c4a6f92c53c59abbe7bd4ebd81d9deb7c130e3c8b`、`SHA256SUMS` `4d29dbc3420231f685ac8ac3e10fabb26d3767a5e84547ddf242871509afa63e`；strict audit/native dependency/exact VS Code smoke 双路通过。
- 同一 current artifact 的 KDF successor 报告为 mode 0600、11200 bytes、SHA-256 `6d352111e51a79399b36c33fd85c69b7394c16850108bfbd48c1a8dbb2d66eb5`；三次 fresh process 均为 target-window/ops16。Lifecycle successor 为 mode 0600、6396 bytes、SHA-256 `b97ab16e1ffbfef49747835cc4207432ec500bcf3bbd3f9c592c1cf4f4335967`，14 个 required boolean、5/5 bodies、三项 nondisclosure 与零 sensitive hit 均通过。
- Full-restart 初版先把三项角色和 stable launch session 交给 pidfd SIGKILL，但独立复核发现 argv-only `root_bound_pids` 可漏掉 `setsid`/daemonized child，也可能误杀仅提到随机根路径的无关进程。修复后 runner 在首个 child 前启用并 read-back Linux subreaper，稳定捕获 session+descendant closure，以 starttime/session/parent identity 复验后才打开 pidfd；真实 double-fork+`setsid`、argv-only、env/cwd/fd 与 procfs permission-denial 回归全部通过。
- 第一份 schema-v3 external report 保留为 predecessor，current validator 明确拒绝。Schema v4 另把 exact isolated environment、profile path、package-owned sidecar path、process closure/mount policy、helper/state/lifecycle 的 token fingerprint-set digest 和两次启动身份交叉绑定；Sublime suite 最终为 84/84（61 product + 23 runner/evidence）。
- 第一次 schema-v4 exact attempt 正确在 root-bound survivor 处 fail closed，随后发现 private runtime 下失联 `fuse.portal` mount 令 cleanup 返回 `ENOTCONN`。失败根保持 0700 供取证；修复固定 `GTK_USE_PORTAL=0` 与无 service activation 的 private D-Bus、加入有界 `/proc/self/mountinfo` gate，并只允许 failure path 在零 live binding、唯一 exact `portal`/`fuse.portal` 情形调用 sealed `fusermount3 -u` 非 lazy 清理。旧失败根与 mount 已验证删除，success path 永不借 unmount 隐藏 residue。
- Clean standalone harness `b051291e4e9ff2891fbd4c827fd8c7030ee3db78` 对同一 `86285ce` artifact 串行重跑三路：normal schema v2 `PASS`（204580 bytes，SHA-256 `6b0608f5a89c6f3747130b7f72d12a4302db2d060fd67385433f0c201501ebd8`）；plugin-host-crash schema v2 `PASS_WITH_DOCUMENTED_BOUNDARY`（204792 bytes，SHA-256 `e4296778ff4cc43b7728cc2b0b66241be3c2506a37efee03630b1c2ecb1c7842`）；full-application restart schema v4 `PASS`（216331 bytes，SHA-256 `6feb626222f94eacbdb32a295b91a20e76bbeefd29dcfe1a0250079bf4651542`）。三份均 create-new 0600/single-link/canonical re-encode，三个隔离根、process 与 mount 均消失。
- Restart v4 首轮 closure 实际包含 6 个进程；两次 main/plugin-host/package-owned sidecar identity 分离且第二轮更新。Checkpoint state 只有长度/SHA/token fingerprint，pre-unlock 连续两秒全 view 无 client/session/vault/marker/known-content/token-window，随后 183-byte saved fingerprint 从同一 EDRY 重开一致并正常关闭。该结果只覆盖 Linux x64、Build 4200、同一隔离 profile/package 的单一路径，不能升级为真实用户 Hot Exit/history/sync、其他 kill variant、其他平台或发布批准。
- 独立终审结论为 0 blocker/0 major/0 minor：重新运行 strict release audit 后与三报告 embedded audit 完全相等，四 real artifact、canonical manifests、全部 materialized members、工具 seals、clean source/origin/fsck 均一致；32 项 schema/closure/count/profile/environment/sidecar/process/canary/helper/state/mount/checkpoint/final-scan mutation 全被 current validator 拒绝，两份 v2 baseline 继续接受。六个记录 PID、三个隔离根与 mount 均已消失。

## 2026-07-13 — Git v5 immutable bundle prerequisites

- v4 receipt gap 的根因已定位为 candidate create→initial receipt、Git mutation→final receipt 与 partial stable receipt 三个窗口；没有持久最终 digest/完整 payload 时，recovery 不能把 torn Inex state 与 foreign bytes 安全区分。v5 选择在非 active scratch 内完成 candidate、final digest、完整 transaction 与 exact inventory，再以一次 verified no-replace directory move 发布 immutable stable bundle；exact partial scratch 只计数/保留且不阻塞。
- `4322612`/`ec6272b` 从 import 专用目录发布中抽出跨平台 verified no-replace primitive：Linux 使用 held-parent `renameat2(RENAME_NOREPLACE)`，Windows 使用无 replace/copy flag 的 `MoveFileExW(WRITE_THROUGH)`；callback 固定接收 caller path，内部仍复验 canonical physical identity，公共 API 明确要求上层 mutation guard 且不是 OS directory-identity CAS。Core 160/160、CLI 全套、workspace Clippy 与 Windows GNU/Wine targeted 7/7 通过。
- `8d298c4`/`d77b242`/`9febba5` 定义 strict v5 canonical manifest、`manifest-v5.json`+`candidate.index` exact inventory、old-v4-visible stable name、exact scratch status 与兼容 `has_pending_recovery`。Linux `inex-git` 78/78、Windows GNU/Wine targeted 11/11 通过。类型名和 rustdoc 明确 inventory-only：真实 stage-zero map、live expected-old 和 transaction Git semantics 仍必须由后续 writer/recovery 在任何 mutation 前验证；production 目前继续写 v4。

## 2026-07-13 — Git v5 production integration continuation

- 重新完整读取 `planning-with-files`、根计划/进度/发现文件并执行 session catch-up；无未同步报告。当前 clean `master` 为 `ed51c59`，领先 `origin/master` 72 个提交，继续按独立可回滚 checkpoint 推进且不擅自推送。
- 复核 `.agent/init_plan.md`：上位计划要求密文 Git merge、冲突恢复与端到端崩溃恢复验证；v5 marker/journal/index 状态机是为闭合现有 v4 receipt-gap 而细化的安全实现，不缩减原始交付范围。
- 当前关键路径冻结为五步：严格 v5 reference schema、sealed bundle 语义加载、真实 `.git/index.lock` 消费与 worktree/index 前滚、恢复/精确清理、SHA-1/SHA-256 与 force-kill 矩阵。已并行启动现有 v4 调用图和 v5 状态机的两路只读审计；主线程同步核对代码与测试缝。
- 初步调用图确认 v4 的 prepare/write/publish/recover 已分成可替换边界，v5 模块也已包含 manifest reference 与 held inventory seal；后续优先扩展 strict journal dispatch 和只读 loader，不直接重写三个 merge plan 的语义代码。
- 完整阅读 v5 schema/inventory/preparation：stable bundle 的唯一完整 transaction 已在 manifest 内，outer marker/journal 可安全收敛为 digest reference；fresh recovery 需要重开 inventory seal，当前调用内则可延续发布前句柄身份。下一实现会把 Git 语义 loader 与 namespace mutation 明确分层。
- 对照 v4 物理顺序后确认 v5 可消除 receipt 窗：stable bundle 在真实 lock 前已是完整、一次发布的 durable receipt；marker 前后的任何恢复都可重新加载同一 manifest。实现还需增加独立 publish staging 副本，stable bundle 始终保持 exact two-member immutable inventory。
- 阅读 v4 commit/recovery/journal 后形成的早期 cleanup 顺序已被后续 reference-only 审计取代：不能先残缺化 bundle 再依赖 journal。当前冻结顺序是 final 后完整 stable→cleanup 原子退休、在完整 cleanup 上删 journal、最后清 cleanup 成员。
- 发现一个必须显式接线的生产分派点：`Git::update_index*` 目前仅识别 v4 `Cas` journal；v5 journal若只加入 parser 而不扩展该分派，会绕过物理 publisher。该点已列入实现与回归测试。
- 现有真实 Git fixture 和 fault hook 足够支撑下一切片，无需引入 mock-only状态机。先实现 strict schema/loader并用 SHA-1/SHA-256验证，再扩展消费侧 checkpoint；保持 preparation 测试原样作为 immutable boundary 回归。
- 第一实现切片已落地：新增 token 唯一派生的 stable/publish namespace reference、canonical `INEXIDX5\0` + strict JSON marker codec、marker bytes reference，以及 fresh-guard stable bundle Git 语义 loader；cleanup namespace 仅完成状态机设计，尚未提前暴露未使用 helper。定向 `v5_` 测试 19/19 通过，包含真实 SHA-1/SHA-256 stage map、reference tamper 和 external live-index drift；尚未提交或接入 production journal/writer。
- 首轮 inex-git all-target Clippy 在测试通过后正确拒绝 20 个 non-test dead-code 项；不是行为失败。修正方向是不做模块级放宽：让 production preparation 返回 reference/marker seals，移除尚未实现 cleanup 所需的过早 helper，仅对下一切片即将消费的 marker parser 与 fresh loader保留窄理由。
- 一次 cleanup-helper 测试补丁因 rustfmt 已把两个绑定压成单行而在写入前拒绝；检查当前块后改用精确上下文，不重复原补丁。
- 收敛 dead-code 后完整 `inex-git` 92/92、all-target/all-feature pedantic Clippy、fmt 与 `git diff --check` 通过；Windows GNU all-target check、pedantic Clippy和 test no-run link 也全部通过。Reference/marker/loader 切片仍待独立差异审查后再提交。
- Reference/marker/loader 独立审查为 GO（0 blocker/0 major/0 minor），另复验 canonical marker 与 fresh loader。两个 Rust 文件单独提交为 `b3671b6`（`feat: bind Git v5 transaction references`）；planning 仍留待本轮状态机推进后独立提交。
- 新增 strict `BundleMergeJournalV5`：stable 文件仍复用既有 journal pathname，但 version 5 只嵌 transaction reference 与从同一 reference 重建的 marker bytes size/SHA；v1-v4 parser 分支不变。Matching stable+journal 可被 locked-safe status 接受，跨 object-format/reference、duplicate/unknown/trailing JSON 全部拒绝；在 publisher 接线前 `recover` 与真实 `update_index*` 显式 fail closed。定向 2/2 与 inex-git Clippy/fmt/diff 通过。
- 独立 schema 审查在提交前发现 1 个 major：matching v5 stable+journal 分支未拒绝额外 reserved v4 state。当前无写入风险但 locked-safe 分类不严格；修复将本切片允许集合收窄为仅 stable+journal，并补 foreign marker-staging 共存负测。
- Major 修复后又消除 status 对同一 journal 的双重读取，`pending/matching_v5` 由单次 parse共同产生；补齐 `update_index_rename` hard-stop 与 marker-size mutation。最终独立复核 GO（0 blocker/0 major/0 minor），完整 `inex-git` 94/94、native Clippy/fmt/diff、Windows GNU check/clippy/no-run 全绿。
- Strict v5 journal 与过渡期 hard-stop 单独提交为 `89f91e9`（`feat: define Git v5 recovery journal`）。下一步已拆为并行边界：独立 worktree实现 sealed candidate→publish staging；主线程冻结真实 marker lock、journal publication和 prejournal recovery，production writer继续保持 v4直至 recovery先闭合。
- Goal continuation 再次核对根计划、进度、发现、session catch-up 与 Git 实态：catch-up 无未同步报告，clean `master` 为 `af40b5d`、领先 `origin/master` 75 个提交。当前执行顺序保持 recovery-first：先审查/合入 publish staging，再以手工物化持久状态证明 fresh recovery，之后才允许 production writer 切换；并行实现仍在独立 worktree，尚未计入主线完成度。
- Publish-staging 独立 worktree 已完成主体第一版但尚未提交：held publish proof、token-derived namespace、随机 0600 retained scratch copy+sync、size/SHA/single-link/stage-map 双遍验证、临界/发布后 guard+reserved namespace+stable bundle+live-old 复验，以及 verified no-replace move/双 parent durability；明确不触碰 index lock、journal、worktree。当前正在修正编译并补 SHA-1/SHA-256 与 partial/foreign/wrongcase/link/hardlink/rebind/live-drift 回归，未通过门禁前不合入主线。
- 另一路只读 lock classifier 已形成未提交初稿：transaction-specific `Absent/Marker/Candidate/Foreign`，strict v5 marker parse/reference 比对，candidate 只绑定 manifest final size/SHA，并把 stage-map/live-old/worktree授权明确留给上层；link/reparse/hardlink与读取中 identity改变均冲突且不删除。它与 publish-staging 同时触及 `candidate_bundle_v5.rs`，合入时必须逐段组合并重跑全门禁，不能假设两次 cherry-pick 无冲突。
- Lock classifier 已提交为独立 commit `2bb9995`：真实 SHA-1/SHA-256、ordinary/wrong-transaction foreign lock、partial/noncanonical/tampered marker、candidate tamper、hardlink/directory/symlink覆盖；`inex-git` 97/97，native pedantic Clippy、Windows GNU check/clippy/no-run、fmt/diff均通过。主线程源码审查未发现阻断项，现等待第二独立审查后再 cherry-pick；production/recovery status仍未改变。
- Publish-staging `0be3fab` 已合入主线为 `b34c507`，包含 crash 后重新打开 stable/publish 两组 held proofs 的 fresh loader；lock classifier 经独立审查 GO（0 blocker/0 major/1 coverage minor）后合入为 `47c6567`。共享 import 冲突已按语义组合；主线程又补 empty/oversize foreign lock和读取中 namespace identity swap 回归，5/5 定向测试与 pedantic Clippy通过，正在跑合并后的完整/Windows门禁。
- 合并后完整 `inex-git` 109/109、native all-target/all-feature pedantic Clippy、fmt、diff check全部通过；Windows GNU all-target/all-feature check、pedantic Clippy与 test no-run link通过。第一次 Windows Clippy仅发现 Unix-only测试 helper 未被 cfg 同步裁剪，改为 `cfg(all(test, unix))` 后闭合；该结果不冒充原生 NTFS/ReFS runtime证据。
- 在继续审计 next-slice API 时发现 `origin/master` 于 05:32:31 被并发主体 push 到 `47c6567`；本线程未执行 push，已通知两个活动代理确认来源并重申禁止 push。当前 `HEAD=ea40261` 完整保留且只领先远端 1，不做回退/改写/再次推送；planning与下一状态机继续仅在本地推进。
- 三 payload journal前授权只读审计已完成：冻结 `authenticate -> original-state/owners/provenance/worktree -> required parent sync -> attributes -> original-state` 两遍策略，并识别 InPlace全 stage auth与 Split-Ours source-parent sync两个不能沿用旧弱点的边界。主线程已抽取 legacy in-place认证并实现尚未接线的三分支只读授权 seam；SHA-1/SHA-256 InPlace、Detected/Split原态和 worktree/stage-auth漂移定向测试通过。
- Marker-lock 代理虽创建了独立 worktree，但相对 `apply_patch` 意外落到共享主 worktree并覆盖 candidate/planning；已立即中断。使用 committed `91153b9` 内容经 `apply_patch` 精确恢复 candidate与三 planning文件，并保留主线程自己的 `lib.rs` authorization差异；无 `git restore/reset/checkout`、无用户改动丢失。Prejournal代理确认始终使用绝对 worktree路径。
- Payload authorization 单独提交为 `858274b`：legacy InPlace recovery认证段抽取后保持原恢复语义；v5 seam额外认证 InPlace全部 present stages，并对三 variant执行 original index/worktree、owners、attributes与 active/tree provenance两遍检查，Detected/Split absent source补 parent sync。完整 `inex-git` 112/112、native pedantic Clippy/fmt/diff、Windows GNU check/clippy/no-run通过；尚待并发槽释放后的独立差异审查，production仍未接线。
- Pre-journal classifier `32b1ef3` 合入主线为 `eec3ea4`：四阶段 stable-only/publish-ready/marker-no-journal/journal-ready、single-read journal分派、journal-aware fresh loader与 exact reserved namespace已接 `recovery_status`，legacy/production hard-stop保持。主线程预审发现 lock只分类一次的并发混合快照风险，补前后 strict lock分类与确定性 absent/marker→foreign fault回归为 `14ce39d`；合并后 `inex-git` 116/116、native/Windows GNU全部门禁通过。
- Payload authorization首轮独立审查为 NO-GO（0 blocker/1 major coverage/1 minor error classification），实现本身未发现安全写入。`6d16b72` 已补 SHA-256 Split/Detected、三variant相关index、rename四种worktree、attributes、active/tree provenance、duplicate owner、wrong guard与失败不变性矩阵，并固定 root binding/provenance错误；完整 `inex-git` 121/121、native与Windows GNU门禁通过，等待复审。
- Marker-lock 实现已在纠正后的绝对独立 worktree提交为 `6128f1d`，仅 candidate module+tests，targeted 7/7、完整116/116及native/Windows GNU门禁通过；其子代理正在对固定 commit做最终审查，主线尚未合入。
- Marker-lock 固定提交独立终审为 GO（0 blocker/0 major/0 minor/0 nit），合入主线为 `1abc1b1`：随机 retained scratch、0600/single-link/held identity、critical audit、verified no-replace move、双 parent durability、moved/not-moved/foreign/ambiguous reconciliation，以及“active marker 可见后绝不自动删除”均已闭合。第一次合入后定向命令误用不存在的 filter 而运行 0 tests，立即以正确 `v5_marker_lock` 重跑为 7/7。
- Payload authorization 对 `6d16b72` 的独立复审翻转为 GO（0 blocker/0 major/0 minor）；产品主线 checkpoint `1abc1b1` 的组合门禁为 `inex-git` 128/128、fmt、native all-target/all-feature pedantic Clippy、`git diff --check`，Windows GNU all-target/all-feature check、pedantic Clippy与 test no-run link全部通过。该 checkpoint 比并发外部 `origin/master=47c6567` 领先 11；未执行 push，下一切片仍是 durable v5 journal，production writer继续 hard-stop。
- Durable-journal 与后续 forward-recovery 两路只读审计完成：前者将 fresh held marker loader列为 journal强杀恢复前置，后者冻结 journal-ready/worktree-prefix/candidate-lock/exact-final/later-unrelated 状态机，并发现旧 cleanup 顺序在只剩空目录时缺 ownership proof。已决定采用 journal→cleanup receipt原子退休，receipt最后删除；当前独立worktree正在实现仅到 `JournalReady` 的 recovery-first增量，不提前解除 worktree/index/production hard-stop。
- Durable-journal 固定 diff经独立复审 GO（0 blocker/0 major/0 minor），独立提交 `8d069b3` 合入主线为 `de150ef`。实现补 fresh held marker及journal-aware post-audit，让 `recover_pending` 从 StableOnly/PublishReady/fresh MarkerNoJournal推进至JournalReady；journal使用随机0600 single-link retained scratch、双payload authorization、verified no-replace与moved/not-moved/foreign协调，任何失败保留marker且不误报 recovered。主线组合 `inex-git` 134/134（并行119.14s）、fmt、native pedantic Clippy、diff-check，以及Windows GNU check/Clippy/no-run全部通过；worktree/live index/cleanup/production writer仍保持hard-stop。
- Goal continuation核对 clean `master=fec3d4f`、领先外部 `origin/master=47c6567` 15个提交，且session catch-up无未同步报告。并行分支继续局限于独立worktree；未push。Core verified-remove经独立GO审查（0 blocker/0 major/2已修minor）形成`a6b0c33`并合入主线为`6566b62`：文件删除消费Windows句柄后以opaque identity对账，空目录删除绑定parent/directory identity与empty inventory，foreign/parent rebind fail closed且真实父目录sync。Native core 170/170、all-target/all-feature pedantic Clippy、rustdoc、fmt/diff，以及Windows GNU check/Clippy/no-run全部通过。
- 主线程审查post-journal初稿识别两个不得合入的边界：`try_clone`保留source/destination原句柄跨`MoveFileExW`会阻塞Windows replace；Detected/Split的old-index verifier仍错误依赖实时`MERGE_HEAD`。已将实现方向固定为opaque filesystem identity后关闭目标句柄，并要求post-journal只认证manifest记录的commit/tree provenance；代理正在补inactive-ref、critical fault/rebind、worktree-prefix与later-unrelated矩阵，临时形态不允许提交。
