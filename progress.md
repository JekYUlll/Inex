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

### Phase 4: VS Code 主客户端

- **Status:** pending

### Phase 5: Sublime 轻量客户端

- **Status:** pending

### Phase 6: Git 合并、迁移与恢复工具

- **Status:** pending

### Phase 7: 跨平台验证、打包与发布准备

- **Status:** pending

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

## 5-Question Reboot Check

| Question | Answer |
|----------|--------|
| Where am I? | Phase 3 — `inexd`、CLI 与本地协议 |
| Where am I going? | Rust core → sidecar/CLI → VS Code → Sublime → Git/import → release verification |
| What's the goal? | 交付 init plan 定义的跨平台密文仓库与编辑器虚拟明文系统 |
| What have I learned? | 见 `findings.md`：冻结格式、依赖、编辑器备份风险与失败安全边界 |
| What have I done? | 完成 Phase 1 基线与 Phase 2 Rust crypto/vault 生命周期；开始 sidecar/CLI 协议实现 |
