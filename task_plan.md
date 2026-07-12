# Inex 跨平台加密日记系统开发计划

## Goal

按照 `.agent/init_plan.md` 的架构与安全边界，交付可在 Windows/Linux 使用的 Rust 加密核心与本地 sidecar、VS Code/Sublime 客户端、Git/迁移工具及验证完备的可安装 MVP，使 Markdown 明文只在编辑器与受控进程内存中出现，磁盘仓库始终保存密文。

## Current Phase

Phase 7 — 跨平台验证、打包与发布准备

## Scope and Acceptance Baseline

- 真实 Git 仓库只保存 `vault.json`、目录元数据与 `*.md.enc` 密文，不创建临时明文 Markdown 文件。
- 口令经 Argon2id 派生 KEK；随机 256-bit master key 被 KEK 包裹；文件使用派生子密钥与 XChaCha20-Poly1305 AEAD。
- 支持创建/解锁/锁定 vault、文件读写、树浏览、内存搜索、换密码、导入与密文 Git 合并。
- `inexd` 提供语言无关的本地 JSON-RPC 接口；VS Code 为主客户端，Sublime 为命令式轻量客户端。
- VS Code 通过真实 `*.md.enc` 上的 CustomEditorProvider 提供目录树、编辑、受控链接/引用、扩展内安全搜索与加密 draft backup。
- Sublime 以 experimental 模式支持 Quick Panel、scratch buffer、自管 dirty/加密 draft 与安全设置 hard gate，不承诺原生虚拟文件系统体验。
- 核心测试覆盖错误口令、格式/AAD 篡改、Unicode 往返、换密码不重写正文、路径约束、会话与 RPC；CI 至少覆盖 Linux/Windows 构建与打包路径。
- 不覆盖管理员/内核恶意软件、内存取证、swap/hibernation、崩溃转储、录屏或键盘记录等高级攻击。

## Phases

### Phase 1: 需求、格式与工程基线冻结

- [x] 从 `init_plan.md` 提取不可变需求、MVP/后续边界与验收矩阵
- [x] 核实现有 Rust/Node/Python/Git 工具链与跨平台约束
- [x] 冻结 workspace/component layout、产品命名、JSON-RPC v1 与 EDRY/vault v1 格式规范
- [x] 建立 Rust/TypeScript/Python 工程骨架、统一质量门与最小文档
- **Status:** complete

### Phase 2: Rust 密码学核心与 vault 生命周期

- [x] 实现 master key、Argon2id KEK、key slot、换密码与敏感内存生命周期
- [x] 实现 canonical EDRY v1 header、文件子密钥、XChaCha20-Poly1305 读写与原子替换
- [x] 实现严格逻辑路径解析、树列表、rename/delete 与内存全文搜索
- [x] 添加单元、篡改、属性与兼容性测试向量
- **Status:** complete

### Phase 3: `inexd`、CLI 与本地协议

- [x] 实现 stdio JSON-RPC 2.0 server、结构化错误与无秘密日志策略
- [x] 实现 session token、空闲锁定、缓存淘汰、并发/etag 冲突与 shutdown 清理
- [x] 实现 `inex` CLI 的 init/import/verify/password/search/serve 命令
- [x] 添加协议契约测试与端到端进程测试
- **Status:** complete

### Phase 4: VS Code 主客户端

- [x] 实现 sidecar 生命周期、密码输入、vault unlock/lock 与状态展示
- [x] 实现 Tree View、真实 `*.md.enc` CustomEditorProvider 与加密 draft backup；不暴露 plaintext TextDocument
- [x] 在受控编辑器内实现 Markdown link/heading/backlink、内存搜索结果面板与定位
- [x] 实现 create/mkdir/etag-conditional rename/delete，并在 custom-editor 关闭或 RPC 失败时认证对账与恢复
- [x] 使用真实 Extension Host 黑盒验证 encrypted backup/recovery 并扫描 isolated profile；持久 profile/Local History/crash 矩阵留作 Phase 7 发布门禁
- [x] 添加 lint、类型检查、单元测试与 Extension Host 集成测试基础
- **Status:** complete

### Phase 5: Sublime 轻量客户端

- [x] 实现 sidecar 客户端、vault 解锁与 Quick Panel 树浏览
- [x] 实现 scratch Markdown buffer、自管 dirty/版本、加密 draft debounce 与安全写回
- [x] 拦截可拦截的 save/close 命令，并在全局 hot_exit/recent-files gate 不满足时拒绝可写模式
- [x] 实现搜索、跳转与 plugin-host/应用退出失败安全降级
- [x] 添加 61 项 Python 测试与独立 data-dir Build 4200 canary/CRUD/宿主崩溃边界矩阵；记录 Safe Mode 不加载第三方包的限制
- **Status:** complete（experimental；宿主崩溃后需重启 Sublime 的平台边界不宣称已消除）

### Phase 6: Git 合并、迁移与恢复工具

- [x] 实现 `.gitattributes`、locked-safe `inex merge-driver` 与已解锁 CLI 三方合并
- [x] 实现加密冲突状态、普通编辑器保存清旗与 journal 恢复流程
- [x] 实现 plaintext copy-import/dry-run、校验报告，并明确拒绝破坏性 in-place 转换
- [x] 实现 vault verify/pending recovery 报告与恢复说明，确保失败不破坏源数据
- **Status:** complete

### Phase 7: 跨平台验证、打包与发布准备

- [ ] 跑通格式、性质、RPC、编辑器、Git、Unicode/长路径/换行的验证矩阵
- [x] 闭合 binding Git rename/modify 源码契约：detected 形态、split 两侧 rename、精确 tree provenance、v2/v3 journal 与恢复负测均通过
- [ ] 在原生支持平台复验 Git rename/power-loss，并在 GA 前保留“禁止并行 Git porcelain”边界或实现真正的 index CAS
  - [x] 实现 alternate-index candidate、Inex 自持真实 `.git/index.lock`、old/candidate digest 绑定与 create-only journal v4
  - [x] 用真实临时 Git 仓库覆盖 foreign lock、并行 porcelain、marker/candidate/published crash states 与 SHA-1/SHA-256
  - [ ] 原生 Windows NTFS/ReFS 复验 replace/write-through/power-loss，并由绑定证据决定是否取消 no-parallel-Git 边界
- [x] 配置 Linux/Windows x64/arm64 CI、Rust 二进制、VSIX 与 Sublime 包产物；远端 hosted jobs 尚待执行
- [x] 完成 threat model、用户指南、安全配置、迁移/升级与故障恢复文档
- [ ] 审计磁盘明文残留、日志秘密、依赖许可与发布清单
  - [x] 将 target-bound Cargo graph、固定四 workspace member、精确许可策略/checksum、许可文本摘要与 libsodium 声明绑定到严格 `THIRD_PARTY_LICENSES.json`
  - [x] 严格验证三包共享 inventory/sidecar，并为 package/lifecycle evidence 定义 canonical report v1 与动态秘密自扫描
  - [ ] 从新 clean HEAD 重建 Linux x64 三包，复验 audit/smoke/lifecycle 并另做 RPC/CLI/Git 负路径秘密 drill
  - [ ] 在所有原生目标重复许可/残留证据并完成独立法务、签名与发布渠道审查
- [x] 在最终 clean commit 上用 system GCC 完成两次逐字节一致的 Linux x64 package/audit/native-dependency/VSIX-install smoke
- [x] 从独立 standalone clean clone 对最终 Linux x64 artifact 完成 import/password/Git-bundle/tree-copy restore/frozen-v1/residue lifecycle drill
- **Status:** in_progress

## Key Questions

1. 在严格遵守 init plan 的同时，哪套 Rust libsodium 绑定能提供可维护的 XChaCha20-Poly1305、Argon2id、KDF 与 secure-memory 能力？
2. EDRY v1 哪些 header 字段必须纳入 canonical AAD，如何兼顾 etag、rename 与未来格式演进？
3. MVP 采用单进程 stdio sidecar 时，两个编辑器的会话隔离、生命周期和异常退出清理如何保持一致？
4. VS Code/Sublime 哪些编辑器行为无法由插件完全禁止，需要明确检测、警告或文档化？
5. 如何让 merge/import 失败保持源密文和源明文不变，并提供机器可验证的结果？

## Decisions Made

| Decision | Rationale |
|----------|-----------|
| 采用单一 Rust workspace + 独立编辑器客户端 | 与 init plan 的“一个引擎、两个客户端”一致，核心安全逻辑只实现一次 |
| 正式运行时以 Rust sidecar 为唯一主路径 | 可被 TypeScript/Python 共用，并隔离高成本 KDF、索引和敏感缓存 |
| MVP 首先实现 Content-Length framed stdio JSON-RPC，协议预留 socket transport | 最快形成可测试的跨平台契约，同时避免 NDJSON 边界歧义并不阻碍后续 Unix socket/named pipe |
| 规划文件放在仓库根目录 | 仓库已有明确 workspace，符合 planning-with-files 约定 |
| EDRY 正文绑定 master-key epoch，不绑定 password key slot | 支持添加/删除 slot 和换密码而不重写正文；每个 slot 自带 KDF/wrap 参数 |
| logical path 纳入 EDRY canonical header/AAD | 防止合法密文被静默换位；rename 必须安全地解密重加密 |
| Git merge 无解锁通道时必须保持 `%A` 不变并报告冲突 | 独立 stdio sidecar 的 session 不能被内建 Git 安全复用，保底路径不得损坏密文 |
| 外部名称统一为 Inex、`inex` CLI、`inexd` daemon、`inex.markdownEditor` 与 `merge=inex`；仅磁盘 magic 保留 `EDRY` | 消除研究报告里的 diaryd/diary/ediary 占位命名，避免协议、打包与 Git driver 混用 |
| VS Code 写入走 CustomEditorProvider 与扩展控制的加密 backup | 普通 modified working copy 会被 VS Code backup tracker 持久化，`files.hotExit=off` 不能阻止该调度 |
| Sublime 严格模式使用 scratch buffer、自管 dirty 与持续加密 draft | pre-save/pre-close 不能 veto，API 也不能在自定义保存后清原生 dirty；非 scratch 方案不可安全接管 |
| Sublime Build 4200 客户端保持 experimental | 宿主 SIGKILL 后官方恢复方式是重启整个 Sublime；实测缓冲区仍可复制，插件无法在死亡窗口运行，故只承诺应用退出后的零磁盘残留，不宣称崩溃瞬时擦除 |
| v1 只承诺目录创建与 Markdown 文件 rename/delete | 目录 rename 会重绑整个子树的 authenticated logical path，需要独立的多文件 crash transaction；在该事务存在前显式 deferred，不用非原子循环伪装支持 |
| 发布包采用严格 allowlist、可移植 ZIP key、内部 manifest 与原生依赖审计 | 产物必须拒绝特殊文件、Windows 路径/权限碰撞、伪 VSIX/PE、脏 provenance 和动态 libsodium；独立发布工具代码审计方可进入 clean-source 构建 |
| Git rename 只由唯一 merge-base 与固定 HEAD/MERGE_HEAD tree entry 证明 | 新 nonce 让密文相似度无意义，file-id 相同也可能是历史副本；detected/split 都必须绑定完整 provenance 与 source-aware journal |
| Git OID 宽度绑定仓库 object format，恢复按 v1/v2/v3 严格 schema | SHA-256 Git 会把 40 位唯一前缀交给 `cat-file` 解析；journal 必须在任何变更前拒绝缩写/混宽 OID，并固定可跨 merge commit 验证的 provenance |
| Binding release 只在独立、独占、静止 checkout 与可信不变工具链上形成 | 首尾 blob/config/identity 复核是有界采样而非 OS 锁；同主体并发写者可在样本间改写并恢复，manifest source identity 也不等于生成物 build attestation |
| 新 Git merge 事务使用 v4 物理 index CAS，旧 v1/v2/v3 仅作恢复兼容 | Git porcelain 无 expected-old CAS；只有 alternate candidate + 真实 `index.lock` + old/candidate digest 才能把最后语义校验、worktree 前滚和 index 发布收缩为一个 fail-closed 事务 |
| verified-file namespace move 保持协作式同用户边界 | Linux/Windows 的最终 rename/MoveFileEx 都是路径操作；句柄身份重验和真实 Git lock 可排斥正常 writer，但不能构成抵抗同一 OS 用户直接 rebind 路径的内核级 handle-bound CAS |

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| `cargo fmt --check` reported trailing blank lines in four new Rust source files | 1 | Run canonical `cargo fmt --all`, then rerun the full quality gate |
| Combined PRD/architecture patch did not match the exact save-step text | 1 | Patch the two files separately after reading their current sections; no partial edit was applied |
| EDRY fixed-header golden test timestamp bytes did not match the fixture header timestamp | 1 | Independently verified decimal/big-endian bytes, corrected the hand-authored vector, and passed all 44 core tests |
| Combined error-log/rustdoc patch missed rustfmt-wrapped function context | 1 | No partial changes; split planning and source patches after reading exact current lines |
| `vault_config` public Result APIs failed pedantic clippy due to missing `# Errors` docs | 1 | Added precise failure contracts; pedantic clippy and warnings-as-errors rustdoc pass |
| `cargo fmt` could not parse a non-ASCII Rust byte-string test literal | 1 | Use an ordinary UTF-8 string and `.as_bytes()`, then rerun fmt/tests |
| Combined clippy-log/source patch missed the rustfmt-compressed assertion | 1 | No partial change; inspect and patch the exact assertion separately |
| Crypto test used redundant `matches!(..., Ok(_))` under pedantic clippy | 1 | Replace with `.is_ok()` and rerun full core quality gate |
| Atomic streaming hash used a 64 KiB stack buffer and failed pedantic `large_stack_arrays` | 1 | Reduce the bounded streaming buffer to 16 KiB; rerun Rust 1.97/MSRV/Windows checks, tests, clippy and rustdoc |
| Interrupted-session RPC framing checkpoint failed 2/15 tests: `Interrupted` was surfaced and one malformed-header expectation disagreed with parser classification | 1 | Inspect the landed parser/test contract, retry interrupted reads, and make malformed-vs-truncated classification deterministic before accepting the module |
| RPC framing passed all tests but pedantic clippy rejected a manual `Option` match | 1 | Replace it with `let...else` and rerun the entire daemon gate |
| Security review found that a 255-byte logical filename becomes 259 bytes after `.enc`, exceeding common component limits | 1 | Reserve the four-byte physical suffix in the final-component bound and add exact boundary tests |
| Security review found serde UUID parsing accepts noncanonical uppercase/simple/braced/URN forms forbidden by vault-v1 | 1 | Add a canonical lowercase-hyphenated UUID serde adapter for vault and slot identifiers with negative tests |
| Security review found core password validation accepted invalid UTF-8 although vault-v1 defines exact UTF-8 bytes | 1 | Reject invalid UTF-8 without normalization/trimming and add a negative test |
| Repository integration exposed a lock-composition gap for collision check/write, conditional delete, rebind, and password transactions | 1 | Add `VaultMutationGuard`, verified staging, conditional delete, and journaled crash-recoverable rebind primitives; then exercise fault/race recovery tests |
| Declared Rust 1.88 MSRV failed the frozen Unicode 17 path/case-fold compile-time gate | 1 | Raise the supported/CI MSRV to the already pinned Rust 1.97 toolchain; keep compile-time Unicode 17 assertions so future table drift requires an explicit format decision |
| Core 110/110 tests passed, then clippy rejected the platform metadata hasher's unnecessary `Result` wrapper | 1 | Make metadata hashing infallible on every cfg branch and rerun the complete Phase 2 gate |
| Phase 2 full gate stopped at rustfmt differences in newly added differential search tests | 1 | Run canonical workspace formatting, then restart the gate from fmt rather than treating later checks as executed |
| Core 111/111 passed but differential-corpus LCG used two potentially truncating `u64 as usize` casts under 32-bit clippy rules | 1 | Reduce modulo an explicitly converted alphabet length, then use checked `usize::try_from` and rerun the full gate |
| Phase 2 portability hardening left rustfmt differences in Linux mount parsing and tree path-budget code | 1 | Record the failed gate, run canonical workspace formatting, then restart compilation and all quality checks |
| Windows GNU core cross-check compiled, but test linking failed in bundled libsodium with unresolved `memset_explicit` and `SystemFunction036` | 2 | The volatile compatibility shim resolved `memset_explicit`; `advapi32` was emitted before the static archive, so move the system-library directive to a package build script/late link position and rerun no-run linking |
| Wine executed 106 Windows core tests; 105 passed and wrong-case `vault.json` rejection failed because case-only rename/equality behavior differs on a case-insensitive Win32 view | 1 | Make exact on-disk component spelling checks use directory-enumeration UTF-16 ordinal equality rather than path lookup semantics, then rerun Wine and retain real NTFS CI as the binding gate |
| Durable namespace-move refactor compiled but left the old `sync_parent` wrapper unused | 1 | Remove the obsolete wrapper, keep `sync_directory` only for structural-directory best effort, and require a warning-free gate |
| Combined Windows path-helper/test patch missed rustfmt-shifted nested-module context | 1 | No partial edit applied; inspect the exact module/test locations and add helper tests and long-path mutation coverage in separate patches |
| Core 118/118 and rustdoc passed, but final clippy rejected Linux-only `filesystem_device`'s uniform `Option` return and a manual test `match` | 1 | Keep the cfg-uniform mount API with a narrowly documented lint allowance and use `let...else`, then rerun the complete gate |
| Native clippy passed, while Windows cross-clippy rejected the cfg-uniform no-op `MountBoundary::contains` receiver | 1 | Add a targeted allowance documenting the shared cross-platform method shape, then rerun Windows clippy/link/tests |
| Draft alias regression patch missed the current encrypted-draft test tail | 1 | No partial test edit applied; inspect the exact test boundary and insert the independent regression before the next test |
| Phase 3 integration gate stopped at rustfmt drift in the new sensitive-JSON test | 1 | Record the failed gate, apply canonical workspace formatting, then restart daemon tests/clippy/rustdoc from the beginning |
| Restarted daemon gate compiled the integrated module but the optional zeroizing-string assertion compared `Option<&String>` with `Option<&str>` | 1 | Use an explicit `as_ref().map(...as_str())` comparison and restart the complete daemon gate |
| Integrated daemon tests passed 25/25, then pedantic clippy rejected owned encoded input as `needless_pass_by_value` | 1 | Keep ownership so caller copies are wiped on every return, explicitly consume the zeroizing owner after canonical validation, and restart the complete gate |
| First handler integration compile found one `Zeroizing<String>` deref mismatch, an unused timeout import, and an uncovered `PlaintextTooLarge` error variant | 1 | Record the failed compile, compare through `as_ref().as_str()`, remove the unused import, map the size variant to `LIMIT_EXCEEDED`, then restart daemon tests |
| Handler restart stopped at canonical rustfmt differences after the compile fix | 1 | Apply workspace rustfmt, then restart compilation/tests rather than treating them as executed |
| Handler 48/48 tests passed, then pedantic clippy found mechanical ownership/match-style issues and one long lifecycle test | 1 | Merge identical error arms, borrow non-consumed wrappers/errors, collapse the nested condition, make the test helper consume its value explicitly, and narrowly document the intentional end-to-end test length |
| Handler audit regression additions introduced two rustfmt-only differences | 1 | Record the gate stop, run canonical workspace formatting, and restart daemon tests/clippy/rustdoc |
| Audit-hardened daemon passed 57/57 tests, then clippy found identical fail-closed branches for terminal and pre-hello states | 1 | Combine the two predicates into one unavailable-state guard and rerun the complete daemon gate |
| Process E2E passed, then clippy rejected its single 108-line lifecycle scenario | 1 | Keep the framed unlock/write/read/search/lock/shutdown flow as one auditable scenario and add a narrow documented test-only allowance |
| First VS Code client typecheck found exact-optional `defaultUri` and readonly tree-array mismatches | 1 | Build dialog options conditionally and return the mutable array shape required by `TreeDataProvider`, then rerun the TypeScript gate |
| Combined VS Code icon/ignore patch missed the current `.vscodeignore` context | 1 | No partial edit was applied; add the icon asset separately after inspecting the existing ignore rules |
| Combined planning update missed the timestamped `progress.md` error-row context | 1 | No partial edit was applied; inspect exact rows and update the planning files with smaller patches |
| VS Code Node strip-only tests rejected a TypeScript constructor parameter property in `sidecar.ts` | 1 | Preserve the callback contract with an explicit class field/assignment, then restart check/test/build |
| Combined VS Code session-epoch patch missed the current controller method context | 1 | No partial edit was applied; inspect the exact controller and land the race fix in smaller patches |
| VS Code post-race-fix gate used a workspace-relative `editors/vscode/src` path from inside that same directory | 1 | Record later gates as not executed, use local `src`, and rerun the complete check/test/build sequence |
| VS Code typecheck found no `CancellationToken.None` API for pre-lock webview synchronization | 1 | Use a scoped `CancellationTokenSource`, dispose it after synchronization, and restart the complete client gate |
| VS Code backup-recovery test seam omitted required `untitledDocumentData` from `CustomDocumentOpenContext` | 1 | Pass explicit `undefined`, then restart check/test/build; the parallel build result is not a complete gate |
| Main-thread Sublime unittest discovery omitted the package directory from `PYTHONPATH` | 1 | Record the invocation error, rerun with `PYTHONPATH=editors/sublime`, and do not classify the import failures as product regressions |
| Main-thread Sublime gate incorrectly passed comment-bearing `.sublime-settings` to strict `json.tool` | 1 | Validate only strict `Main.sublime-commands` as JSON; treat documented Sublime JSON comments as supported settings syntax |
| Final Sublime review found Build 4200 `open_context_url`/macro persistence gaps and an idle-response timestamp drift | 1 | Block the exact browser/macro commands on every hookable path, add regressions, and base initial/renewed deadlines on the worker-thread authenticated response timestamp |
| Sublime macro re-review found fingerprint-equivalent non-list empties and an unsafe `Packages/Default` macro trust prefix | 1 | Require an actual empty list from `get_macro()` and block every `run_macro_file` while managed plaintext exists; no resource namespace is trusted |
| Sublime staged whitespace gate found three new files with an extra blank line at EOF | 1 | Stop before commit, remove only the redundant final blank lines, then rerun tests and the staged gate |
| First Build 4200 E2E probe launched `sublime_text --wait` in the foreground and could not reach its UI-driving steps | 1 | Terminate only the isolated `/tmp` profile processes, relaunch in background, and bound both window discovery and process exit |
| Build 4200 Safe Mode created its profile but intentionally did not hot-load packages injected after startup | 1 | Stop waiting on the watcher; explicitly reload fixed test plugins through the isolated UI, or fall back to a pre-populated ordinary isolated data-dir and document the exact mode |
| Phase 6 audit found late cross-result file-id collision detection and a fixed-size Windows `check-attr` batch | 1 | Preflight the complete conflict result identity set before any write and batch Git argv by encoded byte budget rather than path count |
| The isolated Build 4200 profile loaded Inex but not its QA helper because the helper package lacked `.python-version` | 1 | Pin the test-only helper to Python 3.8 like the product package, then rerun the bounded flow without changing product code |
| Phase 6 durability review found split-index repositories require synchronizing `sharedindex.*`, not only `.git/index` | 1 | Fail closed on split index before merge/recover in v1 and cover the real Git extension with a regression test |
| Real Build 4200 unlock stalled because Python `BufferedReader.read(65536)` waited for a full stdout buffer/EOF before decoding a short RPC frame | 1 | Use a bounded read-once primitive (`read1`/`os.read`) for sidecar pipes and add a real short-frame child-process regression before resuming E2E |
| Phase 6 residual review found configured fsmonitor and partial-clone lazy fetch could execute external helpers during Git plumbing | 1 | Force `core.fsmonitor=false` on every Git subprocess, set `GIT_NO_LAZY_FETCH=1`, and prove a configured helper is never invoked |
| Build 4200 E2E reached unlock/tree UI but sent Enter while Quick Panel still had `selected_index=-1` | 1 | Select the first bounded item with Down before Enter, then rerun from a fresh isolated profile |
| Build 4200 isolated launch exposed both an initial untitled window and the bootstrap window, so generic X11 focus targeted the wrong one | 1 | Bind UI input to the unique bootstrap-title window instead of assuming one Sublime top-level window |
| Real Sublime `document.open` rejected daemon's 22-character document handle because the client reused the 43-character session validator | 1 | Split session/document capability validation by frozen byte length and add a real handler-response regression |
| Build 4200 helper invoked Save/Close through `view.run_command`, but those built-ins dispatch as WindowCommands and silently did nothing | 1 | Drive the exact `window.run_command("save"/"close_file")` path exercised by real menus/keybindings |
| Programmatic generic WindowCommand Save still did not dispatch through Build 4200's interactive command path | 1 | Separate concerns: call Inex's registered save/close commands for the crypto lifecycle smoke, and test native Ctrl+S interception later through X11 input |
| Build 4200 closes a tab while the old Python `View` wrapper can remain `is_valid() == true` | 1 | Define closure by absence of the view id from every live window plus an empty managed registry, not wrapper validity |
| Build 4200 harness could scan/remove its root while reparented plugin-host or crash-handler processes were still exiting | 1 | Track the full isolated process set, terminate and wait for it before residue scan, final PASS, or root deletion |
| Build 4200 crash probe treated empty `xclip` as an exception and then tried to restart a host that the platform requires an application restart to recover | 2 | Probe clipboard/PRIMARY explicitly, classify the reproducible result as `PASS_WITH_DOCUMENTED_BOUNDARY`, recheck for a late replacement host, terminate the whole isolated editor, and require zero root hits |
| First real Sublime CRUD run selected Cancel because the delete Quick Panel already highlighted its first row | 1 | Keep the undeleted ciphertext as failure evidence, select the destructive first row deterministically with Home, and rerun create/mkdir/rename/etag-delete to `crud_complete=true` |
| Sublime draft removal checked only the final file and could follow a symlinked draft directory | 1 | Reject symlink/reparse directories, anchor POSIX stat/unlink to a verified dirfd, recheck fallback directory identity, and prove the redirected target remains untouched |
| Initial release audit found permissive VSIX/ZIP/version/PE checks; follow-up found Win32 names, privileged modes, tag/native gate and provenance bypasses | 2 | Add strict negative tests and workflow bindings until 19/19, actionlint, pedantic/all-features, native audit and independent re-review all return GO |
| Main release-test invocations first omitted `PYTHONPATH=scripts`, then reused zsh's special `path` variable and invalidated PATH | 2 | Treat both chains as invalid evidence, remove generated caches, use fail-fast plus a non-special loop variable, and rerun the complete 19-test/actionlint/Clippy/diff gate |
| Documentation audit found overbroad encryption claims, an incorrect VS Code resource scheme, non-runnable PATH/Python/package examples, and ambiguous support wording | 1 | Align every claim and command with current code, use explicit absolute binaries/Python 3.13.14/build prerequisites, then require an independent zero-blocker/zero-major rereview |
| Rename/modify security audit found detected source omission, historical-copy misclassification, SHA-256 OID-prefix acceptance, and recovery owner-order gaps | 1 | Replace heuristic identity matching with fixed tree provenance, repository-width OIDs, source-aware v2/v3 journals, pre-mutation global owner checks, and adversarial real-Git regressions |
| First provenance-aware CLI detected test had no active `MERGE_HEAD`; intermediate journal validation patch matched the legacy v1 recovery block | 1 each | Form a real no-renames merge before synthesizing detected stages; remove the misplaced v1 field access, add validation to the exact v3 block, and restart tests/Clippy |
| Owner scan initially skipped every other unmerged worktree path | 1 | Compare every non-active conflict worktree digest with its authenticated stage objects so a third identity owner aborts before the first plan writes |
| Final Git audit constructed a conflict path carrying an additional valid stage zero | 1 | Reject stage-zero/unmerged-path intersections from one bounded full-index snapshot, retain local commit/recovery rechecks, and cover a differently identified source-bound EDRY fixture |

| Lifecycle full-snapshot enhancement initially placed restored-repository `git fsck` before `git clone` | 1 | Numbered source inspection caught the ordering error before execution; move `fsck --full` after clone and rerun unit plus real-artifact gates |
| First final-artifact lifecycle drill stopped on a harness-only password sync output mismatch | 1 | Product prints `ParentSyncStatus::Synced`; update the fixed contract and add secret-free stage labels before rerunning from a fresh temporary root |
| Second lifecycle drill treated a persistent `.vault-local/mutation.lock` as a frozen-format rewrite | 1 | Preserve the strict hashes of original `vault.json`/EDRY files, allow only new `.vault-local/` runtime files, and reject every other added path |
| Combined lifecycle hardening patch missed the current function order/context | 1 | No partial edit applied; split environment/RPC/Git/report repairs by exact current function locations and rerun the full drill |
| Provenance-hardened drill rejected Linux `stat` filesystem type `ext2/ext3` | 1 | Retained the synthetic failure root, inspect only the fixed type bytes, allow the standard slash separator, then explicitly remove the test root and rerun |
| Hardened process-tree regression passed but emitted two unclosed-pipe `ResourceWarning` messages | 1 | Close every bounded reader stream at EOF, close RPC stdout on abort, and rerun all 45 release tests with `ResourceWarning=error` |
| Combined source-quality command reached its final step with `actionlint` absent from `PATH` | 1 | Preserve the already-passing Rust results, use the documented pinned `target/tools/actionlint` v1.7.12 directly, then rerun workflow and whitespace checks |
| Independent probes escaped process cleanup with `setsid()` and bypassed artifact preflight by growing an archive before copy | 1 each | Enable Linux subreaper + bounded procfs census + pidfd termination/reaping; replace generic artifact tree copy with an identity-checked, per-file/total-bounded capture and add both attack regressions |
| Final review found source empty directories, end-of-run Git provenance, and post-driver-install refs/objects were not rebound | 1 | Bind source directory manifest and non-canary path scan, re-read `source_revision` at the final boundary, and repeat single-ref/commit/HEAD/unreachable checks after every driver reinstall |
| Untracked-file whitespace probe reused zsh's read-only special variable `status` | 1 | The command stopped without writes; rerun with a neutral `diff_exit_code` variable and preserve the already-passing tracked `git diff --check` result |
| Clean-provenance probe hid changed tracked bytes with `assume-unchanged` while `git status` remained empty | 1 | Reject every non-normal index flag and bind actual bounded regular-file Git blob OIDs to the fixed HEAD tree before reporting `dirtySourceTree=false` |
| Follow-up provenance probes used replace refs, redirected `core.worktree`, executable-mode drift, and oversized Git output | 1 | Sanitize the Git environment/config, reject replacement refs, bind canonical root/gitdir/index plus exact mode/blob tree, and route every Git call through a timeout/output-bounded concurrent reader |
| Expanded provenance regression left its synthetic replace ref active during later assertions | 1 | Assert and delete the replacement immediately after its probe, then rerun all 49 release tests without weakening expected errors |
| Final provenance probes hid case aliases, widened executable semantics, redirected index/worktree/config scopes, and changed effective origin | 1 | Freeze Git case/Unicode/fileMode semantics; require direct standalone `.git`/index; parse an exact local config snapshot; reject includes, worktree config, URL rewrites, duplicate/empty origins; bind owner execute and peeled commit |
| A syntax-only Python invocation omitted `PYTHONDONTWRITEBYTECODE` and created three cache files | 1 | Remove only the command-created `scripts/**/__pycache__` directories, record the invocation mistake, and keep every subsequent gate cache-free |
| Targeted Rust check named a nonexistent inex-cli integration target `git_workflow` | 1 | Keep the already-passing inex-git 31/31 evidence, rerun the actual `git_cli` target, and require its 9/9 result before commit |
| Final Git review found portable prefix, self-hiding ignore, clean-filter execution, split-index and alternate-object gaps | 1 | Reject file/directory portable prefixes, unsafe local config and untracked active ignore files; require direct standalone index/object storage and prove helpers never run |
| First strict local-config allowlist omitted checkout-managed `gc.auto=0` and used POSIX fileMode semantics on Windows | 1 | Permit only exact `gc.auto=0`, branch fileMode by OS, require no EOL conversion, and add the matching package-workflow step/regression |
| Attribute-isolation patch used a non-matching f-string context | 1 | No partial write occurred; patch the exact Git command and environment dictionaries separately, then rerun the provenance test |
| Exact manifest audit did not validate install format or strict JSON parser semantics | 1 | Require exact schemas/install format, strict UTF-8, no duplicate keys and integer schema 1; cover wrong/missing/ambiguous forms and re-audit the real artifact |
| Combined CAS planning-file patch used a non-matching quoted findings context | 1 | No partial write occurred; patch the three planning files against their exact current lines and continue from the clean Git checkpoint |
| Initial full-index check treated empty `git rev-parse --shared-index-path` output as malformed and failed 23 Git tests | 1 | Accept the documented empty output as the normal full-index state, still reject every non-empty shared-index path, and rerun the complete Git suite |
| Wine replace returned `AccessDenied` while the verified destination handle remained open | 1 | Consume and release both verified handles immediately before the path-based replace, document the cooperative same-user boundary, and rerun the Windows GNU/Wine tests |
| A truncated reserved v4 journal staging file could leave an exact pre-journal marker/candidate reservation wedged | 1 | When the stable journal is absent, remove only the exact regular deterministic staging name paired with an authenticated reservation, then clean marker/candidate and add a truncated-staging recovery regression |
| Full workspace Clippy passed product code but rejected two newly extended test functions at 105/100 and 101/100 lines | 1 | Split the parent-ancestor and durability scenarios into focused regression tests, apply canonical rustfmt, and restart the strict Clippy gate |
| A read-only Phase 7 inventory command queried the obsolete `clients/vscode/package.json` path | 1 | The command made no writes; use the repository's actual `editors/vscode/package.json` path and record the inspection miss before implementation |
| First strict-license test run passed 52/53; the duplicate-component fixture correctly failed earlier on its repeated license path than the asserted component-order message | 1 | Keep the earlier fail-closed validation, assert its actual repeated-path error, and rerun the complete release-tool suite |
| Initial exact-libsodium patch assumed the salt constant was derived inline rather than frozen as `16` | 1 | No partial edit occurred; inspect the actual sodium constant/error/version blocks and apply the exact-version patch against current context |

## Notes

- `.agent/init_plan.md` 是产品与架构的上位约束；若实现细节与其冲突，先记录并选择不削弱安全边界的方案。
- 每完成一个阶段立即更新本文件及 `progress.md`；发现和决策持续写入 `findings.md`。
- 所有破坏性迁移默认禁用；任何 in-place 操作必须显式确认并先完成可验证备份。
- Git 作为开发容错边界：已通过门禁的阶段/垂直增量单独提交；未完成或未验证的并行改动不混入稳定提交，不改写已共享历史。
