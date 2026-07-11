# Inex 跨平台加密日记系统开发计划

## Goal

按照 `.agent/init_plan.md` 的架构与安全边界，交付可在 Windows/Linux 使用的 Rust 加密核心与本地 sidecar、VS Code/Sublime 客户端、Git/迁移工具及验证完备的可安装 MVP，使 Markdown 明文只在编辑器与受控进程内存中出现，磁盘仓库始终保存密文。

## Current Phase

Phase 3 — `inexd`、CLI 与本地协议

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
- [ ] 实现 `inex` CLI 的 init/import/verify/password/search/serve 命令
- [x] 添加协议契约测试与端到端进程测试
- **Status:** in_progress

### Phase 4: VS Code 主客户端

- [ ] 实现 sidecar 生命周期、密码输入、vault unlock/lock 与状态展示
- [ ] 实现 Tree View、真实 `*.md.enc` CustomEditorProvider 与加密 draft backup；不暴露 plaintext TextDocument
- [ ] 在受控编辑器内实现 Markdown link/heading/backlink、内存搜索结果面板与定位
- [ ] 黑盒审计 VS Code backup/Local History，并检测相关明文残留风险、提供工作区级安全引导
- [ ] 添加 lint、类型检查、单元测试与 Extension Host 集成测试基础
- **Status:** pending

### Phase 5: Sublime 轻量客户端

- [ ] 实现 sidecar 客户端、vault 解锁与 Quick Panel 树浏览
- [ ] 实现 scratch Markdown buffer、自管 dirty/版本、加密 draft debounce 与安全写回
- [ ] 拦截可拦截的 save/close 命令，并在全局 hot_exit/recent-files gate 不满足时拒绝可写模式
- [ ] 实现搜索、跳转与 plugin-host/应用退出失败安全降级
- [ ] 添加 Python 单元测试与 Safe Mode/独立 data-dir canary 残留矩阵
- **Status:** pending

### Phase 6: Git 合并、迁移与恢复工具

- [ ] 实现 `.gitattributes`、locked-safe `inex merge-driver` 与已解锁插件/CLI 三方合并
- [ ] 实现加密冲突状态与编辑器内解决流程
- [ ] 实现 plaintext copy-import/dry-run/显式 in-place，以及校验报告
- [ ] 实现 vault verify/备份恢复说明，确保失败不破坏源数据
- **Status:** pending

### Phase 7: 跨平台验证、打包与发布准备

- [ ] 跑通格式、性质、RPC、编辑器、Git、Unicode/长路径/换行的验证矩阵
- [ ] 配置 Linux/Windows x64/arm64 CI、Rust 二进制、VSIX 与 Sublime 包产物
- [ ] 完成 threat model、用户指南、安全配置、迁移/升级与故障恢复文档
- [ ] 审计磁盘明文残留、日志秘密、依赖许可与发布清单
- **Status:** pending

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

## Notes

- `.agent/init_plan.md` 是产品与架构的上位约束；若实现细节与其冲突，先记录并选择不削弱安全边界的方案。
- 每完成一个阶段立即更新本文件及 `progress.md`；发现和决策持续写入 `findings.md`。
- 所有破坏性迁移默认禁用；任何 in-place 操作必须显式确认并先完成可验证备份。
- Git 作为开发容错边界：已通过门禁的阶段/垂直增量单独提交；未完成或未验证的并行改动不混入稳定提交，不改写已共享历史。
