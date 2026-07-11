# Inex Findings & Decisions

## Requirements

- 产品是跨平台个人 Markdown 加密日记/私密知识库，目标平台为 Windows 与 Linux。
- 主形态是“真实密文 Git 仓库 + 编辑器虚拟明文视图”，不是 OS 级明文挂载盘。
- 强约束：未解锁不可读正文、磁盘不产生临时 `.md` 明文、关闭会话后只剩密文、Git 只管理密文。
- 威胁模型是日常/社会层面的未授权读取；不承诺抵御管理员、内核、内存取证、swap、dump、录屏或键盘记录。
- 默认保留目录树与文件基名，正文文件追加 `.enc`；文件名加密属于后续增强。
- 主实现为 Rust `inex-core`/核心库 + 本地 `inexd` sidecar；VS Code 是完整主客户端，Sublime 是命令式轻量客户端。
- 密码学结构：随机 master key、Argon2id 口令 KDF、KEK 包裹 master key、文件级派生子密钥、XChaCha20-Poly1305 AEAD。
- Markdown MVP 采用整文件 AEAD；大附件/streaming、加密落盘索引、keychain 和共享会话延后。
- 搜索索引只驻留内存；锁定/退出时销毁。MVP 不依赖 VS Code proposed Search API。
- 保存动作必须同步完成“加密 + 原子写入密文”，禁止明文临时文件。
- VS Code 普通可写 FileSystemProvider 不满足强约束；主编辑路径需使用 CustomEditorProvider、加密 draft backup、树与受控导航/搜索。
- Sublime 使用 Quick Panel + scratch 插件管理 buffer；原生 dirty 无法安全复用，必须由插件自管版本/dirty 并持续写加密 draft。
- Git 使用 `*.md.enc -text -diff merge=...` 与自定义密文 merge driver；冲突内容本身也保持加密。
- 导入默认 dry-run/copy-import；in-place 必须显式二次确认。

## Repository Baseline

- 2026-07-10 检查时，仓库分支为 `master`，跟踪内容只有 `LICENSE`。
- 初始提交实际还跟踪了 Rust 模板 `.gitignore`；其中已有 `target`、`debug`、`*.pdb` 与 rustfmt 备份规则，但尚无 Node/Python/编辑器产物规则。
- `.agent/init_plan.md` 未跟踪，共 347 行，是完整设计研究报告与八周建议时间线。
- planning-with-files session catchup 没有报告未同步的旧会话上下文。
- 当前没有既有代码、构建系统、包管理清单或测试，因此不需要兼容遗留实现。

## Local Toolchain Snapshot

- Linux x86_64 (Ubuntu kernel 6.8.0); Rust `1.97.0`/Cargo `1.97.0` stable。
- Node.js `26.3.1`、npm `11.16.0`、pnpm `10.32.1`、Python `3.12.2`、Git `2.43.0`。
- 系统提供 libsodium `1.0.22` (`libsodium.so.23`) 与 pkg-config 元数据，可在本机做动态链接验证。
- VS Code `1.126.0` 与 `subl` 命令均已安装，后续可执行本机 Extension Host/插件 smoke test。
- 仓库许可证是 GPL-3.0；新增源码与发布说明应保持许可证一致。

## Research Findings

- init plan 已明确组件边界、协议示例、文件格式草案和编辑器能力差异，但若要工程冻结仍需验证当前依赖/API 版本。
- 报告建议 Unix domain socket/Windows named pipe，允许 MVP 使用 stdio 子进程；因此先实现 transport-neutral handler + stdio adapter 是符合上位计划的增量路径。
- 报告里的密文 magic 为 `EDRY`，产品/仓库名是 Inex；格式标识可以保持 `EDRY` 以忠实执行方案，外部命令和扩展使用 Inex 命名。
- 本机工具链足以直接开发和验证三类组件；Windows/ARM 仍需通过 CI/cross-check 验证，不能从 Linux 本机结果推断。
- 原 init plan 草案把 `key_slot` 写入文件 header，但 slot 只是同一 master key 的口令包装入口；正文绑定 slot 会破坏“换密码不重写正文”，因此 EDRY v1 改为稳定 `key_epoch`，KDF/salt/wrap nonce 全部逐 slot 保存。
- 将规范化 logical path 纳入 authenticated header/AAD 可以检测密文换位；代价是 rename 必须重加密，已纳入原子 rename 流程。
- stdio-only 且每编辑器独立 sidecar 时，VS Code 内建 Git 启动的 merge driver 无法安全获取已解锁 master key。保底 merge driver 必须在没有交互密码/认证 broker 时不改 `%A` 并返回冲突；插件可在已解锁会话内读取 Git index stages 进行安全解决。
- 当前 VS Code backup tracker 会对 modified working copy 自动调度磁盘 backup，这不由 `files.hotExit=off` 禁止；因此可写虚拟 TextDocument 会违反“磁盘无明文”。CustomEditorProvider 可让扩展实现 backup，并只把加密 draft 写到 VS Code 指定目标。
- 当前 VS Code Local History 源码会过滤未知 URI scheme，但这不是稳定 API 保证；仍需对目标 VS Code 版本做黑盒残留测试，不能只依赖设置检查。
- VS Code 当前官方 Custom Editor 文档确认：`CustomEditorProvider` 自带扩展管理的 document model，扩展负责 save、backup、dirty 与 undo/redo；这正好允许 Inex 将 `*.md.enc` 作为 binary custom document 并自行写加密 backup，而不能使用仍基于 TextDocument 的 `CustomTextEditorProvider`。
- libsodium 官方绑定目录列出 `libsodium-sys-stable`；其维护者签名的当前 1.24.0 release 可作为 Inex 的窄 FFI 基线。FFI 只允许集中在 core 的一个 audited module。
- 首次锁定依赖后 `libsodium-sys-stable 1.24.0` 的构建链解析到 `zip 8.6.0`（要求 Rust 1.88），因此 workspace MSRV 从初拟 1.85 调整为真实可验证的 1.88；开发工具链继续固定 1.97.0。
- Sublime `on_pre_save`/`on_pre_close` 是不可取消通知，且没有公开 `set_dirty`/`mark_clean`；研究报告中的“非 scratch + 接管保存 + 保留原生 dirty”不可实现。严格模式必须在插入明文前 `set_scratch(True)`，自管 dirty/提示，并用短 debounce + pre-close best effort 只写加密 draft。
- Sublime 应把 `hot_exit: "disabled"`、`hot_exit_projects: false`、`update_system_recent_files: false` 作为可写 hard gate。应用退出无法可靠拦截，因此客户端在独立 Safe Mode/data dir 的崩溃残留测试通过前只能标 experimental/secondary。
- Rust 标准库 `File::lock/try_lock/unlock` 到 1.89 才稳定，当前 workspace MSRV 1.88 不能直接依赖；atomic 层需要窄平台锁后端或显式提高 MSRV。
- Rust 1.97 `std::fs::rename` 提供同文件系统 replacement 语义，但不暴露 Windows durability flags，也不能承诺所有文件系统上的 crash atomicity。v1 坚持 same-directory encrypted staging + `sync_all` + rename、绝不 delete-first，并保持 local-filesystem-only 边界。
- Windows `ReplaceFileW` 在部分失败码下可能让原目标缺失，不满足“失败保留旧目标”，因此不能作为无备份的默认替换路径。
- `unicode-normalization 0.1.25` 固定 NFC 为 Unicode 17，但大小写映射仍来自 Rust `char` 表；Rust 1.88 与冻结语义不一致，故项目 MSRV/CI 基线提升到已固定的 Rust 1.97，并以编译期 Unicode 17 断言阻止未来静默漂移。
- Windows 官方目录句柄可用函数列表没有承诺 `FlushFileBuffers(directory)`；因此目录 flush 只能作为 capability probe，不能作为 Windows namespace commit 的唯一正确性前提。Microsoft 明确支持的 `MoveFileExW(MOVEFILE_WRITE_THROUGH)` 是 Windows 文件名提交屏障，且绝不能启用跨卷 copy。
- Windows `FILE_ID_INFO` 在不支持 128-bit id 的 FAT/exFAT 等文件系统上可以返回全零；此时必须忽略它并退回 `BY_HANDLE_FILE_INFORMATION` 的 volume serial + nonzero 64-bit file index。ReFS/NTFS 的非零 128-bit id 仍优先使用。
- `libsodium-sys-stable 1.24.0` 的官方 MinGW static archive 依赖 `advapi32!SystemFunction036`，并引用部分 MinGW runtime 没有提供的 C23 `memset_explicit`。兼容 symbol/link force 必须只存在于 audited `sodium.rs`、仅编译于 Windows GNU；MSVC/其他平台不受影响。
- 只检查 vault 根挂载不足以保证 local-filesystem-only：Linux 子目录可以是 NFS/FUSE 或 same-device bind mount。v1 同时以 `/proc/self/mountinfo` mount-id snapshot 和 `st_dev` 检查 tree，并在每次 direct/atomic path resolution 与 recovery 时重新比较 root/target mount identity。
- “精确路径存在”不等于“路径无别名”。Linux 可同时存在 `notes`/`NOTES` 或 Unicode full-fold 等价 sibling；direct read/save/delete 也必须枚举每级 parent，要求唯一 exact portable-casefold child，不能只在 list/create 时 tree-scan。
- 文件 size/mtime/creation time 可被同步工具保留，不能作为 plaintext search cache 的安全 freshness key。每次 search query 在 mutation guard 内对当前完整 ciphertext 计算 SHA-256；任何外部 replacement、等长就地篡改或时间戳恢复都会先使索引失效。
- Git for Windows 的产品 release notes 记录了 DOS `~digit` 名限制，而 Git core 的静态 path verifier 规则并不等价于“拒绝所有 8.3-looking name”。EDRY v1 只冻结明确的 basename-final `~0`–`~9` 保守互操作规则；Phase 6 需用真实 Git for Windows 测试。

## Technical Decisions

| Decision | Rationale |
|----------|-----------|
| 根目录持久化 `task_plan.md`/`findings.md`/`progress.md` | 当前有明确项目 workspace，便于跨会话恢复与版本审查 |
| 将八周建议合并为七个验收阶段 | 保留原顺序与全部交付物，同时让每阶段有可执行完成条件 |
| 先冻结格式/协议规范再写密码学代码 | 密文格式和错误语义一旦产生测试向量就需要稳定，前置决策可减少不兼容重写 |
| stdio 是 MVP transport，不是协议边界 | 编辑器均可可靠拉起子进程；handler 后续可复用于 socket/named pipe |
| EDRY canonical CBOR 使用整数键固定 schema，外层固定 12-byte prefix | major/minor、固定 flags 与 u32 header length 可明确演进，AAD 覆盖完整 prefix/header |
| file key 用 keyed BLAKE2b-256(master, domain + vault + epoch + full file UUID) | 完整使用 128-bit file id，清晰域隔离，避免把 crypto_kdf 的 64-bit subkey id 当作完整文件标识 |
| 文件 etag 是完整密文 envelope 的 SHA-256 | 与 init plan 示例、Git/通用工具一致；不泄露正文且能统一检测并发修改 |
| 外部命名统一为 `inex` CLI、`inexd` sidecar、`inex.markdownEditor`、`merge=inex` | 研究报告中的 `diaryd`/`diary:`/`ediary` 是绿地占位符，无兼容负担；MVP 直接打开真实密文 URI |
| VS Code custom editor 直接匹配真实 `*.md.enc`，不注册 plaintext TextDocument | 官方把 CustomEditorProvider 定义为扩展自管模型/save/backup；真实密文 workspace 同时保留原生 Git |
| Sublime 安全优先于原生 dirty UX | scratch 可阻止默认 Save/close prompt 路径；插件用版本、tab/status 标记和加密 draft 补偿 UX，无法证明时不进入可写模式 |
| `vault.json` 在 KDF 前完成大小、版本、slot 唯一性、canonical base64 与 KDF 资源上限检查 | metadata 是攻击者可改的不可信输入；必须在 Argon2 分配内存前阻断 OOM/长时 DoS |
| wrap AAD 和 metadata MAC payload 都使用手写 deterministic CBOR | JSON 属性/slot 顺序不参与安全语义；metadata payload 对 slot UUID 排序并覆盖完整 slot 集合与 feature 状态 |
| 跨进程锁与原子替换封装在单一 atomic backend | 标准锁 API 晚于 MSRV、Windows replace 失败语义复杂；上层不得自行拼接 delete/rename 或绕过 etag 重查 |
| 树扫描将 symlink/reparse、明文 `.md`、非 canonical `.md.enc` 和 case-fold alias 视为 vault 完整性错误 | 防止目录逃逸、跨平台歧义和“被忽略的明文”误判；扫描只读取元数据与路径，不打开正文 |
| 全文搜索仅接受已解锁内存正文并对文档、查询、fold 临时量和 snippet 使用 Zeroizing 容器 | MVP 不落盘索引；锁定时 `clear`/Drop 擦除，同时以总字节/文档/结果上限限制资源消耗 |
| 原子写入的条件检查必须在同一个 OS mutation lock 内完成 | 只在锁外检查 etag 会造成 TOCTOU；staging 可提前完成，但 commit 前必须锁内重读完整目标 digest |
| RPC framing 的原始 body 和序列化输出也属于敏感内存 | 即使 JSON value 随后持有字段，原始 password/content 副本也必须用 Zeroizing buffer；错误只保留固定分类与 `io::ErrorKind` |
| 逻辑文件名上限必须为物理 `.enc` 后缀预留 4 个字节 | final logical component 不能沿用目录的 255-byte 上限，否则合法逻辑路径在 ext4/NTFS 上无法创建物理文件；v1 采用更保守的跨平台交集 |
| UUID 的语义正确不等于 wire encoding canonical | `uuid` 的通用解析器接受多种拼写；vault-v1 的稳定 JSON 必须显式要求 lowercase hyphenated form |
| 结构检查与 commit 必须由同一个 guard 串行化 | 单独的 OS lock 类型不足以组合 tree collision scan 与写入，且不可在持锁时递归调用自带加锁的 API；repository 层统一使用 `VaultMutationGuard` |
| rename/rebind 不能靠“先写 destination，后删 source”而没有恢复记录 | 两个目录项无法单次原子变换；先同步 journal，再提交并验证 destination，最后删除 source，崩溃后按 etag 确定性恢复，才能既不丢源也不悄悄留下未知半状态 |
| EDRY v1 的 Unicode 语义同时锁定依赖表与编译器表 | NFC 使用精确 `unicode-normalization 0.1.25`，case mapping 使用 Rust 1.97 Unicode 17；版本不匹配必须编译失败而不是改变已有 vault 的路径碰撞结果 |
| Windows namespace commit 使用 write-through move，删除先退休到 encrypted tombstone | 目录句柄 flush 没有官方跨文件系统保证；write-through move 能把 logical name 变更纳入同一平台 primitive，crash 最多遗留 `.vault-local` 密文 tombstone |
| OS namespace call 报错后必须重查完整 etag 状态 | write-through flush 可能在 rename 可见后报告失败；只有 exact pre-state 可返回 I/O failure，exact requested state 可返回未确认 durability，其他状态返回显式 indeterminate/conflict |
| Recovery 对 journal path 重新执行 no-link/no-mount/identity 验证 | 合法 journal 创建后祖先仍可能被换成 symlink/junction/mount；不重新验证会让 recovery 在 vault 外 inspect/remove |
| Search 查询用完整 ciphertext fingerprint 而非 metadata fast path | 正确性和不返回 stale plaintext 优先于查询前的额外密文 I/O；metadata-preserving external mutation 必须可检测 |
| Windows GNU shim 仅服务交叉验证，发布矩阵以原生 MSVC 为主 | shim 已通过 link/Wine ABI 测试，但 Wine 不能替代 NTFS/ReFS power-loss 和 native handle semantics evidence |
| 开发过程以 Git verified checkpoint 管理 | Phase 1/2 基线为 `075f8fd`，Phase 3 foundation 为 `99044dc`，CLI hardening 为 `7128a8b`，watchdog-backed daemon 为 `815f216`，authenticated keepalive 为 `cb8e17c`，failure-safe import 为 `2f287e3`；后续继续按 editor/Git 等可独立回滚的验收增量提交 |
| v1 导入只支持 absent-destination copy import，明确拒绝 in-place | 先删除/改写源目录无法给出跨平台可证明的失败安全语义；copy-only 让源明文保持只读，并允许完整 encrypted staging 复验后一次性 no-replace 发布 |
| import 发布使用私有 ciphertext-only marker 区分 OS 模糊结果 | rename 返回错误不能证明目录未移动；P/S/L/marker identity 可重建 exact moved、exact unmoved 或 indeterminate，marker 清理失败必须返回独立非零结果并告知不得重跑同一目的地 |
| VS Code 明文清理必须区分确定性与 best effort | Rust sidecar key/cache 可明确清零；Node Buffer 由扩展覆写，但 JS string、V8/Chromium/VS Code 内部副本无法确定性 zeroize，因此锁定会销毁 webview/drop references，最终磁盘残留结论必须来自 isolated-profile canary 审计 |
| stdio server 必须以 bounded reader channel + 定时主循环驱动 idle expiry | 单线程阻塞读取下一帧会让无请求会话的 master key/search index 超过 15 分钟驻留；session 的惰性 expiry 只有配合 watchdog 才满足协议 |
| `inex serve` 只信任同目录 `inexd` 或显式 `INEXD_PATH` | sibling 缺失时隐式 PATH 搜索可能把后续解锁口令交给同名恶意程序，生产启动路径必须失败关闭 |
| CLI hidden-TTY 的读取期硬上限需要修补/替换 `rpassword` | 7.5.4 的公开 TTY 路径在 Enter 前持续增长私有 `SafeString`，自定义 bounded Reader 又失去 Unix echo-off/Windows Console mode；当前显式 stdin 是硬上限路径，TTY 限制如实文档化且不得假称已解决 |
| handler 本身也必须是 fail-closed 终态机 | 即使 stdio transport 正常会在 shutdown/mismatch 响应后退出，公开 dispatcher 仍不得在终态继续 hello/create/unlock；active vault 也只能显式 lock 后再 unlock，不能由无旧 capability 的请求静默替换 |
| RPC 结果在构造期必须预留 framing 上界 | core tree 的合法资源上限可能大于单帧 24 MiB；listTree 在分配结果项时按保守 JSON 上界计数并提前返回 `LIMIT_EXCEEDED`，不能等 writer 无法发送后才失败 |

## Issues Encountered

| Issue | Resolution |
|-------|------------|
| `init_plan.md` 引用的是研究阶段的内部引用标记，不能直接作为工程依赖版本依据 | 实施前针对会变化的 Rust/VS Code/Sublime API 使用官方当前资料复核 |

## Resources

- `.agent/init_plan.md` — 产品、威胁模型、架构与里程碑上位计划
- `/home/horeb/.codex/skills/planning-with-files/SKILL.md` — 持久化计划工作流
- `docs/PRD.md` — P0/P1/P2 验收矩阵与 release gate
- `docs/spec/edry-v1.md` — EDRY/vault/key/path 规范草案
- `docs/spec/json-rpc-v1.md` — 本地 RPC、session 与错误契约草案
- Libsodium official Rust bindings: https://doc.libsodium.org/bindings_for_other_languages
- `libsodium-sys-stable` 1.24.0 signed release: https://github.com/jedisct1/libsodium-sys-stable/releases/tag/1.24.0
- VS Code Custom Editor API: https://code.visualstudio.com/api/extension-guides/custom-editors
- VS Code working-copy backup tracker source: https://github.com/microsoft/vscode/blob/main/src/vs/workbench/services/workingCopy/common/workingCopyBackupTracker.ts
- Sublime Text API: https://www.sublimetext.com/docs/api_reference.html
- Sublime Safe Mode: https://www.sublimetext.com/docs/safe_mode.html
- Microsoft MoveFileExW: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
- Microsoft directory handles: https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-a-handle-to-a-directory
- Microsoft FlushFileBuffers: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
- Git for Windows release notes: https://github.com/git-for-windows/build-extra/blob/main/ReleaseNotes.md

## Visual/Browser Findings

- 2026-07-10 官方 VS Code 文档明确区分 `CustomTextEditorProvider`（标准 TextDocument，VS Code 管 save/backup）与 `CustomEditorProvider`（扩展自管 document model/save/backup）；Inex 必须使用后者。
- 当前官方 Custom Editor 文档说明 dirty 通过 `onDidChangeCustomDocument` 事件表达，undo/redo 由扩展提供回调；custom document 在最后一个 editor 关闭后 `dispose`，可触发 `document.close`/缓存清理。
- 官方 libsodium bindings 页面当前列出维护者的 `libsodium-sys-stable` Rust binding；GitHub 1.24.0 release 显示签名发布。
