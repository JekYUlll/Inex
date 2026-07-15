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
- Build 4200 实机 hook probe 证明 `open_context_url`/`old_open_context_url`、`toggle_record_macro` 与 `save_macro` 都进入 `EventListener.on_text_command`；因此可在 managed view 上确定性改写为固定阻断命令，但分类 helper 与 listener 实际分支必须同时有测试，不能只靠静态命令名列表。
- Build 4200 的 Python 3.8 plugin host 被异常终止后，Sublime 主进程仍可保留原 managed view，且宿主不会在短窗口内自动重启；仅靠进程内 registry 无法识别孤儿明文。产品必须在首次明文插入前给 view 写入不含秘密的固定布尔 marker，并让新宿主在启用功能前先固定文本 scrub 所有 marker view。宿主死亡到重载之间没有插件代码能隐藏该 editor buffer，黑盒 probe 证明它仍可被主动复制；这属于既有 editor-memory/clipboard 边界而非磁盘残留保证，必须如实保留 experimental 状态，不能宣称瞬时 fail-safe。
- Sublime 官方 API environment 文档把 plugin-host crash 后的恢复描述为重启 Sublime；Build 4200 实测 mtime、内建 plugin command 与 dead console 都不会在同一主进程恢复宿主。因此 QA 的正确成功条件是 `PASS_WITH_DOCUMENTED_BOUNDARY` + 整个应用退出后的零磁盘命中，而不是伪造同进程 scrub PASS。
- Build 4200 的真实 InputPanel/QuickPanel 可稳定驱动注册的 New Folder/New Markdown/Rename/Delete WindowCommand；删除确认面板首项可能已被选中，确定性选择应使用 Home 而不是假定 `selected_index=-1` 后按 Down。最终 authenticated tree checks 与四个 CRUD event 证明产品路径，不再用静态/私有 helper 冒充 E2E。
- 发布归档的可移植性需要同时冻结路径、类型、权限与规模：拒绝 Win32 禁止字符、普通/上标设备名、case/Unicode/prefix collision、symlink/FIFO、setuid/setgid/sticky、member storm/oversize；不能先掩掉权限位再审计。VSIX/PE/TOML/tag/origin 也必须解析其真实控制结构，而不是字符串或文件名启发式。
- 本机 xlings Rust 链接环境把 Linux ELF interpreter/RUNPATH 写成 `/home/horeb/.xlings/subos/default/...`；同机 package smoke 不能证明这种本机构建可移植。Linux 发布证据必须来自干净的原生 runner，并应拒绝携带构建机 home 路径的 ELF 产物。
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
- EDRY rename 每次都会换 nonce，Git 的密文相似度不构成 provenance；相同 authenticated file-id 也可能来自历史副本。rename/modify 只能由唯一 merge-base 与固定 `HEAD`/`MERGE_HEAD` 的 source/destination mode+OID 精确树状态证明。
- SHA-256 Git 会让 `cat-file` 接受唯一的 40 位十六进制前缀，因此“语法上允许 40 或 64 位”不足以安全恢复。Git wrapper 必须冻结仓库 object format，所有 index/tree/ref/result/journal OID 都要求对应完整宽度，zero OID 也从该宽度生成。
- rename journal 必须区分 in-place v1、split v2 与 detected v3；固定 commit provenance 让 index 已 final 后即使 merge commit 删除 `MERGE_HEAD` 仍可清理 journal。检测型 rename 始终要求旧 source 不存在，split 只允许精确 S/D 暂态 owner，任何第三 tracked/untracked owner 在前滚前拒绝。
- 重复读取 index 不能消除最后一次检查到 `git update-index` 的跨进程 race；在没有持有同一 `index.lock` 或候选 index CAS 前，“不得并行运行其他 Git porcelain”是产品边界，不能宣称任意外部 Git 并发均 fail-closed。
- Git index plumbing 允许同一 physical path 同时出现 stage 0 与 stages 1/2/3；只读 `ls-files -u` 会漏掉前者，而 mode-zero rename batch 会删除全部 stages。全局预检和每个 original-state commit/recovery 判定都必须显式拒绝这种交集。

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
| 开发过程以 Git verified checkpoint 管理 | Phase 1/2 基线为 `075f8fd`，Phase 3 foundation 为 `99044dc`，CLI hardening 为 `7128a8b`，watchdog-backed daemon 为 `815f216`，authenticated keepalive 为 `cb8e17c`，failure-safe import 为 `2f287e3`，VS Code base/CRUD 为 `f51d4e9`/`b3bad32`，Sublime client/read/capability/final 为 `ee09d60`/`bc10b85`/`2211e55`/`b124170`，encrypted Git merge/rename hardening 为 `02260d8`/`862d28c`，audited release pipeline/docs 为 `d042360` |
| Git rename provenance 绑定唯一 base 与固定两侧 commit tree | file-id 只证明身份，不能证明一次 move；tree mode/full OID 同时约束 source 缺失、destination 新增和另一侧 source 修改，拒绝 copy/rename-rename/歧义 |
| Git merge journal 保持稳定文件名并以内层 v1/v2/v3 演进 | v1 兼容单路径恢复，v2/v3 分别保存 split/detected 双路径、object format、file-id 与固定 provenance；严格 version dispatch 可避免宽松 optional 字段造成降级 |
| v1 目录 CRUD 明确限定为 mkdir + Markdown 文件 rename/delete | 目录 rename 必须为子树内每个 EDRY 重新绑定 authenticated path，普通循环无法提供 crash atomicity；在设计多文件 journal 前必须 deferred 并如实写入 PRD |
| 发布文档中的命令本身也是验收面 | clean checkout 必须显式准备锁定的 vsce/extension dependencies、构建 `dist/extension.js`、调用 Python 3.13.14、审计原生依赖并给 smoke 传 exact VS Code CLI；不能用前文隐含状态或 PATH 假设 |
| v1 导入只支持 absent-destination copy import，明确拒绝 in-place | 先删除/改写源目录无法给出跨平台可证明的失败安全语义；copy-only 让源明文保持只读，并允许完整 encrypted staging 复验后一次性 no-replace 发布 |
| import 发布使用私有 ciphertext-only marker 区分 OS 模糊结果 | rename 返回错误不能证明目录未移动；P/S/L/marker identity 可重建 exact moved、exact unmoved 或 indeterminate，marker 清理失败必须返回独立非零结果并告知不得重跑同一目的地 |
| VS Code 明文清理必须区分确定性与 best effort | Rust sidecar key/cache 可明确清零；Node Buffer 由扩展覆写，但 JS string、V8/Chromium/VS Code 内部副本无法确定性 zeroize，因此锁定会销毁 webview/drop references，最终磁盘残留结论必须来自 isolated-profile canary 审计 |
| VS Code 自动 Extension Host harness 证明的是受控 backup/recovery 路径，不等价于全部发布矩阵 | 测试宿主会强制 in-memory workbench storage；因此可验证 encrypted backup round-trip 和隔离根 canary 扫描，但真实持久 profile 的跨进程 Hot Exit、Local History、dirty close/crash restore 仍必须在 Phase 7 对最终 VSIX/平台 binary 执行 |
| stdio server 必须以 bounded reader channel + 定时主循环驱动 idle expiry | 单线程阻塞读取下一帧会让无请求会话的 master key/search index 超过 15 分钟驻留；session 的惰性 expiry 只有配合 watchdog 才满足协议 |
| `inex serve` 只信任同目录 `inexd` 或显式 `INEXD_PATH` | sibling 缺失时隐式 PATH 搜索可能把后续解锁口令交给同名恶意程序，生产启动路径必须失败关闭 |
| CLI hidden-TTY 的读取期硬上限需要修补/替换 `rpassword` | 7.5.4 的公开 TTY 路径在 Enter 前持续增长私有 `SafeString`，自定义 bounded Reader 又失去 Unix echo-off/Windows Console mode；当前显式 stdin 是硬上限路径，TTY 限制如实文档化且不得假称已解决 |
| handler 本身也必须是 fail-closed 终态机 | 即使 stdio transport 正常会在 shutdown/mismatch 响应后退出，公开 dispatcher 仍不得在终态继续 hello/create/unlock；active vault 也只能显式 lock 后再 unlock，不能由无旧 capability 的请求静默替换 |
| RPC 结果在构造期必须预留 framing 上界 | core tree 的合法资源上限可能大于单帧 24 MiB；listTree 在分配结果项时按保守 JSON 上界计数并提前返回 `LIMIT_EXCEEDED`，不能等 writer 无法发送后才失败 |

## 2026-07-12 Phase 7 continuation findings

- 当前已证明的是干净源码上的 Linux x64 可复现发布检查点，不等价于 `.agent/init_plan.md` 要求的 Windows/Linux GA；关闭 Phase 7 必须逐项区分“本机可形成的新证据”和“只能由原生平台、托管服务或外部审查形成的证据”。
- Hosted恢复/供应链修复已固定为`681cf1c`，其本地165/0/12及交叉编译门禁只证明源码检查点，不替代原生Windows动态证据；迁移功能从该干净Git边界开始开发，避免把两个风险面混入同一提交。
- Git 管理边界保持为：稳定 `master` 上每个纵向增量单独提交，验证失败时保留工作树证据，未经授权不推送远端；这既提升开发容错，也避免把尚未绑定的 hosted CI 结果误写成已执行。
- Phase 7 的三个未勾选项都是聚合门禁；`docs/release-checklist.md` 显示本机仍可加强的绑定证据集中在最终产物 import/backup/restore、源码/日志/动态 canary 与依赖许可清单，原生 Windows/ARM、持久编辑器配置、签名和法务必须保持独立未完成状态。
- `docs/release-checklist.md` 把最终产物的成功 import→Git commit→backup→新路径 restore→unlock→字节比对列为明确 blocker；现有 CLI 已提供 copy-only import、verify、password 与 Git driver 命令，足以在 Linux x64 产物上做一次无破坏的绑定演练，但目前没有单一可重复的 lifecycle drill 工具把这些步骤、源哈希不变和磁盘 canary 扫描连成证据。
- 最终 Rust ZIP 同时携带 `inex` 与 `inexd`，现有 framed JSON-RPC `vault.unlock`/`file.read` 可以从打包后的 daemon 认证解密并逐字节对照源文件；公开 v1 fixture 也包含完整口令、逻辑路径和期望 plaintext，可用于证明最终产物只读打开旧格式且不改写 fixture。
- `inex git install-driver` 只写仓库本地 config 与可跟踪 attributes/ignore；因此 lifecycle drill 可以用 Git bundle/clone 明确证明本地绝对 driver 不随备份传播、恢复后必须显式重装，同时验证 refs/objects 与密文树一并可恢复。
- 发布审计器已严格验证三种 archive 的一致 version/platform/source provenance，可作为 lifecycle drill 的入口门；16 MiB 最大 Markdown 经无 padding base64url 后约 22.37 MiB，仍低于 daemon 的 24 MiB frame ceiling，因此最终 daemon 可对边界文件做完整认证字节比对。
- 独立恢复审计指出 Git bundle 只证明已提交 Git refs/objects 与密文树，不能替代包含未提交状态、空目录和故障期 `.vault-local` 的完整文件系统快照；演练应同时形成 Git bundle restore 与 clean full-snapshot restore，并把真实 fault-state preservation 留作单独故障注入门禁。
- 当前只有单一 `0.1.0` artifact；最终 daemon 对冻结 v1 fixture 的不改写读取是格式向后兼容 checkpoint，但不应被表述为两个发行版本之间的真实 upgrade/rollback。
- 密码变更演练必须同时证明两件看似相反但都重要的性质：当前 `vault.json` 拒绝旧密码且所有 EDRY 哈希不变；历史完整 metadata 备份与旧密码仍能解开同一 master key。这能防止文档把 slot rewrap 误报为历史凭据撤销。
- Git 没有可直接调用的 index expected-old CAS porcelain；GA 级事务必须让 Git 通过 alternate index 生成候选，由 Inex 以 O_EXCL 持有真实 `.git/index.lock`，在锁内重验 old digest/owner/provenance、前滚 worktree，再原子发布候选。它需要 journal v4 和原生 Windows replace/power-loss 证据，不能作为当前发布演练的顺手小修。
- “冻结 fixture 不改写”绑定的是原始格式资产 `vault.json` 与 EDRY envelope 字节；认证读取可按正常锁协议创建 Git-ignored `.vault-local/mutation.lock`。审计应允许这类明确的本地运行时文件，同时拒绝原始哈希变化和任何其他新增路径。
- 真实最终产物演练证明了 Linux x64 正常路径：copy-only import、最大文件、密码 slot rewrap、认证全字节读取、Git bundle clone、完整 regular-file snapshot restore 与 v1 只读兼容均成立；它仍不是 import publication ambiguity、故障期 `.vault-local`、真实跨版本 rollback 或原生 Windows/ARM 证据。
- 残留审计不能只扫 vault：最终 harness 将整个隔离临时根（唯一排除仍应保留的 plaintext source）纳入 raw/encoded/UTF-16 动态秘密检查，并额外按文件名拒绝空 plaintext `.md`，避免“空文件无 canary”成为假阴性。
- 独立复审发现 audit 后按路径重开 Rust ZIP 会留下 audit→execute swap；绑定证据必须执行同一份内存 snapshot，并把 artifact SHA-256、artifact source commit、harness source hash/commit/dirty 状态写入固定 JSON 报告。仅有 artifact count/platform 不足以长期追溯 PASS。
- Release harness 的子进程还必须固定 `TMPDIR` 与隔离 cwd、精确断言旧密码得到 `AUTH_FAILED`，并把 frozen-v1 称为 compatibility 而非真实 upgrade；真正 upgrade 仍要求两个已校验发行版本。
- 三路复审补充的强判据：fixture 必须固定身份且绝不能把未验证 `logicalPath` 拼入磁盘路径；`git bundle verify` 必须显式在目标 vault 上下文执行；driver config 必须按 Rust shell-quote 规则整体相等；filesystem restore 重装 driver 后必须再验 clean status；`verify` 输出、完整 `vault.listTree` 集合和报告 schema 都要精确断言。
- Clean regular-file tree copy 只证明内容/目录集合恢复，不证明 ACL/xattr/ownership/目录 fsync/掉电耐久；报告字段和文档必须避免用笼统 `filesystemSnapshotVerified` 暗示真实 OS snapshot 或 crash-safe backup。
- 绑定后的报告必须同时显示 artifact source 与 harness source：旧 final artifact 可以合法来自 `76ac04a` clean commit，而新增 release harness 在提交前必须显式是 dirty；只有脚本/测试/文档提交后重跑得到 clean harness source，才可把该 PASS 固化为发布 checkpoint。
- 最新安全复审否决了当前 harness 的最终绑定资格：冻结 v1 fixture 在摘要校验后重新按外部路径打开四个文件，仍有 check→use 换包窗口；修复必须先把固定名称、限长、no-follow 的同一批字节捕获到私有边界，再对这些字节验哈希、解析和写出。
- Linux 正常路径还必须补齐四类可证伪条件：每个 framed RPC response 都不得回显动态秘密且必须符合精确 schema；Git 备份只能包含 harness 创建的唯一 main commit/ref 并比较源/恢复 refs/HEAD；Git 初始化前物理 vault 必须符合精确密文 allowlist；父进程退出后仍须有界清理持管道后代并有界收尾 stdout/stderr。
- 动态残留结论必须覆盖文件与目录相对路径组件，以及标准/URL Base64 padded、unpadded 和三种流对齐；报告字段必须明确排除被设计保留的 plaintext source，不能把排除后的零命中写成全根零命中。
- Native Windows 仍是独立未覆盖门禁：NTFS ADS、Job Object 子进程树清理和 Rust `canonicalize` 的 `\\?\` 路径语义都不能从 Linux 演练推断；Git driver installer/verifier 还必须拒绝 canonical executable path 中会被 Git 展开的 `%` placeholder。
- Git driver 的 `%` placeholder 问题必须在产品 installer 而不只在 Python verifier 中关闭：Git 在 shell parsing 前替换 `%O/%A/%B/%L/%P/%S/%X/%Y`，单引号不构成保护。当前实现选择拒绝 canonical executable path 中任意 `%`，并把校验放在 `.gitignore`、`.gitattributes` 和 local config 的任何写入之前。
- 真正可绑定的 lifecycle PASS 必须 fail-closed：工作树 dirty 时在 artifact 使用前退出；native Windows 在 Job Object/ADS 门禁前退出；Linux 报告只把 `plaintext-source` 列为明确排除根，并以 exact physical allowlist、单 ref/commit/unreachable-object 拒绝和 RPC method schema 共同支撑零泄漏/恢复结论。
- Intermediate resolution（现已被下一条结果取代）：前述“目前没有单一 lifecycle 工具”和“dirty harness 需提交后升级”记录的是本轮早期状态；工具实现并 fail-closed 后，当时尚需从 clean HEAD 重跑才能升级 provisional checkpoint。
- Superseding resolution：上述剩余动作已在独立 standalone clone 完成。harness `1e01842fc26e…` 与 artifact `76ac04aa5940…` 均为 clean canonical provenance；五正文、两类 restore、driver relocation、frozen-v1 unchanged、进程树收尾和指定明文源之外零敏感残留全部 PASS。该结论只升级 Linux x64 normal-path lifecycle，不关闭 native/fault-state/two-version/signing/legal 门禁。
- `git status` 的“clean”不是 commit-byte provenance：`assume-unchanged`/`skip-worktree` 可隐藏实际工作树差异。发布公共 `source_revision()` 必须拒绝非普通 index flags，并在 clean 情况下逐个按仓库 object format 计算真实 regular-file Git blob OID，与固定 HEAD tree 完整匹配；开始/结束双采样只是补充，不能替代字节绑定。
- Git clean provenance 还必须把命令解释环境纳入边界：清除继承的 `GIT_*`、禁用 replacement objects/fsmonitor/untracked cache、显式拒绝 `refs/replace/*`，并绑定 canonical worktree、gitdir、index identity、portable tree path、文件 mode 和 Git 输出/时间上界；否则同一个表面 HEAD 可被替换对象、`core.worktree` 或 helper 重定向到其他内容。
- 首尾两次完整 Git blob 重算能检测校验过程中的普通改写，但不能把一个同用户可写的 live checkout 变成原子 snapshot：攻击者仍可在最后一次读取后改写。发布/证据工具因此只允许在受信任的独占、静止 checkout 中运行；若未来要求抵抗并发写者，必须从私有捕获的固定字节构建并验证产物，而不是无限追加 `status`/rehash 轮次。
- Git 配置的“raw canonical origin”仍不足以证明有效来源：local include、worktree config、`url.*.insteadOf` 与重复/空 URL 都能改变或扩展有效 remote。绑定实现现只接受直接 standalone `.git`，精确解析并首尾比较 local NUL config snapshot，拒绝 include/worktree/url rewrite/push URL，且要求 raw/effective origin 都恰好一个并一致。
- Git 的大小写和 mode 语义必须由 verifier 固定，而不是相信 repo config：`core.ignoreCase=true` 可在 Linux 隐藏 `tracked`/`TRACKED` 别名，任意 `0o111` 也不是 Git executable bit。所有 provenance Git 调用现强制 `core.ignoreCase=false`、`core.precomposeUnicode=false`；POSIX 使用 `core.fileMode=true`，Windows 使用原生非 filemode 语义。blob 校验在 POSIX 按 owner execute 位绑定 `100755`，并用 peeled `HEAD^{commit}` 报告真实 commit OID。
- Manifest 的 commit/clean 标记只证明受信任 release-host 上被采样的源码 provenance；它不证明 `target` binary、VS Code `dist`、vsce 或其他 ignored/generated input 由该 commit 构建。可复现双构建、artifact hash、原生依赖审计与可信工具链是相互独立的证据面。
- Clean source 的 portable tree 必须同时拒绝 exact key 与 file/directory prefix 碰撞；Linux 可表示 `foo` 文件和 `FOO/bar`，Windows/大小写不敏感文件系统不能。HEAD tree 验证现维护 portable file/directory 双集合，两种插入顺序都 fail-closed。
- Git 的 ignore/helper 面同样参与 clean 判定：未跟踪 root/nested `.gitignore` 能用 `*` 隐藏自身，`filter.*.clean` 能在 `status` 时执行外部命令。实现现将 local config 限为窄 allowlist、关闭 global excludes/自动维护/submodule traversal，拒绝 active private excludes，并只容许位于已整体忽略父目录内的 generated `.gitignore`；真实 marker 回归证明 filter helper 未执行。
- “Standalone checkout” 包括直接 object database 与单体 index：linked/sibling worktree、index symlink、split `sharedindex.*`、objects/info alternates 和 worktree config 均被拒绝。Windows 不模拟 POSIX physical execute 位；Git status 在 Windows 固定 `core.fileMode=false`，但仍绑定 commit tree mode与真实 blob bytes，并要求 `core.autocrlf=false`。
- 跨平台 release checkout 的 EOL 策略必须在 materialization 前生效；checkout 后才写 `core.autocrlf=false` 只能让异常 fail-closed，不能防止转换。根 `.gitattributes` 现以 `* -text` 禁止全树 Git EOL 转换，package workflow 仍显式 pin false，actual blob hash 作为最后门禁。
- “Exact manifest schema” 同时要求 exact keys、语义值与 parser 一致性：直接 `json.loads(bytes)` 会接受 UTF-16/32、重复键 last-wins，以及把 `true`/`1.0` 与整数 1 等同比较。artifact audit 现先 strict UTF-8 decode、递归拒绝重复键、要求非 bool 整数 schemaVersion=1，并精确验证三类 `installFormat`。
- Git index CAS 的最小安全单元不是延长 `git update-index` 子进程，而是四个可认证物理状态：原 `.git/index` 完整摘要、alternate `GIT_INDEX_FILE` 生成的候选索引摘要、Inex 专属随机 marker 的真实 `.git/index.lock`，以及内层 v1/v2/v3 语义 payload 的 v4 journal。worktree 只能在 lock 存在、old digest/owner/provenance 重验通过且 v4 已 fsync 后前滚；候选只能以 `candidate -> index.lock -> index` 两次原子 namespace move 发布。
- v4 不应删除或覆盖无法认证的现有 `index.lock`。发布前崩溃的 Inex lock 必须用完整 magic+random token marker 区分；空文件、部分 marker、摘要不符的 candidate 或任意其他 lock 都 fail closed。为避免 create+write 在崩溃后留下不可识别的空 lock，marker 应先在私有目录完整写入/fsync，再用跨平台 no-replace move 争用 `index.lock`。
- create-only v4 可以由精确物理摘要推断 crash phase，不需要为安全性原地改写 phase；任何 published phase 在“publish 已成功、phase 尚未更新”的崩溃点仍要读物理状态，且额外 journal replace 会增加新窗口。恢复必须枚举 old/final index、marker/candidate/absent lock、original/final worktree 的全矩阵；原生 Windows NTFS/ReFS 的 replace/write-through/power-loss 仍是独立发布证据。
- stable v4 journal 不能直接 create+write：崩溃留下的 partial JSON 会阻断后续 recovery。安全路径是先在 token 派生的私有 staging 完整写入并 fsync，再 no-replace 发布；只有 stable journal 缺失、reservation marker/candidate 精确认证且 staging 是预留 regular file 时，恢复才可删除该残片。
- Windows `MoveFileExW` 在 Wine 下不允许替换一个仍由调用方持句柄打开的 destination；最终 path/handle identity 复核后必须释放句柄再执行路径替换。该选择可满足真实 Git `index.lock` 的协作式排他模型，但公共 helper 和架构必须明确它不是抵抗同用户直接 namespace swap 的内核级 compare-exchange。
- v4 的 `object_format` 不仅约束 stage/result OID 宽度，还必须与 v2/v3 内层 rename provenance 格式一致，并在无 Git 的 journal 结构校验阶段拒绝三个 commit OID 的错误宽度或非 canonical hex；运行期 tree/provenance 重验仍是第二道语义边界。
- 许可生成器若只读取 build host triple，会在交叉打包时把 host 依赖图写进 target artifact；四目标当前都恰有 77 个组件，但 Linux/Windows 各有 5 个平台组件互换，因此计数相等不能证明清单正确。`--platform` 必须映射到固定 Rust target triple 并写入/验证 inventory。
- 当前 artifact auditor 对 `THIRD_PARTY_LICENSES.json` 使用宽松 `json.loads(bytes)`，允许 UTF-16、重复键 last-wins、bool schema、未知字段、任意非空 source/license 和缺 checksum；三包也未互证 inventory bytes 与内嵌 `inexd` digest。package manifest 的文件哈希不能替代这些许可/发行集合语义约束。
- 自动许可门应对当前 Cargo 表达式采取精确、人工登记的工程 policy，并默认拒绝未知表达式/source/缺 checksum；不要临时实现不完整 SPDX parser。它只能形成可追踪的工程证据，不能替代 `OR`/`AND` 选择、GPL 对应源码与归属义务的独立法律审查。
- Cargo 的 `workspace_members` 不是可信的第一方 allowlist：根目录内 path dependency 会被自动提升为 workspace member。许可生成器必须把第一方集合固定到四个受审 `crates/inex-*` manifest，并拒绝额外/缺失 member 与其他 `source = null` dependency。
- 许可 inventory 仅列路径不足以绑定实际法律文本；每个 Cargo/native `licenseFiles` record 必须包含内容 SHA-256，artifact auditor 逐项复算，三包共享 inventory bytes 才能同时证明共享文本摘要。
- `windows-x64` 发布许可图固定为 MSVC triple，单凭 PE machine 不能区分 GNU/MSVC。`runtime-info` 必须同时报告编译 target、debug assertions 与 libsodium runtime；release smoke 固定要求 MSVC triple 和 `rust-debug-assertions: false`，因此 GNU/debug 产物不能被错标。
- 生命周期报告的秘密自扫描必须覆盖 JSON `ensure_ascii` 转义后的 Unicode/引号/反斜杠形态，并将已扫描的同一序列化 bytes 直接写到 stdout；重新序列化一份逻辑等价对象会削弱证据链。
- 严格离线许可测试读取 Linux/Windows target metadata 与 registry license texts；独立 CI job 必须先安装固定 Rust 并 `cargo fetch --locked`，否则空 Cargo cache 会在测试收集后因 offline metadata 缺包失败。
- 最终负路径证据不能只依赖单元测试中的 redacted error：CLI wrong-password+secret-query、RPC `AUTH_FAILED` 和 locked merge-driver 必须用最终 packaged binaries 执行，输出用完整动态 variants 扫描，merge input 前后绑定 bytes/identity/stat，最后再扫隔离根与 serialized report。

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

## 2026-07-12 Phase 7 fault/recovery follow-up

- Hosted Windows 能形成的绑定证据是 NTFS 上 `TerminateProcess`/强杀后的新进程恢复；它不能替代 ReFS、Hyper-V guest power cut 或物理断电。三类结论必须在报告和 checklist 中分开。
- Git v4 在 real `.git/index.lock` 之前只依赖 RAII 清理会漏掉强杀残留；新增 pre-lock intent 的方向正确，但首版独立复审发现 guard 之前的 reservation staging 窗仍会被 `has_pending_recovery` 误报为 clean，且可能永久阻断下一事务，因此当前差异保持 NO-GO 直至 orphan staging 可发现/分类。
- Token-derived 私有路径不自动等价于文件所有权。普通 `create_new` 冲突、hardlink/reparse、错误大小写别名和未知 reserved state 都必须保留并 fail closed；Windows cleanup 前还需通过目录枚举确认 exact spelling，不能让大小写敏感 inventory 配合大小写不敏感 lookup 误删别名。
- Core atomic write 已新增真实双进程 force-kill test：子 test 在 verified staging、lock 前、replace 前及 namespace commit 后/parent sync 前阻塞，父进程用 OS kill 终止，再证明 target 只可能是完整 old/new ciphertext 且 OS lock 已释放。该本机结果只绑定 Linux；Windows 需 hosted/native 执行后才能升级证据。
- Sublime Build 4200 原 runner 把随机口令写入 fake zenity 脚本且未扫描口令，原 `root_scan_hits=0` 不能作为 password-residue 证据。runner 现改用真实绝对 zenity，口令仅从 `xdotool --file -` stdin 输入 masked dialog，并把口令加入 UTF-8/UTF-16/hex/base64 全根扫描；正常 CRUD 与 plugin-host SIGKILL 边界均实跑为零磁盘命中。
- Linux VS Code persistent-profile 原型能安装 exact VSIX 并启动真实 Extension Host，但 Xvfb/xdotool 无法可靠触发 1.125.0 Command Palette/extension activation。为避免坐标猜测或生产测试后门造成假阳性，未验证 runner 已完全撤销；该门禁仍需可观测的官方 UI/accessibility driver 或人工原生矩阵。
- `SECURITY.md` 的 strict tooling/lifecycle 数字曾滞后于 59/59 与 `d44ead9`，现同步修正；新增的 0.1.0 pre-alpha release notes 明确为 draft/NO-GO，并列出格式、工具链、libsodium、当前安全性质、deferred states 与 upgrade/rollback 边界。
- `init_plan.md` 要求创建时把 Argon2id 校准到 250–750 ms，但生产 `Vault::create`、CLI init/import 与 RPC 缺省路径仍固定 3 ops/64 MiB；`create_with_params` 只是 deterministic seam。v1 可安全收敛为固定 64 MiB/parallelism 1、仅有界校准 ops 3..20，并用 process cache + fake clock/benchmark 单测避免 CI 抖动；冻结 fixture 继续显式参数。
- RPC 的 optional raw `kdf` 不能沿用最高 1 GiB/ops20 unlock ceiling 作为 creation 输入上限；absent 应走校准，explicit compatibility 路径需独立较窄 creation cap。password add/change 也不能无条件降回默认参数，应至少继承并 clamp 当前已认证 slot 的强度。
- Superseding pre-lock resolution：strict reservation + initial/final candidate ownership receipts 已闭合首版复审的 clean-miss/误删边界。目录枚举拒绝 wrong-case reserved aliases；canonical orphan staging 可精确清理，partial/multiple/link/reparse/foreign/未知 state 全部保留冲突；stable v4 journal 双可见只在完整绑定相等时移除 receipts/prelock。最终冻结复审为 0 blocker/0 major/0 required minor。
- Receipt 安全性与可用性边界必须分开：candidate 已持久化但 initial receipt 尚未发布、Git 已改写 candidate 但 final receipt 尚未发布、或 partial receipt 都会被发现并保留，不会误报 clean 或误删；但 fresh recovery 不能自动判归属，仍返回 `RecoveryConflict`。该点与 native NTFS/ReFS power-loss 继续阻止 GA，不否定本次 fail-closed checkpoint。

## 2026-07-12 Argon2id creation calibration

- v1 production calibration 固定 64 MiB 与 parallelism 1，只在 ops 3..20 内搜索；默认策略的结果或失败用 `OnceLock` 每进程缓存，自定义测试策略取 v1/creation/reader 三者交集。计时循环只使用固定公开 dummy password/salt，不接触调用者口令。
- 搜索必须精确定义不可达窗口：floor 已慢则选 floor，全区间过快则选 cap，离散跳跃越过 250–750 ms 时保留已测的 above-window 点。该窗口只约束单次 dummy KDF 测量；真实 create/import 还要做实际 KDF、wrap、原子提交与 reopen，因此本机端到端约 1.26 s 不矛盾。
- creation cap 与 reader ceiling 是不同信任边界：默认新 vault 仅允许 ops 3..20 且内存精确 64 MiB；旧 slot reader 仍允许 ops 20/1 GiB。RPC 的 nonnegative integer 越界返回 `KDF_POLICY`，负数/小数/字符串/未知字段返回 `INVALID_PARAMS`，host calibration failure 返回固定 `INTERNAL_ERROR`。
- 直接/daemon 显式策略和自动校准都在创建 absent root 前纯验证；无效策略不会留下目录。Import dry-run 在校准前返回，真实 import/init 在读取新密码和创建 staging 前取得缓存参数，缩短口令驻留。
- no-downgrade 需要绑定 authenticated slot，而不是只在 CLI 选一次参数。首轮组合审计发现“已继承的 >64 MiB 参数再被 Vault 当作 new-vault candidate”会二次拒绝，修正为 Vault add/change 对最终参数按分量取 max 并只受 password-slot floor/reader ceiling。随后独立复审又发现公开低层 `crypto::add_password_slot` 可绕过 authenticated binding，现已收窄为 `pub(crate)`；公共写槽入口仅剩 Vault。
- Frozen v1 fixture 与显式 `create_with_params` 保持确定性。真实 CLI `init` 与 `password add` 进程测试分别绑定 3..20/64 MiB 创建和 stronger-slot 继承，daemon unit/stdio 绑定 absent/explicit/error mapping 与 root 无副作用；安全与文档复核最终均为 GO。

## 2026-07-12 current-product Linux x64 release checkpoint

- 首次从 `cb6ccbb` 重建时，严格 artifact audit 按设计拒绝缺少 `docs/release-notes-0.1.0-pre-alpha.md` 的包。根因是 README 新增该链接后，producer `DOCUMENTATION_FILES` 未同步，而 auditor 会解析所有包内 Markdown 链接。修复把 release notes 同时加入三包构建 allowlist 和 auditor 独立 required set，并用真实 README + 全文档集合回归闭合链接；发布工具套件从 59 增至 60 项且全绿。被拒绝的 `cb6ccbb` 包不作证据。
- 主 checkout 的 repo-local `diff.algorithm=histogram` 不在严格 provenance allowlist 内，因此 binding build 必须来自 standalone clone。最终使用三个 `--no-local --no-hardlinks` clone，固定 canonical origin、`core.autocrlf=false`、`gc.auto=0`，并把 native target/artifact/TMP 放在 checkout 外；三者均由 `source_revision()` 绑定 clean `fd543f494669b8e82e9b7c6dabf071b17954be28`。
- 两套独立 system-GCC/offline release build 逐字节一致：`inex` `392ab0ed…`、`inexd` `e210525b…`、Rust ZIP `4479350f…`、Sublime ZIP `411944bb…`、VSIX `f573721d…`、SHA256SUMS `398ee5e8…`。两轮 strict audit 绑定 77 个 Cargo component、147 份 license/NOTICE、inventory `228bfeb7…` 与相同 sidecar；两套隔离 VS Code 1.125.0 install/bundled-sidecar smoke 均通过。
- 第三个 clean clone 对只读 artifact 连续两次完成 lifecycle PASS：5 个正文（含精确 16 MiB）、password rewrap、CLI/RPC/locked-Git 三项 nondisclosure、Git bundle 与 clean tree-copy restore、driver relocation、frozen-v1、physical allowlist、Linux descendant cleanup 均成立，`plaintext-source` 外动态秘密命中为 0。第二次 canonical report 保存在私有 ignored 路径 `target/strict-release-fd543f4-lifecycle/evidence/linux-x64-fd543f4.json`，SHA-256 `989cff808665de168fa5f76b3ca47107cae9879fc96b916b72e65d91c1c49d11`。
- 该 checkpoint 只闭合当前 Linux x64 package/audit/smoke/normal lifecycle。Lifecycle 不记录 Argon2 单次校准计时/所选 ops，也不覆盖 Git v4 receipt-gap 强杀恢复或 packaged persistent editor profile；原生 Windows/arm64、fault/two-version、签名/发布/法务与独立 build attestation 继续保持 open。
- Artifact manifest 精确绑定 `fd543f4`，但包内文档是该提交的构建时快照，仍只陈述较早的 `40ff728` artifact 证据；新的 `fd543f4` 结果只能记录在后置 planning/docs 与外部 lifecycle report 中。故本轮包是 current-product engineering checkpoint，不是可直接发布的 candidate；真正候选必须在 evidence/docs 冻结后从 successor commit 重建并完整复验，且仍不能把 source identity 当作独立 build attestation。
- 可闭合的 successor 设计不是把新 archive SHA 写回会进入同一 archive 的 Markdown，而是让所有 package-bundled docs 只描述验证条件，并明确自身不作 attestation；精确 source/artifact/manifest/inventory/sidecar/lifecycle 结果仅进入外部 ignored report 与不参与 package contents 的 planning successor。这样下一次 clean build 不存在自引用哈希，且证据提交不会被误称为 artifact source。
- Superseding package source 为 clean `5aa0b8c773a018f23082ffeca853e971e47064bc`。实际三包枚举确认 bundled docs 中精确 checkpoint、旧 artifact digest 与任意 40–64 位 hex identity 均为零；剩余 PASS 语言只属于 source/editor/tooling 证据或候选条件。A/B 的 Rust binaries 仍与前一 code checkpoint 一致，但包含 generic docs 的三包哈希更新为 Rust `a0be5e6f…`、Sublime `bb504221…`、VSIX `dcfde351…`、SHA256SUMS `14c14b9c…`，四者在两次独立构建间逐字节一致。
- 最终外部 lifecycle ledger 为 `target/strict-release-5aa0b8c-lifecycle/evidence/linux-x64-5aa0b8c.json`，权限 0600，canonical/schema validation 通过，SHA-256 `22916a1f95ade1bb5a04a568db27c850022d710a2d9ab4c1f87aefd734ca10b4`。它绑定 clean artifact/harness source `5aa0b8c`、三项 nondisclosure=true、5 个正文/精确 16 MiB、outside-source hits=0、bundle/tree-copy/driver/frozen/allowlist/descendant cleanup=true；planning successor 只记录该结果，不改变 artifact provenance。

## Visual/Browser Findings

- 2026-07-10 官方 VS Code 文档明确区分 `CustomTextEditorProvider`（标准 TextDocument，VS Code 管 save/backup）与 `CustomEditorProvider`（扩展自管 document model/save/backup）；Inex 必须使用后者。
- 当前官方 Custom Editor 文档说明 dirty 通过 `onDidChangeCustomDocument` 事件表达，undo/redo 由扩展提供回调；custom document 在最后一个 editor 关闭后 `dispose`，可触发 `document.close`/缓存清理。
- 官方 libsodium bindings 页面当前列出维护者的 `libsodium-sys-stable` Rust binding；GitHub 1.24.0 release 显示签名发布。

## 2026-07-12 Argon2id diagnostic evidence boundary

- Production calibration 的稳定证据不是完整 measurement trace，而是同一缓存对象中的 selected params、selected monotonic observation、measurement count、outcome 或 failure。Creation API 只能投影该对象，不能把 evidence 当作输入；这样减少性能指纹面并防止诊断与实际默认参数分叉。
- `selected-observed-ns` 计时从 `derive_kek_argon2id13` 前开始，包含参数/limits validation、首次可能的 libsodium 初始化、secure output allocation 与 pwhash，结束于 derived key drop 前。因此字段不能叫纯 KDF latency，250–750 ms 只是一次公开 dummy 决策观测的 inclusive 首选窗口。
- 有界二分在噪声或非单调时不测完 ops 3–20；甚至未测 ops 可以位于窗口而已测路径返回 `maximum-below-window`。原生报告只能验证 packaged selector 发出的选中点与五类 outcome 不变量，搜索语义权威仍是 injected deterministic tests。
- 一个有效外部报告运行五个 packaged processes：`inex runtime-info`、`inexd --runtime-info` 两个 probe，加上恰好三次新的 `inex kdf-calibration-info` attempt。`attemptCount=3`/`retryCount=0` 只约束 calibration attempts；每次 CLI 都是新进程，不能证明后来 init/import/daemon 的同进程缓存会选相同 ops。
- 执行前哈希不足以把 runtime output 绑定到 packaged binary：同用户可执行文件可在 probe/attempt 中自改。Linux harness 必须去除提取副本 write bits，并在每个边界以物理 identity、不可回设的 ctime、metadata 和 digest 同时复验 executable 与 artifact snapshot；这仍依赖无同主体 harness writer 的显式信任边界。
- Windows 零 residue 不能由普通 `os.walk` 推断，因为 NTFS named streams 可挂在文件或目录且不出现在默认 tree；同样，先运行再 Assign Job Object 存在后代逃逸窗口。Windows evidence 必须在 suspended-before-Job、Job-empty confirmation、完整 ADS enumeration 和原生测试存在前 fail closed；Wine、交叉编译或仅有 JSON schema 测试都不能替代。

## 2026-07-12 Linux x64 native KDF evidence result

- 可复现性门禁必须比较原生二进制本身和四文件发布集，而不只比较 `SHA256SUMS`。clean `eeca0bc` A/B 在 system GCC 下六项都由 `cmp` 证明 byte-identical；两路 strict audit 还共同绑定 clean canonical source、77 个 Cargo component、147 份 license text、inventory `228bfeb7…` 与 sidecar `ec27ba2…`。
- 默认宿主 PATH 会把 `gcc`/`ld` 指向 xlings；该路线在候选链接完成前被主动中止，最终 A/B 都在新 target 中显式固定 `/usr/bin/gcc`、`ar`、`ranlib`。性能/发布证据必须记录并隔离这种宿主工具链漂移，不能因 Cargo 命令成功就视为 native gate 通过。
- 三次 packaged fresh process 在 16 logical CPU、29217185792 bytes physical memory 的本机都选择 ops 16，单次公开 dummy 决策观测为 277.26–290.94 ms，处于 inclusive 250–750 ms 首选窗口；这只证明该时点的 selector 输出与资源范围，不证明 unlock/create/import 的端到端耗时。
- 每次 attempt 的 Linux `/proc` 观测峰值 VmHWM 为约 70.1 MB、VmPeak 72204288 bytes；这与固定 64 MiB KDF memory 加进程开销相容，但 VmHWM 不是 libsodium allocation 的独占测量，不能从差值反推精确 KDF RSS。
- 报告 `attemptCount=3`、`retryCount=0`、三个 ordinal 都被保留，canonical re-encode 与原 bytes 相等，外部文件为 create-new 0600。其 SHA-256 `8d8a9adf…` 只绑定本次 Linux x64 运行；Linux arm64 与两个 Windows MSVC 原生 row 仍保持 open。
- 当前 artifact 的 normal-path lifecycle 不能从旧 `5aa0b8c` 继承；第三 clean `eeca0bc` harness clone 的新报告将 artifact/harness source 同时绑定到 clean `eeca0bc`，并在运行后再次验证四文件集合与 `SHA256SUMS`。报告 SHA-256 为 `30904006…`，14 个必需布尔项全真且零 sensitive residue hit。
- 该 lifecycle 的 `notCovered` 仍精确包含同主体 release-host writer、签名/发布、fault-state/power-loss、hosted CI、独立法务、two-version upgrade/rollback、其他原生平台、editor persistent-profile residue 与 generated-input independent build attestation；Linux x64 normal-path PASS 不得升级成这些结论。

## 2026-07-13 exact packaged Sublime evidence boundary

- 对 live artifact 先 audit、再按路径重读 ZIP 仍有 rebind 窗；Build 4200 binding runner 必须先把四文件封存到私有 snapshot，审计同一 snapshot，并从审计捕获的内存 member bytes 物化 package。包内 daemon 与完整 installed tree 都必须跨 GUI 运行复验，不能用 source copy 或 `target/debug` 替代。
- Artifact source 与 harness source 可以是两个不同 clean commit，只要各自 provenance、文件 digest 和前后 identity 独立绑定；强制二者相等会让后置 evidence harness 永远无法审计既有包。当前 v2 reports 精确记录 artifact `eeca0bc` 与 harness `5967c8f`，不 relabel 任一方；旧 `50b84b8` 与中间 `ba35a80` v1 reports 保留为 predecessor，不原地补写新 schema。
- `root_scan_hits=0` 只能描述本轮隔离根与本轮严格 scanner。旧 runner 曾在失败时保留带随机口令的 fake zenity 文件，故不能从单次零命中推导全局主机无 residue；本轮已定向删除 28 个 proven legacy roots，未知/不同结构目录继续保留。
- Plugin host 死亡后的 PRIMARY 可以返回完整 earlier-opened 137-byte plaintext，而当前 saved view 为 183 bytes；这不是“不匹配所以无泄漏”，而是宿主仍暴露本轮已观测的另一份完整 managed plaintext。边界验证应接受与任一已绑定 opened/saved fingerprint 的精确长度+SHA 匹配，同时拒绝部分 token、未知字节或不可读 channel 形成 PASS。
- 外部报告若只保存 `events` 名称仍不足以复审。有效报告要绑定 bounded helper JSONL raw seal、record count/event counts、去时间 normalized observations/digest，并把它们与 scenario result 逐项相等；packaged import stdout/stderr、实际 `/proc` sidecar、所有 executed helper 和 installed tree 也需进入交叉绑定。
- “materialized members 与 installed tree 彼此相等”仍可能同时漏掉产品文件；current validator 必须嵌入由 audited archive digest 绑定的 canonical Rust/Sublime `PACKAGE-MANIFEST.json`，要求 Rust CLI 精确命中 manifest，并让 Sublime manifest 的 177 项 payload 加 manifest 自身与 178-file installed tree 完全相等。第四个 `SHA256SUMS` seal 也必须从三包 audit records 重建 size/SHA，而不能只检查三个 archive seals。
- 新增必需 manifest 字段与固定 exclusions 后，外层 Build 4200 evidence 不得继续复用 schema v1；否则同一 reportType/version 会指向两套互不兼容 root schema。Current normal/crash 使用严格 v2，旧 v1 只保留为历史证据；嵌套 release-set audit 与 package manifests 仍按自身 v1 validator 解释。
- 本轮两路只闭合 exact-package baseline，不是 persistent-profile matrix。Same-profile restart、application kill、真实 keyboard/menu Save variants、export/clipboard/macro、draft stale/corrupt、project/non-project、idle/daemon fault、CRUD 负路径、Windows 与发布签名仍在 `notCovered`；Sublime 的 experimental 标签不得取消。

## 2026-07-13 Git receipt-gap design audit

- v4 prelock 只绑定 old index/token/candidate basename；initial receipt 前无法区分 Inex candidate 与同-token foreign regular file，initial 后 Git 可留下 candidate.lock/partial/final candidate，而 final receipt 前没有最终 digest 或完整 transaction payload。Partial receipt 同样无法区分 torn publication 与 foreign bytes，因此猜测删除会降低现有 foreign-preservation 标准。
- 可保持 fail-closed 的 v5 方向是 immutable bundle：在非 active scratch 内完成 alternate-index mutation、stage-map 验证、old/final digest、完整 merge payload、exact inventory 与 file identity，fsync 后以 verified no-replace directory move 一次性发布 stable token directory；稳定 bundle 不再原地修改，marker/journal 只引用 manifest digest。
- 未发布 partial scratch 默认保留、报告但不阻塞新事务，就无需把未知对象当作 Inex 所有而删除；若产品要求自动删除所有 partial scratch 或零残片，则仍需要新的信任/scope 决策。原生 NTFS/ReFS directory move、file-ID 与 power-loss 证据仍不可由 Linux SIGKILL 替代。

## 2026-07-13 portal-safe Sublime restart findings

- “杀掉已知三角色/同 session”不等价于“杀掉应用闭包”。子进程可以在 capture 前后 `setsid()` 或 double-fork；可靠的 Linux harness 必须先成为 confirmed child subreaper，稳定枚举 session 与 descendant closure，为每个 `(pid,starttime,parent,session)` 打开 pidfd 并复核，之后才发 SIGKILL。任何未进入已验证闭包的 root-bound survivor 都只能让 evidence fail closed，不能按 argv 猜测后直接 kill。
- 进程是否绑定隔离根不能由 argv substring 推导。当前 census 只接受 exact isolated HOME/XDG/TMP 环境值，或 `/proc/<pid>/{exe,cwd,root,fd}` 指向根内路径；argv-only 明确不是 binding。对已验证 closure/adopted candidate 的 EACCES/EPERM 是证据失败，只有 ENOENT/稳定 identity 消失可当作已退出。
- GUI harness 还必须把 mount namespace 纳入 residue 结论。D-Bus activation 曾在 private `XDG_RUNTIME_DIR/doc` 留下 dead `fuse.portal`，即使 process census 归零，普通 `rmtree` 仍以 `ENOTCONN` 失败。Success path 现在要求 checkpoint/final mount count 都为零且绝不 unmount；failure cleanup 只对零 live binding、唯一 exact `portal` source + `fuse.portal` type 使用 sealed `fusermount3 -u`（非 lazy），未知/活/额外 mount 均保留并失败。
- Schema v4 的新增字段不是装饰性声明：isolated environment 可重建 profile/package-owned sidecar 路径和 process environment digest；state token fingerprint-set digest 必须同时匹配 helper normalized observation、state seal 与 lifecycle；两份 profile binding、两次 sidecar path 或 token/state 联动伪造均由 validator 拒绝。旧 v3 因 root schema 不同保留为 predecessor 而不是原地升级。
- 当前 full-restart PASS 证明的是同一 exact package/隔离 profile 在一次完整 SIGKILL 路径上的磁盘与 restart 行为。它不消除 plugin-host-dead 时可复制明文的既有边界，也不覆盖真实用户 profile、Hot Exit/history/sync/backup、keyboard/menu variants、其他 kill 路径或其他平台；Sublime 必须继续 experimental。

## 2026-07-13 Git v5 prerequisite findings

- Stable v5 bundle 必须保持 immutable，因此后续不能像 v4 一样把唯一 candidate member 移动到 `.git/index.lock`；writer/recovery 应从 sealed bundle 复制到 token-derived publish staging，再在持有 real Git lock 时替换 exact marker，stable bundle 直到 journal 和最终状态确认后才按 exact inventory 清理。
- v5 manifest/inventory validator 只证明 canonical schema、member physical shape、size/digest 与 exact namespace；任意伪 `DIRC...` bytes 仍可能通过 inventory 层。任何 worktree/index mutation 前必须在真实 Git 上下文验证 candidate 完整 stage map、object format/OID width、live expected-old 和 transaction payload 语义，不能因类型名包含 verified 就跳过这一层。
- Portable Windows test 不能用 case-only rename 假设制造 wrong-case entry，也不能让 API callback 在 Windows 悄然收到 `\\?\` canonical path 而 Linux 收到 caller path。测试现直接创建并枚举 wrong-case member；directory primitive 冻结 callback caller-path 契约，内部另持 canonical identity。Native NTFS/ReFS ADS、file-ID abrupt-kill/power-loss 仍是独立 GA gate，Wine 只验证代码路径与 fixture。

## 2026-07-13 Git v5 production integration audit

- 当前上位 `init_plan.md` 对 Git 的绑定要求是密文仓库、自定义 merge driver、安全冲突状态与端到端崩溃恢复；它没有规定具体 journal wire format。v5 设计必须保持这些产品语义与 v1-v4 恢复兼容，同时把 receipt-gap 从人工 fail-closed 状态升级为可认证自动恢复。
- `ed51c59` 已把完整 alternate-index mutation、真实 stage-map 验证、canonical manifest 与 exact two-member inventory 收缩到 scratch，再一次性发布 stable bundle；它仍未改变 production v4 writer、真实 index lock、journal 或 worktree。因此下一增量的安全边界是“消费一个已封存的 bundle”，不能重新在 stable bundle 内写 phase 或移动其唯一 candidate member。
- 当前 v4 production 主链集中在 `prepare_index_cas`、`write_cas_journal`、`publish_cas_index` 与三个 `commit_*` 调用点；恢复入口为 `recover_pending -> recover_cas_pending`，稳定 journal 文件名继续复用 `git-merge-journal-v1.json` 并按内层 version 严格分派。v5 最小切入应保留旧 parser/recovery，只为 `PendingMergeJournal` 增加新 variant，并让新 writer 先走 sealed-bundle loader 而不是复制 v4 receipt ownership 逻辑。
- 现有 `candidate_bundle_v5` 已预置 `CandidateBundleManifestReferenceV5`、manifest reference 校验和持句柄 inventory seal，说明 outer marker/journal 可以只绑定 manifest size/SHA 与 stable basename；下一步必须使用这些既有类型，避免再发明一个平行 digest 表述或只按路径重开 bundle。
- Stable inventory seal 在目录发布前持有 candidate/manifest 文件句柄和目录 identity，发布后继续把同一 inode 绑定到 stable path；fresh recovery 则可用 `validate_candidate_bundle_inventory_v5` 重开并重新形成 seal。两条路径都必须在 mutation guard 内进一步验证 live index snapshot/stage map 与 sealed candidate stage map，inventory 本身不能授权写入。
- Preparation 已保证 manifest 的 old/final size+SHA、object format、完整 `MergeJournalPayload` 和 candidate member 一致，并在 scratch 发布临界区/发布后复验 guard、namespace、live old index 与 candidate 语义。后续 outer schema 不应重复 payload；只引用 stable basename 和 manifest reference，可以让 manifest 成为唯一完整事务内容并减少两份 payload 漂移。
- v4 的真实锁顺序是：prelock/receipts/candidate 完成后发布 marker 到 `.git/index.lock`，再写 stable journal，随后前滚 worktree并把 candidate 移入 lock/index。v5 stable bundle 本身已是完整 ownership receipt，因此 marker 可只携带 token、stable basename 与 manifest reference；若在 journal 前强杀，fresh recovery 仍能从 stable bundle 认证 old/final/payload，而不再需要 v4 的 initial/final receipt 猜测。
- v5 不能把 bundle 内 `candidate.index` 移出目录。需要一个 token 派生、legacy-visible 的 publish staging regular file作为可消耗副本；其任意 partial/foreign/tampered 状态都必须由 stable manifest + exact file shape 判定，不能用 basename 推断所有权。若 lock 尚未取得，恢复可删除仅在完整 digest 匹配时的副本，或重新从 sealed bundle创建；未知字节一律保留并冲突。
- v4 `recover_cas_pending` 在 live old 时要求 marker+candidate 或 lock 内 candidate，并先把候选 stage map 与当前 old map对比；live final 时要求 candidate/marker/lock 已消失；然后复用 payload recovery。v5 应沿用这套“物理 index state先分类、语义 recovery 后执行”的顺序，但 stable bundle 必须直到 journal 与最终 worktree/index 都确认后才清理。
- 早期 provisional cleanup 顺序（已由第 312 行取代）曾设想 journal 最后删除；reference-only journal 不复制 transaction，因此不能在 bundle 残缺后独立认证 final 状态。冻结实现必须先把完整 bundle 原子退休，在退休目录仍完整时删 journal，再清退休目录。
- `Git::update_index`/`update_index_rename` 只在真实 index 且 stable journal dispatch 为 `Cas(v4)` 时改走物理 publish；alternate index 始终走 direct plumbing。新增 v5 variant 后必须显式路由到 v5 publisher，否则三个 production commit/recovery 调用点会悄然退回普通 Git porcelain，重新引入 CAS 窗。
- v4 marker 是固定 ASCII canonical bytes，直接重复 old/final digest；v5 marker 可使用新 magic `INEXIDX5\0` 并编码 token、stable bundle basename、manifest size/SHA。所有 old/final/payload只能从经过 reference 验证的 manifest导出，避免 marker、journal与manifest三方字段不一致。
- Stable bundle basename 已故意以 legacy `git-index-candidate-v4-` 前缀开头，使旧 v4 二进制 fail closed。v5 publish staging也应保持该 prefix 并使用不可与 stable directory 混淆的固定子前缀；新 namespace scanner必须按 exact grammar区分一个 stable dir和至多一个配对 publish regular file，同时旧 writer仍只看到 reserved name并拒绝启动。
- `exact_reserved_private_names` 会捕获所有 `git-index-candidate-v4-` 项但不区分类型，正好提供 downgrade fail-closed；current v5 scanner只识别 scratch/stable directory。接入 publish staging 时必须扩展 v5 scanner或新增 transaction-specific inspector，否则 generic recovery会把合法 staging误判为未知 reserved conflict。
- 现有 `CandidateBundlePreparationFixture` 已能在真实 SHA-1/SHA-256 conflict repository 中生成 transaction、stable bundle和 old stage map，且 v4 real-recovery fixtures 已覆盖三种 payload。新测试应复用这些 fixture：先为 schema/loader添加不写 worktree/index 的定向测试，再为每种 payload把 commit调用切到 v5，避免新建一套弱化 mock。
- 当前 preparation checkpoint 已覆盖 partial scratch、foreign lock、manifest/candidate tamper、目录 identity swap、stable collision/clone、live index drift。下一测试增量应聚焦消费侧独有状态：publish copy partial/foreign、v5 marker前后、journal staging/stable、worktree前滚、candidate-in-lock、final index、bundle member cleanup与journal cleanup。
- 现有测试 helper 在 preparation 返回后释放 mutation guard；这恰好允许 loader 测试用 fresh guard 模拟进程重启，而不只验证同一调用栈持有的旧句柄。Schema/loader 回归应同时覆盖 fresh guard + reopened inventory 与当前调用持句柄 revalidation两种路径。
- Reference schema 采用 `object_format + token + stable basename + manifest size/SHA + token-derived publish staging basename`；marker 为 `INEXIDX5\0` 后接 strict canonical JSON。这样 marker/journal可共享同一引用，journal 后续只需额外绑定 marker bytes size/SHA，完整 transaction仍只有 manifest 一份。
- Cleanup 的安全顺序修正为：final 状态确认后把完整 stable bundle 原子退休到 token-derived cleanup directory；在 cleanup仍为 exact full inventory时删除 reference-only journal；随后才按 candidate、manifest、空目录逐步清理。这样强杀不会产生“残缺 bundle + 仍依赖它解析 transaction 的 journal”。
- Stable v5 journal validator 必须从 embedded transaction reference 重建完整 canonical marker，再要求 journal 的 marker size/SHA 完全相等；只验证一个语法正确的 digest reference不够。当前 schema已落实该三向绑定，并让 locked-safe status只接受与实存 stable manifest交叉匹配的 v5 journal。
- 在 v5 physical publisher 尚未接线的过渡 checkpoint，存在合法 v5 journal时 `Git::update_index*` 必须返回 `RecoveryConflict`，不能退回 direct plumbing。这样即使测试或未来版本留下 v5 journal，也不会在下一切片前重新打开无 CAS 窗。
- Locked-safe status 的 v5/legacy 判定必须来自同一次 stable journal parse；若先判断 v5、再第二次读取给 legacy classifier，同用户重绑可把两次结果混成不可能的组合。`89f91e9` 前的最终修订让 `(pending, matching_v5)` 由一次读取共同返回，并保持 same-user最终尾窗属于既有协作边界。
- 真实 marker lock 获取可复用 v4 的 `create_private_file`、verified no-replace file move 与双 parent durability判据，但不能复用 v4 prelock/receipt ownership。v5 的 durable owner是已发布 stable bundle；任何 marker前失败都应保留 bundle及可认证 publish staging，由 recovery决定清理或继续，而不是依赖 RAII猜测删除。
- 当前 `recovery_status` 仍先以 generic v5 scanner 只识别 stable bundle，再让 `legacy_has_pending_recovery` 接受 exact stable+journal；真实 `.git/index.lock` 完全位于 `.vault-local` reserved-name 集合之外。下一增量必须独立分类 Git lock path，并把 stable-only/publish-ready/marker-no-journal/journal-ready 作为一个 transaction-specific snapshot 合并到 locked-safe status，不能仅扩宽 legacy reserved allowlist，否则会把 journal-before-marker 或 foreign lock组合错误接受。
- Existing v4 `prepare_index_cas` validates payload、alternate stage map 和 locked live index，但 worktree target、identity owner 与 rename provenance 的 revalidation 分散在三个 `commit_*`/`recover_*` 流程且与实际写入相邻。v5 在发布 durable journal 前需要抽取只读 `authorize_*` 层，按 payload variant 证明原始 worktree/index/owner/provenance 仍成立；不能把 inventory loader 的 stage-map成功或后续会执行的 recover函数当作 journal前授权。
- Fresh v5 pre-journal authorization 可从 manifest payload 自足重建身份：in-place 需认证 result object 与 identity stage 来派生 file-id，并要求 exact original conflict、无 stage-zero、worktree expected digest、owner 与 attributes；detected rename 可复用 `authenticate_detected_rename_recovery`，再要求 detected original index、active/tree provenance、source absent、destination expected digest、owner 与两路径 attributes；split rename 可复用 `authenticate_rename_recovery`，再要求 split original index、active provenance、source/destination 两个 original state、owner 与 attributes。三种分支都必须拒绝 already-final index/worktree 作为“journal前”状态，避免把 post-journal crash 倒推成未授权新 journal。
- Publish helper 的同调用栈 held file proof 不能替代 crash 后恢复：一旦进程退出，fresh recovery 必须从 token-derived publish path 重新打开 single-link regular file，绑定 exact reference/manifest final bytes和 stage map，并在 stable inventory、live old index、guard/namespace 前后复验后形成新的 held proof。若只提供 `prepare_*` + `revalidate_*` 而没有 fresh loader，`PublishReady` 状态仍无法安全推进到 marker lock。
- 合入的 publish slice 已补 `load_candidate_publish_staging_v5`，fresh process 可重新形成 stable inventory 与 publish file 的 held proofs；lock classifier 同时保持只读边界，`Candidate` 仍仅代表 final size/SHA。下一 pre-journal classifier 必须把 fresh publish loader成功、lock state、live-old/stage-map、payload authorization 与 exact reserved namespace合并成同一次状态判定，不能单独凭 `Candidate` 枚举推进。
- Fresh publish loader 当前严格要求 `.vault-local` reserved 集合仅为 stable+publish；真实 marker 位于 `.git/index.lock`，因此 `MarkerNoJournal`仍可复用，但 `JournalReady` 多出 stable journal 后不能直接调用同一入口。状态 inspector需要让 journal-aware路径在一次 read/classification中验证 stable+publish+journal exact集合，再复用底层 held/semantic proof，或为 loader显式传入允许的 journal状态；绝不能临时忽略 journal后做第二次不绑定读取。
- 2026-07-13 05:32:31 `refs/remotes/origin/master` 的本地 reflog记录 `update by push`，远端从旧 checkpoint推进到 `47c6567`；当前主线程没有执行 push，且本地 `ea40261` 未丢失、仅变为领先远端 1。后续继续把远端视为并发外部状态，不回滚、不 force-push，也不把尚未提交的 planning改动混入远端结论。
- v5 marker/journal scratch 不能复用 legacy `create_private_file` 的失败清理语义：该 helper 在 write/flush/sync失败时主动删除 partial path，而 v5 的可认证性模型要求随机 non-active scratch 在任何未知失败后保留且仅计数。应复用 publish slice 的 retained scratch create/write模式；`atomic_move_verified_file_no_replace` 只给原始 move error和双 parent sync结果，marker/journal调用者必须自己分类 source/destination后态且一旦 active marker可见绝不回滚删除。
- Payload authorization审计确认现有 loader完全不覆盖 vault object认证、worktree原态、file-id owner、attributes与 active rename provenance。Journal前必须抽取 read-only `authorize_payload_before_v5_journal`：InPlace 额外认证所有 present stages而非仅 identity stage；Detected复用完整 recovery auth并要求 source absent+parent sync；Split复用完整 recovery auth且 Ours-rename source absent同样要在 journal前补 parent sync。三种分支只接受 original index/worktree，首次检查后还须在 fully-synced journal scratch 的临界发布闭包内再执行一次。
- Locked-safe pre-journal inspection也必须把真实 `.git/index.lock` 纳入前后快照：只在 semantic loader前分类一次会允许普通并发 Git在多次 index/stage-map读取期间改变 lock，最终混合旧 lock状态与新语义证明。当前冻结为语义加载前后各 strict classify一次且必须完全相等；任何 absent/marker/foreign/candidate转变都保留状态并返回 Conflict。
- Payload authorization首轮独立审查确认实现无越权写入但以验证矩阵不足判 NO-GO；补强后现绑定 SHA-1/SHA-256三 variant正向和相关 index drift、rename source/destination drift、attributes、active/tree provenance、duplicate owner与wrong guard，并比较注入后 index/worktree/journal/lock不变。v5入口另显式要求 `vault.root == git.root == guard root`，rename active provenance 的缺失/畸形统一为 `IndexChanged`；journal publisher接线前仍需最终复审翻转为 GO。
- Payload authorization 最终独立复审已为 GO：`6d16b72` 的 SHA-1/SHA-256 三 variant、相关 index/worktree drift、attributes、active/tree provenance、duplicate owner、root/guard binding与失败不变性形成组合证据；后继 marker 提交未修改该授权实现，因此 durable journal publisher 可把此 seam 作为发布前与 critical closure 内的两次只读授权边界。
- Marker lock 现在只证明 v5 已获得并持有 canonical owner，不证明 journal 或 transaction 已可恢复；下一状态机必须在每个 `StableOnly -> PublishReady -> MarkerNoJournal -> JournalReady` 转移后从磁盘重新分类，不能凭 helper 返回值推断新状态。marker 一旦 active，即使后续 journal scratch/write/sync/move 失败也必须保留，fresh recovery再从 sealed bundle、publish staging与 marker reference重建授权。
- Durable-journal 独立审计发现 `MarkerNoJournal` 曾缺少 fresh-process held marker proof：classifier 只能描述 bytes 类型，不能持有 `.git/index.lock` path identity；同进程 `AcquiredIndexLockMarkerV5` 又依赖已消失的 scratch basename。journal publisher 必须先重新打开 canonical marker，绑定 single-link/path identity、stable/publish/live-old/stage-map，再做两次 payload authorization，不能凭枚举推进。
- 原冻结 cleanup 顺序仍有 manifest-delete→rmdir 强杀缺口：reference-only journal若已物理删除，candidate/manifest又已删完，fresh process只见空 cleanup目录，basename不足以证明可删除。修订为 final后 stable→token-derived cleanup，再把 held active journal原子 no-replace退休为 canonical cleanup receipt；receipt持续绑定 reference/token/cleanup name，跨 candidate→manifest→rmdir 全程保留，目录消失后才删 receipt。cleanup directory与receipt继续使用旧v4可见 reserved prefix以保证 downgrade fail closed。
- Journal后 later-unrelated index只能在 publish/lock已消失、worktree/owners为final，且当前完整stage map在事务保护case-fold keys上与candidate final精确相等时接受；事务外路径可变化，任何source/destination大小写或Unicode alias、额外stage、mode/OID/path spelling变化均冲突。不能复用v4只检查result entry存在的弱fallback。
- Journal后的两个 file replace 不能靠 `try_clone` 把 source/destination 原句柄跨 move 保留来证明 moved inode：Windows `MoveFileExW` 可能因仍打开的原句柄失败。跨平台闭合方式是先从已验证 single-link held file捕获 opaque filesystem identity，消费并关闭所有被替换路径的句柄，再以 reopened source/destination与该 identity做 moved/not-moved/foreign reconciliation；journal与stable bundle的非目标句柄可继续持有。
- Journal发布后不能再要求实时 `MERGE_HEAD`/`CHERRY_PICK_HEAD`。Manifest payload已经持久绑定 ours/theirs/base commit和三棵树 provenance；fresh recovery应认证记录的对象与tree关系、original/final index和worktree状态，而不是调用 `verify_active_rename_provenance`。当前 post-journal初稿在 `verify_authenticated_payload_old_index_v5` 的Detected/Split分支仍残留该调用，必须修复并用删除active ref后的SHA-1/SHA-256三payload矩阵证明。
- Cleanup需要的core原语必须消费待删文件句柄后再执行Windows path-based delete，保存不透明volume/file-id作后态分类；目录删除则两次验证parent identity、目录identity与empty inventory。删除失败后只接受exact old=`NotRemoved`或absent=已删除，foreign rebound/parent rebound一律`Indeterminate`且不再触碰；成功后真实同步父目录并诚实报告`Synced/NotSynced`。
- Cleanup receipt状态冻结为`StableJ -> CleanupFullJ -> CleanupFullR -> CleanupManifestR -> CleanupEmptyR -> ReceiptOnly -> Clean`，唯一物理顺序是stable directory原子退休、active journal原样no-replace退休为receipt、依次verified-remove candidate/manifest/空目录、最后删除receipt。Receipt与cleanup dir分别使用`git-index-candidate-v4-cleanup-receipt-v5-{token}`和`git-index-candidate-v4-cleanup-v5-{token}`，保持旧v4 scanner downgrade fail closed。
- Reference-only journal在stable移到cleanup后不能再走固定stable loader：必须从journal reference/token派生cleanup路径，用原stable basename验证relocated manifest/inventory；manifest内容绝不改写。Journal移为receipt后，receipt成为独立cleanup capability，后续删除只认证canonical receipt、当前exact cleanup形态与held identity，不再依赖可能已被用户继续修改的Git/worktree。
- Post-journal完成分类不能只返回`candidate_matches`布尔值；LaterUnrelated必须绑定分类时持续持有的single-link live-index identity，并在所有外部hook后验证当前path仍指向该identity。`3ddf79d`/主线`4754a32`已用initial/final delete、foreign replacement与lock reappearance矩阵闭合该窗口；同一inode的非协作原地内容改写仍明确位于协作式同用户威胁模型之外。
- Cleanup每次只执行一个namespace transition，随后丢弃旧句柄并fresh reclassify；任何系统调用错误也只接受相邻两态。尤其最后receipt unlink若parent sync未确认，需再次显式sync `.vault-local`；重启只允许receipt重现或全clean，不能凭basename重建或猜测已删除receipt。
- Post-journal错误协调不能用`is_ok()`把所有失败压成`RecoveryConflict`：namespace post-audit若返回I/O、Git plumbing或`DurabilityNotConfirmed`必须原样传播；只有语义状态不匹配才允许继续检查pre-state，pre证明exact not-moved时返回原move I/O，两侧都不匹配才是Conflict。Recorded provenance同理只把`UnsupportedConflictEntry`映成journal/state错误，保留merge-base/tree读取的operational错误。
- Owner扫描也位于post-journal critical/final授权链。`TreeError::Io`、`VaultError::Io`及嵌套`VaultError::Tree(TreeError::Io)`必须投影为scrubbed `GitError::Io`；非canonical/link/collision/crypto等语义失败仍归WorktreeChanged。否则权限/设备故障会被误报为用户并发修改并妨碍准确恢复。
- Live-index首次moved-inode proof与After-hook final proof都必须在完整stage-map classifier之后再次重验journal、lock absent及live identity；只在classifier前检查会让分类期间的exact-byte新inode、old/foreign rebind或重现`index.lock`穿透。首次proof只接受ExactFinal+candidate identity；final proof只接受ExactFinal+candidate identity或LaterUnrelated+new identity，并始终拒绝old identity。
- Replace系统调用报错时即使post audit返回operational error，也必须继续尝试只读pre audit：pre证明exact not-moved时应返回原move I/O；否则优先传播post operational、再传播pre operational，只有post/pre都属于语义状态不匹配才归RecoveryConflict。跳过pre会丢失一个可确定的物理结果。
- LaterUnrelated不能以“live不匹配candidate/old identity”这种负证明授权：path缺失与任意foreign新inode同样得到两个false。完整stage-map分类必须打开并持有当时的single-link live File，前后绑定path并返回opaque classified identity；classifier后的hook/sync结束后，current path必须仍匹配该classified inode，再应用Exact=classified=candidate、Later=classified!=candidate/old规则。
- 当前 cleanup 接线的精确控制面是 `recover_bundle_v5_pending -> ExactFinal/LaterUnrelated -> recover_pending hard-stop`；cleanup成功前不得让该分支返回 recovered，也不得解除 `Git::update_index*` 对 `BundleV5` 的显式拒绝。七态清理必须拥有独立于 active stable/journal inspector 的物理分类，因为 stable 一旦退休后，现有 `inspect_candidate_bundle_namespace_v5` 与 `v5_payload_from_reference` 都无法再从固定 stable path重建事务。
- `.agent/init_plan.md` 把 Git冲突、端到端崩溃恢复和 Windows/Linux一致性列为发布前测试层，不只要求正常merge结果。因此 cleanup receipt不是附加安全增强，而是让已发布v5 journal能够从任一强杀点最终收敛为clean的上位交付条件；在完整force-kill矩阵前必须继续保持GA NO-GO。
- 当前仓库已有core atomic write的真实子进程force-kill harness，但Git v5 preparation/marker/journal/post-journal仍主要由同进程hook fault矩阵覆盖。Cleanup定向hook可以先证明每个相邻磁盘态与foreign/rebind拒绝；production接线后还必须增加独立进程在每个namespace checkpoint阻塞、由父进程OS强杀、再由fresh `recover_pending`收敛的绑定测试，不能把返回错误等同于进程死亡。
- 可复用的native harness模式已经在`inex-core`验证：同一test executable以`--exact`启动child，通过隔离root/ready-path/checkpoint环境变量进入阻塞hook；父进程有界轮询ready与early-exit，调用平台`Child::kill`并wait，再从新进程/新guard检查磁盘态。Git v5需要额外证明每个强杀态最终`recover_pending == Ok(true)`且active stable/journal/cleanup/receipt/index.lock全部收敛，不只证明old/new bytes完整。
- 两个冻结cleanup basename都以legacy `git-index-candidate-v4-`开头，现有`exact_reserved_private_names`会自动把它们视为reserved并对wrong-case fail closed。这正是downgrade安全边界，但也意味着新的cleanup inspector必须在进入legacy fallback前完整消费“exact cleanup/receipt集合”；否则合法中间态会被旧恢复逻辑当成foreign conflict，或更危险地被宽松忽略。
- Production v5不能通过修改低层`Git::update_index*`的BundleV5分支来上线：这些方法没有`Vault`或`VaultMutationGuard`，无法重验payload/worktree/owner或绑定held journal identity。三种commit入口应在构造`MergeJournalPayload`后统一调用持有vault+guard的高层状态机，移除各自v4-only手工worktree/index尾巴；低层BundleV5 hard-stop应保留作错误调用防线，v4 `publish_cas_index`与v1-v4 recovery完全不变。
- 端到端v5 kill矩阵需要覆盖StableOnly、PublishReady、MarkerNoJournal、JournalReady、三payload的worktree中间点、CandidateInLock、ExactFinal/LaterUnrelated，以及CleanupFullJ、CleanupFullR、CleanupManifestR、CleanupEmptyR、ReceiptOnly、Clean。每次kill后从fresh CLI recovery断言首次recovered=1、二次=0、payload/index正确、事务外stage保留、`.git/index.lock`和全部active/cleanup namespace消失；主矩阵至少SHA-1/SHA-256×三payload。
- Cleanup state不能只是枚举；每个非Clean variant必须携带当前磁盘形成的held proof：full inventory持有两member句柄与dir identity，manifest-only持有manifest File+dir identity，empty持有dir identity，J/R持有raw canonical bytes+File。Classifier前后重枚举exact reserved inventory并重验path identity，才能让后续一步mutation消费proof而不在分类/删除之间重新按basename猜所有权。
- Journal→receipt必须移动active BundleV5 journal的原文件、原canonical bytes和原inode identity；重新serialize/create一个等价receipt会丢失ownership连续性。J+R同时可见、两者皆无、same-bytes clone、wrong token或foreign receipt都不是可协调态。最后receipt unlink的path absent也不自动等于Clean：若core只报告parent `NotSynced`，必须再次显式sync `.vault-local`，失败则返回DurabilityNotConfirmed。
- Cleanup的fresh classifier只证明物理capability，不替代事务完成语义：从StableJ或任何Cleanup*状态进入删除前，必须先用仍完整的manifest或此前已绑定的receipt语义重新证明ExactFinal/LaterUnrelated及payload/worktree/owner final。尤其CleanupFullJ若直接清理，会允许攻击者搬运一个结构合法bundle+journal而绕过final-state authorization。
- “操作已进入下一物理态但parent sync失败”不能简单返回DurabilityNotConfirmed后让下次按新态继续；否则后续删除会建立在未持久化的namespace边上。每个edge driver在开始下一edge前都必须对当前态的parent durability重新形成成功证据，或让状态携带可识别的待同步边界；bytes-equal path reclassification不能替代原inode moved-proof。
- Cleanup每条边都必须同时绑定“被改变目标”和“未改变的持久capability”：stable→cleanup后旧held active journal仍须指向同inode；candidate/manifest/empty-dir删除后旧held receipt仍须指向同inode。只对新态fresh reopen/bytes校验，会允许同用户在operation窗口把J/R替换成bytes-identical clone并让后续步骤误用新capability。
- Cleanup driver与首个stable-retirement edge应在类型签名中携带`Vault`、`Git`和`VaultMutationGuard`，而不是只接收root再假定调用方仍持锁。这样critical closure才能重验completed payload/index/worktree/owners，也能阻止未来从未串行化的调用点绕过；production writer接线回归还需证明v5成功后不会继续执行旧v4手工`update_index*`尾巴覆盖LaterUnrelated。
- `verify_payload_completed_v5`只验证事务精确路径的最终语义，不等价于completed-index classifier：cleanup cutover还必须比较完整stage map在受保护raw case-fold/Unicode keys上的projection，并持有/重验live index identity与`index.lock` absent。StableJ可复用现有stable classifier；CleanupFullJ必须从relocated candidate构建等价classifier，否则relocation后注入uppercase/Unicode alias仍可能被清理掉最后恢复能力。
- Edge后的fresh classifier只证明“某个结构正确的目录现在存在”，不能证明它是操作前capability的连续后态。Stable/full/manifest-only/empty cleanup目录与remaining manifest member都要在operation后用旧held identity连续验证；只保持J/R不足，尤其remove candidate时若丢弃manifest File，窗口内same-bytes manifest-only directory rebind会被接受。
- Fault matrix必须故障注入“被测试的物理原语/同步围栏”，不能在协调器之前提前返回或在真实同步成功后只改写结果值。有效ErrorBefore应让primitive返回Err且磁盘仍old，再观察共同reconciliation/fence；有效NotSynced应来自primitive或可观测sync seam，并证明explicit fence确实被调用、fence失败传播且state不越边。否则测试会在删除关键协调代码后仍然通过，属于假覆盖。
- 最终cleanup coordinator使用统一private physical driver区分attempted/completed；生产固定`Run`，测试ErrorBefore/After/NotSynced走同一common reconciliation并由可观测sync seam证明old/expected fence。`c08ee91`/`07a34c4`/`761b146`因此只闭合“已存在v5事务的可靠清理”，不自动使三个真实merge writer从v4切换到v5，也不替代真实子进程OS kill证据。
- Production writer不能在已持有`VaultMutationGuard`时调用会自行加锁的`recover_pending`，也不能先drop guard再重入。应抽取单guard的`drive_v5_to_clean_locked`，让normal commit和fresh wrapper共用全部disk classification；正常路径只在最终Clean返回`Ok(())`，fresh recovery首次完成返回true、二次false。
- `prepare_candidate_bundle_v5`的返回错误不等于stable未发布：AfterPublish或parent durability失败可能留下exact active stable。高层必须按磁盘态协调：scratch-only保留且返回原错，exact own stable进入同一locked driver或留给fresh recovery，foreign/duplicate/payload mismatch原样保留并Conflict。任何无条件`?`后重试prepare都会冒着第二bundle或v4 fallthrough风险。
- 强杀暂停能力不能放进CLI integration：依赖方式编译`inex-git`时不会启用其`cfg(test)`，若要注入只能暴露feature/env/hidden command并污染可发布artifact。正确边界是在writer固定提交预留private composite hook + production ZST，后继测试提交仅由`#[cfg(test)] mod v5_force_kill_tests`解析child环境和阻塞；正式CLI可作为恢复/输出证据层，但不拥有暂停入口。
- Native force-kill harness应让ready/control位于vault外、checkpoint只出现在同步Git子进程已退出处、父进程有界轮询ready/early-exit后`Child::kill`并wait，再启动全新recover child。Pre-stable scratch kill期望recovery=0且fresh merge可继续；active state首次recover=1/二次=0；ReceiptOnly之后或Clean为0。Linux/Windows结果只能证明无析构进程死亡与fresh reclassification，不能表述为设备掉电证据。
- Production writer固定为`53ce227`后，后继force-kill测试提交不得修改任何非test writer路径；若发现checkpoint seam不足，应回退并形成新的writer固定提交再审，而不能在harness提交里顺手改变production语义。这样正式artifact可绑定writer commit，测试二进制仅增加`cfg(test)`child/rendezvous逻辑。
- Force-kill磁盘canary不能只递归扫描raw文件：Git loose/pack object会压缩正文，且candidate/result object可能unreachable。每个case必须在kill后恢复前、首次恢复后、二次恢复后同时扫描control/repo regular raw bytes，并通过`git cat-file --batch-all-objects --batch`解压枚举全部Git objects；canary本身不得进入路径、branch、commit message、scenario、ready/result或argv。
- Ready record是跨进程授权边界，必须由repo外control目录中的unique staged file经create-new、完整write/flush/sync、关闭、atomic no-replace rename与parent sync发布，绑定parent nonce、writer pid、object format、payload、checkpoint和repo root。Malformed visible ready应立即fail closed；ready后再次`try_wait`，任意timeout/panic/early-exit都由parent-side child guard kill+wait，wait完成前禁止打开recovery或删除fixture。
- Force-kill 覆盖不能用“每 payload 只选一个代表性 common checkpoint”的 92-case pairwise 表替代完整矩阵。机器断言必须为 SHA-1/SHA-256 × 三 payload 各自构造 candidate 7、publish 5、marker 6、journal 6、post-index 6、cleanup 6，再加 payload-specific worktree（1/1/2）与六个 LaterUnrelated case；expected 集合需逐项等于实际集合，单独 `len == N` 不足以防重复/漏项。
- 幂等恢复证据的“fresh”是进程边界而非函数调用次数：首次恢复 child 必须退出并被 wait，第二个新 child 才能证明 recovery=0；父进程随后再本地调用不能替代。Pre-stable candidate scratch又是另一类语义：首次恢复应为0、原index/worktree不变、retained scratch允许存在且不阻塞新merge，不能复用active transaction的final-state断言。
- Ready文件经原子rename可见不等于其parent sync已被确认；writer必须在ready helper完整返回后再发布独立armed ACK，父进程只对armed ACK完成读取/绑定/存活复核后kill。Linux child census还必须枚举`/proc/<pid>/task/*/children`，只读leader TID会漏掉libtest worker线程创建的Git子进程。
- 证据harness的最终清理检查不能用`Path::exists()`：该API把metadata错误折叠为false，可能把无法验证的目录状态写成clean。应使用`try_exists()`并传播错误；Windows native还需要真实process-tree/handle-leak runtime证据，非Linux no-op只能维持静态可编译而不能关闭该门禁。
- “fresh recovery child”不足以单独证明进程隔离：如果父进程仍持有已解锁`Vault`、`Git`或fixture内部File/密钥状态，kill后的观测仍不是纯fresh-disk边界。严格harness应由setup child创建fixture并退出关闭所有句柄，父只持序列化control与paths；恢复/最终验证都另起child，pre-stable续跑也在fresh verifier中完成。
- 短side plaintext若同时出现在合法Git branch/commit metadata，不能直接加入全对象blind byte scan，也不能因此省略。可证伪方案是：通用canary继续扫描全部raw和所有解压对象；`ours\n`/`theirs\n`采用精确raw metadata排除并对所有Git blob（含unreachable）按object type解压扫描，确保合法commit对象不误报、plaintext blob/scratch仍必报。
- Fixture setup child若要把`TestDirectory`留给后续进程，必须先原子发布control/ready，再显式detach仅目录owner并正常退出；父只有在setup成功reap且control/ready精确绑定后才能启动writer。进程退出本身关闭fixture内Vault/Git/File/密钥内存，后继final verifier重新unlock/open，避免`mem::forget`把句柄保留在仍存活的父进程。
- 对合法Git metadata冲突的处理若只是“exact path整文件不扫描”，路径集合虽窄但内容边界仍宽：同一文件被追加一份side plaintext也会被豁免。更强证据是让fixture正文使用不进入branch/commit/path的unique canary，从而零排除地全raw/全object扫描；次选是认证合法metadata bytes或精确剥离已证明的occurrence后继续扫描余下内容。
- Canary长度本身也是证据稳定性边界：`ours\n`/`base\n`等5-byte token在随机ciphertext中有可观的长期碰撞面，完整230×多阶段raw扫描会放大flaky假阳性。专用canary应足够长、静态可审、逐payload确实进入base/ours/theirs/merged plaintext，同时与Git metadata/control/path/argv零碰撞，才能使用统一零豁免扫描。
- 不必为三种payload都重写fixture：InPlace是短正文与Git metadata碰撞的来源，可单独自建neutral fixture；Detected/Split既有长正文可在setup child中实际解密stage/result并与冻结canary逐项比较。关键是每个被扫描token都由真实plaintext来源证明，而不是仅把一个未使用常量加入scanner。
- Full-body canary只能证明完整正文未残留，不能证明crash-time partial write没有留下前缀、单行或中段。Linux绑定证据应同时扫描足够长且互异、并由真实解密stage/result证明包含关系的fragment；mutation必须只泄漏fragment，避免测试仍由完整正文命中而掩盖缺口。
- `git cat-file --batch-all-objects --batch`的安全价值在于覆盖reachable与unreachable对象；回归若只提交reachable commit没有绑定这一点。应使用`git hash-object -w`写入fragment-only blob、删除输入且不创建ref，再要求统一scanner仍捕获。
- Setup child用`mem::forget`转移临时目录owner后，父进程必须立即接管RAII cleanup；否则timeout/panic会留下vault甚至残余明文。进程guard也不能在kill失败后调用无界`wait()`：只有有界`try_wait`证明writer已reap才允许启动fresh recovery，析构路径同样不得永久挂起。
- Mutation regression不能用`catch_unwind(|| whole_scanner())`证明detector命中：Git命令失败、目录枚举或文件读取panic也会让测试假PASS。应先在catch外完成I/O/status并断言注入fragment确实存在，再只捕获纯字节detector的预期panic。
- Setup owner的严格转移不能依赖“成功child退出后再parse control”：parent应在spawn前声明cleanup guard，并在一旦可认证取得root时arm；drop order必须保证setup/writer/recovery child先有界reap、fixture后删除。Guard回归也应有durable ready证明目标已park，并分别覆盖显式kill与Drop路径。
- Linux v5 force-kill绑定最终是六个原生shard、精确230个case，而不是6个代表点：两object formats分别覆盖InPlace 37、DetectedRename 37、SplitRename 38，所有case均执行setup退出、writer OS kill/reap、两次fresh recovery、final verifier与plaintext/object residue检查。634秒全绿只关闭Linux进程强杀；Windows进程树、NTFS ADS与设备掉电仍是独立门禁。
- 默认`cargo test -p inex-git`不会执行full shard是刻意设计：本轮164个非ignored测试全绿，11个ignored由5个child entry和6个full shard组成；发布证据必须同时保留默认套件结果与显式六分片230/230结果，不能仅引用其中一个。
- 可体验artifact与当前产品提交必须精确区分：本机现存VSIX最新只到`5aa0b8c`，历史planning记录的`86285ce`四文件artifact虽通过A/B reproducibility、strict audit与exact VS Code smoke，但原文件已清理；`389d9fb`又包含其后的Git v5 production writer与强杀闭环。若要给出当前进度下的安装体验，应从clean current HEAD重新生成并审计engineering demo，同时继续保留pre-alpha/NO-GO声明；旧包的成功安装不能证明新源码可打包。
- Phase 7文档本身是artifact输入，因此恢复实现升级后不能先打包再靠外部说明纠正。当前README/SECURITY/release checklist/notes与architecture/operations/binding spec仍把new writer写成v4 receipts并声称receipt-gap自动恢复open；这会让新包错误指导恢复。正确current边界是production v5 immutable bundle + marker/journal/live-index identity + durable cleanup receipt，legacy v1-v4只保留读取/恢复；Linux 230-case强杀已闭合，但Windows Job/handle、ADS、NTFS/ReFS power-loss与ref-only/legacy并行仍open。
- Windows审计发现一个独立于runtime证据的production缺口：v5 exact bundle inventory只枚举普通目录项和unnamed file data，不能看见bundle目录、candidate或manifest上的NTFS named streams。优先后继应在core Windows platform层提供fail-closed ADS枚举primitive并接入v5 initial/held/cleanup revalidation；Linux只能用Windows GNU交叉编译证明结构，真实ADS语义仍须NTFS/ReFS native MSVC测试。Job Object强杀和设备power-loss是另外两类证据，不能互相替代。
- Hosted CI状态应从远端run本身而不是本地workflow存在性推断。当前`gh run list`绑定两次failure，最新为`b9ad906`/run `29233324592`；GitHub详情接口在本轮网络路径持续EOF，故只能把“已运行且失败”视为已确认，把具体job根因、日志和修复保持为待取证，不能继续写“尚未push/run”也不能凭公开annotation摘要修改测试期望。
- 当前进度已经有可追溯的Linux x64 VS Code体验包：`target/current-demo-bd2b58e/release-artifacts/linux-x64/inex-vscode-0.1.0-linux-x64.vsix`精确绑定clean source `bd2b58e`，SHA-256为`f12bb3a4d0d9439ec5c9409b5371be035767880cf4d1e8cdcc65dffadb2a8c41`，冻结1.125和本机1.128隔离安装均通过。可体验Unlock/Lock、Encrypted Vault tree、加密Markdown CRUD与内存搜索；它仍是未签名单构建pre-alpha engineering demo，不能外推Windows、A/B reproducibility、完整persistent-profile/lifecycle或GA安全结论。
- 2026-07-14 ADS实现初查：仓库目前没有`FindFirstStreamW`/`FindNextStreamW`、`BackupRead`或等价named-stream枚举原语；Windows句柄、extended path、reparse拒绝、directory/file identity及`GetFileInformationByHandleEx`集中在`inex-core/src/atomic.rs`的cfg Windows平台模块。v5现有inventory只在`candidate_bundle_v5.rs`检查目录entry与普通文件形态，源码注释也明确只绑定unnamed stream，因此不能通过补文档关闭生产缺口。
- `inex-core::atomic`已公开`FilesystemFileIdentity`/`FilesystemDirectoryIdentity`和held-handle/path重验证，但ADS枚举需要新增独立物理属性证明；现有Windows module可复用`extended_path`、`CreateFileW`共享模式和reparse/identity检查。理想core API应在非Windows为明确no-op成功、Windows对普通文件/目录返回“只有unnamed stream”或I/O失败，不能把不支持/拒绝访问/枚举中断折叠为“无ADS”；v5调用方再把任何非clean结果映射为scrubbed conflict/I/O并保留capability。
- v5接线的最小共同控制面不是每个writer checkpoint逐处加检测，而是强化`validate_candidate_bundle_inventory_at_path_v5`与`held_inventory_matches_path_v5`：前者覆盖scratch/stable/fresh full cleanup装载，后者覆盖critical publish、held stable/relocated/full cleanup及删除前重验证。manifest-only与empty cleanup不再经过full inventory，必须分别在`load_cleanup_manifest_v5`、`revalidate_held_cleanup_manifest_v5`、`load_candidate_cleanup_v5`的empty分支、`revalidate_held_cleanup_empty_v5`和实际remove前检查目录ADS；manifest-only还必须检查held manifest文件ADS。否则攻击者可在candidate删除后的后半清理阶段附加目录或manifest named stream而不改变entry集合/unnamed digest。
- Microsoft官方Win32契约提供比path-based `FindFirstStreamW`更强的handle-bound方案：`GetFileInformationByHandleEx(FileStreamInfo=7)`对任意handle返回8-byte aligned `FILE_STREAM_INFO`链；无stream时以`ERROR_HANDLE_EOF`表示，named-stream支持取决于文件系统。文件默认stream名为精确`::$DATA`，目录默认没有`$DATA`但可有named stream。实现应在held file/directory handle上有界扩容解析该链，只接受零项或唯一`::$DATA`，把`ERROR_INVALID_PARAMETER`（不支持streams）、拒绝访问、buffer上限和任何malformed链都作为错误fail closed；不得把unsupported filesystem误当clean。
- 既有测试组织允许把core与v5证据分层：`atomic.rs`已有platform内部测试模块和跨平台主测试模块，适合对synthetic `FILE_STREAM_INFO`字节链做Linux可运行parser负测，并在`cfg(windows)`真实创建file/directory ADS；`inex-git/src/lib.rs`约10k/19k行已有candidate preparation/cleanup hook与真实repo fixtures，适合增加Windows-only bundle/manifest/directory ADS mutation回归。Windows GNU no-run只能证明FFI/layout/接线可编译，Wine可作API冒烟，native NTFS/ReFS仍是唯一绑定runtime门禁。
- Candidate preparation现有`CandidateBundleTestAction`可在`CriticalAudit`或`AfterPublish`精确变异scratch/stable成员并证明不发布/不接受；ADS回归可在Windows分支扩展`CandidateAds`/`ManifestAds`/`DirectoryAds`三种action，写入`<path>:inex-test-stream`后要求同一production inventory路径失败且named stream随原capability保留。Cleanup后半段最好另用现有durable cleanup fixture分别推进到Full/ManifestOnly/Empty再注入ADS，才能证明不是只有initial validator被强化。
- ADS core实现可以复用既有`GetFileInformationByHandleEx` FFI而不新增依赖或path-based stream搜索：`FILE_STREAM_INFO`不返回实际written length，但链由末项`NextEntryOffset=0`和每项`StreamNameLength`自描述，因此固定零初始化64 KiB aligned buffer可安全按byte解析；clean file的唯一default entry远小于上限，`ERROR_MORE_DATA`或`ERROR_INSUFFICIENT_BUFFER`本身足以证明不是该clean形态并应拒绝。该选择限制攻击者控制的内存增长，同时保留`ERROR_HANDLE_EOF`作为“没有data stream entry”的clean结果；其实际NTFS/ReFS/非stream文件系统行为仍需原生矩阵绑定。
- 首轮v5接线复审揭示“immutable bundle inventory”与“整个恢复事务的物理owner”是两层不同契约：前者的dir/candidate/manifest及cleanup/journal/receipt已闭合，后者还包括publish staging、marker/candidate `index.lock`和completed live index。MoveFileEx/replace会携带或删除源文件named stream，所以只在stable bundle上验ADS不足以阻止隐藏属性跨状态传播；当前检查点应把所有v5恢复元数据/index owner统一做held-handle stream proof，而worktree ciphertext属于另一个domain-file原子写入审计面，不能混入本子项后宣称整个vault零ADS。
- Windows对抗测试不能只证明fresh loader拒绝：关键证据还应覆盖物理临界点，至少包括stable→cleanup三owner、CleanupFull目录/manifest阻止candidate删除、真实journal→receipt不移动、ReceiptOnly不删除、首次worktree mutation不发生及SplitRename两步之间不删除source；所有拒绝都必须读取原ADS证明攻击者状态被保留。Windows GNU no-run只验证cfg/API接线，原生NTFS/ReFS执行仍是唯一runtime闭环。
- Phase 7原计划把已完成的v5源码实现与仍缺的Windows原生运行证据嵌套在同一未勾选父项下，容易把历史源码缺口误报为当前工作。当前真实分界是：immutable bundle、production writer、七态cleanup、Linux 230/230与全部v5 transaction owner ADS源码接线已完成；原生NTFS/ReFS ADS、Windows Job进程边界、Windows 230、power-loss、最终候选全平台KDF/残留/许可、CI绿色运行和外部签名/法务仍开放。计划应把source checkpoint与native evidence拆成独立复选项。
- ADS提交后README、SECURITY、architecture与release checklist仍声称production inventory不枚举named streams，已成为会进入下一包的错误边界说明。正确表述是Windows源码以handle-bound `FileStreamInfo`拒绝全部v5 transaction owner的unexpected ADS并在critical move/delete重验；Windows GNU与对抗测试源码只关闭实现切片，Wine的`ERROR_INVALID_FUNCTION`保持fail closed，native NTFS/ReFS矩阵仍是绑定门禁。Python package/KDF lifecycle的全根ADS residue扫描是另一控制面，当前Windows gate仍不得删除。
- Windows force-kill `ChildGuard`若只把普通`Command::spawn`后的process加入Job，子进程可在assignment前运行并派生逃逸后代。可信源码路径必须先建`KILL_ON_JOB_CLOSE` Job，以`CREATE_SUSPENDED`启动，先Assign并证明Job内恰有根进程，再恢复唯一primary thread；正常、错误、显式kill与Drop都要有界查询`QueryInformationJobObject`直到`ActiveProcesses==0`后才关闭Job/Child句柄并删除fixture。KILL_ON_JOB_CLOSE只能作为RAII后盾，不能替代显式归零证据。
- GitHub CI run `29233324592`精确绑定`b9ad906d70fb3d53f01406247b4ba22e11e61875`，6个失败job归并为4个独立根因，不能用一次泛化workflow改动关闭：Rust quality与Linux x64都在CLI add/add用例失败；Sublime Linux把3.13-only Build4200 harness混入3.8 discovery；两条Windows Rust job下载的mutable `stable-msvc`资产已漂移；Sublime Windows请求了官方manifest根本不存在的3.8.18 win32 asset。VS Code unit/两版Extension Host、release tooling和Linux arm64 compile已成功；package workflow仍无run。
- 当前HEAD仍可本机复现合法no-ancestor add/add的v5 recovery conflict：stage2/3是两份独立新文档，允许具有不同file ID；`authenticate_all_in_place_stages_v5`却把所有stage ID强制等于result ID，导致journal发布前以operational error退出并留下stage2/3。修复必须只放宽这种严格形态，继续逐stage绑定logical path并把result绑定到选定identity；CLI回归还要拒绝稳定错误前缀`inex: `，不能仅把任何exit 1都当成预期unresolved。
- Sublime CI应把61项Python 3.8 product tests与23项Python 3.13.14 Build4200 runner/evidence tests显式分层，而非给3.8导入失败加兼容依赖。`actions/python-versions`当前manifest显示3.8.18无任何win32 asset，Windows可用最高3.8为3.8.10 x64；Linux可继续3.8.18。release/package quality的3.13阶段运行runner tests，3.8阶段只运行core/markdown/password/python38-syntax/rpc模块。
- `download.libsodium.org/.../stable-msvc`是可变输入：CI观测archive从固定`fd816a…`漂到`d0a945…`，minisig也漂移。版本化官方`1.0.22-RELEASE/libsodium-1.0.22-msvc.zip`与minisig当前固定SHA-256分别为`3e03a726…`、`3210cf4d…`，内部同时含x64/ARM64 v143结构；下载器应从该版本化资产获取并以crate硬编码要求的`*-stable-msvc`本地名保存，仍同时执行本地SHA-256与crate minisign验证。GitHub asset需要HTTPS-only redirect，漏掉`curl --location --proto-redir =https`会把redirect response误报为checksum mismatch。
- Microsoft的Job Object契约支持当前源码设计：已入Job的进程默认把子进程纳入同一Job链，只有链中允许breakaway时`CREATE_BREAKAWAY_FROM_JOB`才可逃逸；`JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.ActiveProcesses`是当前关联进程总数；`ResumeThread`返回恢复前suspend count。因此源码必须把ExtendedLimit回读精确限制为仅`KILL_ON_JOB_CLOSE`、在唯一primary thread恢复前证明root已分配且ActiveProcesses=1，并在可证明路径以ActiveProcesses=0作为关闭/删除fixture的前置证据。官方参考：https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject 、https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information 、https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread 。
- Windows Job错误路径不能在ActiveProcesses/Terminate/Close证据失败后把`ChildGuard`静默disarm，再让外层panic unwind删除fixture。正确fail-closed语义不是伪造active-zero，而是child一旦spawn，若bounded cleanup无法证明完成就立即abort测试父进程：已assigned树由进程退出关闭Job触发KILL_ON_CLOSE，未assigned child仍保持CREATE_SUSPENDED且未接触fixture，同时fixture保留供审计。只有child尚未spawn，或cleanup/句柄关闭已完整证明后，才可把普通错误返回给上层。
- `JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.ActiveProcesses`只有在进程退出且其全部process references释放后才递减；因此不能持有Rust `Child`的process handle等待Job归零。Windows正确销毁顺序必须是：Job terminate、用Child handle取得root ExitStatus、drop Child释放handle、仍持有Job查询ActiveProcesses==0、最后close Job。若drop Child后query失败，guard要保留job-only armed状态供Drop重试，持续失败时abort；否则原生Windows成功路径本身会超时，而GNU交叉编译无法暴露该运行时顺序错误。
- 最终Job Object源码把不可逃逸启动、唯一primary-thread owner/liveness重验、exact active-one和释放process reference后的active-zero证明组合为一个armed capability；错误路径只在尚未spawn或完整关闭后返回普通错误，否则保留Job/Child所有权并在持续无法证明清理时abort父测试进程。该设计已通过固定diff独立安全复审，但交叉编译与Linux test adapter仍不能证明原生Windows descendant inheritance、计数变化和句柄释放时序。
- 发布工具85/85与Sublime 84/84是两套不同统计：新增第85项是libsodium输出路径经parent symlink解析后的CR/LF注入回归；Sublime仍严格由61个Python 3.8产品测试和23个Python 3.13.14 Build4200 runner/evidence测试组成。文档若把两者一起机械替换会制造错误的产品兼容性证据。
- 真实长期Markdown仓库不能由现有copy-import安全初始化：source根的`.git`会进入严格路径扫描并因reserved component失败，所有非小写`.md`常规文件仅计数后跳过，目标发布后也不创建Git仓库。用户源的25 MiB图片又超过EDRY v1 16 MiB Markdown上限，因此“忽略`.git`+允许png后缀”仍会丢附件或伪造支持；必须先增加独立认证附件类型、tree/RPC/editor读取与Git属性/冲突策略。
- 保留旧明文Git objects与“新密文仓库”在安全语义上冲突：复制`.git`、使用alternates、graft或把旧commit设为parent都会让push/bundle继续携带可恢复的明文历史。安全默认只能建立全新object database和一个current encrypted snapshot commit，同时把原仓库保持只读历史档案；全历史重写需要逐commit拓扑、稳定file-id lineage、附件/rename语义与逐commit解密等价验证，是独立experimental迁移。
- Required-feature negotiation必须与tree/Vault能力同一原子切片发布：仅让`vault.json.requiredFeatures=[1]`和EDRY kind 2可解析、但仍使用Markdown-only scanner，会把合法`.asset.enc`静默从树、冲突检查、search fingerprint、verify和RPC中消失。feature-free旧vault可继续忽略历史无关文件，但必须显式拒绝canonical asset；feature-1 vault则必须拒绝任何未分类普通文件。
- 附件格式不能只依赖encode/decode round-trip证明兼容性：若编码器与解码器同时误改registry ID，round-trip仍全绿。独立literal canonical-CBOR向量必须直接固定key 7=`2`与key 11=`[1]`，并与既有Markdown wire fixture并存。
- 源Git读取边界不能只验证`.git/objects`目录本身与alternates：Git仍可能跟随内部loose object、pack/index、multi-pack-index、HEAD/ref/packed-refs的symlink/reparse进入外部路径。Repository import需在仓库发现前后对完整Git control namespace做bounded no-follow/local-filesystem physical manifest，并继续以HEAD/index/raw blob/worktree双轮语义证明绑定选定snapshot。
- Repository import发布vault和发布新`.git`是两个独立原子边界；若在vault已发布后才首次写恢复标志，进程死亡会留下看似普通但没有Git的完整vault。恢复intent必须在加密staging内由master key认证并随vault一起发布，随后以固定`candidate-ready`、`cleanup-ready`和历史`complete`收据收敛；`complete`之后正常Git演进不得被finalizer回滚到初始seal。
- 上述“两次发布”假设已被更小且更强的事务边界取代：新 `.git` 不需要在 vault 发布后构造。Repository import 可在同一个隐藏 sibling staging root 内完成 vault、附件、全新 object database、无 parent 根提交、独立解锁、全树/对象审计与递归 durability，随后只对整个根执行一次 marker-bound verified no-replace publication。这样发布前 final 必然 absent，发布后 final 必然已含完整 Git；repository 专用 intent/owner/external Git staging/finalizer 反而增加不必要的中间状态和实现风险，故已从 v1 契约删除。
- Opaque asset 的锁内原子写入不能把 staging 放在内容目录：进程强杀会留下 `.inex-ciphertext-stage-*`，feature-1 严格 tree scan 会把它视为未知内容；按名字递归清理又可能删除 legacy 用户文件。最终边界是先获取 vault mutation lock，再只在保留的 `.vault-local` 私有命名空间 staging；下一 guard 仅清理 identity-bound、single-link、无 ADS、同 mount、大小有界的 exact lowercase orphan，所有危险别名保留并 fail closed。
- `inex git install-driver` 目前仍以 DocumentsOnly profile 扫描 vault 且只管理 `*.md.enc`，所以即使附件核心已完成，feature-1 vault 的 Git driver 安装也会失败。Repository-import 实现必须同时让 Git tree 验证接受 assets，并增加 `*.asset.enc binary`；现有 merge object 32 MiB 边界不能直接复用到 64 MiB asset loose object 审计。
- 2026-07-14 `import-repository`正常完成路径已经由真实MyBlog全量运行证明，而不再只有dry-run：clean source HEAD `4fc19f87…`与728提交保持不变；323个tracked `100644`文件全部进入目标，其中306个Markdown、17个附件、最大图片25,074,521 bytes。目标为单个无parent根提交、326个tracked密文/元数据路径，locked verify报告306/17，`git fsck --full --strict`通过且工作树无`.md`明文名。
- 独立fresh-unlock验收不能只依赖SHA-256抗碰撞假设；当前实现对每个已认证解密体重新调用descriptor/Git-bound `SourceSnapshot::read_entry`并做exact slice equality，逐项Zeroizing drop，末尾再完整revalidate source。该缺口已由独立复审判FULLY CLOSED。
- Git对象审计已从只列OID/type/size提升为读取root commit、每个tracked blob与每个unique tree：blob与held worktree ciphertext逐字节相等，tree做typed rehash，对象集合仍拒绝额外reachable/unreachable对象，完整audit末尾再统一复验tracked worktree seals。冻结GA仍要求从approved path/OID trie独立序列化raw tree并改为bounded streaming batch比较；整对象Zeroizing Vec只足以支持当前64 MiB Linux preview边界。
- Whole-root正常publication的完整性不等于跨进程retry安全。当前16-byte随机marker的ownership依赖原进程held handles，`TargetRepository` seal也只在内存；move后kill再运行会先因destination已存在而拒绝。安全恢复需要generic canonical publication claim/candidate seal、existing-only read-only reconcile guard、held marker删除和真实SIGKILL矩阵；在此之前preview必须让用户保留`publication-reconcile`现场且不得盲重跑或手删marker。
- VS Code首次使用已经从“locked tree仍暴露CRUD并弹`Inex vault is locked`”改为welcome Import/Unlock与context gate；Import通过绝对regular bundled/配置CLI和shell-free argv任务读取双口令，成功只提供Open New Vault，不在仍打开明文source workspace时误解锁target。39/39 Node与真实Extension Host验证import→sole ciphertext workspace→asset open/chunk/close→hide/reveal→lock/shutdown→CRUD/backup/residue，真实鼠标folder picker/任务终端/persistent profile仍待最终VSIX人工门禁。
- 发布包必须同时携带平台匹配的`inex`和`inexd`，否则locked onboarding虽可见却无法执行repository import。当前package/audit/smoke以exact pair allowlist、native binary检查及`sharedCliSha256`绑定Rust ZIP/VSIX同一CLI字节；严格release-tool 86/86与Sublime 84/84通过，正式候选仍需从clean提交重新构建、审计和隔离安装。
- 当前可安装Linux x64 engineering demo精确绑定artifact source `7fb83ec0fb0bab4c031f290922fac7b717b61d76`；VSIX路径为`target/current-demo-7fb83ec/release-artifacts/linux-x64/inex-vscode-0.1.0-linux-x64.vsix`，SHA-256=`3ebf47eb6e7c0de732ea109332cca2c63981e8e6a11181a0dd87276ee30346c5`。Standalone package的strict release-set audit绑定`dirtySourceTree=false`、shared CLI=`d85e7290…`、shared sidecar=`f8e07b45…`，native audit和本机VS Code 1.128.0 isolated install/package smoke通过；这是Node 26单构建未签名preview，不是Node 22 A/B可复现或GA批准。
- 2026-07-14 raw index底层证明已固定为`62fa0aa`并在`b4ab8cf`收紧：parser直接处理SHA-1 index v2/v3/v4，拒绝非stage-0、非`100644`、semantic flags、zero OID、非UTF-8/不安全path、非canonical v4 varint、错误排序/填充/trailer及危险/未知extension；只允许唯一的TREE/REUC/UNTR/EOIE/IEOT。真实Git 2.43证明IEOT不要求EOIE，现已接受该合法组合；`FSMN`因其EWAH bitmap承载会被Git强制禁用路径隐藏的`CE_FSMONITOR_VALID`而全面禁止。
- 2026-07-14 独立Git对象证明已固定为`d8805bd`：approved tracked path与独立typed blob OID自底向上构造canonical raw trees，再以一个严格`cat-file --batch`逐字节核对所有blob/tree/commit及exact object inventory，commit也由独立canonical bytes计算typed SHA-1，不依赖Git命令返回的预期值。
- 2026-07-14 当前bounded streaming只对直接`git cat-file`子进程形成固定2秒终止/回收界限；恶意Git包装器若派生后代并让其继承stdout/stderr，reader join仍可能等待。trusted-local Linux preview可接受，GA必须增加Unix进程组/Windows Job或等价完整process-tree终止证据，并继续处理同UID对象/可执行文件TOCTOU。
- 2026-07-14 publication recovery的GA设计正在从随机16-byte进程内marker升级为持久v2 claim：统一文件identity scheme、candidate seal、existing-only reconcile、held-marker exact unlink和fresh/live分流；规范必须明确这仍是未实现目标，当前可安装demo只承诺正常完成路径，发布后强杀不得盲目重跑。
- 2026-07-14 raw index生产接线`b4ab8cf`从同一次openat2/descriptor读取同时形成RawIndex与identity/size/SHA-256 binding，所有source Git前后重验，并要求raw、`ls-files -s`、HEAD tree三方map全等。same-inode/same-size index改写在revalidate/read_entry均fail closed；精确恢复原bytes后重新通过。该证明仍不消除同UID攻击者在Git读取窗口swap-and-restore，后者继续属于GA hostile-race门禁。
- 2026-07-14 publication规范`3fd797e`冻结marker v2/candidate seal v1/existing-only guard：initial publisher必须持有同一个no-create/no-recovery `mutation.lock`跨seal、whole-root move、sync、marker unlink、clean audit与terminal result；普通mutation阻断整个reserved marker prefix。只有canonical v2在已发布target上自动reconcile，legacy/malformed/alias/unknown保留并要求manual audit；pre-move staging marker不授予fresh process权限。
- 2026-07-14 publication identity必须在捕获时选择唯一主scheme，而不能让同一对象同时携带modern与legacy候选：否则不同时间/不同API可为四个角色选择不同投影，破坏marker的uniform-scheme证明。Windows策略固定为“modern非零即唯一modern；modern成功但全零才查询唯一legacy；modern错误直接fail closed”，因此能力漂移表现为不相等/不可编码，而不是静默fallback。
- 2026-07-14 marker codec的类型边界必须表达物理角色，而不能只接收四个相同wire值：scheme-2下目录与文件底层布局相同，type-erased接口会允许把directory identity误放入marker-file槽且仍生成canonical bytes。当前构造器只接收三个`FilesystemDirectoryIdentity`与一个`FilesystemFileIdentity`，从API层阻止角色互换。
- 2026-07-14 existing-only reconcile lock与普通`VaultMutationGuard`是不同能力：前者必须对缺失root/local/lock返回错误且零创建、零权限修复、零staging recovery，只在已有单链接零字节lock上做nonblocking OS lock并持续revalidate；否则fresh reconcile会在未证明ownership前改变现场。公开missing分类现明确为`Io(NotFound)`，与spec中missing/replaced/busy统一失败tuple兼容。
- 2026-07-14 reserved publication marker检查不能复用普通“busy/integrity”错误：canonical v2代表可自动对账，legacy/malformed/alias/unknown或inspection-indeterminate代表必须人工审计，两者的允许动作不同。daemon与客户端必须保留机器可区分的`PUBLICATION_RECONCILE_REQUIRED`/`PUBLICATION_MANUAL_AUDIT_REQUIRED`，否则UI会诱导错误重试或把仓库发布现场误报为文档认证失败。
- 2026-07-14 candidate-seal encoder与candidate collector必须是两个明确层次：encoder只冻结canonical九段wire并对already-audited typed records做defense-in-depth校验；exact physical/worktree/index/tree/object/Git-control inventory、marker held-identity排除和跨段一一对应只能由live/fresh collector建立。把encoder测试通过写成“candidate seal已生产接线”会掩盖跨进程恢复的核心缺口。
- 2026-07-14 fresh/live共用的第一层应是marker-free target-only physical collector，而不是直接改legacy marker-aware audit：前者先形成完整section 1与section 9 typed evidence，并严格拒绝所有marker/private额外项；后者最终必须接收持续持有句柄的typed marker owner，不能继续使用pathname、裸identity或`bool publication_marker`作为跳过授权。
- 2026-07-14 marker-free physical manifest是pre-lock证据，不是无锁原子快照或publication authority：assembler必须用其root/local/lock identities获取exact existing-only lock，在持锁状态重新收集并逐项比较，随后从create-new marker直至move/sync/marker unlink/final audit持续持锁。缺少这次pre-lock→held-lock比较时，即使section 1/9编码正确也不能授权发布。
- 2026-07-14 当前candidate physical collector在Linux具备openat2 no-symlink/no-xdev/beneath、single-link、local-filesystem及目录终态identity/ADS证明；Windows GNU只证明代码可编译。非Linux traversal仍按现有same-filesystem策略fail closed，必须等原生Windows held-handle/ADS/junction/local-volume矩阵后才能宣称Windows运行支持。
- 2026-07-14 target raw index不能复用source的64 MiB/100,000 profile，也不能仅由`ls-files`重建：candidate section 4必须保留raw `CE_NAMEMASK`、stage/flags、extension与checksum证明。当前`e5744ce`已用独立68 MiB/100,003 profile从同一secure held bytes生成语义与物理四元证据，并在Git探针后绑定较晚完整`.git` inventory；但旧`ls-files`/`ls-tree`全量输出仍限64 MiB，因此尚不能把100,003项parser边界外推为end-to-end GA。下一live assembler必须直接消费raw map、独立构造canonical trees，并从exact loose-object inventory逐对象streaming typed-rehash，且其marker-free snapshot在held mutation lock下重验前不具有publication authority。
- 2026-07-14 `80af987`已消除target端64 MiB Git文本输出瓶颈，但“命令输出streaming”不等于candidate auditor的全局内存上限已闭合：现有`TargetRepository`与临时proof仍可同时持有tracked、raw-index、tree和Git-control多组canonical paths，canonical tree descriptor还曾保留全部raw body。最终fresh collector必须让sections 2/4/5/8的路径借用section-1物理manifest或以visitor即时编码，raw index只保留v4前一path/IEOT必要摘要，tree自底向上逐棵hash后立即释放body；不得通过把各section独立合法的256 MiB预算相加后拒绝来伪造全局上限。
- 2026-07-14 `604624e`证明raw-index语义不需要拥有第二份canonical path：v2/v3可直接比较expected bytes，v4只需借用expected previous/current path验证strip/suffix，IEOT每块首项以空prefix独立解码并与expected partition绑定；生产长期状态只保留version/OID。canonical tree descriptor同样只需OID/size/SHA-256，raw body应在每棵完成typed hash后立刻释放。
- Exact revalidation中的“最终会拒绝symlink”不足以授权一次普通pathname open：`File::open`本身已可跟随恶意symlink并在FIFO/device上阻塞或接触外部对象。安全顺序必须让secure descriptor-relative open得到的held handle贯穿hash、ADS和binding复验，整个过程不再按可变路径重开文件。
- 256 MiB是全进程同时驻留的canonical-path bytes上限，不只是持久manifest的字段总和。当section-1恰好占满预算时，递归栈上的累计`PathBuf`、临时slash `String`以及每层secure directory保存的root-to-child path都构成违规副本；final rewalk必须从唯一manifest借用parent path/basename，只传稳定record ID，并让child directory handle只保留parent fd/name/identity。
- `75f754e`关闭的是section-1形成后的exact revalidation峰值，不是初始采集峰值。现有collector仍先拥有`Vec<NamespaceSeal>`，在审计中同时建立最终records与`BTreeSet<CaseFoldKey>`；即使最终manifest只有一份path，这个过渡阶段仍会复制大量canonical/folded bytes。fresh assembler必须重构该采集路径，用唯一owned record path上的借用排序/prefix/collision证明，不能把最终静态结构误当成全流程驻留上限。
- `865937d`已关闭上述初始采集峰值：section-1路径唯一由最终record拥有，碰撞层只保留定长fingerprint，完成排序检查后立即释放；collector、最终manifest与exact revalidation均不再形成第二份owned canonical-path清单。这个结论不外推到sections 2–8：raw index、tracked/tree/object/commit证据仍必须以`PhysicalRecordId`和临时借用路径组装，且持锁后要再次证明同一physical baseline。
- Fresh evidence中的`PhysicalRecordId`只有在aggregate永久借用产生它的同一`MarkerFreePhysicalManifest`时才是capability；让`project()`接收任意manifest会把旧OID/角色重投影到另一组identity/hash。`f003c64`与`21d0cee`均使用opaque manifest-bound aggregate，字段private且projection无替换manifest参数。
- `.gitattributes`/`.gitignore`不能因“工作树、index与blob OID自洽”就视为安全：非canonical filter/merge规则也会完全自洽并进入seal。fresh sections 2/4/5必须把同一held文件的identity/size/SHA/OID进一步绑定固定`TARGET_ATTRIBUTES`/`TARGET_IGNORE`；`vault.json`则不能固定字节，必须由后续authenticated config authority按同一physical ID与digest交叉绑定。
- 当前fresh模块已经消除sections 2–8的持久owned path与tree/object body，但还不是publication authority：raw index body尚未和section-8同一held `.git/index`四元绑定，object verifier尚未由受控16 KiB `cat-file --batch` reader消费，config与authenticated vault语义未绑定，且pre-lock证据必须在existing-only mutation lock下完整重验后才能输入candidate seal。
- Held snapshot的callback返回前会重验file、ancestor与root namespace binding，但单次snapshot不会在callback后再次hash同inode同长度正文；该边界必须由后续existing-only lock窗口内的最终whole-manifest exact revalidation拒绝，不能把snapshot本身称为hostile same-UID原子快照。
- `git config --file -`不等于Git只读取stdin：若current directory仍在仓库且未设置隔离`GIT_DIR`，Git会自动发现并打开`.git/HEAD`/`.git/config`，甚至会因路径config语法损坏而让valid stdin解析失败。所有held config语义解析必须经固定参数的isolated runner，在清空环境后把`GIT_DIR`指向平台空设备；普通repository/uninitialized命令不能共享该隔离标志。
- Runtime object proof只有在mutation lock窗口内部创建才证明运行时对象审计发生于受控时序；让统一constructor接受锁外预制proof，即使proof永久绑定同一physical manifest，也无法排除proof完成后、lock取得前的对象漂移。因此`InitialCandidateAuthority`构造器必须内部创建并销毁全部borrowed tracked/tree/Git/runtime/auth evidence，只把owned physical manifest、held root、seal和仍持有的lock移出。
- 当前CLI `build_and_audit_staging_vault`在Git target构造前drop freshly audited/unlocked `Vault`，与authenticated authority所需生命周期不兼容。最小接线应返回私有audited-vault owner并让其活到locked aggregate完成；重新unlock则必须重跑完整内容审计，不能只验证metadata MAC。
- 即使held lock与最终exact revalidation接线，advisory lock仍不能约束非合作same-UID写入或swap-and-restore；`GitRunner`也只对direct child有deadline，恶意后代继承pipe仍可使reader/writer join无界。两项都继续是GA边界，当前最多是trusted-local Linux preview。
- v2 marker不能用旧publisher的pathname `OpenOptions`补丁：需要在held `.vault-local`下create-new并持续保留no-follow writable handle、exact file identity和同一scheme投影，完成canonical write/file sync/marker-parent sync/root sync后才能成为claim authority；fresh reconcile还需要existing-marker held opener。没有这些capability时直接整根move会制造无法安全恢复的post-move状态。
- Marker unlink成功但parent sync或clean audit失败是单向状态，不能“恢复”marker：必须进入`PostUnlinkAbsentIndeterminate`，唯一允许动作是重试marker-parent sync、marker-free clean audit和held lock revalidation。若进程在unlink effect后死亡，fresh进程只见clean target，无法知道上次调用是否成功，这是不可消除的ACK gap而非可重建journal缺口。
- publication-specific unlink不能把generic verified-remove的普通`Result`当作事务结果，也不能继承其path-based parent sync。正确组合是保留原marker fd与完整held authority，只把fd clone交给pathname unlink；随后独立分类old-present/absent/replacement/indeterminate，只有原fd为`nlink=0`且exact reserved namespace absent才形成post owner，并始终由held `.vault-local` descriptor完成唯一可信sync。删除已生效后的任何失败都保留同一lock与claim进入live-only单向状态，绝不补建marker。
- destination absence只能是held common-parent descriptor上的bounded observation，不能被命名为reservation或永久proof：marker create-new前与Initial fresh复审后都要观察一次，链接类/跨挂载/不确定lookup不能降格为absent；真正防覆盖仍由后续复审与no-replace whole-root move完成。
- Initial→StagingAudited不能只比较candidate seal后丢弃初审摘要：在同一held-lock evidence scope冻结worktree、Markdown、asset与Git object四项u32，并在marker-aware fresh audit后逐项对账，能让终端计数与安全状态共享同一来源。marker写入前的旧physical manifest必须显式drop以避免两个最高256 MiB路径manifest叠加；core一旦返回Held，任何后续错误都必须把marker/lock放进无forward API的terminal owner。
- held publication marker必须直接拥有existing-only mutation lock，而不能借用它或与它并列返回：否则后续typestate要么形成Rust自引用，要么允许marker authority在lock已drop后继续存在。`347b4cd`让marker owner按值消费lock且把lock放在最后字段，同时持有common/root/local/file descriptors；下一层可消费Initial authority而无需重新取锁。
- v2 marker的durability不能复用path-based `sync_directory`：路径可在检查后换绑并同步错误对象。当前Linux原语只在held `.vault-local`和root directory handles上`sync_all`，创建/打开与canonical正文复验也全部descriptor-relative；Windows在具备等价handle-relative create/share-delete/native证据前继续fail closed。
- ordinary mutation的pre-lock reserved-marker scan会把扫描期间首次出现的`.vault-local`视为indeterminate，这是安全的fail-closed路由，不等同于OS lock未串行。锁竞争测试若从完全空private namespace起跑，会把这条保守分类与锁语义混测；先稳定创建existing lock namespace后再并发，才能精确断言一条commit和一条etag Conflict。
- held root在整根rename后仍指向同一目录inode，但原`SecureSourceDirectory`的root pathname binding仍是staging旧名；post-move descriptor traversal必须由完整`HeldPublicationMarkerV2`先对destination重验，再从同一held fd复制一个只读、destination-bound view。仅凭held fd identity而继续使用旧pathname ADS/binding检查会错误拒绝合法发布，也不能通过重新pathname-open替代held authority。
- marker-aware physical manifest返回后必须保留同一brand的最终exact入口。若只暴露`physical()`，普通marker-free exact会因合法marker失败；若重新collect则会产生新manifest pointer brand，不能为已经绑定旧brand的sections 2–8封口。最小安全组合是wrapper隐藏`&HeldPublicationMarkerV2`和current-bound held root，只暴露借用physical/root及内部授权的`require_current_exact(current_root)`。
- Git control shape preflight必须是fixed-size proof，而不能为方便`require_loose_object`缓存第二份全loose OID/record集合；百万control边界下该Vec会与随后构造的exact object/control evidence同时驻留。canonical loose path只有54 bytes，可在栈上由OID生成并对唯一physical manifest二分查找，保持O(N log N)且不泄露caller-selected manifest或record ID。
- target-only config proof不能自行调用marker-free `physical.require_current_exact`：fresh reconcile的合法v2 marker被section 1有意排除，该调用必然把marker误判为额外private state。该proof只闭合exact config snapshot、isolated parser及held/root/runner前后identity；同brand的完整marker-aware全树exact必须由外层`HeldMarkerPhysicalManifest`在所有fresh sections完成后统一执行，initial-only路径仍保留marker-free exact。
- Fresh root-commit bootstrap必须把“candidate语法/品牌失败”与“isolated Git执行失败”保留为两个内部错误通道：fresh reconcile需要原样返回已scrub的`Io`/`GitCommandFailed`，而initial-only旧API仍显式折回既有`CandidateSealError`。该区分应穿过held snapshot回调，并在root/hooks/ADS后置重验完成后才释放错误，不能用全局或runner side channel。
- 只在Git命令前检查target root identity不足以约束整根替换窗口；固定target-only reader必须在成功和每一种命令失败后再次验证held root、current pathname root及empty-hooks绑定。真实command-window rename回归证明即使wrapper返回合法commit bytes，也必须由post-command guard拒绝旧inode结果。
- Fresh marker-aware九段审计不能把owned marker与借用其physical/git/runtime证据一起装入可移动struct，否则形成自引用；安全组合是局部借用完成聚合，先释放runtime/git/tree/tracked/runner，再由同一wrapper做最终exact，只返回固定大小、明确无authority的摘要。下一consuming typestate可在构造器局部借用该审计后再按值move marker，无需`Pin`、unsafe或自引用库。
- Reconcile输出中的Markdown、asset、worktree与Git object计数必须从已经验证的opaque tracked/runtime evidence重新校验并checked转换，而不能按physical文件名另扫一次或信任caller计数。这样计数与实际candidate seal共享同一manifest brand，同时不复制任何canonical path。
- Marker的publication-id是candidate seal前缀输入而不是外部真实性oracle：fresh审计必须直接使用canonical marker中的ID重算并比较seal。组合回归应固定“用旧ID算出正确seal，再写入另一非零ID的canonical marker”，证明ID变化会因seal不匹配失败且marker原样保留。
- Fresh existing-only不能通过marker-free collector预取expected identities再调用公开`ExistingVaultMutationLock::acquire`：合法v2 marker会让marker-free层失败，而marker-aware层又必须先拥有Held marker，形成循环。最小安全桥是core fused opener：同一descriptor链打开root/`.vault-local`/exact zero-byte single-link `mutation.lock`，在exact fd上前后重验并nonblocking持锁，再按值消费lock与held root打开canonical v2 marker；API只返回Held owner，不返回lock/identities或任何create/recovery能力。
- Generic marker codec只保证portable child names，不知道repository-import domain grammar。Fresh高层接受Held owner后仍必须验证domain精确等于repository candidate domain、staging名精确为`.inex-import-staging-`加32位lowercase hex、destination byte-equals规范化请求且portable-fold不以staging reserved prefix开头，并验证marker common-parent与请求outer parent一致；应与Initial抽取共享helper避免策略漂移。
- 现有generic no-replace整根move可作为Initial的物理namespace operation，但其pathname destination/parent sync和单一`ParentSyncStatus`不能形成v2 durability authority。安全组合必须忽略该sync结论，在move后先以Held owner重新证明destination角色并做第二次完整marker-aware audit；真正durability需要一个不可拆分的borrowed core primitive，按held root fd后held common-parent fd的顺序同步，并在每个屏障之间/最后重复`require_published_at`，不能暴露两个可任意排序的raw sync getter。
- 公共安全错误若保留`#[source] io::Error`，即使手写Debug/Display脱敏，调用方仍可通过枚举解构或`Error::source()`取得可能含路径的底层文本；“scrubbed”类型级承诺必须只存`io::ErrorKind`或固定类别。Fresh fused opener已按这一更强边界丢弃原始source，后续publication错误应沿用。
- Fresh入口不能复用`StagingAuditedClaim`：后者拥有staging adoption/no-replace move语义，会给重启进程错误的forward capability。Fresh只能直接形成marker-last `PublishedWithMarker`；Initial必须在完成no-replace move与destination fresh复审后才汇合到这个共享后半状态。
- Generic verified directory move的`NotMoved`只在parent/held source identity不变、source仍exact且destination absent时返回，可在额外staging-role+fresh重验后保留为唯一可重试Initial owner；`DestinationExists`、`Indeterminate`、critical-audit `Io`都不能自动重试或清理，必须保留marker/lock进入terminal owner。`Ok`只证明exact namespace move，不能信任其pathname `ParentSyncStatus`；仍要destination role→fresh九段重审→role gate后才能构造`PublishedWithMarker`。
- Generic verified directory move的critical callback并非对所有返回值都执行：路径解析、目标已存在、resolver I/O或binding不确定可在callback前分别返回`InvalidPaths`、`DestinationExists`、`Io`或`Indeterminate`。高层wrapper必须按`(callback count, callback failure, move result)`联合分类，保留这些0-call terminal preflight结果；只有0-call `Ok`/`NotMoved`或多次callback才是driver契约异常。
- Initial整根move后的terminal owner必须把root切换为实际destination再做post-move复审；否则marker/lock虽仍安全持有，但诊断状态会错误指向已消失的staging名。generic move的parent sync无论报告`Synced`还是`NotSynced`都不形成durability，后继仍必须经过held root fd与held common-parent fd的独立同步transition。
- Publication durability的最小充分组合是先调用core内建role包夹的held root/common-parent同步，再无条件执行一次`role→fresh九段audit→七字段compare→role`；同步前重复昂贵fresh audit不增加既定cooperative-lock威胁模型下的授权强度。`Ok+review`才是Durable，`Err+review`才可重试，任何review失败都必须terminal。
- Durability owner不能保留`HeldPublicationMarkerV2Error::Io`中的原始`io::Error`：即使Debug/Display脱敏，枚举解构或`Error::source()`仍可能泄漏路径。当前transition在错误进入状态前就归一化为fixed variant或`io::ErrorKind`，并用单一shared comparator防止Initial与durability七字段顺序漂移。
- 高层不能直接返回core的`HeldPublicationMarkerV2UnlinkOutcome`：否则root与expected audit会和authority分离，且调用方可能把“marker已删除”误当成“候选已clean”。正确映射必须把RemovedAndParentSynced命名为`CleanAuditPending`、unsynced限制为parent-sync retry、replacement/indeterminate封入terminal，并持续保留同一lock。
- Core的`NotRemoved`只证明exact marker仍在，不自动证明候选正文未漂移；高层必须在unlink前做完整published review，并在`NotRemoved`后再次review，只有两次role/fresh/七字段/role均通过才重新授予Durable unlink能力。marker一旦absent，任何状态都禁止再次unlink或重建marker。
- marker删除并确认parent durability后，普通marker-free collector仍不足以形成最终成功：它会独立重开root，切断unlink后保留的authority链。安全组合必须由`SyncedPostUnlinkPublicationMarkerV2`派生destination-bound held-root view，以borrowed wrapper隐藏manifest/authority，并在同一authority下执行Forbidden collection、完整九段aggregate、held-root exact rewalk、retained-marker seal compare与最终absence gate。审计错误只有在absence仍exact或暂时indeterminate时可保留同一owner重试；marker replacement、root rebind、七字段漂移或明确authority变化必须terminal且保留现场。`PublishedClean`仍须持有锁/authority直到后续CLI acknowledgement完成，不能在“审计成功”与输出之间提前析构。
- 高层publication API不能只返回摘要并立即drop线性authority：CLI的成功report与失败execution error都必须私有拥有最后typestate，在完整stdout终态写入并flush前保持mutation lock；错误诊断只能在随后消费owner后输出。`b34691c`已把这一lifetime落实到initial创建路径，且公共API只暴露固定计数、lowercase root OID与scrubbed failure kind。
- 当前`repository_import::plan`仍先调用`plan_source_repository`，再由`DestinationPlan::new`拒绝existing destination；这违反fresh reconcile的target-only顺序。下一切片必须先做参数归一化、source/destination disjointness与existing reserved namespace分类，exact canonical v2直接进入existing-only guard；整个分支不得读取source Git/body、提示口令、校准/运行KDF或输出creation字段。
- Fresh real reconcile与Initial创建可以安全共享`PublishedWithMarker`之后的驱动，但入口authority必须分离：fresh只由fused existing-only opener和target-derived audit构造，不能接受Initial的`TargetRepository`/Vault/source seed，也不能获得staging move能力。`25bd9b2`把这条边界固定在公开函数签名与源码契约测试中。
- Existing exact-v2 dry-run可以复用同一fused opener与fresh audit，但必须在公开边界上返回authority-free fixed snapshot，并在返回前释放held owner；它不能返回`PublishedWithMarker`或任何sync/unlink方法。`8ec4dd7`验证marker bytes/identity不变和lock释放，后续CLI只需序列化该瞬时审计快照，不得把它描述为已reconciled。
- CLI的existing-only入口必须把“源路径验证”严格限制为路径/physical identity不相交证明，而不能退回source Git planning：先稳定解析source与destination parent，再对existing destination完成有界目录identity walk；只有absent destination才能进入`plan_source_repository`、password、KDF和construction。
- 仅比较source root、destination parent与destination root三处identity不足以拒绝预存bind-mount别名：destination parent/root可能等于source深层子目录。当前Linux walker从held source root只打开目录、以`NO_SYMLINKS|NO_XDEV`递归并比较所有目录identity；稳定非目录完全跳过，目录分类竞态fail closed。
- Reserved namespace的分类值不是可长期缓存的terminal proof。即使namespace枚举前后同为`absent`，目标目录本身也可能已被另一个同分类目录替换；non-v2终态输出前必须重新证明parent identity、destination identity和namespace class三者均未漂移，否则只能报告`reserved-inspection-indeterminate`。
- Reconcile acknowledgement的authority生命周期因模式不同而不同：preview在返回固定摘要前释放read-only guard；real success与所有post-claim failure必须让opaque owner跨完整有界stdout block的write+flush存活，随后才消费/drop authority并输出scrubbed stderr诊断。
- `resolve_verified_directory`的前后identity采样和held walker能关闭稳定alias及普通canonicalize换绑，但不是抵抗hostile same-UID inode ABA的内核CAS；分类后把非目录换成目录的竞态同样仍在threat gate。计划与文档必须继续把这两项列为GA未完成，不能因`d9dc345`而升级承诺。
- VS Code Task不能先`executeTask`再注册结束监听：非Git小目录、快速失败或target-only reconcile都可能在Promise返回前结束。可靠组合是在start前同时监听process-start/process-end/task-end，按同一`TaskExecution`缓存早到事件；观察到process-start后即使TaskEnd先到也必须等待process-end，未启动底层进程的TaskEnd才映射为unknown exit，并在同步throw/async reject/全部终态释放所有订阅。
- UI的一次`lstat`不能绑定CLI最终dispatch模式。existing target在spawn前消失会转入fresh creation，因此不能据UI分类放宽`INEX_PASSWORD_STDIN`保护；扩展始终拒绝该环境注入口，并明确exact reconcile不会询问口令、若出现口令必须取消。该提示不取代后端的physical identity/fail-closed审计，hostile same-UID变化仍属trusted-local preview边界。
- 长期多提交仓库的“初始化”必须在交互层显式说明语义：fresh路径只复制clean tracked HEAD（Markdown和普通附件）到一个新的parentless密文提交，原仓库/明文历史保持不变；existing exact-v2路径又完全不做source Git planning。因此统一完成提示只能声明selected target通过初始化或对账审计，不能声称reconcile使用了当前选中的source HEAD。
- Umbra不能仅靠现有vault master key或把标签放入Markdown前言实现：普通vault解锁/Outer Mode本来可以读取EDRY正文，因而kind/tag/profile必须由独立随机K_umbra再次加密。安全v1需要feature-2协商、authenticated metadata中的独立Umbra key-slot、reserved encrypted config和包含public marker/outer entry加nested slot cipher的canonical document container；否则Outer搜索、普通编辑或配置同步都会泄漏私密分类。
- Umbra v1 的 keyslot 不能复用 `vault.json` password slot：它须具有独立的 salt、KEK、随机数据密钥与 slot-file AAD。Outer master key 不参与 `K_umbra` 派生或解包；因此 feature-2 不能在 private container 支持之前提前标记为 reader-supported。
- 已解锁会话的 Umbra 密码重置安全地以 live `K_umbra` 为唯一授权：重新生成 salt/nonce/KEK、原子替换 slot 文件即可；绝不能要求或保留旧 Umbra 密码，也绝不能逐 slot 重加密作为密码修改的副作用。
- Vault 层的 Umbra session 必须持有 slot 的 ciphertext etag，以在已解锁会话中用 CAS 原子替换 password slot；不能在外层 mutation guard 内再次调用独立 atomic writer，否则会造成重入锁风险。内部目录须在同一 guard 下创建并验证类型、挂载和大小写别名。
- 配置 envelope 必须把 vault ID、`K_umbra` 的 key ID、canonical `.inex/config.umbra.inex` 路径和 schema version 作为 AAD/derivation context；只用单一 Umbra key 而不做 domain separation 会让 config 与 private-slot 密文跨用途替换缺少明确边界。
- Private slot ciphertext 的 AAD 必须覆盖公开 Outer strategy；否则攻击者可把 `drop`、`placeholder`、cover text 等公开语义替换而仍让私密正文解密成功。slot key 还须绑定 logical document path 与 slot ID，禁止 slot 在文档间移植。
- feature negotiation 必须按能力包含关系判断、而不是比较整个 feature vector：启用 Umbra 后已有 opaque-asset vault 的 authenticated metadata 合法值是 `[1,2]`。但每个 Umbra Outer EDRY envelope 仍必须精确声明 `[2]`，确保容器 reader 选择不会与普通 Markdown/asset 混淆。
- Outer projection 不需要 `K_umbra` 才能读取（它只含公开 Markdown、slot ID、公开 outer strategy 和 slot ciphertext），但创建或保存 feature-2 container 必须要求 live Umbra session；常规 `Vault::read` 必须拒绝 feature-2 envelope，避免普通客户端把内部 JSON 误当 Markdown 展示或回存。
- 私密 slot 的“移除/解包”必须先在同一 live session 解密并验证 ciphertext，再在内存中移除并执行 ETag 条件保存；只有保存成功才能把 payload 返回给上层 RenderMap/编辑器。这样失败写回不会让上层把尚未持久化的私密 Markdown当作已恢复的普通正文。
- Slot 表与 Outer marker 不是可独立保存的两份状态：缺 marker 会丢失 Umbra 可见性，dangling marker 会使渲染失败，重复 marker 会使同一私密正文多次进入投影。因此所有 feature-2 create/save/insert/remove 路径均需验证“每个 slot 恰一个 canonical marker”，而包裹/解包必须把 Outer Markdown 替换与 slot 密文变化放在同一 ETag 条件事务中。
- `apply_private_annotation` 的安全提交边界是“当前 feature-2 ETag + 完整 Umbra 投影 + 完整 RenderMap”三者同时一致；单靠投影 hash 不能表达存储并发，因此写入仍由 feature-2 ciphertext ETag CAS 收尾。纯文本区先通过 RenderMap 映射回一个完整 Outer 段，随后按倒序替换 marker，才能在已有私密块周围安全处理多选且不发生坐标漂移。
- daemon 不能把 Umbra 复用成普通 `document.open`：后者会调用普通 EDRY 读取路径并按设计拒绝 feature-2。独立 `umbra.document.open` 仅在同一 Outer capability session 已持有 `K_umbra` 时渲染 projection，锁定后统一映射为认证失败；RPC capability `umbraV1` 让客户端在发送密码或私密投影请求前先协商支持。
- `umbra.annotation.apply` 必须接收完整、由同一 `umbra.document.open` 返回的 RenderMap，而不是仅接受 client 的 range：handler 逐项限定 map/selection/spec 的结构与资源上限后，核心仍以传入投影 hash、RenderMap 等值和 ciphertext ETag 重新认证。响应只在成功提交后附带新 ETag、投影和 RenderMap，客户端不得自行推演 slot ID 或 marker。
- RenderMap 不仅要记录私密 fenced block 范围，还必须记录普通 projection 段到 Outer Markdown 的一对一坐标；否则多选 wrap 无法在已有私密块周围安全地回写 Outer 容器。跨段或跨私密块的普通选区统一按 mixed/partial 拒绝。
- Neovim 已被纳入正式交付目标，但优先级固定最后。它必须以 Lua 客户端复用 `inexd` 的已验证 Umbra RPC，绝不能绕过 `K_umbra` 会话或直接解析 feature-2 容器；因此先完成 daemon/VS Code 共享协议与隔离回归，再进入其骨架实现。
- `umbra.annotation.remove` 的 RPC RenderMap 将私密投影范围规范化为 `privateSlots[].startByte/endByte`（不是 Outer segment 使用的 `projectionStartByte/projectionEndByte`）。客户端或回归必须消费 daemon 返回的完整 map，而非从 marker 或 UI 坐标推导 slot/range；`cover` profile 也必须在 UI 端无条件收集公开文字，避免把不一致的 catalog flag 变成可到达的无效 core 请求。
- `noSelectionTarget: paragraph` 必须按 UTF-8 byte buffer 的连续非空行解析，不能用“当前行”冒充；以纯函数返回不含换行符的 range，blank/whitespace-only line 返回 undefined，使 host 在复制 snapshot 后立刻清零，而不会把空白段提交给 daemon。
- 编辑器本地偏好只允许影响交互（`paragraph`/`line`/`reject` 与 unwrap confirmation）；其解析必须对非法值安全回退。不能将“上次 tags/profile”塞入 VS Code settings，因为那些是受 `K_umbra` 保护的语义数据；若未来实现 useLast，必须仅保留可在锁定时清理的 session 内存状态并配套回归。
- Cursor-inside-private 编辑不能把零长度 cursor 直接作为 RPC `TextRange`：core 的 canonical range type 故意拒绝空范围。客户端应由 authenticated RenderMap 确认 slot 后选择该 canonical fenced block 开头的一个 ASCII marker byte，作为严格 `InsidePrivateSlot` 的非空证明；绝不能由 slot ID 或未认证 UI 坐标直接编辑。
- VS Code 的 edit picker 可从已解锁、canonical projection 的 fence header 预选 kind/tag/Outer，但这只是 UX 初值：被解析的 tag IDs 必须仍属于加载后的 encrypted catalog，实际 edit 绝不能信任 header/slot ID 而跳过 daemon 的 projection+RenderMap+ETag 复核。Cover text 只作为明确公开字段重新询问，不从私密 payload 猜测。
- Tag catalog 的加密不等于只加密 JSON：schema 还必须验证 stable-ID 唯一性、catalog 排序、profile/default 的所有引用和 Cover prompt 语义。否则一个认证正确却相互矛盾的 catalog 会在跨编辑器同步后造成无法选择/保存的 annotation；所有管理操作应走 Vault 的 authenticated load→mutate→CAS save，而非编辑器直接写密文文件。
- VS Code sidecar 的 tag mutator 也需要在 client 边界限制 canonical ID、UTF-8 文本与完整 reorder permutation；这不是替代 daemon 验证，而是防止 UI/extension bug 将超限或重复私密元数据送入本地 RPC。每次 mutation 后 UI 应重新从 daemon 加载 catalog，而不能合成持久状态。
- Tag label/description 是 `K_umbra` 保护的私密 catalog 数据，即使在 VS Code UI 也不能用普通 `showQuickPick` 承载：普通 API 没有可由 lock event 主动清空/关闭的 picker handle。所有含私密 label 的选择必须使用 `showSensitiveQuickPick`; 后续非私密操作菜单不得把 label 拼入 title/detail。
- Profile 的 stable ID 与 tag ID 同样是加密 catalog 内的语义；edit 不得实现为 remove+create，否则用户 keybindings/default profile 会失效。删除 profile 时必须在同一 authenticated config save 中清理 default reference，不能留下一个 schema 上悬空的 defaultProfileId。
- Profile RPC 的 nested object 不能复用 annotation 的公开 cover-text spec：profile 仅保存 Outer mode 与 `promptForCover`，不保存任何实际 cover text。所有 profile field（包括 ID、label、selected tag IDs）是 K_umbra catalog 数据，必须经 sensitive 参数层读取且只把 validated values交给 core。
- VS Code profile 管理器必须把“复用 annotation picker”限制为 metadata draft：`cover` 仅是 profile 的 mode/prompt 语义，不能在 create/edit profile 时采集一次性公开 cover text。真正将 profile 应用于 slot 时才收集该公开内容；否则会把无归属的 cover 文本留在 UI 流程或错误写入 catalog。
- `toggleBehavior` 的 `useLast`/`askOnFirstUse` 不能把上次 tag IDs 或 Outer 选择写入 editor-local settings；实现只能保持在当前 authenticated extension session，并在 Umbra lock 时主动丢弃。`useDefaultProfile` 不信任 settings 提供 profile ID，而从已解锁 encrypted config 的 validated defaults 得到 stable ID。
- `headingSection` 只能以 Markdown ATX heading 识别当前章节，且应以 byte range 返回给既有 RenderMap/daemon 边界；没有前置 heading 时返回 undefined，而不是用整份文档作为便利回退。
- `useDefaultProfile` 只有在用户可安全设置 encrypted default 时才是完整功能。默认 profile ID 必须由 `K_umbra` catalog transaction 写入/验证，不能由 VS Code window setting 或快捷键参数承担；profile 删除时同一 transaction 清空 default，避免悬空选择。
- Umbra 的 canary/atomicity 回归若长到难以审查，应拆为显式命名的 test helpers，而不是压低 Clippy 门槛：辅助函数仍在同一测试模块中持有真实 Vault、Outer container 与 ciphertext evidence，因而不改变安全测试的执行边界。
- CustomEditor 的 textarea 不能原生表达多 cursor，因此多范围采用显式 Add range/Clear ranges UI，不在 extension 中截获原始键盘事件。host 仍限制每条 webview message 的 range 数、整数性与 UTF-8 byte 边界，最终 selection normalization/partial-private 拒绝仍由 daemon/core 认证。
- Sublime tests 不是 Python package 安装模式；从 repo root 执行时必须指定 `PYTHONPATH=editors/sublime`。否则 `inex_rpc` 等插件同级模块无法被 unittest discover 导入，属于 test invocation 环境错误而非插件代码回归。
- Sublime 的 Umbra mutation client 必须同时把 projection byte buffer、ciphertext ETag、完整 RenderMap 作为一个认证输入边界；不能由 UI 根据 fenced marker 推导 slot ID 或重新构造 map。响应 generation 应 canonical decode 为精确 32 bytes 后立即清零临时缓冲；客户端仅保留可再次序列化的 canonical text form。
- Release lifecycle harness 的 process-containment assertions 以 Linux pidfd/subreaper 为硬安全前提；当前环境缺失该能力时必须 fail closed，不能降级为普通 process-group kill 或将未执行的 assertions计入发布证据。Python release tests 从 repo root 运行需显式 `PYTHONPATH=scripts`。
- Sublime 的 Umbra lock 是 `K_umbra` 生命周期操作，不能复用 vault lock：它必须只丢弃 daemon 的 Umbra session，Outer tree/session 保持可用。客户端必须拒绝 `initialized: false, unlocked: true` 这类逻辑不可能的 status，防止 host UI 在无密钥状态展示私密操作。
- Sublime 不能把 Umbra 密码写入 input-panel/settings；复用受审计的外部 masked prompt，并把密码变量限制在 worker scope。每次 password/status 回调都要重新验证 Outer client identity 与 generation，避免旧会话在 lock/reunlock 后完成私密初始化或解锁。
- Sublime 的 repeated Quick Panel 无原生多选，安全实现应只把 encrypted catalog label 保留在 `AnnotationPickerState`，每次点击后再展示，且在 cancel/lock/dispose 调用 `clear()`；不能将标签 label 放进 settings、command args 或持久化状态。
- Annotation profile 与 instance annotation spec 不能共用 cover payload：profile 的 `cover` 只表达 `promptForCover` 语义。Sublime 在 profile apply 后仍必须在真正 daemon mutation 之前请求一次公开 cover text，避免把无归属文字写入加密 profile catalog。
- Sublime standard Quick Panel 没有可保存的 multi-select handle；stateful picker 必须在每次选择后重开，并在 lock 时同时 clear in-memory state 和 `hide_overlay`。仅 clear state 而让旧 overlay 保留会使锁后仍可见私密标签。
- 进入 Umbra container 不是客户端 buffer 标记：普通 document 必须先用 current ciphertext ETag 调用 `umbra.document.convert`，然后放弃 normal document identity并重新读取 canonical Umbra projection。feature-2 由 EDRY header 的 authenticated `required_features=[2]` 表达；RPC `metadata.flags` 仍是内容 flags，只可为 0/1，客户端不得把两者混为一谈。
- Umbra projection 不能伪装为 `document.open` handle：普通 close RPC 只对 daemon-issued normal handles 有效。Sublime model 必须以空 handle + authenticated RenderMap 表达 Umbra document，并在 mutation 成功时整体替换 projection identity。
- normal→Umbra transition 的安全顺序是 daemon CAS convert、daemon authenticated projection open、main-thread identity recheck、model transition、再关闭旧 normal handle。任何 dirty/locked/stale model 都要在 transition 前拒绝，且传入 projection 必须 wipe。
- 当 `umbra.document.convert` 已成功后，普通 document buffer 已不能安全继续作为 normal document 保存。若随后 projection open、UI identity recheck 或 transition 失败，Sublime 必须锁定并 scrub 全部 managed buffer，而不能仅恢复 view 可编辑性。
- Sublime selection points 是 host character offsets，annotation RPC 却要求 canonical UTF-8 byte ranges；必须从当前 view 前缀编码计算每个 selection 的 start/end，而不使用 Python character index。apply completion 必须同时检查 Outer 与 Umbra generation，否则 Umbra lock 后异步响应可重新安装私密文本。
- Sublime annotation picker/confirmation 可跨越异步 worker；因此 RPC worker 不得读取可变的 `ManagedDocument.content`。必须在主线程验证 view 与 model 一致后复制 projection，明确为 success/cancel/error 三条路径分配清零所有权；remove 仍只把 selection/ETag/RenderMap 交给 daemon，客户端不从 fence 或坐标推断 slot ID。
- Neovim 是正式但最后优先级的客户端目标：Lua 端只能作为 `inexd` JSON-RPC 的受控消费者，沿用 same-vault Outer/Umbra key lifecycle、ETag/RenderMap mutation boundary 与宿主残留 gate；任何直接解密 EDRY/feature-2 或重做密码学的实现都超出冻结架构。
- Sublime edit 的 visible fence header 只能用作已解锁 UI 预选，绝不是授权输入：客户端先以 authenticated RenderMap 找到 slot，再将完整 projection、ETag 和同一 map 发给 daemon。cursor 是零长度，必须转换为 block 内最小非空 byte range；完整 block selection 则必须拒绝 edit 并走需确认的 remove。
- Sublime toggle 只能作 RenderMap 路由器，不能根据 fence 文本或 slot ID 作授权分类：all complete ranges 才可 request remove，单一 contained range 才可 edit，任何与 private range 的 partial overlap/mixed selection 都必须在 picker 前拒绝。Linux keybindings 必须作为 `.sublime-keymap` 数据贡献，而非 Python raw-key event handler；新 Python module 还必须同步加入 release allowlist，否则生成 package 会在运行时缺少模块。
- Sublime profile shortcut 的 `profile_id` 可来自用户 keymap，但不是可信配置来源：每次调用仍必须在 live Umbra session 中读取 encrypted catalog、查找 exact profile 并由 picker state 验证 tag/Outer 语义。`cover` 是一次性公开实例字段，不可由 profile 携带；其验证失败/取消时必须释放已捕获的 private projection。
- Sublime tag/profile 管理必须经 daemon mutation RPC；client 要在请求前限制 ID、文本、排序和 canonical tag sequence，并把任何 malformed acknowledgement 当作 terminal protocol violation。这样 UI 后续只拥有 transient catalog data，永远不直接操作 `.inex/config.umbra.inex`。
- 加密 catalog 的 AEAD 认证不足以保证安全可用：客户端还必须完整验证 tag/profile/default schema 与所有 cross-reference，特别是 default/profile 的 canonical tag order 和 cover/prompt pairing。否则一个已认证但语义矛盾的 sync 冲突可能把 private labels 送进 UI 后才失败，或者生成不可持久化的 annotation spec。
- Sublime tag management 只能以 transient repeated panel 表现 encrypted label；每次 mutation 成功后必须丢弃旧 config 并重新经 daemon `config.get` 读取，而不是在 host 端修改 cache。lock 时调用 `hide_overlay`，并以 Umbra generation 阻止旧 panel/worker 完成后继续写入。
- Annotation profile 管理与 annotation apply 必须分开：profile picker 只能保存 kind/tag IDs/Outer/prompt metadata，不能复用需要 `coverText` 的 instance picker。编辑 profile 时 stable ID 不能变化，但 label 可改变；remove 后 daemon 在同一加密 config transaction 中处理 default reference。
- 主 checkout 含历史 linked worktrees 时，release packager 应拒绝其 provenance。可审计构建须在 `--no-local` standalone clean clone 中进行、origin 指向 canonical repository；同时显式绑定 `/usr/bin/gcc`/Cargo linker，避免 PATH 的 xlings linker 生成 nonportable interpreter。当前 `739b9f0` Linux x64 三件 artifact 已经通过结构交叉审计，但这只证明本地 construction，不替代 pidfd lifecycle、isolated editor runtime 或发布签名证据。
- `smoke_release_artifacts.py --vscode-cli /usr/bin/code` 是当前候选的正确安装验证入口：它自己创建 disposable extensions/profile context，并检查 packaged VSIX 安装后的 exact bundled CLI/sidecar layout、executable mode 与 runtime probe。手动 `code --install-extension` 只能作为诊断，不能替代该完整 smoke record。
- Neovim 插件不得把 sidecar 当作无参数 JSON line protocol：`inexd` 必须以 Content-Length frame 常驻启动，`system.hello` 必须发送 client、clientVersion、protocolMajor 三个 required params。Lua 侧只拥有 process/transport 生命周期；任何 vault key、EDRY parsing、Outer/Umbra projection 都必须继续留在 daemon。
- Lua local 的作用域从 declaration 才开始：将 `HELLO_PARAMS` 写在 `ensure_started` 后会让 callback 捕获 global nil，导致 RPC client 以“request invalid”失败。Neovim buffer MVP 必须先拒绝 feature-2 并保持普通 projection 只读；设 `swapfile=false`/`undofile=false`/`bufhidden=wipe` 只是 host-residue gate 的必要基础，不能替代对 cmdline/shada/undo/LSP/third-party plugin 的独立证明。
- Neovim transport smoke 必须在同一 event loop 内用 `vim.wait` 等待 asynchronous pipe callback；普通 headless module-load 只能证明 Lua syntax，不能证明 Content-Length reader、spawn、hello response 或 close path。测试 sidecar 路径用 environment 输入，避免把 machine-local binary path 写进 plugin configuration。
- Neovim `vim.base64.decode` 接受 canonical unpadded Base64URL 的大多数长度，但会拒绝某些需要尾部填充的合法 payload（例如 `Cg`）。Lua client 必须在协议边界先严格验证 unpadded URL alphabet/长度，再转换 `-_`、补齐至四字节组并 decode；不能要求 daemon 改用 padded/standard Base64，因为 daemon 的 canonical RPC 协议已固定为 unpadded Base64URL。
- Neovim ordinary buffer 只能用 `buftype=acwrite` 加 buffer-local `BufWriteCmd` 承接 `:write`：`acwrite` 使 `inex://` 名称不会被作为本地文件关联，但仍拒绝静默 abandon；保存回调必须保留 captured ETag、session 和 document identity，只有 daemon 返回同路径且 canonical metadata/durability 后才清除 modified 标志。
- `bufhidden=wipe` 与单窗口 browse 不可兼容：切换到 tree 会 wipe 原 document，而不是仅隐藏它。不要为便利改为 `hide`；tree 应在独立 split 显示，并与 document 一同由 lock/stop 主动 wipe，才能同时保持使用体验与关闭残留边界。
- Neovim 内存搜索不能用普通 `input()`，因为 query 可能进入命令行 UI/历史；`inputsecret()` 至少避免明文回显。它仍不消除宿主/OS 内存边界，因此 query/result 都必须只驻留在当前回调或 lock/stop wipe 的 scratch buffer，且 README 不应声称该机制覆盖 shada、第三方插件或内存取证。
- Neovim 目录创建应保持 daemon 的单层语义：不根据 `InexNew` 的嵌套路径隐式逐级 mkdir，也不把任意 parent 视为已认证。用户必须先显式执行 `InexMkdir`；这样失败路径和 Git/daemon 的 atomic directory invariant 不会被客户端便利逻辑重写。
- Neovim Umbra lifecycle 只能保存非秘密状态旗标，绝不可缓存 password、KEK、slot cipher 或 `K_umbra`。初始化是否允许须先以 authenticated `umbra.status` 判断；Umbra-only lock 与 Outer lock/stop 的本地先行清理保证旧 RPC callback 不会把已锁状态重新标成解锁。
- `required_features` 与 `metadata.flags` 是两个不同层次：feature-2 private container 的身份来自 authenticated EDRY header `required_features=[2]`，但 RPC metadata 的 `flags` 仍只是 content flags（normal/unresolved merge 为 0/1，draft 为 2/3）。把 feature number 当作 metadata flag 会让真实 daemon projection 被客户端错误拒绝；该问题已由 Neovim 实际 convert/open 回归发现并在 Sublime Umbra RPC 中修正。
- Neovim normal→Umbra 不能只切换 buffer label：必须执行 CAS convert、再读取并严格验证 daemon projection/RenderMap、重检当前 session/Umbra/buffer identity，最后关闭 normal handle。CAS 成功后任一步失败都应直接 lock/scrub，因为普通 buffer 已没有合法 save path；只读 private projection 也必须在 Umbra-only lock 时主动 delete，而不仅在 Outer lock 时处理。
- 私密标注的 mutation response 比 document-open response 多出 `durability`，客户端不能把完整五字段 object 直接传入严格四字段 projection parser；必须先对 mutation response 作 exact 五字段/durability 验证，再显式抽取 projection 四字段解析。否则会在成功 daemon 写入后错误拒绝新投影，导致客户端停留在过期 RenderMap。
- 产品语义中的 private tag 是“零或多个”。daemon annotation spec 和 annotation profile parser 先前错误给 `required_sensitive_string_array` 传入最小长度 1；这会让空标签的合法标注不能通过 RPC。该最小长度已更正为 0，而 tag reorder 仍正确要求非空完整 permutation。
- Neovim `nvim_create_user_command` 的 `nargs` 不是任意整数；只允许 `0`、`1`、`?`、`*`、`+`。多参数安全命令应使用 `*` 并在 callback 内对参数数量/数字性做明确校验，不能依赖注册 API 隐式强制。
- Neovim visual mark 的 API 坐标不可混用：`nvim_buf_get_mark` 返回 1-based row、0-based byte column，而 `nvim_buf_get_offset` 接受 0-based row。私密 selection 要传 UTF-8 byte range，必须在这两个边界显式转换。canonical private fenced block 末尾含换行，字符级 visual range 不能表达完整 block；linewise selection 应把 end 扩到下一行的起始 offset（或文件末尾），才能安全路由到 confirmed remove。
- Toggle 分类不能只分 plain/complete/partial：RenderMap 单一 private block 内的严格非空 range 应走 `umbra.annotation.edit`，而完整 block 必须继续只走需确认的 remove。客户端只负责 range 路由，不可从 visible fence/slot ID 重建 metadata；daemon 的 projection+ETag+RenderMap 复核仍是授权边界。
- Neovim catalog 读取必须在私密 label 进入 picker 前完整验证 tag/profile/default 的 schema 与交叉引用；AEAD 认证不能替代语义验证。读取 API 只能把 result 交给同一 live Umbra callback，不能在 module state/editor setting 中缓存，以便 Umbra lock 不留下标签或 profile 名称。
- Editor-local shortcut 不能承担 Umbra default profile/tag 配置；它最多触发一次 live encrypted catalog read，再将 validated defaults 作为 one-shot mutation spec 使用。
- Repository-import Git plumbing 现在以 Unix `process_group(0)` 启动，并用 safe rustix `kill_process_group` 在超时/异常前清理同组的 inherited-pipe descendants；Linux shell+background-sleep 对抗回归验证 direct child 与 descendant 均被回收。该机制不能约束主动 escape group 的 hostile same-UID descendant，也没有替代 Windows Job、pid identity/TOCTOU 或完整 process-tree GA 门禁。

## 2026-07-16 VS Code CustomEditor regression discovery

- Browser `<textarea>` normalizes CRLF presentation text to LF. The existing navigation and selection message paths passed that presentation text into `InexDocument.applyEdit`; opening a CRLF Markdown ciphertext and merely invoking Headings could therefore mark the CustomDocument dirty and re-encrypt LF-normalized bytes. This exactly explains the observed unchanged-worktree `.md.enc` Git modifications and must be fixed at the webview/presentation boundary rather than by changing Git attributes.
- Git's normal Source Control diff sees EDRY ciphertext and must remain binary/opaque: handing plaintext to Git textconv or a background SCM subprocess would bypass the authenticated Inex session and risks disclosure. A future diff feature must be an explicit authenticated Inex revision comparison view, not a normal Git plaintext diff contribution.

## 2026-07-16 Cross-editor semantics and requested plaintext export

- CodeMirror/Lezer (VS Code), Sublime syntax resources and Neovim Treesitter/UI need not share an implementation to share behavior: `inexd` remains the only source of document identity, authenticated Markdown navigation, private RenderMap semantics, searches and mutation authorization. Editor-local parsers are display-only and must never become persistence or authorization inputs.
- A requested administrator/strengthened-mode Markdown export must not be modelled as an admin bypass. The safe product shape is an explicit plaintext export capability available only to an already authenticated Outer session (and an independently unlocked Umbra session for private content), with a distinct high-risk confirmation and a destination outside the vault. It necessarily creates user-authorized plaintext and therefore cannot preserve the normal no-plaintext-on-disk guarantee.

## 2026-07-16 VS Code webview repair decisions

- The CustomEditor now preserves canonical CRLF bytes by presenting LF-only text to textarea and mapping all presentation byte/UTF-16 offsets back to canonical plaintext. Selection messages no longer mutate content; navigation snapshots any genuine unsent edit through the same mapping, so heading/link interaction remains current without turning CRLF normalization into ciphertext rewrites.
- Markdown presentation is intentionally a second, display-only webview script rather than a prerequisite editor runtime. An initial monolithic inline highlighter could make a webview syntax error prevent the `ready` handshake and thereby break backup/recovery integration. The main controlled editor starts first; the presentation layer has no host-message authority, no persistence path and cannot block lifecycle behavior. A future CodeMirror migration must retain this availability and authority separation.

## 2026-07-16 CRLF ciphertext Git no-op regression

- The isolated VS Code Extension Host fixture now imports a real CRLF Markdown file, opens it alongside an image-bearing note, hides/reveals both CustomEditors, closes them, and runs `git -C <vault> status --porcelain=v1 -z`. The output is required to be empty before any intentional mutation. This is a direct regression gate for the reported false `.md.enc` `M` state, rather than an inference from in-memory presentation mapping tests.
- This evidence is limited to the disposable Extension Host profile. It does not claim that VS Code persistent-profile Local History/SCM extensions or a user-specific configuration cannot create independent side effects; those remain release-gate work.

## 2026-07-16 Markdown presentation boundary

- The CustomEditor display layer can offer substantially richer Markdown visual tokens without turning plaintext into a normal VS Code document: it reads only the already-present textarea string and writes escaped spans into its own `aria-hidden` overlay. The textarea remains the sole input/selection/snapshot path.
- The presentation script must not receive `acquireVsCodeApi`, `postMessage`, network, file, or clipboard capability. A source-level regression now rejects those identifiers in the presentation script itself; the primary webview script remains the only host-message authority.
- Static API isolation is supplemented by VM rendering: Markdown containing a literal `<script>` must become escaped display text while heading/list/emphasis/code/link/quote/rule spans still appear. This protects the intentional `innerHTML` display sink from becoming an injection path.
- This improves highlighting but is intentionally not a Markdown language-server integration. LSP completion/diagnostics would require an explicit separate in-memory editor architecture and its own residue/lifecycle security proof.

## 2026-07-16 Real repository bundled-CLI import gate

- A real repository import must run as one observable process: the 324-entry, 46 MiB `_blog` clone spends over two minutes in KDF/encryption/object audit after printing its public source plan. Tool output windows can return before that child exits; launching another import would create concurrent plaintext clones. Use one detached tracked process, poll its PID/output, and explicitly clean its one temporary root after verification.
- A byte-count prefix is not necessarily valid UTF-8 and is unsuitable as an `rg` fixed-string canary. Use a complete nonempty source Markdown line, validate it with `iconv`, then require an encrypted-vault scan to return no hit. The earlier truncated-pattern scan was rejected by `rg` and was not counted as evidence.

## 2026-07-16 Plaintext Export v1 boundary

- Plaintext export cannot share the normal CustomEditor or Git/SCM code path: a successful export deliberately creates user-visible plaintext on disk, whereas the editor pipeline must remain ciphertext-only on disk. The safe common boundary is therefore a daemon-owned, session-bound two-step transaction with a capability that is invalidated by Outer/Umbra lock rather than an editor-local confirmation boolean.
- Outer-only export must never decrypt feature-2 slots or catalog; Umbra-inclusive export requires a separately live Umbra session and emits canonical annotated Markdown without exporting a standalone private-tag/profile configuration. This gives an intentional portable Markdown result while avoiding accidental profile/catalog plaintext persistence.
- The existing `atomic_publish_directory_no_replace_checked` is deliberately vault-specific: it requires an import-prefixed sibling staging name and an internal `.vault-local` directory/marker. Export must not fake that structure or reuse the vault marker protocol for plaintext output. The lower-level `atomic_move_verified_directory_no_replace_checked` already provides the required generic sibling no-replace publication, source/parent identity rechecks and fsync checkpoints without those vault assumptions; export should use that primitive directly rather than introduce a duplicate publisher.
- A first planning-only patch tried to append an error-table row using stale context and was rejected before changing files. The corrected patch narrows the edit to the exact live export checklist/finding paragraphs; no product source or plan state was partially written.

## 2026-07-16 Outer-only export projection

- Feature-2 disk plaintext is the canonical Outer JSON container, not directly exportable Markdown. `render_outer_projection` must replace authenticated marker occurrences from the public `OuterSlotStrategy`; emitting container JSON would expose ciphertext grammar to users, while using full `render_umbra_projection` would incorrectly require/decrypt `K_umbra`.
- The first new assertion encoded a literal backslash plus `n` instead of a newline and failed one focused test. The test was corrected before any broader gate; all three projection tests and pedantic core Clippy now pass.

## 2026-07-16 Plaintext export staging transaction

- Export staging cannot use an RAII delete-on-drop helper: after authenticated plaintext has been written, automatic cleanup risks deleting user-authorized output or hiding an incident. `PlaintextExportStaging` therefore deliberately retains the directory on every pre-publication failure while the generic no-replace move prevents replacing an existing final destination.
- The generic mover alone does not audit export content. The caller-provided audit runs after the final identity/absence checks; the next export engine slice must write only create-new restrictive files, fsync and digest them, then make that manifest audit the publish callback.
- The staged-file manifest initially proved only files recorded by the writer; this is now superseded by the exact-tree Vault export engine below.
- The Vault export engine now makes the manifest exhaustive: logical directories are recorded even when empty; ordinary Markdown, opaque assets and feature-2 document projections are all create-new staged entries. Audit recursively permits only those exact registered paths and rejects links or unexpected siblings before publication. An Umbra-inclusive attempt checks for a live `K_umbra` before tree discovery or staging writes, so a locked request cannot leave a partial plaintext tree.
- A confirmation capability must own the authenticated logical tree snapshot, not merely counts returned to UI: commit now receives the stored snapshot, so later-added paths are excluded and missing/unsafe snapshot paths abort before publication. The empty sibling staging root is reserved during prepare to bind parent/destination identities without writing plaintext; it remains intentionally retained on later failure under the documented incident-handling policy.
- CLI export invokes the same strict `RpcService` request surface as `inexd`, rather than importing the core plaintext writer. This keeps prepare/commit/capability behavior identical in the command-line process while avoiding a second serialization or filesystem implementation. The destructive confirmation remains outside password stdin handling: ordinary use requires hidden typed `EXPORT PLAINTEXT`; the only bypass is the intentionally named `INEX_EXPORT_TEST_CONFIRM=1` test hook exercised by a real child-process regression.
- `create_dir_all` is unsuitable below plaintext staging because a same-user replacement can redirect a nested path through a symlink. The writer now creates and link-checks every component individually; its remaining same-user namespace TOCTOU boundary is the generic publisher's documented cooperative-writer scope.

## 2026-07-16 VS Code security-status semantics

- Reporting only the Outer session state makes an unlocked vault look equivalent to an active Umbra session. `Inex: Show Security Status` must query `umbra.status` only through the current authenticated session and display the initialized/unlocked distinction; query failure remains "private data unavailable" rather than defaulting to unlocked.
- The first intended Extension Host command was named `test:integration`, but the package deliberately exposes `test:extension:local`; the missing-script failure was non-evidence. The declared local Extension Host gate then passed.

## 2026-07-16 VSIX package audit invocation

- `audit_native_dependencies.py` accepts the standalone release `inex` and `inexd` paths, not the packaged Rust ZIP. Passing the ZIP stopped the first post-package chain before smoke/install; artifact structure audit had already passed but no installation claim was made. Re-running the audit with both release binaries, then package smoke, then explicit VSIX install completed successfully.
- VS Code CLI emitted host-owned Node `DEP0169` `url.parse()` deprecation text during install, while installation exited successfully and package-vs-installed `extension.js` digests matched. Treat this as host CLI noise unless a trace attributes it to Inex.

## 2026-07-16 Umbra password-reset editor boundary

- The frozen Umbra v1 semantics permit a password reset only while `K_umbra` is live; the editor must therefore not route this command through the normal unlock/initialize helper. It first authenticates the current sidecar session's `umbra.status`, rejects a locked status, and collects only a new password plus confirmation.
- The RPC receives the new password as a bounded sensitive parameter and returns only `{"ok": true}`. A post-change lock must make the old password fail while the replacement unlocks the same private document; this proves a slot rewrap rather than a new-key/private-data rewrite.
- The current Linux bundle was rebuilt from a clean `03f5011` checkout after this protocol addition. Artifact/native-dependency/smoke gates passed and the package extension hash exactly matches the installed VS Code extension. The VS Code CLI again emitted the host Node `DEP0169` warning; it did not alter the successful install or hash comparison.

## 2026-07-16 CLI Umbra password change boundary

- A CLI invocation does not inherit an editor's live `K_umbra`, so it cannot implement the no-old-password reset path. Its explicit command instead requires current Outer and Umbra credentials, then delegates only the rewrap to the same daemon RPC. The VS Code command remains the intended path for a user who forgot the old Umbra password but has not locked the existing session.
- JSON-RPC optional fields must be omitted, not serialized as `null`: `vault.unlock` has strict optional UUID parsing. The CLI constructs `slotId` only when the user supplied `--slot`, preventing a silent protocol incompatibility.
- Because the VS Code bundle embeds both CLI and daemon binaries, a CLI-only source change still requires release-set repackaging. The `499ac92` package was audited/smoke-tested and its embedded `inex`/`inexd` hashes were compared directly with the installed extension, not inferred from the unchanged TypeScript bundle hash.

## 2026-07-16 Outer search feature-2 boundary

- The ordinary Markdown-only search rebuild rejected every feature-2 envelope, so one Umbra document could make Outer search unavailable. Rendering the authenticated public Outer container before indexing restores expected Outer search without weakening the key boundary.
- The renderer has no private key input and emits only deliberate Outer strategy output. Regression must test both private Markdown and private tag identifiers as canaries; a successful public search alone does not prove metadata isolation. Umbra-private search must not be folded into `search.query` without a separate `K_umbra`-bound index contract.
- The `cdc0ef7` release set was independently rebuilt and installed after this daemon/core change. The installed `inexd` binary was compared directly with the binary inside the VSIX; an unchanged extension JavaScript bundle would not be adequate evidence for this backend-only behavior.

## 2026-07-16 Umbra private-search boundary

- Outer search and Umbra search must never share an index: a shared index would retain decrypted projection text after Umbra lock or make private matches reachable through the ordinary command. `umbra.search.query` therefore owns a second zeroizing memory index and rejects locked sessions before either rebuild or query.
- Every persisted-document mutation already invalidates the Outer index. Making that invalidation also clear the Umbra index ensures private projection results cannot survive a write that changes their byte ranges; `lock_umbra` independently clears it before dropping `K_umbra`.
- The VS Code command uses the normal command contribution/keybinding model, not raw key handling. It invokes the normal independent Umbra unlock gate, keeps the query in the existing sensitive input path, and opens selected hits only through the CustomEditor so no private result becomes a plaintext VS Code TextDocument.

## 2026-07-16 Historical Git compare boundary

- A revision-compare API must not expose a `String` revision parameter. Even with shell-free spawning, arbitrary revision expressions expand the Git attack surface and make response provenance difficult to audit. The first bridge therefore exposes only a closed enum for `HEAD` and its first parent.
- Reading a Git blob is not sufficient: a valid Git object can still be another vault, another epoch, or a ciphertext path substitution. The bridge maps the canonical logical path itself and sends every returned blob through `authenticate_committed_envelope`, which binds those cryptographic contexts without materializing a plaintext file.

## 2026-07-16 Historical compare test evidence

- A parser-only test cannot establish that the compare RPC reads Git history instead of the current worktree. The daemon fixture must produce two independently encrypted commits, unlock a fresh session through the production RPC, and assert the returned roles and decoded bytes against each committed historical body.
- The test fixture's canaries remain in in-memory Rust assertions and encrypted Git blobs only. They are scrubbed from JSON response objects before test return; no product log or editor persistence claim follows from this daemon-only evidence.

## 2026-07-16 Historical Umbra compare boundary

- Historical Umbra rendering cannot call the ordinary on-disk `render_umbra_projection`: that would compare the worktree instead of the selected Git blob. The vault therefore needs a separate envelope-taking API which authenticates the historical envelope first and decrypts its slots only with an existing live Umbra session.
- Outer and Umbra compare must remain separate RPC methods. Returning a full historical Umbra projection from the Outer method would make a client-side scope mistake a private-data disclosure; a locked Umbra request must fail rather than degrade to a public result.

## 2026-07-16 Historical Umbra canary semantics

- A parent revision may legitimately contain text that later becomes private, so an Outer compare test cannot require a canary to be absent from both sides. The correct assertion is that the head projection, after the text is wrapped as Drop private content, excludes body and tag canaries while preserving unrelated public text.
- Umbra compare isolation needs two assertions: an Outer-only session must receive `AUTH_FAILED`, and only a separately unlocked Umbra session may receive the historical private projection. Testing only the successful unlock path would not prove the independent password boundary.

## 2026-07-16 Extension Host historical compare fixture

- The standard imported-vault fixture has one parentless commit, so a production compare command cannot be exercised there. A second `--allow-empty` ciphertext-repository commit is sufficient for the command path because it creates an exact HEAD/parent pair while retaining every encrypted blob and avoiding a plaintext mutation in the runner.
- A command trace alone does not prove the editor boundary. The Extension Host regression consequently retains the custom-tab `assertNoPlaintextTextDocument` check before and after the command, while the existing full isolated-root residue scan remains the persistence evidence.

## 2026-07-16 Extension Host Umbra compare wiring

- The host fixture may commit only the already encrypted feature-2 `plain.md.enc` output of the annotation lifecycle; committing or constructing a private plaintext body in the JavaScript runner would weaken the exact boundary being tested. The command trace then proves the UI reaches the independent Umbra RPC without exposing response content to the test harness.

## 2026-07-16 Controlled compare rendering boundary

- A usable secure compare view does not need VS Code's native diff editor. Once the daemon has returned its already bounded, authenticated fixed HEAD/parent bytes, a script-free Inex webview can render a deterministic linear line alignment. Common prefix/suffix rows are unchanged; only the unmatched middle ranges are highlighted. This avoids arbitrary revision controls, plaintext documents and quadratic LCS work.
- The renderer is still a plaintext sink for the duration of the open Inex panel, so every line must be escaped and the existing panel lock/dispose buffer wipe remains mandatory. The added tests explicitly reject active script markup as output while retaining it as literal displayed Markdown text.

## 2026-07-16 Multi-hunk revision alignment

- A common-prefix/common-suffix-only presentation is safe but visually misleading for two independent edits: all stable lines between the first and last edit appear changed. A deterministic patience-style anchor pass improves this without granting a webview Git/script capability: only lines unique in both local segments are anchors, ordered by a longest-increasing sequence of Parent positions; unanchored regions retain a linear fallback rather than unbounded LCS work.
- The alignment result remains view-only derived state. It does not alter the authenticated bytes, create a document URI, persist a diff cache, or relax the existing lock/dispose byte-buffer wipe path.

## 2026-07-16 Cross-editor encrypted catalog evidence

- Schema unit tests of two clients do not prove catalog portability. The meaningful boundary is a real ciphertext vault written through VS Code's typed sidecar and subsequently opened by a separately spawned Sublime RPC client. The cross-client test now binds the VS Code `umbra.tag.create` trace, a post-password-change Umbra lock, a fresh Sublime daemon unlock, and an encrypted config read.
- Test orchestration itself must not normalize a private tag label into process metadata. The helper has a fixed test-only assertion and receives only executable/vault paths as argv; the dynamic Umbra password is piped on stdin, never placed in an environment variable or temporary file.

## 2026-07-16 Cross-editor private-slot evidence

- Catalog compatibility alone cannot prove that two editors agree on a feature-2 document projection. The strengthened matrix has VS Code create a tagged private slot through the same typed sidecar API, then requires a fresh Sublime daemon to independently unlock Umbra and parse the resulting RenderMap. A one-slot check proves the shared document container/projection contract without making test code inspect private Markdown.
- The Sublime helper owns the returned projection bytearray and wipes it in `finally`. Its only observable result is a fixed success token, so neither the private slot body nor catalog content becomes subprocess output, test failure text, or a persisted fixture.

## 2026-07-16 Cross-editor feature-2 Outer boundary

- Feature-2 Outer data is not a normal editor projection in this v1 contract. `Vault::read` rejects a required-feature document, while the separate `read_umbra_outer_document` API is reserved for explicit limited projections such as export. The cross-client test therefore expects ordinary Sublime `document.open` to fail before `K_umbra` is unlocked, rather than treating a public JSON container as Markdown.
- A successful subsequent `umbra.document.open` after independent unlock proves this is scope separation rather than an unreadable/corrupt document. This is the correct observable test for “no feature-2 private projection reaches an Outer editor buffer.”

## 2026-07-16 Read-only Outer projection viewer

- Public feature-2 rendering must not be smuggled through the ordinary document API merely to make Outer strategies visible. A distinct daemon method can authenticate the container and render its public Drop/Cover/Placeholder output without accessing `K_umbra`; a distinct no-script VS Code panel then makes that output observable without turning it into an editable normal buffer.
- The public response intentionally has no RenderMap. A RenderMap exposes opaque slot identities and exact private boundaries, which are not needed for a read-only Outer view and would violate the stated projection minimization boundary.

## 2026-07-16 Tree-triggered Outer projection boundary

- A tree context-menu command can preserve the same boundary as the editor command when it consumes the provider's session-bound `InexTreeNode`, rechecks that session against the controller, and passes only its canonical logical path to the existing authenticated public RPC. It must not derive a `file:` URI or synthesize a normal Markdown TextDocument.
- The meaningful regression is not merely command registration: lock Umbra first, then invoke the tree path and require a new `umbra.document.openOuter` trace. That demonstrates the visible Drop/Cover/Placeholder viewer does not silently depend on residual `K_umbra` or a still-open Umbra document.

## 2026-07-16 Expanded Markdown presentation without LSP

- A controlled editor can improve common Markdown readability without registering a plaintext language document: front matter, task lists, strikethrough, autolinks and table separators are all line-local display transforms over the existing textarea value. They must remain non-authoritative; canonical parsing, navigation and persistence stay in the authenticated host/core paths.
- The overlay still uses an HTML sink, so each new formatter must preserve the single escaped-span construction route. A VM test that includes both the new syntax and a literal script-shaped string is stronger evidence than class-name presence alone.

## 2026-07-16 Source Control compare boundary

- A Source Control context menu can improve the ciphertext-diff workflow without taking ownership of native SCM: accept only the Extension Host's `vscode.Uri` (or its `resourceUri` wrapper), rebind it through the current controller's root/canonical-path validator, and invoke the pre-existing daemon-owned fixed historical comparison.
- Resource selection must not be mistaken for a request to compare the mutable worktree. Keeping the closed HEAD/parent pair preserves the no-plaintext-Git and no-unsaved-snapshot boundary while giving users a direct secure history view beside their changed ciphertext file.

## 2026-07-16 Adjacent annotation selection boundary

- The core/daemon already own the only authoritative range normalization and accept `mergeAdjacent` as an authenticated operation parameter. The VS Code setting must therefore be a boolean interaction preference only: forward it to apply/remove (and never place selected ranges, tags, or profile data in settings) rather than reimplementing mutation normalization in the webview.
- Defaulting it to `false` retains the frozen semantics that adjacent selections remain distinct. Opting in only changes whether touching ranges coalesce after daemon RenderMap validation, so overlapping, partial-private, stale-map, and atomic rollback checks remain in the common core path.

## 2026-07-16 Quick redaction boundary

- A public Outer viewer is not a mode transition by itself: it may coexist with a live private projection. The `Ctrl+Alt+O` contract must instead capture only a canonical logical path from a clean live Umbra editor, lock Umbra first, wipe the editor-side projection, then ask the Outer-only RPC for its deliberate public rendering.
- Keeping the transition as its own command avoids changing the semantics of ordinary `openOuterProjection` from a tree node. The panel still owns its public byte buffer and joins the existing vault-lock/dispose wipe set; it must never turn its output into a VS Code plaintext `TextDocument`.

## 2026-07-16 Umbra core completion evidence

- Feature-2 negotiation is enforced at two layers: the vault configuration update requires a live Umbra session and is ETag-conditional, while a feature-2 document rejects the ordinary Markdown read path and exposes only the dedicated authenticated Outer or Umbra APIs. The targeted core tests exercise both locked failure and successful committed metadata.
- Private-slot functionality is no longer a partial model stub: mutation requires live Umbra and the canary regression asserts private slot data never appears in the Outer container. Remaining work is matrix/runtime evidence, not a missing core transaction implementation.

## 2026-07-16 Repository import evidence boundary

- A real-source `--dry-run` is useful for proving the production source classifier sees the user's actual object format, tracked count, Markdown/asset limits, and clean HEAD policy. It is not enough to claim a finished encrypted publication unless the final source revalidation and exit result are observable.
- The authoritative automated substitute for the full transactional contract remains the CLI integration test: it builds a real source repository, runs production import, verifies a fresh parentless ciphertext Git commit, and exercises the early rejection paths before destination creation. Persistent manual import remains required for the UI/password picker experience.

## 2026-07-16 Neovim profile RPC boundary

- `umbra.profile.create` does not accept profile fields at the top level: the daemon requires one exact nested `profile` object. `umbra.profile.edit` additionally requires top-level `profileId`. Keeping those shapes exact prevents a UI-only implementation from silently failing or broadening the protocol parser.
- Reusable profiles carry only kind, tag IDs, Outer mode and the derived `promptForCover` boolean. Public cover text is per annotation instance and must remain outside profile editing, so the editor does not accidentally persist display text in semantic catalog metadata.

## 2026-07-16 Working-tree compare boundary

- A secure SCM comparison may decrypt an already persisted, authenticated worktree envelope, but must never treat the CustomEditor textarea as a Git revision. This preserves save semantics and prevents a second plaintext ownership path.
- Working-tree/HEAD is distinct from the existing fixed historical HEAD/parent compare; keeping it a separate daemon method avoids widening historical revision input or silently adding private Umbra scope.

## 2026-07-16 Saved-worktree implementation boundary

- The worktree reader must authenticate the envelope after the same secure bounded regular-file/path-chain checks used by Vault reads. A Git status output or a raw `fs::read` of `*.enc` is insufficient: neither proves vault/path/epoch binding, and the latter would bypass link/TOCTOU protections.
- A normal dirty worktree is the intended left side, but active Git operation control state is not. Primary local `.git` validation plus explicit MERGE_HEAD/CHERRY_PICK_HEAD/REVERT_HEAD/rebase/sequencer refusal cleanly separates “saved document changed” from an incomplete repository transaction without invoking Git filters or user hooks.
- The VS Code parser uses a separate exact `workingTree`/`head` response model rather than widening the historical `head`/`headParent` model. This makes an accidental revision/worktree substitution fail before any plaintext reaches the controlled webview.

## 2026-07-16 Feature-2 saved-worktree evidence

- A plain-document worktree fixture cannot establish the Umbra boundary. The correct test first commits a real Drop private slot, then changes only public Outer Markdown in the uncommitted saved envelope; a fresh Outer-only compare must retain the public delta while excluding both private-body and tag canaries.
- This fixture demonstrates that the current on-disk feature-2 envelope still flows through the same authenticated Outer renderer as historical compare. It does not use a live Umbra projection as a shortcut, so an Outer session remains sufficient and cannot accidentally inherit `K_umbra`.
