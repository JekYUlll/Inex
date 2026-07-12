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
