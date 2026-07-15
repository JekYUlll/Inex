# Inex Progress Log

## 2026-07-15 — Neovim 独立 Umbra keyslot 生命周期

- 新增 `InexUmbraStatus`、`InexUnlockUmbra`、`InexLockUmbra`。插件先以 exact `umbra.status` 判定初始化状态；第一次初始化显示“密码无法恢复”警告并经用户确认后才将 masked password 发给 `umbra.initialize`，既有 keyslot 则使用 `umbra.unlock`。
- 所有 status/lock 响应都严格检查 object key 与 boolean 状态。Lua 只保留 non-secret `umbra_unlocked` flag；Umbra lock、Outer lock 和 stop 都先将其清除。Umbra lock 不锁 Outer session。
- headless 临时 vault 验证 initialize/unlock→Outer retained→Umbra lock→Outer retained，以及 Outer lock 后 Umbra local state 消失；transport smoke 与 `git diff --check` 通过。feature-2 projection、annotation picker/tag/profile UI 仍未在 Neovim 实现。

## 2026-07-15 — Neovim 受控目录创建

- 新增 `InexMkdir`：目录 path 经过与 tree 一致的有界、相对、无控制字符/反斜杠/alias 验证后，才调用 daemon `file.mkdir`；结果必须为 exact `{ok:true}`，不作隐式父目录创建或本地文件系统写入。
- lifecycle 回归在 Unicode document 保存/search 后创建 `notes`，刷新 tree 并验证 `[D] notes`；同一测试仍验证 lock wipe。transport smoke 与 `git diff --check` 通过。

## 2026-07-15 — Neovim masked 内存搜索

- 新增 `InexSearch`：交互搜索词来自 `inputsecret()`，不使用普通 `input()`；最多 4 KiB 的 query 仅作为当前 RPC 参数传给 daemon `search.query`，回调后立即丢弃 Lua 变量。
- search response、tree response 现都要求 exact object keys；search hit 逐项限制 path、byte range、line、UTF-16 column、snippet 长度与控制字符。结果只存于独立 split 的 nofile、swap/undofile/modeline/buflisted 关闭、lock/stop wipe 的 buffer，Enter 仅打开认证 Markdown path。
- 更新 lifecycle headless：编辑并保存 Unicode 文档后搜索 Unicode token，验证 result buffer 内容与选项，并证明 lock 同时 wipe search/tree/document。transport smoke、`git diff --check` 通过。

## 2026-07-15 — Neovim 受控 vault tree 浏览

- 新增 `InexBrowse`：只接受 daemon `vault.listTree` 的有界、无重复且 kind/path 受限条目；tree 进入 `nofile`、swap/undofile/modeline/buflisted 关闭、`bufhidden=wipe` 的 scratch buffer。Enter 仅可打开已验证的 Markdown file entry；目录和附件不会被误作明文文件打开。
- tree buffer 在独立 split 中创建。初版在当前窗口替换 document，触发既有 `bufhidden=wipe` 并导致测试 `Invalid buffer id`；修正为保留文档窗口、只让 tree 占用新 split，未削弱 wipe-on-hide 安全策略。
- headless lifecycle 现在验证 tree 行、buffer 选项、文档窗口保留及 lock 时同时 wipe document/tree；transport smoke 也通过。

## 2026-07-15 — Neovim Outer 受控编辑与保存

- Neovim ordinary Outer buffer 改为 `acwrite`：`InexSave` 与普通 `:write` 都由 buffer-local `BufWriteCmd` 拦截，只向 `inexd` 发送带 current ETag 的 `file.write`，绝不把 `inex://` 内容写至宿主文件路径。
- Lua 端补齐严格 canonical unpadded Base64URL encoder/decoder；decoder 先限制 URL alphabet/大小、按需补位给 Neovim decoder，再重新编码比对 canonical wire text。这样空文档可如 daemon 协议定义那样保存为空 payload，单字节/Unicode 内容仍可安全读写。
- `outer_lifecycle.lua` 已验证：创建空文档、编辑 Unicode Markdown、正常 `:write`、CAS 加密保存、lock wipe、re-unlock/open 后逐行一致。现有 transport `system.hello` smoke 亦通过。

## 2026-07-15 — 可追踪全仓主线回归

- 以单一可追踪 session 重跑 `cargo test --workspace --locked` 并获得 exit 0：365 passed、12 ignored，耗时 225.49s；包含 core 的 Umbra/Outer 隔离、daemon/CLI、repository-import、v5 publication/recovery 以及代表性 native force-kill 边界。12 个 ignored 项是明确要求分片并行运行的完整 native force-kill matrix child/full-shard tests，不被计作已执行证据。
- 同一工作树中 VS Code 继续通过 `pnpm check && pnpm test && pnpm build`（57/57）；Sublime 继续通过 `PYTHONPATH=editors/sublime python3 -W error::ResourceWarning -m unittest discover -s editors/sublime/tests -v`（96/96，1 个 Linux pidfd/subreaper 条件 skip）。
- 这些门禁证明当前源码回归基线，不替代最终 VSIX 的人工 locked-first-use/persistent-profile 测试、原生 Windows/arm64、签名、hosted CI 或发布批准。

## 2026-07-15 — 主线 Umbra 实施状态校正与全仓回归

- 计划审计确认 Umbra 设计/实现、daemon+VS Code 交互层、Sublime picker/profile/keymap 三个父项的所有实现子项均已完成；将父项校正为完成，避免把真实代码与计划状态割裂。跨编辑器目录、canary/残留及 Outer 隔离的聚合矩阵仍保持未完成，不能由单客户端单元测试替代。
- 已启动全 workspace Rust 回归；其中 `inex-git` 的 Linux 强杀/恢复矩阵仍在运行，结果返回前不把 Rust 全仓门禁计为通过。VS Code 已通过 strict typecheck、57/57 tests 和 production build；Sublime 已在 ResourceWarning-as-error 下通过 96/96 tests（1 个 pidfd/subreaper 平台条件 skip）。

## 2026-07-15 — Neovim Outer 受控 buffer 生命周期

- 完成 `InexUnlock`、`InexNew`、`InexOpen` 与 `InexLock` 的最小 Outer 闭环：仅经 `inexd` 的 `vault.unlock`、`file.write`、`document.open/close` 和 `vault.lock` 调用；普通 buffer 显式拒绝 feature-2，保持只读。
- 新增 `outer_lifecycle.lua`：在一次性临时 vault 内验证解锁、创建、打开、swap/持久 undo/modeline/buflisted 禁用、只读、锁定前清空 session 以及 managed buffer wipe。真实 headless 运行通过；既有 `headless_smoke.lua` transport/hello 回归也通过。
- 修复 Neovim 内置 decoder 对 unpadded Base64URL 尾部填充的兼容性：客户端严格限制字符集与长度、转换 URL alphabet 后补齐再 decode；不改变 daemon canonical wire format。空新文档使用单个换行的 canonical `Cg`，渲染为纯空白 Markdown buffer。
- `InexOpen`/`InexNew` 不再提供宿主普通文件系统补全，避免把逻辑密文路径误导为本地明文路径；嵌套目录创建、树浏览、保存、搜索及 Umbra 仍未实现。

## 2026-07-15 — Neovim 正式目标补充与优先级冻结

- 用户将 Neovim Lua 插件补充为正式交付目标，并明确它必须排在最后：CLI/daemon 与 VS Code 维持最高优先级，Sublime 维持既定 experimental 范围。
- 当前 Goal 服务仍为 active，但其接口不支持改写 active objective；没有将未完成的旧 Goal 伪造为 complete/blocked。根 `task_plan.md` 是本轮可执行目标与优先级的权威记录。
- Phase 5.5 已有通过 headless RPC smoke 的 Lua 传输骨架，以及进行中的 Outer 受控 buffer 增量，故状态从 pending 校正为 in_progress。后续 Neovim 只复用 `inexd`，不引入第二套协议、密码学或 feature-2 容器解析。

## 2026-07-15 — Sublime Umbra catalog boundary

- 提交 `c5005b1`、`c9b7bc6`：Sublime 独立 Python RPC client 新增已认证 `umbra.status` / `umbra.config.get`，并拒绝超量、无 ID、profile 引用未知 tag 或 default 引用未知 profile 的响应。
- `PYTHONPATH=editors/sublime python3 -m unittest discover -s editors/sublime/tests -v` 通过 84 tests（1 个 Linux pidfd/subreaper 环境 test skipped）；直接从根 discover 的模块导入失败已确认只是缺 `PYTHONPATH`，不记录为产品失败。
- 下一步：在此验证边界上实现 Sublime stateful annotation picker 与 profile application；不得把未验证 catalog 值放入普通设置或日志。

## 2026-07-15 — VS Code Extension Host lifecycle regression

- 在当前 `f829d69` 后运行 `pnpm --dir editors/vscode test:extension:local`，本机 `/usr/share/code/code` 与隔离 Xvfb profile 通过真实 Extension Host 流程：feature-1 repository import、受控附件预览、CRUD、加密 backup/recovery 和 residue audit。
- 该自动矩阵确认多范围 host 改动未回归既有加密生命周期；它不替代多范围 Add range 工具栏的人工 UI 路径，也不替代 persistent-profile/跨平台发布门禁。

## 2026-07-15 — VS Code multi-range private annotation

- 提交 `1a2d665`：CustomEditor 从单一 selection 改为有上限的 validated range list。用户可在 webview 工具栏依次 Add range，再调用 annotation command；所有 ranges 伴随同一 projection/RenderMap/ETag 交给 daemon，失败仍由核心原子回滚。
- 完整 private-block remove 支持多个 block；metadata edit 明确拒绝多 range，避免把不同 slot 的元数据混合。锁定、投影替换和 dispose 会清除所有 range。
- 验证：VS Code check、57/57 tests、build、diff-check 通过。

## 2026-07-15 — Restore strict all-target Clippy baseline

- 提交 `6d3ea0c`：将两个超过 Clippy 100-line 限制的 Umbra regression test 拆为命名辅助断言，保持私密 slot lock、canary 非泄漏、多选原子性、陈旧 ETag 与 private-range 拒绝的原测试语义；没有使用 lint `allow`。
- 验证：`cargo clippy -p inex-core -p inex-daemon --all-targets -- -D warnings` 通过，core 297/297、daemon 71/71、fmt 和 diff-check 通过。此前记录的 test-only Clippy 基线告警已解决。

## 2026-07-15 — Encrypted default annotation profile

- 提交 `3b9f5c5`：新增 `UmbraConfigV1::set_default_profile`、Vault wrapper、`umbra.profile.setDefault` RPC 与 VS Code sidecar/client UI。Profile management 可 Set as Default/Clear Default；ID 始终在 encrypted config 中验证、保存，不能由普通 editor setting 注入。
- core profile test 与 daemon lifecycle 现在验证设置 default、`config.get` 读回以及 remove profile 自动清除 default。core 全量 297/297、daemon 全量 71/71、core/daemon lib Clippy、VS Code check/57 tests/build/fmt/diff-check 均通过。
- 初次全目标 Clippy 曾定位出 `vault.rs` 两个超过 100 行的既有测试函数；后续已在 `6d3ea0c` 通过提取命名辅助断言解决，未放宽 lint。

## 2026-07-15 — VS Code heading-section annotation target

- 提交 `20fe50d`：`inex.privateAnnotation.noSelectionTarget` 现在支持 `headingSection`。无选区时从当前 ATX 标题开始，至下一个同级或更高标题前结束；光标不属于标题章节时拒绝，避免意外包裹整篇文档。
- 新增 heading range 与 preference parsing 回归。验证：VS Code check、57/57 tests、build、diff-check 通过。

## 2026-07-15 — VS Code configurable annotation toggle

- 提交 `53ee77b`：贡献 `toggleBehavior`（alwaysAsk/useLast/useDefaultProfile/askOnFirstUse）和 `rememberLastSelection`。`Ctrl+Alt+/` 现在按配置选择 chooser、当前解锁 session 的 last spec 或 encrypted defaults 指定的 profile。
- last spec 包含私密 tag IDs，因此只驻留 extension 的当前解锁 session 闭包，并由 `controller.onDidLock` 清除；不写入 VS Code settings、工作区或日志。default profile 只在 Umbra 已解锁后从 daemon catalog 读取。
- 新增纯行为回归。验证：VS Code check、56/56 tests、build、diff-check 通过。

## 2026-07-15 — VS Code encrypted annotation-profile management

- 提交 `fe77dc5`：sidecar 增加 `umbra.profile.create/edit/remove` typed RPC client，发送前限制 stable ID、标签、tag ID canonicalization、kind/Outer 和 Cover-prompt 语义。
- 提交 `6450df6`：新增 `Inex: Manage Private Annotation Profiles`。可 create/edit/remove profile；profile label、stable ID 与 profile 列表都使用可被 Umbra lock 主动清空/关闭的 sensitive UI。编辑保持 profile ID，删除不触碰已有私密 slots。
- Profile editor 复用 kind/tag/Outer picker，但明确产生无实例 cover text 的 draft；只有真正 apply profile 到文档时才会提示公开 cover text。
- 验证：VS Code `check`、55/55 tests、`build`、`git diff --check` 通过。下一步：补齐 profile/default 的端到端 UI matrix，并继续多选/Outer 隔离及跨客户端验证；Neovim 仍保持最后优先级。

## 2026-07-15 — Goal update: Neovim last-priority MVP

- 用户将 Neovim Lua 插件纳入正式目标；优先级仍为 CLI/daemon、VS Code、Sublime experimental、Neovim。
- 更新活动计划：Nvim 仅可复用 `inexd` JSON-RPC 与现有 Outer/Umbra 会话隔离，禁止新建独立协议或密码学路径。
- 当前进行中：补全 daemon `umbra.config.get`，使 VS Code 与后续 Nvim 能在仅 Umbra 已解锁时读取加密的 tags、profiles 与 defaults。

## 2026-07-15 — Encrypted annotation catalog RPC and VS Code contract

- 提交 `f697a47`：daemon 新增 `umbra.config.get`，只在有效 Umbra session 读取 encrypted tag catalog、profiles 与 defaults；锁定后返回统一认证失败。完整 daemon 回归 71/71、严格 Clippy、fmt 和 diff-check 通过。
- VS Code sidecar 接入 `loadUmbraAnnotationConfig` 与 exact-shape parser：限制 tag/profile/aliases 数量和字符串大小，验证 stable ID、重复项、canonical tag list、tag/profile 引用及 default profile 引用，拒绝异常 daemon 返回值进入 UI。
- `pnpm --dir editors/vscode check` 和测试 50/50 通过。下一步仍是 feature-2 现有文档的受控转换/投影生命周期；完成它后才将 QuickPick 与 active verified webview selection 接到真实 apply RPC。

## 2026-07-15 — Existing document conversion to Umbra feature-2

- Vault 新增 `convert_document_to_umbra_outer`：仅 live Umbra session 可将 ordinary committed Markdown 在 ETag 条件写入下替换为空 slot 的 feature-2 Outer container；保留 file ID、created time 与 content flags，普通 `read` 此后继续拒绝该 container。核心回归覆盖锁定、陈旧 ETag、身份保留、Outer 内容一致及重复转换拒绝。
- daemon 新增 `umbra.document.convert`，使用同一 ETag/metadata/durability 响应契约；服务生命周期覆盖普通文档转换后只能通过 `umbra.document.open` 得到投影。
- 首次运行发现 `MethodRegistry::all()` 的 `u32` 位图在第 32 个方法左移溢出。已改为带编译期容量上限的 `u64` 表示，并处理 64-bit 满表边界；不是放宽协议解析。
- 验证：`cargo test -p inex-core --lib` 293/293、`cargo test -p inex-daemon --lib` 71/71，以及两 crate 严格 Clippy、fmt、diff-check 全通过。

## 2026-07-15 — VS Code feature-2 CustomEditor lifecycle

- `umbra.document.open` 现在携带 authenticated public document metadata；sidecar 严格校验其 exact response shape。
- CustomEditor 将 normal daemon document handle 与 Umbra projection 建模为互斥状态。普通打开失败时仅在 Umbra 已解锁的同一 session 尝试 feature-2 projection；转换命令预先同步/保存普通 buffer，关闭 normal handle，执行 CAS conversion，再原子替换为只读投影。
- feature-2 projection 暂不允许直接 Outer 编辑或 draft recovery，避免用普通 `file.write`/draft 路径错误持久化容器。锁定、dispose、投影替换都会清零 Markdown buffer 与 RenderMap generation。下一步将使用现有 verified webview selection 和多选 QuickPick 调用 `umbra.annotation.apply`。

## 2026-07-15 — VS Code private annotation command MVP

- 新增 `inex.togglePrivateAnnotation` 与 `inex.choosePrivateAnnotation`；它们先独立初始化/解锁 Umbra（首次明确显示不可恢复警告），确保 feature-2 metadata 已启用，再转换 active ordinary CustomEditor 为 Umbra projection。
- `QuickPick.canSelectMany` 实现 kind/Outer 单选与 tag 多选，所有标签和 profile 数据仅从已解锁 daemon catalog 取得；Cover 文本单独提示为明确公开数据。选择完成后 CustomEditor 将完整当前 projection、RenderMap 和已验证 UTF-8 selection 交给 `umbra.annotation.apply`，并仅采用 daemon 返回的新投影。
- package 贡献默认 `Ctrl+Alt+/` 与 `Ctrl+Alt+Shift+/`，不处理原始按键事件。Outer projection 编辑/draft recovery、toggle unwrap/edit、profile shortcut 与管理命令仍待下一切片，当前保持 fail-closed。

## 2026-07-15 — Atomic private annotation unwrap core

- Vault 新增 `remove_private_annotations`：要求 caller 提供当前 ETag、完整 projection、完整 RenderMap 和选区；仅 `CompletePrivateBlocks` 分类可以继续。所有 payload 先经 `K_umbra` 认证，再在单一 feature-2 CAS 中以原 Markdown 替换 markers、删除 slots 并重新渲染。
- 回归验证 partial private range 被拒绝且不写入；完整 block 解包恢复仅 Umbra projection，密文文件不出现正文或 tag canary。`cargo test -p inex-core --lib` 294/294、严格 Clippy、fmt/diff-check 通过。下一步接 daemon `umbra.annotation.remove` 和 VS Code 确认 UI。

## 2026-07-15 — VS Code confirmed private annotation removal

- sidecar 新增严格的 `umbra.annotation.remove` client；CustomEditor 始终复制当前 projection、etag 和 RenderMap 后提交，成功后只替换 daemon 返回的新 projection。
- 新增 `Inex: Remove Private Annotation` 命令，默认需 modal confirmation，且必须选择完整 private block；没有 active/unlocked Umbra projection 或空选区时拒绝。
- 验证：daemon 71/71、严格 Clippy；VS Code typecheck 和 50/50 tests 通过。下一步 profile shortcut 与 metadata edit；当前不把普通 selected text 当作 remove，保持 core 分类拒绝。

## 2026-07-15 — VS Code annotation profile application

- `inex.applyPrivateAnnotationProfile` 接受 `{ profileId }` command args，并只接受 canonical stable ID。profile 由 Umbra-unlocked encrypted config 返回，找不到/锁定/session 改变均拒绝。
- profile 复用普通 chooser 的 initialization/unlock/feature-2 conversion/verified selection/apply 流程；`promptForCover` 仅收集明确公开的 cover text。`pnpm --dir editors/vscode check` 和 50/50 tests 通过。

## 2026-07-15 — Comment-like toggle resolution

- `togglePrivateAnnotation` 不再无条件打开 chooser：CustomEditor 以当前 authenticated RenderMap 的 exact range 判断 active selection 是否覆盖完整 private block。只有该情形才显示确认并调用 remove；普通/空/partial selection 不会据 slot ID 猜测解包。
- VS Code typecheck 与 50/50 tests 通过。后续仍需实现 cursor-inside metadata edit、multi-cursor adapter、tag/profile management 和 Sublime/Nvim 客户端。

## 2026-07-15 — Documented current annotation MVP boundary

- PRD now distinguishes the shipped VS Code command/profile path from deferred multi-cursor, no-selection expansion, metadata edit, management UI, Outer editing, and draft recovery. This prevents the frozen target specification from being misread as completed behavior.

## 2026-07-15 — Cursor paragraph default

- A zero-length VS Code textarea selection now expands to its current non-empty line before private annotation. The implementation operates on validated UTF-8 byte offsets and zeroizes the temporary content snapshot; it does not alter remove semantics. Typecheck and 50/50 tests pass.

## 2026-07-15 — Vault feature-2 启用事务

- 提交 `538168d`：`Vault::enable_umbra_private_annotations` 只接受 live Umbra session；它调用已认证 core metadata upgrader，并以 vault.json etag CAS 提交，随后重新 parse 确认 exact committed metadata 才更新内存 config。锁定 session 的调用被拒绝。

## 2026-07-15 — 已认证 feature-2 metadata 升级基础

- 提交 `92c0bc6`：新增 `enable_umbra_private_annotations`，先验证当前 metadata MAC，再排序加入 feature-2、重算 MAC 并通过 reader policy 复验；不改变 master key 或 Outer password slots。该函数为 Vault 后续原子启用事务提供核心基础。

## 2026-07-15 — Feature-2 Outer EDRY profile

- 提交 `72b639d`：feature registry 与 EDRY header 现在识别 `[2]`，但只允许它和 UTF-8 Markdown logical-path profile 精确组合；新增 `encrypt_umbra_outer_document` 会先认证 `vault.json` metadata，再写入带 feature-2 的 Outer container header。
- 该 API 尚未由 Vault 对外暴露，也尚未提供启用 feature-2 的 metadata 事务；因此普通 existing vault 不会无意生成 Umbra 文档。测试覆盖 feature-2 header 绑定，Clippy 通过。

## 2026-07-15 — Outer 容器严格解码边界

- 提交 `4973257`：`UmbraDocumentV1` 现可在不解密 private slots 的情况下严格解析 Outer container，拒绝未知版本、非法 slot ID、非 canonical ciphertext 与错误算法；round-trip 回归与私密 canary/Outer 策略篡改回归均通过。
- 该切片刻意未改动 legacy `Vault::read/save_document`：现有 EDRY header 仍只承诺普通 Markdown，feature-2 与专用 Umbra read/write API 需一起落地，避免把 container JSON 误当编辑正文。

## 2026-07-15 — 加密 private slot 与 Outer 容器基础

- 提交 `f20d2b6`：新增 `UmbraDocumentV1`、公开 `OuterSlotEntry` 与加密 `PrivateSlotPayloadV1`。私密 kind、tag IDs、Markdown 与 timestamps 仅序列化到 K_umbra slot ciphertext；Outer 容器仅有 marker/Outer strategy/cover 与 nonce/ciphertext。
- 每 slot 子密钥与 AAD 同时绑定 vault ID、logical path、key ID、slot ID 和 canonical Outer strategy。测试证明 private canary 不进入 Outer JSON，并且修改 Outer strategy 后 slot 无法认证解密。
- 尚未接入 EDRY/Vault 文档读写与 feature-2 negotiation，故当前不能向客户端暴露 Umbra 投影。

## 2026-07-15 — Vault 加密 catalog/profile 存储

- 提交 `2f607ff`：新增 `Vault::load_umbra_config` 和 `save_umbra_config`。两者都先要求 live Umbra session；Outer 状态下直接返回 `UmbraLocked`，不会读取 config 路径或密文。
- 保存采用 vault mutation guard + etag CAS，随后从磁盘重新安全读取、比较完整密文字节并用当前 K_umbra 再次认证/解密后才更新 session etag。`.inex/config.umbra.inex` 受 atomic allowlist、大小/挂载/symlink/reparse/大小写别名门控。
- 测试证明：Outer 无法 load，保存后的 config canary 不出现于磁盘，解锁状态可往返读取，锁定后再次 load 被拒绝。

## 2026-07-15 — 加密 Umbra catalog/profile 信封

- 提交 `d0b6b13`：新增 `UmbraConfigV1`、tag/profile/defaults 模型和 `.inex/config.umbra.inex` 的 AEAD envelope。配置专用 subkey 从 live `K_umbra` domain-separated 派生，AAD 绑定 vault ID、key ID、canonical internal path 与版本。
- tag 标签、profile 名称、tag IDs 和 defaults 只存在 config ciphertext 内；canary 测试确认 `INEX_SECRET_TAG_CANARY` 不会进入磁盘 JSON，跨 vault decrypt 失败且不返回部分配置。
- 尚未把 envelope 连接到 Vault load/save API，因此当前阶段不宣称 catalog 已可由客户端持久同步。

## 2026-07-15 — Vault Umbra 会话与密码槽生命周期

- 提交 `67e87cf`：`Vault` 现在拥有 memory-only Umbra session，并提供初始化、独立解锁、锁定和已解锁会话的密码重设。锁定或丢弃 Vault 会释放 protected `K_umbra`；Outer password 从未传入这些路径。
- 密码槽仅在受控 `.inex/keyslots/umbra-default.inex-keyslot` 创建/替换，创建与替换均使用现有 vault mutation guard 的原子写入和 etag CAS。内部目录、slot 文件、挂载边界、symlink/reparse 与 ASCII 大小写别名都 fail closed。
- `umbra_status` 最多验证公开 slot 元数据，绝不派生 KEK 或解密 `K_umbra`；错误密码、非初始化 vault、已锁定会话和重复初始化均有独立错误。
- 验证：`cargo clippy -p inex-core --all-targets -- -D warnings`，`cargo test -p inex-core --lib`（280/280）通过；回归覆盖独立密码、lock 后禁止重设、旧密码失效和新密码解锁。

## 2026-07-15 — 目标补充：Neovim 最后优先级客户端

- 用户要求增加 Neovim 插件，但明确优先级为 CLI/daemon 与 VS Code 之后。已列为 Phase 5.5：复用 `inexd` JSON-RPC 和同一 Outer/Umbra 安全边界，不新增独立加密实现，也不阻塞当前 Umbra MVP。
- Neovim MVP 范围是受控 buffer、保存、树/搜索与私密标注命令；swap、shada、undo、LSP 等宿主明文残留风险必须经 headless 验证和文档门控，未验证前不得宣称安全。
- 后端 Goal API 仍拒绝在未完成 Goal 存在时创建替代目标；已将用户的新优先级写入持久计划，继续以 `task_plan.md` 作为阶段执行真源，不伪造完成状态。

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
- Cleanup receipt下一切片的独立只读设计审计已冻结七态状态机、两个old-v4-visible canonical namespace、relocated full/manifest/empty loader、active journal原样退休为receipt、四个verified-remove步骤及每步fresh reconciliation/force-kill矩阵。该审计未改代码；实现必须先闭合当前post-journal前滚，再按stable→cleanup、journal→receipt、candidate→manifest→rmdir→receipt的唯一顺序推进。
- Post-journal分支已接入`6566b62` core API并把两次replace改为消费真实source/destination句柄、以opaque file identity做fresh path reconciliation。SHA-1/SHA-256×InPlace/Detected/Split exact-final矩阵通过；完整worktree original/destination-final/final prefix与删除`MERGE_HEAD`后的恢复矩阵通过（155.15s）；事务外stage变化被归类为LaterUnrelated，而raw Git注入的uppercase `.ENC` alias按Conflict拒绝。首次inactive-ref失败和测试注入路径误用均已记入task plan；剩余门禁是post-move fault/rebind矩阵与全量native/Windows验证。
- 独立并行审计在中间diff上复验exact-final定向测试通过、all-target check仅有未消费seam warning；首次pedantic Clippy因publish helper参数/长度和未使用fault action失败。该结果不计为门禁通过，代理已被要求用结构化context/小型reconciliation helper并真正执行fault矩阵来消除warning，不使用模块级放宽。
- 扩展审计进一步要求post-move允许正常Git立即产生LaterUnrelated、move post/pre协调传播operational错误、recorded provenance只收敛Unsupported语义错误，并把owner scan的Tree/Vault I/O保留为scrubbed Git I/O。上述均已纳入当前slice硬门禁；另要求unsynced-parent及merge结果真实commit后fresh recovery测试，修完前不允许固定提交。
- 修复后fmt与all-target/all-feature check无warning；owner Tree/Vault I/O mapping以完整测试路径1/1通过。首次短`--exact` filter跑0和marker矩阵对故意损坏live index的错误预期均已记入task plan；产品按设计传播`GitCommandFailed(ReadIndex)`且replace未调用，测试现改为核对operational error及marker/publish保留，正在全矩阵重跑。
- 扩展后的publish→marker fault矩阵1/1通过（90.76s），lock→live矩阵1/1通过（106.90s）；覆盖moved/not-moved/foreign、source/destination同字节clone、journal rebind、critical worktree/owner/live drift、after-move、LaterUnrelated与unsynced-parent fresh retry。真实merge commit回归1/1通过（47.58s）：SHA-1/SHA-256×Detected/Split在HEAD已成为merge commit且`MERGE_HEAD`消失后，fresh recorded-provenance recovery仍接受ExactFinal/LaterUnrelated。
- 其余targeted同样全绿：LaterUnrelated 21.94s、SHA-1/SHA-256×三payload ExactFinal 83.61s、三payload worktree prefix/inactive-ref 154.49s。随后pedantic Clippy只发现八项结构/测试lint（8参数、by-value mapper、105行dispatcher、两个长fault test、同match arm），无行为失败；修复采用context降参和小helper拆分，不使用模块级allow，已记入task plan。
- C分层重构后marker/live fault再次1/1通过（92.42s/106.95s），pedantic Clippy全绿。首轮完整suite为138/141（168.42s）：一个产品错误分类在early journal无marker时冒出raw open I/O，另两项旧测试仍断言journal-only/unwired前驱状态。实现已先strict classify lock再held-open，两项测试已更新为当前ExactFinal/final digest/lock absent且继续证明scratch保留与direct update hard-stop；fmt/Clippy复绿，正在三条定向及全suite第二轮。
- 三条定向复验后完整suite第二轮141/141（166.77s），fmt/diff与Windows GNU all-target check（7.35s）、pedantic Clippy（3.41s）、test no-run link（5.84s）全绿，形成固定commit`166c42d`。但固定commit最终审查判NO-GO（2 blocker/2 major）：classifier后的journal/lock/live identity未fresh重验；final rename owner I/O、in-place stage read I/O仍被收敛；replace双错误协调未始终执行pre-proof。该commit未合入，代理已按精确fault seam/error taxonomy修复并必须重跑全门禁与第二次固定审查。
- 第二固定delta`ad9585c`闭合上述项及journal NotFound两窗，新增mapping/journal/marker/live fault均绿，完整143/143（169.27s）、native/Windows GNU全门禁通过。一名仅看固定delta的审查者给GO（0/0/0），另一名给NO-GO：LaterUnrelated只用`candidate_matches=false`表示新inode，classifier后live被删除或换任意foreign inode也同为false，末尾会误接受。该delta仍未合入；下一修复必须让classifier返回并绑定其held live identity，hook后要求path仍匹配该classified inode，并补initial/final delete/foreign/lock fault后第三次全门禁与双审查。
- 第三固定delta `3ddf79d` 让 completed-index classifier 在整个分类期间持有 live `File`，返回 opaque identity，并在 initial/final hook 后重验 exact classified inode、old/candidate 关系与 `index.lock` absent；delete、foreign replacement 与 lock reappearance 故障矩阵全部闭合。两路独立复审均为 GO（合计 0 blocker/0 major，仅一路记录同用户非协作原地改写属于既定威胁模型外的可接受 minor）。该源码合入主线为 `4754a32`；主线 `inex-git` 143/143、0 失败（186.80s），且与固定分支两个改动文件逐字节等价。下一切片只剩 durable cleanup receipt、production writer 与端到端 force-kill recovery；Phase 7/GA 继续保持 in_progress/NO-GO。
- Cleanup receipt 切片已启动：主线先以 `d23d575` 独立提交同步 post-journal 完成证据，工作区随后保持 clean。当前调用图确认 `recover_bundle_v5_pending` 只返回 ExactFinal/LaterUnrelated，`recover_pending` 随即以“cleanup later slice”硬停为 `RecoveryConflict`；`Git::update_index*` 对 v5 journal也仍显式 hard-stop。实现与两路只读审计已在独立分支并行启动，主线不提前解除任一 production gate。
- Production writer只读审计确认当前保持NO-GO是正确的：InPlace/Detected/Split三个真实commit入口仍完整走v4 `prepare_index_cas -> write_cas_journal -> 手工worktree/index -> remove_journal`，v5 preparation无生产调用点；低层`Git::update_index*`又没有Vault/guard，不能靠放行BundleV5来接线。冻结的最小安全路径是三payload统一进入高层`commit_payload_v5`，依次fresh prepare/classify、durable journal、post-journal forward、七态cleanup并强制Clean；正常写与fresh recovery共用同一状态机，v1-v4 parser/recovery与v4 CAS dispatch原样保留。
- Cleanup只读安全审计对当前fail-closed主线给出“启用前NO-GO，6 blocker/3 major”，不是现存误删漏洞。硬门禁冻结为：classifier携带full/manifest/empty/journal-or-receipt held proof；old-v4-visible exact namespace与wrongcase拒绝；relocated loader保持manifest原stable basename；active journal原canonical bytes/原inode no-replace退休为receipt；candidate→manifest→empty dir→receipt逐步verified-remove；每步仅接受相邻旧/新态并完成正确parent durability，最后receipt unlink若NotSynced须显式重sync `.vault-local`。非法cross-product与每边force-kill/rebind矩阵已发给独立实现分支。
- Cleanup实现第一轮全量 `inex-git` 为138/146（94.82s）：8项失败全部是pre-cleanup历史断言仍期待`recover_pending -> RecoveryConflict`，而新状态机已按设计成功清理。修复策略不弱化产品：需要只停在post-journal的定向测试改调`recover_bundle_v5_pending`，真正E2E则升级为`Ok(true)+Clean`并核对namespace消失；完成后从头重跑146项。
- 历史断言分流后第二轮完整 `inex-git` 146/146、0失败（189.08s）。新增cleanup证据包含：SHA-1/SHA-256×三payload端到端收敛Clean；七态逐步fresh-held walk；stable+cleanup/J+R/token/legacy/wrongcase/link/hardlink/extra/foreign非法组合；以及stable/journal/candidate/receipt相同字节新inode rebind拒绝。当前结果仍是独立分支开发证据，需native静态、Windows GNU与固定diff双审后才可合入。
- 随后的独立mutable-diff安全审计最终以4 blocker/2 major否决该146/146快照：fresh CleanupFullJ恢复未重新证明payload/worktree/index final；中间edge若物理完成但parent sync未确认，fresh invocation会直接从next-state继续并越过durability缺口；journal→receipt move返回错误时，bytes-only classifier可能接受foreign same-bytes receipt而未绑定原journal inode；stable move后旧held journal、candidate/manifest/rmdir后旧held receipt也未跨operation post-bind，允许窗口内same-bytes clone。另有loader blanket mapping吞operational I/O和六edge fault矩阵不足。实现状态已退回in_progress，分支正在按身份/耐久/错误优先级修复，当前测试不计安全门禁。
- Cleanup静态门禁两次暴露纯结构lint：首轮5项为large proof enum、needless ownership和三个过长审计/测试单元；审计返修后3项为两个`map_err` owned adapter和durability fence decision unit。修复使用boxed large variant、能借则借、对`Result::map_err`必须消费error的adapter保留所有权，并只在不可拆分的单函数安全表上加窄理由；最终pedantic需在全部授权/identity/fence差异完成后重跑，早先全绿不继承。
- 四blocker返修后的完整native `inex-git` 为150/150、0失败/ignored（193.51s），最终pedantic Clippy在该源码快照上全绿。新增定向闭合StableJ critical与CleanupFullJ fresh completed reauthorization（index/worktree drift拒绝）、每态前后durability fence、journal move old/new/foreign原inode协调、stable/J/R post-operation same-bytes rebind拒绝和operational I/O taxonomy。下一步先固定独立Git commit，再让两路审查只看exact commit；当前仍不计主线完成。
- Cleanup固定提交为`e4ed0010da896b07228fb6b294ac5e40f70394b8`（`feat(git): retire v5 recovery through durable cleanup`），独立worktree clean且未push。除native 150/150、fmt、pedantic Clippy、diff-check外，Windows GNU all-target/all-feature check（7.56s）、pedantic Clippy（3.69s）与test no-run link（6.12s，生成`inex_git-39bbb8652bb2bed2.exe`）全部通过；两路审查正在只看exact commit，尚未合入主线。
- `e4ed001`双路exact-commit复审均为NO-GO，且发现两个互补阻断：安全审查指出StableJ/CleanupFullJ完成态再认证只检查事务精确路径、未重跑完整stage-map与protected case-fold/Unicode alias投影；writer审查指出stable/J/R之外的cleanup directory/member capability在物理操作后未连续identity-bound，fresh classifier可接受same-bytes新inode。另确认`remove_cleanup_manifest_v5`与directory publish仍有operational I/O压缩，以及非法cross-product/六edge error-before/error-after/NotSynced矩阵不足。固定commit不改写，分支将追加delta、全门禁和双审。
- 追加固定delta `a0b98ed6815ba5f09898aae08103ea23f98f420d`（`fix(git): harden v5 cleanup authorization`）保持父`e4ed001`不变、worktree clean。绑定结果为cleanup定向10/10（33.87s）、完整library154/154（197.74s）、fmt、native pedantic Clippy（2.53s）、delta diff-check、Windows GNU check（1.08s）/all-target pedantic Clippy（2.55s）/test no-run（3.04s）全绿。实现代理已启动`final_commit_review`与`final_delta_audit`两路exact-delta审查；主线程重复启动审查因四线程上限被拒，未重试。
- `a0b98ed`两路复审出现GO/NO-GO分歧，按严格NO-GO处理。通过项是完整alias classifier、post-edge target/member identity、I/O taxonomy与常规fault结果；阻断在测试真实性：`ErrorBefore`由`before_physical`直接返回，未进入物理原语/共同协调器，`NotSynced`只在已正常执行并可能已同步后覆盖返回值，无法证明explicit fence被调用或失败会传播。分支需追加private test-only physical-operation/fence seam，真实形成error-before无副作用、error-after有副作用、NotSynced、fence counter/failure，再跑全门禁与双审；当前固定链不合入。
- 第三固定delta `3cc1cf768edbf151bb31ef5d102f41b5751df2e4` 未改写两个前驱，独立worktree clean。六边统一private physical driver：ErrorBefore不调用原语但进入common old-state reconciliation，ErrorAfter执行原语后返回Err，NotSynced执行原语并把真实返回态送入协调器；sync-fence seam记录(state, physical status)并可在expected fence失败。6×4矩阵断言old双fence、expected fence、NotSynced可见、fence失败传播且只到相邻态；matrix1/1（45.73s）、cleanup10/10（46.49s）、全154/154（197.78s）、fmt、native pedantic Clippy、diff-check、Windows GNU check/Clippy/no-run全绿。两路原审查者正在只看`a0b98ed..3cc1cf7`。
- 第三delta双审最终GO/GO，确认attempted/completed分离、六边全走private driver、NotSynced进入expected-state sync seam、fence失败不推进下一edge、post-proof优先级fail closed，且生产只使用`Run`、fault variants均为private `cfg(test)`。三提交按顺序合入主线为`c08ee91`/`07a34c4`/`761b146`；主线源码与`3cc1cf7`两个文件逐字节等价，重新通过完整`inex-git`154/154（197.74s）、fmt、native pedantic Clippy、diff-check及Windows GNU check/Clippy/no-run。Cleanup receipt切片完成；production writer与真实OS force-kill仍保持open，未push。
- Production writer切片已在新worktree `agent/git-v5-production-writer` 基于`99a23d6`启动；当前重构删除三个v4手工尾巴并增加统一v5高层边界，尚未固定。独立调用图审计要求唯一一次guard获取，normal与fresh共用不再加锁的disk-classified driver，保留各payload原始preconditions和低层BundleV5 hard-stop。另冻结prepare错误分叉：只有retained partial scratch时可直接返回原错；若exact自有stable已发布，即使prepare报告durability/post-audit错误，也必须在同一guard下fresh classify继续或保留给recovery，绝不能二次prepare、fallthrough到v4或删除capability。
- 真实OS force-kill只读设计完成：暂停能力只能通过`inex-git`内部private composite hook与`cfg(test)` unit-child模块进入测试二进制，禁止CLI隐藏参数、production环境变量、Cargo feature或公开test API。建议writer固定提交P预留production ZST/no-op hook及prepare/publish/marker/journal/worktree/post-index/cleanup checkpoint；后继H只新增`v5_force_kill_tests.rs`，父进程启动同一test executable、外部ready文件同步后用`Child::kill`/wait，fresh child调用公共recover。完整原生证据为两object formats×三payload×全部durable checkpoints（约260 kill cases，另6 LaterUnrelated），强杀不冒充power-loss。
- Production writer新增三组矩阵均通过：真实entry 87.23s、composite hooks/LaterUnrelated 88.78s、fresh recovery 87.50s；但首轮全量为156/157，既有live-index fault矩阵的MoveThenError从预期成功协调回归为`RecoveryConflict`，exact rerun稳定复现，因此不是并发抖动。实现分支正在比较composite wrapper与原post-journal worktree/checkpoint/critical-audit顺序；修复前不固定提交，且不得修改旧测试期望来掩盖回归。
- 回归定位为generic composite worktree wrapper误改既有test-only fault fixture的字节级顺序；基线同一定向177.40s通过，恢复旧test-only worktree流程而production recovery继续走composite hooks后，定向176.25s通过。Writer固定commit为`354a50bd978742c171e12d84f04505b4719298cb`（base`99a23d6`）：三个commit入口payload后只调用`commit_payload_v5`，v4手工tail删除，legacy v1-v4保留，private composite hooks+production ZST覆盖完整链。绑定门禁为真实entry87.23s、hooks/LaterUnrelated88.78s、checkpoint failure/fresh recovery87.50s、全157/157（204.36s）、fmt/native pedantic/diff及Windows GNU check/Clippy/no-run全绿；双路exact-commit审查中。
- Writer双路exact-commit审查最终GO/GO，固定提交合入主线为`53ce227`。主线`lib.rs`与`354a50b`逐字节等价，重新通过`inex-git`157/157、0失败（204.08s）、fmt、native pedantic Clippy、diff-check及Windows GNU check/Clippy/no-run。三个真实merge入口现只走single-guard v5 disk-classified driver，v4 parser/recovery/CAS兼容保留，low-level BundleV5 hard-stop不变；production writer切片完成，下一步只新增cfg(test)强杀harness，未push。
- Force-kill harness已在新的独立worktree/分支启动，base为planning successor`b9ad906`、生产writer固定为`53ce227`；实现代理另启子审计检查现有private hook/checkpoint。另一路安全审计冻结test-only/source-diff、child/rendezvous、fresh recovery与plaintext边界；第三个执行分片审计因四线程上限未启动，主线程不重试或中断，后续本地制定Linux完整矩阵分片。
- Force-kill初稿新增纯test文件并在既有tests模块内声明，代表性真实child kill/fresh recovery测试1/1通过（94.87s）、native pedantic Clippy通过；尚未固定。安全审计列出提交前硬门禁：tests模块前writer bytes/Cargo/candidate零差异；ready staged create-new/flush/sync/close/no-replace+parent sync并绑定canonical nonce/pid/scenario/root；parent RAII guard保证所有失败kill+wait；recovery必须两个fresh child；pre-stable/Clean为0→0、active为1→0；每case在kill后/一回/二回扫描repo+control raw bytes及`git cat-file --batch-all-objects --batch`解压的全部reachable/unreachable objects，覆盖plaintext/password canary；LaterUnrelated比较exact stage entry；全表machine-count含split1/2与Clean；Windows最终repo删除是handle leak gate。初稿正在补齐这些项。
- 2026-07-13 goal continuation 恢复后重新读取 planning-with-files 规则、根计划/进度/发现并运行 session catch-up（无未同步输出）；主线仍为 `b9ad906`、仅三份 planning 文件 dirty，产品源码未变。独立 force-kill worktree 正把原 92 个粗粒度 case 改为每 payload 都覆盖 candidate/publish/marker/journal/post-index/cleanup 的完整笛卡尔矩阵；当前检查时枚举已扩展但旧匹配名仍处于并发重构中间态，因此未运行编译、未把该快照计为证据。冻结要求仍是纯 `cfg(test)` diff、机器构造 expected unique set、Linux 全矩阵与双路 fixed-commit review 后才可合入。
- 当前 harness 协议审阅又发现并反馈六个必须在冻结前关闭的 test-only 缺口：recovery ready staging 的文件名分派重复匹配 writer；二次幂等 recover 仍在同一 child；pre-stable candidate scratch 被错误当作 final/零 retained；ready 未显式绑定 object format 与 payload identity；ready 可见后未再次确认 writer 存活；Windows 删除未做 bounded retry handle-leak gate。实现者正在同完整 230-case 表一起修复，尚未提交或运行门禁。
- Force-kill harness 固定父提交为 `7b9b733`（base `b9ad906`），exact diff 仅有 tests 内 include 与新 `v5_force_kill_tests.rs`，production/Cargo/candidate/lock 均未改。230 unique cases = 两格式 ×（InPlace 37 + Detected 37 + Split 38）+ 6 LaterUnrelated，机器 expected/actual 集合相等；代表6场景约92秒、fmt/diff/native pedantic及Windows GNU Clippy/no-run已绿。两路协议审查确认 durable ready+post-sync armed ACK、全TID Linux child census、kill+wait、两次独立fresh recovery、pre-stable完整快照和bounded cleanup；完整230 runtime shards尚未运行，Windows native descendant/runtime仍保持open。
- exact review 还指出最终 cleanup 的 `Path::exists()` 会把metadata error压成false，削弱“目录确实不存在”的证据；不改写父提交，追加最小test-only delta改为`try_exists().expect(...)`，需重新跑fmt/coverage/代表性或等价门禁并复审后再合入。
- `try_exists()` cleanup delta 已重新通过 `cargo fmt --all -- --check`、`git diff --check`、230-case exact machine coverage 1/1、native all-target/all-feature pedantic Clippy，以及6个真实代表性 writer-kill/two-fresh-recovery/canary/cleanup场景 1/1（92.46s）。下一步将该单文件delta作为独立Git提交固定，再做exact delta审查；完整230 ignored runtime shards仍未启动。
- cleanup fail-closed delta 已固定为 `42685dc`（父 `7b9b733`），未改写父提交。已并行启动单delta安全审查与完整 `b9ad906..42685dc` Linux harness终审；第三个shard执行计划代理因协作线程容量拒绝启动，已记录并改由主线程在两路审查期间本地派生，不中断高优先级审查。
- Full Linux矩阵已完成compile-once/no-run预备，当前exact test binary为`target/debug/deps/inex_git-4a86e66107fa3990`；六个ignored shard分别绑定SHA-1/SHA-256与InPlace/DetectedRename/SplitRename，必须直接调用同一binary并行运行，避免六个Cargo前端争用build锁。单delta审查初步确认`42685dc`为单文件单hunk纯test-only且worktree clean，终结论仍待返回。
- `42685dc` 单delta终审GO（0 blocker/0 major/0 minor），且独立复跑fmt、230 coverage、native/Windows GNU Clippy及Windows no-run均绿；但完整链`b9ad906..42685dc`终审为NO-GO，发现两项Linux证据blocker：父进程全程持有含Vault/Git/master-key状态的`ProductionEntryFixtureV5`，以及canary未独立覆盖与branch/commit metadata碰撞的in-place `ours\n`/`theirs\n`。完整230 shards在这两项修复前不启动，避免固定弱证据。
- 新隔离修复代理首次因线程容量无法spawn；exact reviewer返回后已复用原实现线程继续同一worktree。修复方向冻结为setup child创建并detach fixture后退出、父仅保留path/control/scenario、两个recovery后fresh final-verifier child完成prestable新merge/最终验证；side plaintext使用窄path/type-aware扫描，全部Git blob（含unreachable）单独覆盖ours/theirs，通用canary继续覆盖全raw与全objects。
- 隔离/canary修复仍在独立worktree编辑中，当前约为单test文件+345/-16行、1994行总长，尚未启动编译或测试；主线程不读取并发半成品形成结论，只确认没有production/Cargo文件被改，并继续等待实现者原子收敛后再运行门禁。
- 实现者已按source-diff要求用apply_patch移除独立worktree内临时planning改动；当前mutable diff重新只剩`v5_force_kill_tests.rs`（约+458/-53），父协议已声明收敛为setup→writer→两次recovery→final verifier且父无fixture/Vault/Git/recover/commit调用。尚未编译，仍不计为通过。
- 隔离/canary mutable fix 已完成但未提交：新增setup child发布带prestable digest的control后detach fixture并退出，父等待成功reap后才启动writer；两个fresh recovery后由fresh final verifier完成prestable production `commit_payload_v5`或active final验证。LaterUnrelated stage也由first recovery原子发布、second/final精确绑定。Side canary现对raw tree做精确Git-metadata排除，并对`--batch-all-objects`列出的全部blob逐个解压扫描；通用canary仍扫全raw与全objects。
- 门禁结果：native no-run、完整模块路径230 coverage 1/1、fmt、native pedantic、代表6场景1/1（91.58s）、Windows GNU no-run/pedantic及diff-check通过。一次短filter实际运行0 tests，未计证据并已用完整exact path纠正；首次Clippy的4项setup解构lint经or-pattern修复后复跑通过。当前仅test文件mutable，正进行独立fixed-diff审查，完整230 shards仍未启动。
- 主线程源码复核确认parent body仅创建control `TestDirectory`、序列化request/control与路径，setup成功退出后才启动writer，最终验证在新child；旧句柄隔离blocker结构上已消失。Canary仍有待审判断：当前side扫描对10个exact Git metadata路径整文件跳过，虽所有Git blob仍逐个扫描，但整文件跳过可能隐藏追加到合法metadata文件的side plaintext；已要求独立审查决定是否必须改为unique noncolliding fixture plaintext或只剥离/验证合法occurrence后扫描。
- 两路exact mutable review均确认setup/final-child句柄隔离旧blocker已关闭，但canary结论NO-GO：向被整文件豁免的`.git/COMMIT_EDITMSG`/`MERGE_MSG`/`config`追加`ours\n`可绕过raw side扫描，per-blob扫描也不覆盖loose metadata；短5-byte token还有随机密文假阳性风险，slash-string allowlist不具Windows原生语义。当前diff继续保持未提交，完整230 shards继续不运行；实现改为长force-kill专用正文canary+neutral Git metadata，删除全部豁免并加mutation regression。
- Canary第二轮修复正在同一独立worktree实施，当前mutable test文件约+549/-52、2162行；尚未编译，未触碰lib.rs production prefix/Cargo/planning。主线程继续等待完整原子改动，不在半成品上重复先前门禁。
- Canary第二轮实现已完成且仍未提交：仅自建InPlace fixture，使用neutral anchor/leftlane/rightlane Git metadata与4个至少16-byte长完整正文；Detected/Split保留现有长正文，并由setup child解密stage/result逐项绑定。统一canary现在无metadata/path/type豁免地扫描全部raw regular files及`cat-file --batch-all-objects --batch`全部对象；4个旧metadata路径追加mutation和commit-object mutation均证明可检出。Native no-run/fmt/230 coverage/native pedantic/代表6场景91.79s/Windows GNU no-run+pedantic/diff-check全绿；Clippy曾只报148行fixture helper，已用窄test-only理由allow后复跑通过。最新mutable diff正等待独立复审。
- 第一条最新snapshot审查已GO（test文件SHA-256 `fbd6d93c…`，相对`42685dc`为+780/-52，0 blocker/major/minor）：确认长canary由真实InPlace/Detected/Split stage+result解密绑定，raw scanner无任何路径分支，全对象scanner对`--batch-all-objects`输出使用同一列表，metadata/commit mutation有效，旧Windows path separator问题消失。已启动第二路全链审查，并明确要求评估完整正文canary对partial plaintext的证据强度；双GO前仍不提交。
- 第二路全链安全审查结论为NO-GO：完整正文canary无法证伪仅泄漏前缀/中段/单行，setup child detach后的父进程缺少异常路径目录owner，`ChildGuard`在kill失败后可能无界`wait()`，object mutation也尚未证明unreachable blob被枚举。Linux修补限定为test-only：真实正文长fragment统一扫描、fragment-only raw/unreachable-object回归、parent RAII cleanup与有界`try_wait`；Windows native Job Object/进程树和完整230 runtime仍独立保持open。
- 现场复核现有可体验包：Linux x64 VSIX仍存在，SHA-256为`dcfde351dfa170c69d94a3f4f4fd8b9295bbb236729327ab5041456cb1a4123d`，manifest为Inex `0.1.0`、VS Code `^1.125.0`；本机VS Code `1.128.0` x64满足要求。先前口头所称CLI zip basename不准确，实际配套包为`inex-rust-0.1.0-linux-x64.zip`，两者均由同目录`SHA256SUMS`绑定；该包仍是`5aa0b8c` pre-alpha快照，不代表最新v5 writer/harness源码。
- VSIX内部命令元数据确认可体验Unlock/Lock、Encrypted Vault树、创建/重命名/删除加密Markdown与内存搜索，且内置`bin/linux-x64/inexd`；package没有可选`extension/README.md`，使用说明以源码`docs/user-guide.md`为准。文档仍明确标注当前为pre-alpha、尚未指定supported VSIX，体验应使用一次性隔离profile。
- 使用一次性`user-data`与`extensions`目录执行本机VS Code CLI真实安装，返回`Extension ... was successfully installed`并精确枚举`horeb.inex-vscode@0.1.0`；隔离profile随后删除且不存在。CLI同时输出host Node `DEP0169 url.parse()` deprecation warning，但命令exit 0且无证据指向扩展调用栈，因此不计Inex产品失败。
- Force-kill hardening首轮门禁中native no-run、230 exact coverage-set与4个canary/guard定向测试已PASS；pedantic Clippy仅报两个test-only结构lint（101行rename断言与best-effort cleanup相同match arms）。实现者正以小helper/分支折叠修复后重跑，不增加模块级allow，也未启动完整230 runtime。
- 修补快照已稳定为test文件SHA-256 `533d4e3c11ed36ded0f015d128588c668bae6c6b591036be46cd12372a86825c`（相对`42685dc`为+1189/-76）：7个full-body+10个>=9-byte fragment统一进入raw/all-object scanner，真实stage/result/password绑定；raw fragment-only与unreachable `hash-object -w`回归；parent detached-fixture RAII；ChildGuard仅bounded `try_wait`；协议`try_exists`；pre-stable声明收窄为worktree/index bytes。实现门禁fmt、diff、5项定向/coverage、native no-run+pedantic、Windows GNU no-run+pedantic及6代表case（91.62s）全绿，230 runtime未跑。
- 主线程对相同SHA独立直接运行5个exact binary定向门禁，canary metadata与unreachable-object测试均按预期在`catch_unwind`内部触发scanner panic后整体PASS，ChildGuard、detached-fixture RAII和230 expected/actual集合均1/1，fmt/diff继续PASS；`b9ad906..mutable`只有tests内module include与新增test文件，Cargo及production candidate文件无差异。现进行双路固定字节全链复审。
- 固定SHA首路终审GO（Linux 0 blocker/major/required-minor），但进程安全复审NO-GO（0 blocker/1 major/2 minor）：raw/all-object mutation把枚举、I/O、Git status与detector共同包进`catch_unwind`，任一操作性panic可假PASS；setup parent cleanup guard仍在control read/parse后才建立；ChildGuard回归未握手进入park且未直接覆盖Drop。完整230继续不启动，当前回到同一test-only分支修正因果与owner/Drop证据。
- 第二轮test-only核心修补已编译且6项exact定向PASS：tree/all-object I/O先成功并证明fragment存在后只捕获detector；显式kill与Drop分别在durable park-ready后证明reap；Linux Drop回归额外证明`/proc/<pid>`消失；fixture owner真实panic unwind清理；230集合闭合。Parent另在setup spawn前持有已知TMP owner容器，从而覆盖control parse/timeout窗口。首轮native Clippy仅报一个可折叠`if let`，正等价改写后重跑。
- 第二轮fixed SHA为`7b26f35806226babb67152f3f847e634921ffd935e8b8e2ca89b2718a9174d18`（相对`42685dc`为+1388/-82，2971行）。Parent在control root内先持有并sync `fixture-owner` guard，再以SetupRequest和TMPDIR/TMP/TEMP绑定setup child；child在建fixture前验证canonical temp root，repo必须是owner direct child。Mutation先通过同一tree/all-object I/O helper证明精确单fragment，catch只包bytes detector；ChildGuard显式与Drop ready/reap、真实panic cleanup均闭合。Fmt/diff、6 exact、coverage、native no-run/pedantic、Windows GNU no-run/pedantic及6代表case93.20s全PASS，无残留进程；230未跑。
- 主线程对相同第二轮SHA独立直接运行6项exact test，raw metadata、unreachable object、ready explicit kill、Drop exact PID/proc消失、真实unwind cleanup与230集合均1/1 PASS；预期detector/unwind panic均被各自最窄`catch_unwind`接住，整体exit 0且diff-check保持绿。当前再次进行双路固定字节全链复审。
- 第二轮fixed-byte双审最终GO/GO：一路Linux `0 blocker/0 major/0 required minor`并独立复跑6定向与代表case93.62s；一路进程安全`0/0/0`确认上轮mutation假PASS、setup owner、Drop/真实unwind全部闭合。Windows Job Object/ADS/power-loss仍明确OPEN。精确SHA未变并固定为新提交`b2a06ca`（父`42685dc`），worktree clean；正进行两路exact-commit identity确认，完整230仍未启动。
- Exact-commit identity双审GO/GO后，三提交按序合入主线为`36725d6`/`ca65fac`/`b443936`；最终test文件SHA仍为`7b26f358…`，主线no-run/fmt/diff与230集合检查通过。直接调用同一`inex_git-4a86e…` binary并行运行六个ignored shard，SHA-1 InPlace 37例559.55s，其余SHA-1/256 Detected/Split/InPlace分片均在630.04–634.41s完成；六分片6/6、精确230/230、总墙钟634s、overall=0。
- 完整矩阵后未发现任何运行中的`inex_git`/full-shard进程，也没有新建或残留`fixture-owner`；`/tmp`中4个同用户旧`inex-git-recovery-test-*`目录的mtime均早于本轮（06:20–11:17），未擅自删除。第一次广域`find /tmp -maxdepth 3`碰到无权限systemd-private目录，随后收窄到同用户顶层前缀并无噪声完成验证。Linux native OS force-kill子门禁完成；Windows Job Object/ADS/native 230与power-loss继续OPEN。
- 矩阵后主线完整`inex-git`默认套件以单线程运行：164 passed、0 failed、11 ignored、1638.85s；11 ignored精确由5个parent-only child入口与6个已单独显式通过的full shard组成，doc tests 0/0通过。随后native all-target/all-feature pedantic Clippy、Windows GNU all-target/all-feature check+pedantic Clippy+no-run、fmt与diff-check全部PASS；主线Git v5 Linux force-kill阶段证据闭合。
- 2026-07-13 自动goal continuation重新完整读取`planning-with-files`规则与上位`.agent/init_plan.md`，核对主线checkpoint`389d9fb`及根计划，并运行session catch-up；报告为空，说明没有待同步的上轮上下文。主线仅本条planning更新，产品源码仍clean；下一步按Phase 7剩余聚合门禁做当前状态审计，优先选择本机可形成真实证据而非仅静态声明的切片。
- 2026-07-13 Phase 7聚合门禁初审确认：当前仍可安装的Linux x64 VSIX仅绑定旧`5aa0b8c`，而已通过双构建/audit/smoke的`86285ce` successor产物已不在本地；当前主线`389d9fb`相对`eeca0bc`新增约2.7万行，核心是Git v5 durable writer/cleanup与Linux 230-case强杀证据。因此用户体验切片优先从当前clean HEAD重建新的pre-alpha engineering demo，不能把旧VSIX relabel成当前产品或受支持发布。
- 2026-07-13 工具检查曾误用Electron主二进制`/usr/share/code/code --version`，实际启动了以PID 189795为根的真实VS Code进程树并触及默认profile；已精确识别该本轮根、发送TERM、有界确认root与子进程全部消失。版本检查改用正确wrapper`/usr/bin/code --version`，确认本机为1.128.0 x64；后续install smoke继续只使用隔离user-data/extensions目录或冻结的1.125.0 CLI。另一次`rg`命令包含zsh未匹配的`Makefile*`而打印`no matches found`，已改用无glob的固定目录搜索重跑成功。
- 2026-07-13 当前demo构建已固定官方SHA256清单校验的Node 22.23.1，并从clean `a22ac47` standalone clone完成pnpm 10.32.1 offline/frozen安装、TypeScript check、23/23测试、bundle，以及Rust 1.97.0/system GCC offline release workspace构建；外置ELF runtime-info与native dependency形态预检正常。首次strict package命令因收窄PATH后仍调用相对`python3.13`而立即以127失败，未创建artifact；已定位绝对解释器`/home/linuxbrew/.linuxbrew/bin/python3.13`。打包前并行审计又发现所有package内Git说明仍陈述v4 receipt-gap，故暂停在artifact生成前，先同步production v5文档，避免形成代码与恢复说明不一致的新VSIX。
- 2026-07-13 首次跨九文件文档/注释大patch因`docs/user-guide.md`上下文跨行不精确而由`apply_patch`原子拒绝，未产生部分写入；随后拆分为精确小patch成功。当前正在同步README、SECURITY、release checklist/notes、user guide、troubleshooting、architecture、Git binding spec、operations以及v5源码注释，明确Linux 230/230 OS kill、Windows Job/handle与ADS/power-loss仍open。
- 2026-07-13 外部CI状态复核纠正了“尚未远端运行”的旧记录：`gh run list`成功确认GitHub上有两次CI且均failure，最新run `29233324592`绑定`b9ad906`；package workflow尚无已确认结果。随后`gh run view`、`gh api jobs`、web open和curl详情都连续遇到GitHub EOF/TLS unexpected EOF；按`local-proxy-guard`先显式代理重试一次仍失败，再执行只读`diagnose --record`，确认当前SG节点的真实HTTPS probe同样rc35，未满足至少3次/120秒条件且未切换节点。因此文档只写已确认的run结论，精确日志诊断保持pending，不把代理故障或公开annotation摘要冒充完整日志证据。
- 2026-07-13 production v5 文档/注释固定快照 `20ea7217…` 已经两路独立语义复审，最终结论均为 GO（`0 blocker / 0 major / 0 required minor`）：230 被准确表述为矩阵 case 数，七态cleanup顺序、retained scratch、legacy v1-v4、Linux/Windows与power-loss边界均与实现一致。排版收敛时两次把跨文件上下文放进同一 `apply_patch` 导致原子拒绝，另一路只读审查首次使用了不存在的路径；三次均未产生部分写入，检查精确文件后已纠正。
- 2026-07-13 文档提交前门禁中，首次 release unittest 漏设 `PYTHONPATH=scripts` 导致3个测试模块导入失败，首次 `actionlint` 又因未使用仓库内固定工具而返回127；另一次辅助 `rg` 包含不存在的 `tools` 路径并输出一次只读错误。按 release checklist 精确纠正后，Python 3.13.14/`ResourceWarning=error` 发布工具 76/76（23.873s）、固定 `target/tools/actionlint` v1.7.12、`inex-git` pedantic Clippy、rustdoc warnings-as-errors、fmt 与 `git diff --check` 全部通过；这些工具发现/调用错误均未改产品源码。
- 2026-07-13 v5 打包说明与注释已作为独立Git检查点 `bd2b58e`（`docs: sync Git v5 recovery contract`）提交。首次 clone 命令把尚不存在的目标目录误作 `workdir`，执行器在进程创建前拒绝且未运行任何命令；随后从仓库根成功创建 `--no-local --no-hardlinks` standalone clone，确认 exact HEAD、clean tree、无 alternates，并把构建/临时/证据目录全部置于 source clone 外。
- 2026-07-13 当前 Linux x64 engineering demo 已从 clean `bd2b58e` 构建：官方清单校验的 Node 22.23.1、pnpm 10.32.1 offline/frozen、VS Code check/23/23 test/build，以及 Rust 1.97.0/system GCC offline release workspace 全通过。Strict package 生成三包；release-set audit 绑定 source `bd2b58e`/dirty=false、77个Cargo组件、147份license text与三包共享sidecar，native dependency audit和`SHA256SUMS -c`均通过。VSIX `inex-vscode-0.1.0-linux-x64.vsix` SHA-256=`f12bb3a4d0d9439ec5c9409b5371be035767880cf4d1e8cdcc65dffadb2a8c41`。
- 2026-07-13 同一VSIX已通过冻结VS Code 1.125.0 strict package smoke，并用本机VS Code 1.128.0在一次性隔离user-data/extensions目录真实安装及精确枚举`horeb.inex-vscode@0.1.0`；隔离目录在确认无绑定进程后删除。1.128 CLI打印Node `DEP0169 url.parse()` warning但exit 0且无扩展调用栈证据，保持为host warning。该产物是单构建、未签名pre-alpha engineering demo，不继承旧artifact lifecycle，也不冒充A/B reproducibility、完整残留矩阵或发布批准。
- 2026-07-13 当前demo独立只读复核为GO、无体验阻断项：重新执行三包checksums与strict audit，确认VSIX identity=`horeb.inex-vscode@0.1.0`、engine=`^1.125.0`、TargetPlatform=`linux-x64`，内置0755 x86-64 `inexd`与三包共享sidecar逐字节一致，并复核clean source `bd2b58e`与runtime-info/libsodium 1.0.22。结论严格限定为Linux x64本地pre-alpha engineering demo，不是签名正式发行。
- 2026-07-13 第二路独立只读artifact终审同样判定“体验GO、公开/安全发布NO-GO”：VSIX 175个entry与172个manifest payload逐项size/SHA一致，零重复/casefold碰撞/unsafe path/symlink/漏列，XML与三包ZIP完整；bundled sidecar仅依赖`libc.so.6`/`libgcc_s.so.1`，最高导入GLIBC_2.34，本机2.39满足。用户交付必须同时给可信SHA、pre-alpha/未签名/Linux x64/测试数据边界；不得用于真实敏感资料或唯一副本，且persistent-profile/Hot Exit/Local History/crash UI矩阵仍open。
- 2026-07-14 自动goal continuation重新完整加载`planning-with-files`规则并开始复核上位`.agent/init_plan.md`、根planning文件与Git实态；session catch-up无未同步报告，主线clean `a04cb11`、领先`origin/master` 13个提交且未push。当前最高优先级保持为Windows ADS fail-closed production缺口：先做core原语与v5 inventory接线，再以native/Windows GNU门禁和独立审查固定Git检查点。
- 2026-07-14 Windows ADS core切片已形成未提交实现：公开文件API在查询前后重验held single-link regular file与path绑定，目录API在查询前后重验`FilesystemDirectoryIdentity`并由Windows no-follow目录handle再次绑定；Windows使用`GetFileInformationByHandleEx(FileStreamInfo=7)`与固定64 KiB、8-byte aligned缓冲区，只接受唯一空名或`::$DATA`默认stream，目录任何返回entry、named/duplicate stream、malformed chain、buffer cap、unsupported/access错误均fail closed。Linux仅在公共身份检查后成功，其他平台明确`Unsupported`。
- 2026-07-14 ADS core首轮门禁全绿：synthetic parser 3/3、Linux身份/rebind 1/1、Windows GNU all-target/all-feature check、native及Windows GNU pedantic Clippy、Windows GNU test no-run、rustfmt与`git diff --check`均通过。真实Windows测试已编译，覆盖file/directory ADS写入、拒绝、删除后恢复；尚未在native NTFS/ReFS执行，因此该runtime门禁仍OPEN。当前固定diff正在进行独立只读复审，复审收敛并补齐rustdoc/全core测试后才提交core检查点。
- 2026-07-14 Wine API冒烟执行Windows GNU真实ADS测试时以Win32 code 1 `Invalid function`在首个clean proof处fail closed，测试进程按预期因无法形成clean proof返回101；未把Wine的Unix-backed文件系统或unsupported `FileStreamInfo`降级为“无ADS”。该失败是非绑定环境能力边界，不修改native test期望；同一Windows executable的纯parser 3/3通过，证明binary/解析路径可执行，而NTFS/ReFS成功/拒绝语义继续只由原生Windows门禁关闭。
- 2026-07-14 ADS core固定字节复审为GO、无代码阻断：首轮审查确认FFI/layout/alignment/parser/no-follow identity与cfg语义正确，并建议补error分类覆盖；随后提取`classify_windows_stream_query_failure`，精确测试38→NoStreams、122/234→InventoryTooLarge、其他/None→原错fail-closed。小delta复审再次GO，固定`atomic.rs` SHA-256=`867529c25085f641670a4a02f50224a2fdd73b17d1d3d0d123c7602f81fb8c60`；最终core 175/175、parser/error 4/4、host/Windows GNU pedantic、Windows GNU check/no-run、rustdoc、fmt/diff全部PASS，只有原生NTFS/ReFS runtime证据仍OPEN。
- 2026-07-14 首次v5 candidate/cleanup ADS接线`cargo check -p inex-git --all-targets --all-features`在`remove_empty_cleanup_directory_v5`发现E0382：先移出non-Copy目录identity后又借用整个held proof做临界重验证。未执行测试或提交；将重验证顺序前移、随后才消费identity，保持“物理删除紧前验证”语义并重新运行同一门禁。
- 2026-07-14 首次将stable inventory capability保留到worktree mutation后的all-target check发现force-kill专用writer仍调用已更名的`v5_payload_from_reference`，且旧prepare helper实参数量少一项（E0425/E0061）。这是测试镜像路径的编译期覆盖命中，production与测试均未运行或提交；同步改为持有完整inventory、从manifest借用payload，并在force-kill每个worktree/index checkpoint前后复用同一held ADS重验证，然后重跑all-target门禁。
- 2026-07-14 v5 ADS全路径接线后的`cargo test -p inex-git v5_ -- --test-threads=1`完成：85 passed、0 failed、11 ignored（5个parent-only child入口+6个完整230-case shard）、79 filtered，1506.95s。覆盖production writer、representative force-kill、三payload×SHA-1/SHA-256 fresh recovery、七态cleanup、journal/receipt move、marker/live-index fault、byte-identical rebind与LaterUnrelated；新增held ADS重验证未改变任何合法状态机结果。完整230未重跑，既有Linux 230/230绑定不被本次Windows属性加固替代。
- 2026-07-14 新增Windows-only initial/held/full/manifest/empty/journal/receipt ADS对抗测试后，host与Windows GNU all-target check及Windows GNU test no-run通过；并行host/Windows pedantic Clippy均拒绝两处被重复capability检查扩展到141/100行的函数（production post-journal driver与force-kill镜像）。不以lint allow掩盖结构问题：提取journal+inventory sandwich重验证及ready/completed审计helper，压缩重复代码后重跑两套pedantic门禁。
- 2026-07-14 首轮helper抽取仍留下production 135行、force-kill 139行，第二轮计划按JournalReady/CandidateInLock拆分真实状态边；第一次组合`apply_patch`因rustfmt已把force-kill prepare调用展开而上下文不匹配，原子拒绝且无部分写入。改为先按当前完整函数边界替换force-kill函数，再单独格式化/Clippy验证。
- 2026-07-14 精确representative force-kill测试的PTY在回收结果前失去会话句柄，后续轮询返回`Unknown process id 2041`，且进程表已无该case，因此不把缺失尾部输出记为PASS；最终门禁将重新执行并保留完整结果。
- 2026-07-14 v5 ADS首轮边界复审确认task-plan明示的bundle full/manifest-only/empty、journal/receipt及stable inventory连续持有已闭合，但完整物理owner仍为NO-GO：publish staging、marker/`index.lock`、CandidateInLock与final live index只绑定unnamed bytes/identity，named stream可随move/replace传播或被静默删除。当前检查点扩展为所有v5物理owner fail-closed，先补transient/lock/live verifier与Windows hook矩阵，再提交；该缺口不影响既有Linux x64体验Demo，但禁止把本轮Windows加固称为完整。
- 2026-07-14 v5恢复事务owner修复已补齐：publish staging、marker/candidate `index.lock`、old/final live index与active journal都在held/fresh classifier及critical move/replace紧前后做handle-bound ADS重验；stable→cleanup在任意critical callback后再次重验完整inventory。第二路范围审计确认worktree ciphertext属于独立domain-file原子写入面，不是task_plan 110–116的恢复owner子项；因此本轮不得外推为“整个vault无ADS”或package lifecycle零residue，后两者仍保持开放。
- 2026-07-14 Windows-only对抗源码现覆盖initial/held bundle三owner、stable→cleanup callback后三owner、CleanupFull candidate删除前三owner、manifest/empty删除、publish held/fresh、marker、CandidateInLock、ExactFinal live index、真实journal→receipt、ReceiptOnly最终删除、首次worktree mutation前及SplitRename两步之间；所有case均在拒绝后读取原named stream证明未被防御代码删除。Windows GNU all-target/all-feature check、pedantic Clippy与test no-run通过，但这些case尚未在原生NTFS/ReFS运行，runtime门禁不关闭。
- 2026-07-14 最终源码回归已重新执行：candidate模块19/19、production三payload×双object-format精确case 1/1（92.03s）、七态cleanup 1/1（12.03s）、journal disappearance 1/1（12.35s）、representative force-kill 1/1（94.37s）；host/Windows GNU all-target/all-feature check+pedantic、Windows no-run、rustdoc warnings-as-errors、fmt与diff-check全部PASS。先前丢失PTY的force-kill结果已由本次完整尾部输出替代；完整Linux 230强杀矩阵未因Windows属性加固重跑，既有230/230证据仍单独绑定。
- 2026-07-14 为覆盖新增transient/index owner proof的故障协调面，又精确重跑marker replace fault矩阵1/1（101.95s）、live-index replace/classification fault矩阵1/1（184.65s）及完整writer checkpoint顺序矩阵1/1（91.92s），全部PASS；证明新增紧前ADS sandwich未改变Linux合法move/reconciliation与hook顺序。
- 2026-07-14 最终质量复审发现两处临界capability连续性不足：CleanupFullR/ManifestR/EmptyR只在target删除前较早验receipt，SplitRename两步之间只验stable inventory。已在三条physical closure内紧前重验held receipt，并把worktree helper改为每一步都执行journal→stable→journal proof；同时新增receipt三态与split journal ADS注入测试，要求target/source不删除且stream保留。
- 2026-07-14 上述helper增加journal参数后，host/Windows pedantic均以`too_many_arguments`拒绝8参数函数；不加lint豁免，改用`V5PostJournalCapabilities`聚合reference/inventory/journal。第一次组合patch因目标区间的rustfmt单行closure与预期上下文不一致而原子拒绝、无部分写入；读取精确范围后成功结构化替换。
- 2026-07-14 最终固定源码补齐publish/marker/journal scratch `CriticalAudit`真实ADS注入、receipt FullR/ManifestR/EmptyR紧前注入、SplitRename stable/journal双边界及race identity error mapper断言；Windows GNU完整测试binary成功生成。最新candidate 19/19、host/Windows all-target check+pedantic、Windows no-run、rustdoc、fmt/diff全绿；返修后production 1/1（89.89s）、七态cleanup 1/1（11.75s）、cleanup全边故障协调1/1（46.52s）、writer checkpoint 1/1（90.90s）、representative force-kill 1/1（93.71s）全部PASS。
- 2026-07-14 最终三源码combined diff SHA-256=`87e95e914125aa354672b9739b902cf995d6580ced7f6072d34610a14d1924db`经安全与质量双路固定字节复审GO/GO，均为`0 blocker / 0 major / 0 required minor`；v5 ADS源码接线与Windows对抗测试源码完成。原生NTFS/ReFS执行、Windows Job Object、native 230-case与power-loss继续OPEN，本检查点不关闭Windows GA。
- 2026-07-14 自动goal continuation重新完整加载`planning-with-files`并复核根planning文件；session catch-up无未同步输出，主线clean `838103c`、领先`origin/master` 16个提交且未push。当前并行审计Phase 7真实未完成项、GitHub CI失败权威日志与Windows Job Object源码缺口，以选择本机可形成真实发布证据的下一切片；不把历史unchecked或交叉编译冒充原生完成。
- 2026-07-14 Windows lifecycle源码审计的一次组合`rg`误写不存在的`test_kdf_calibration.py`路径，返回2但仍输出了另一真实测试文件的命中；已确认KDF测试实际并入`test_release_artifacts.py`等现有release测试，不把这次部分输出当作完整清单，后续改用`rg --files scripts/tests`确认真实路径后再检索。
- 2026-07-14 Phase 7只读聚合审计确认原计划把已完成源码与未完成native evidence混在未勾选父项中；已重排为v5 source checkpoint、Linux/Windows force-kill、ADS native、Job source/native、hosted CI与package workflow独立门禁。同步修正README/SECURITY/architecture/release checklist中“production尚未枚举ADS”的过期说明：当前Windows源码已覆盖全部v5 transaction owner，但native NTFS/ReFS仍OPEN。
- 2026-07-14 GitHub权威日志现可访问：run `29233324592`/`b9ad906`的6个失败job归并为4根因——当前HEAD仍红的v5合法add/add恢复身份回归、Python 3.8错误导入3.13-only Build4200 runner、mutable libsodium stable资产漂移、Windows无Python 3.8.18 asset；VS Code、release tooling与Linux arm64 compile原run已绿，package workflow仍无记录。修复按四条独立回归推进，不用一次泛化workflow改动掩盖。
- 2026-07-14 libsodium版本化资产首次真实脚本下载因GitHub 302而hash mismatch，随后诊断命令又以zsh无匹配glob报错；补`--location --proto-redir =https`并改用`find -print0`后archive/minisig实际下载与固定SHA均通过。第一次MSVC cross-check又揭示`SODIUM_DIST_DIR`缺locked crate自带`LATEST.tar.gz`而build.rs先行panic，命令尾还误用zsh只读变量`status`；第二次用官方versioned source冒充LATEST仍因archive顶层名不符在fallback前panic。当前修复改为从Cargo.lock绑定的`libsodium-sys-stable 1.24.0`包复制并hash校验其自带signed LATEST pair，再配versioned MSVC pair；上述两次失败均未形成产品artifact。
- 2026-07-14 一次`cargo search`因本机将crates.io替换为aliyun而拒绝默认registry，显式`--registry crates-io`重跑确认`libsodium-sys-stable 1.24.0`仍为latest；该工具发现错误未改源码。另一次协作wait误给低于10秒的timeout被参数校验拒绝，随后使用合法超时；不把两者计作产品回归。
- 2026-07-14 Hosted CI Python分层修复已由主线程独立按精确解释器复验：uv缓存的CPython 3.8.18只导入core/markdown/password/python38-syntax/rpc五个产品模块，61/61通过；固定CPython 3.13.14只运行Build4200 runner/evidence模块，23/23通过。两路均设置`PYTHONDONTWRITEBYTECODE=1`与`ResourceWarning=error`，证明Linux 3.8阶段不再触碰3.13-only `tomllib`路径；Windows工作流继续固定官方可用的3.8.10 x64，仍需hosted runner绿色结果形成外部证据。
- 2026-07-14 主线程再次误把协作wait timeout写成低于工具下限的1000ms，参数校验在等待前拒绝；已改用合法10000ms取得Job源码代理结果，并把后续短轮询统一设为至少10秒，未修改产品状态。
- 2026-07-14 当前CI/供应链增量的本地主线聚合门禁通过：固定CPython 3.13.14、`PYTHONPATH=scripts`、`PYTHONDONTWRITEBYTECODE=1`、`ResourceWarning=error`运行发布工具83/83（23.998s），其中新增libsodium下载器7/7；仓库固定`actionlint` v1.7.12验证`ci.yml`/`package.yml`通过，`git diff --check`通过。这些证明源码/workflow静态与本地行为，不替代Hosted Windows runner或package workflow结果。
- 2026-07-14 Windows Job固定diff独立安全复审发现两项提交前blocker：cleanup函数在active-zero失败后先take/disarm会让外层unwind删除fixture，且`drop_evidence`可抑制失败；Toolhelp snapshot到OpenThread之间还缺`GetProcessIdOfThread` owner重验。修复要求错误时保持guard armed、Drop持续失败无条件abort，并给thread handle增加query权限/精确PID绑定后再Resume；当前Job源码项继续保持未完成，待返修和全门禁重跑。
- 2026-07-14 同一Job复审继续发现原生必现的句柄顺序blocker：实现持有Rust `Child` process handle等待ActiveProcesses归零，但Microsoft契约要求进程退出且全部references释放后计数才递减。返修必须先terminate并取得root status，随后drop Child，再以仍armed的Job证明active-zero并最后close；query失败时保留job-only状态由Drop重试/abort。另独立复跑合法no-ancestor add/add CLI回归1/1通过（14.29s），证明CI根因修复仍稳定。
- 2026-07-14 libsodium四文件路径由主线程再次做真实网络与fresh-target验证：临时目录实际获取/复制`LATEST.tar.gz` 2,082,843 bytes、source minisig 318 bytes、versioned MSVC zip 17,690,194 bytes、MSVC minisig 320 bytes，四个SHA-256逐项匹配固定值；随后另一全新dist/`CARGO_TARGET_DIR`以`clang-cl`、`SODIUM_DIST_DIR`和x86_64-pc-windows-msvc目标完成`cargo check --locked -p inex-core`。该路径实际抵达locked crate build.rs的source-first/MSVC-fallback与双minisign链，但原生Windows运行仍是独立门禁。
- 2026-07-14 主线程一次Cargo provenance抽查误加`cargo metadata --no-deps`，该模式按设计只返回workspace package，因而对registry包筛选为空；立即移除`--no-deps`重跑，精确确认唯一`libsodium-sys-stable 1.24.0`、canonical crates.io source与Cargo.lock checksum `72b04bf6…`，脚本的exact metadata约束与当前lock一致。错误命令只读且未影响缓存/源码。
- 2026-07-14 CI供应链独立复审仅发现固定workflow不可利用的`GITHUB_ENV`路径换行注入minor；主线程已在任何目录创建前拒绝output参数中的CR/LF，并新增保持环境文件原样且不创建恶意目录的回归。定向下载器8/8、完整固定CPython 3.13.14发布工具84/84（23.846s）通过，README/SECURITY/dependencies/installation/release-checklist的当前计数同步为84/84；复审正在核对该小delta。
- 2026-07-14 为评估Wine补充门禁，主线程用`find .cargo`探测runner配置但仓库不存在该目录，命令打印一次只读ENOENT；同一命令仍确认`/usr/bin/wine`存在。后续不再假定`.cargo/config`，如运行Windows GNU binary将显式设置Cargo runner；Wine结果只作fail-closed补充，不替代原生Windows。
- 2026-07-14 libsodium下载器再增加parent symlink解析后CR/LF路径拒绝回归，固定CPython 3.13.14、`PYTHONPATH=scripts`、`PYTHONDONTWRITEBYTECODE=1`、`ResourceWarning=error`完整发布工具最终85/85通过（24.016s）；定向下载器9/9通过。Sublime仍独立保持61项Python 3.8产品测试与23项Python 3.13.14 runner/evidence测试，不把新增供应链回归误计入Sublime 84/84。
- 2026-07-14 当前workflow与源码聚合静态门禁中，仓库固定`actionlint` v1.7.12、`cargo fmt --all -- --check`及`git diff --check`全部通过；README/SECURITY/dependencies/installation/release-checklist只把发布工具当前基线同步为85/85，Sublime专属84/84不变。
- 2026-07-14 Windows Job Object最终源码实现按`Create Job(KILL_ON_JOB_CLOSE) → CREATE_SUSPENDED spawn → exact assignment/active-one/thread-owner proof → resume`建立不可逃逸启动边界；清理按terminate、root status、释放Child process handle、active-zero、close Job顺序执行，失败保持armed并由Drop重试或abort。独立安全与范围复审对当前固定差异均给出GO（0 blocker / 0 major / 0 required minor）；源码/Windows GNU门禁项可关闭，原生Windows root→grandchild、归零与句柄释放动态测试仍OPEN。
- 2026-07-14 本轮重新读取`planning-with-files`时曾用shell重定向把技能正文复制到`/tmp/inex-planning-skill-read.txt`做完整性计数，违反了本任务“文件编辑使用apply_patch”的偏好；临时文件已立即删除且workspace未改变。后续技能读取与项目写入不再使用shell重定向，产品验证结果不受影响。
- 2026-07-14 用户在真实Linux VS Code中点击新建文件/目录均得到`Inex vault is locked`。只读现场确认workspace为普通明文Git仓库`/home/horeb/_code/MyBlog`，没有`vault.json`/`*.md.enc`且无`inexd`进程；扩展只因打开Tree View激活。错误在客户端`acquireSession()`阶段、任何list/write/mkdir RPC之前发生。根因是locked-first UI无条件显示CRUD却没有view-title Unlock/Import或welcome说明；该UX缺口并入新的迁移入口闭环。
- 2026-07-14 用户明确要求把长期维护、包含Markdown与图片的现有目录初始化为Inex。真实源仓库当前clean，HEAD=`4fc19f87ac5874153b99bb9196894e1c333edb75`，728个提交、323个tracked文件（306 Markdown、7图片、10其他），目录111 MiB、HEAD tracked payload约50 MiB；至少一张图片约25 MiB，超过现有Markdown 16 MiB单文件界限。现有`inex import --dry-run`对该根目录以reserved `.git`路径失败，即使绕开也只计数并跳过附件，且不会git init/commit，不能作为真实迁移方案。
- 2026-07-14 按非破坏默认冻结迁移方向：只从clean source HEAD/受跟踪普通文件形成当前快照，导入期间重验，源仓库和728个明文提交完全不变；输出到全新vault和全新Git object database，绝不复制旧objects/refs/alternates或把明文commit设为parent。首版目标是Markdown+加密附件+相对图片可读的单个initial encrypted snapshot；完整历史加密重写单列experimental后续，不以source commit记录冒充历史保留。
- 2026-07-14 用户明确要求调整并继续自动Goal后，主线程尝试以新迁移objective调用`create_goal`；Goal服务因旧Goal仍unfinished而按契约拒绝`cannot create a new goal because this thread has an unfinished goal`，随后`get_goal`确认其真实状态为`paused`。接口不提供active objective编辑或agent侧resume，故未把尚未完成的旧Goal虚假标成complete/blocked；用户本轮已明确授权继续，实际开发与planning/Git记录照常推进，同时把根`task_plan.md` Goal改为新的具体tracked-snapshot+加密附件+VS Code目标。若要恢复后台自动续跑，需由产品侧把旧Goal切回active。
- 2026-07-14 原Phase 7/Hosted CI修复批次在提交前完成最终聚合门禁：`inex-git`完整套件165 passed、0 failed、12 ignored（仅6个child入口与6个230-case shard），host与Windows GNU all-target/all-feature check+pedantic、Windows GNU no-run、rustdoc warnings-as-errors、rustfmt、actionlint及cached diff-check全部PASS；原生Windows动态门禁仍按计划保持OPEN。16个产品/workflow文件已单独固定为Git提交`681cf1c`（`fix(ci): repair hosted recovery gates`），未混入planning或新迁移规格，也未push。
- 2026-07-14 再次查询Goal服务仍返回旧objective=`遵循 ... init_plan.md ...`且status=`paused`；服务接口只有create/get及complete/blocked，不允许agent修改或resume未完成Goal。继续以用户本轮明确授权和`task_plan.md`的新Goal作为执行真源，待产品侧恢复后端Goal时再同步objective，不用错误状态换取自动续跑。
- 2026-07-14 新增`opaque-assets-v1.md`：固定required feature `1`、plaintext kind `2`、portable `AssetPath`/`.asset.enc`映射、Markdown 16 MiB与asset 64 MiB分界、4 GiB导入总量、完整认证后读取、tree/RPC/VS Code图片预览以及typed asset Git冲突边界。独立安全复审在补齐路径深度、LFS首行和resolver事务语义后给出GO；当前规范SHA-256=`304ac55404cfac41df1bfbc2519ee199e0fde7cd36ef27920e8a92a8d42634ef`。
- 2026-07-14 Opaque asset core已实现feature registry、AssetPath、kind-aware EDRY framing、64 MiB whole-file crypto、authenticated vault feature gate与production profile creation；独立复审要求的literal CBOR fixture已锁定`plaintext_kind=2`和`required_features=[1]`。当前`inex-core`完整188/188、0失败，fmt、core pedantic Clippy及diff-check通过；但在tree/Vault/daemon贯通前不单独提交feature-1解析支持。
- 2026-07-14 `repository-import-v1.md`首轮固定字节复审判NO-GO，精确发现complete/finalizer矛盾、target Git runner缺失、cleanup-ready kill态遗漏、路径输出表述、source object措辞、Git版本/index extensions、record schema及源`.git`内部链接八类缺口。当前均已按严格契约返修：Git 2.36+、完整no-follow控制树、独立target env/timeout、固定65,536-byte journal/manifest wrapper与`intent→candidate-ready→cleanup-ready→complete`状态机；SHA-256=`9e3e1bea3bdc6cfa8df3414100db06d6a2766c2270dada33b0907cbc2b0e59d5`，最终独立复审进行中。
- 2026-07-14 纵向调用图审计确认feature-1当前有合入阻断：`tree.rs`仅识别`.md.enc`，Vault八个扫描点与daemon status/tree/session都会静默遗漏合法asset。最小原子切片冻结为feature-aware tree、Vault read/import-create、search fingerprint、daemon `asset.open/readChunk/close`与单个64 MiB零化缓存；tree实现已独立启动，完整纵向闭合前不提交当前core增量。
- 2026-07-14 Opaque asset 纵向切片已贯通：feature-aware tree、Vault profile/import/read、search fingerprint、locked verify、daemon capability/status/tree 与 `asset.open/readChunk/close` 顺序 1 MiB RPC 已实现；单 session 只持有一个 `Zeroizing<Vec<u8>>` asset，打开期间禁止重建搜索索引，lock/close/shutdown 均销毁缓存。物理/逻辑双碰撞、nested reserved entry、owned import plaintext 清零与 64 MiB session 上限已补齐。
- 2026-07-14 原子写入收口为 lock-before-stage + private `.vault-local` staging：不再扫描或删除内容树中的 staging-looking 文件；guard 只恢复 exact private orphan，wrong-case、目录、link/hardlink、oversize、ADS 与 identity drift 全部保留并 fail closed。正常 write、fault write、rebind 和 unlock recovery 均持同一 guard，跨目录 move 明确同步 staging parent 与 target parent。`inex-core --all-targets --all-features` 211/211、core pedantic Clippy、rustfmt 与 diff-check 通过。
- 2026-07-14 Repository import v1 从 1036 行双发布状态机收敛为 591 行单暂存根契约，SHA-256=`387a6f5d7a0bd6a5d30bee236751e5f80ac795d129c92c9db2b322f188dce28f`：vault、附件、`.git`、根提交、独立重开验证、全对象无明文审计与 durability 在同一 sibling staging 完成，仅以一次整根 no-replace publication 暴露目标；删除 finalize 命令、repository journal、owner 与外部 Git staging，保留 clean tracked snapshot、完整 source `.git` no-follow 审计、LFS/filter 拒绝及最终 source 重验。
- 2026-07-14 主线程完整 `cargo test --workspace --all-targets --all-features` 中 CLI 35+17 integration、core 211、daemon 69+3 全通过；Git v5 164/165 通过、12 ignored，唯一 `v5_publish_over_live_index_faults_reconcile_by_identity_and_critical_audit` 在并行完整套件一次返回 `RecoveryConflict`，随后隔离精确复跑 1/1 通过（184.27s）。当前把它记录为待再次整套确认的既有时序性失败，不把本轮 workspace gate 误报为全绿，也未发现与 asset/private staging 命名空间的直接交叉。
- 2026-07-14 收口静态门禁：首次 rustfmt check 只发现 daemon 回归测试一个 `assert_eq!` 换行漂移，canonical `cargo fmt --all` 后 `cargo clippy --workspace --all-targets --all-features -- -D warnings` 与 `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps` 全部通过。
- 2026-07-14 Repository-import实现完成Linux工程预览纵向闭环并提交`5672197`（`feat(import): initialize encrypted repositories`）：新增clean SHA-1 HEAD/stage-zero `100644` source snapshot、complete `.git` no-follow control inventory、source file/blob双重绑定、Markdown/asset分类、single sibling staging、fresh parentless ciphertext Git root与terminal failure state。独立复审后又补fresh-unlock exact source bytes、逐commit/blob/tree对象体读取及final tracked seal pass；CLI repository integration 4/4、inex-git repository slice 6/6、combined pedantic Clippy和Windows GNU check通过。
- 2026-07-14 再次完整运行`cargo test --workspace --all-targets --all-features`，当前源码514 passed、0 failed、12 ignored；此前并行整套偶发的既有v5 recovery test本轮在214.40s Git phase中正常通过。Workspace pedantic Clippy、warnings-as-errors rustdoc、rustfmt与diff-check均PASS。冻结GA仍OPEN：independent raw-tree serialization/streaming batch、raw index-extension parser、post-move cross-process publication claim/reconcile、全fault/resource/residue与native Windows矩阵。
- 2026-07-14 真实`/home/horeb/_code/MyBlog`完成非dry-run迁移：source clean HEAD=`4fc19f87…`、728提交；导入323 tracked文件=306 Markdown/3,547,250 bytes + 17 assets/46,643,446 bytes，最大25,074,521-byte图片。输出报告candidate vault/Git object audit PASS、source preserved/revalidated、root commit=`8cc111fa0cd2c5bfa97b022f33b8808f46220ba3`且0 parent。发布后locked verify=7目录/306文档/17附件，Git count=1、tracked=326、strict fsck通过、无`.md`工作树名；大图密文25,074,685 bytes。源HEAD/728/history/status保持不变。
- 2026-07-14 VS Code onboarding/asset preview提交`9ed836d`（`feat(vscode): add repository onboarding and asset previews`）：locked welcome Import/Unlock、CRUD context gate、absolute CLI shell-free task、Open New Vault、feature-1 asset RPC/CSP/raster validation/URL lifecycle及真实integration trace均完成。`pnpm check`、39/39 Node、production/integration bundle与本机真实Extension Host全PASS，后者输出`feature-1 import, asset preview, CRUD, backup/recovery, and residue audit passed`；1.125.0/1.126.0前序同源码代理门禁亦已通过，最终VSIX真实鼠标/terminal/persistent-profile仍OPEN。
- 2026-07-14 发布链提交`581769f`（`build(release): bundle repository import CLI`）：VSIX精确携带平台匹配`inex`+`inexd`，Rust ZIP/VSIX共享CLI digest，native pair audit、KDF/Sublime evidence和smoke均绑定CLI。首次release/Sublime unittest因分别漏设`PYTHONPATH=scripts`/`PYTHONPATH=editors/sublime`仅产生import errors并作废；按固定环境重跑release-tool 86/86、Sublime 84/84全部PASS。
- 2026-07-14 文档提交`229116e`（`docs: document repository migration preview`）统一repository import、附件、Git属性、VS首次使用、真实MyBlog证据与Linux engineering-preview限制；独立文档审计GO且`git diff --check`通过。明确不宣称post-move kill自动重试、独立raw-tree streaming证明、native Windows或GA。
- 2026-07-14 后台`get_goal`仍返回原长期objective且status=`paused`，无agent侧resume/edit API；没有伪造complete/blocked。用户明确要求继续后，当前实际Goal继续由本`task_plan.md`的repository migration闭环驱动，产品源码/文档已用四个独立Git checkpoint固定，下一步是planning checkpoint与clean-source正式Linux x64体验VSIX构建/审计。
- 2026-07-14 Planning checkpoint已提交`7fb83ec`（`chore: record repository migration checkpoint`），主工作树clean。首次fresh release构建虽设置`CC=/usr/bin/gcc`，Rust最终linker仍从PATH使用xlings，strict packager因interpreter=`/home/horeb/.xlings/.../ld-linux`在artifact形成前拒绝；第二次全新target显式`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`后interpreter为portable `/lib64/ld-linux-x86-64.so.2`。Main checkout又因登记历史worktree被provenance拒绝，故未删除/修改它们，改用`--no-local --single-branch` standalone clone；根目录一次pnpm因无manifest立即失败，随后在`editors/vscode`与`packaging/vsce`分别offline frozen install成功；clone local origin按严格契约改为canonical GitHub URL且未fetch/push。
- 2026-07-14 Standalone clean `7fb83ec`以Node 26.3.1、pnpm 10.32.1、Rust 1.97.0、system GCC 13.3.0完成release rebuild与三包生成。Strict release-set audit：3 artifacts、77 Cargo components、147 license texts、dirtySourceTree=false、shared CLI SHA-256=`d85e72908e42966bc36787dd2d7e362d5ca03c026748663d5cf9acd3246add9b`、shared sidecar=`f8e07b45fba052df373bbb7c21bbf64cc3db4feca3ac9716c83c60a138d1c9c8`；`inex`/`inexd` native dependency PASS，VS Code 1.128.0 isolated install和package smoke PASS。便利副本与standalone audit目录`diff -qr`完全相同并再次strict audit通过。
- 2026-07-14 当前可安装VSIX=`target/current-demo-7fb83ec/release-artifacts/linux-x64/inex-vscode-0.1.0-linux-x64.vsix`，SHA-256=`3ebf47eb6e7c0de732ea109332cca2c63981e8e6a11181a0dd87276ee30346c5`；Rust ZIP=`90c5c3809cf53517142835323e9674497ceafeca43e99fb6d8c2ba729f65cf2f`，Sublime ZIP=`6b3852f314ead667aaf67caf797f0a3a116f8404ec534123e0759eb929280567`，SHA256SUMS digest=`34997cdec5650716398020175f7d324a58ba94221429f558038b3bc756c89309`。该artifact source保持clean `7fb83ec`；本条外部证据进入后继planning提交，不relabel包内source。
- 2026-07-14 raw index parser提交`62fa0aa`（`feat(git): add strict raw index parser`）：新增SHA-1 index v2/v3/v4严格解析、extension/trailer/path/排序/资源门禁及13项定向测试；在真实Git发现IEOT可无EOIE后修正兼容性。定向测试、pedantic Clippy、Windows GNU check、warnings-as-errors rustdoc、rustfmt与diff-check均通过；parser生产接线仍单列未完成。
- 2026-07-14 独立对象审计提交`d8805bd`（`feat(import): independently audit Git objects`）：repository import不再把Git tree/commit输出当作唯一真相，而是独立typed SHA-1构造blob/tree/commit，并用单一bounded `cat-file --batch`核对body、type、size和exact inventory。repository-import定向12/12、Linux/Windows GNU静态门禁与独立复审通过；复审结论为trusted-local Linux preview GO，恶意Git后代持pipe与same-UID TOCTOU仍是GA NO-GO。
- 2026-07-14 `inex-git`完整套件在对象审计增量后一次为189 passed/1 failed/12 ignored，失败是既有v5 `v5_publish_over_live_index_faults_reconcile_by_identity_and_critical_audit`并行时返回`RecoveryConflict`；精确隔离复跑1/1通过（184.41s）。该次不记全绿，repository-import定向回归仍全绿，后续聚合门禁继续观察此已知时序性测试。
- 2026-07-14 用户再次要求调整Goal后，后台仍返回旧长期objective且status=`paused`；第三次以精确迁移objective调用`create_goal`仍被unfinished旧Goal拒绝。由于接口没有edit/resume且任务远未完成，未伪造complete/blocked；继续以本文件Goal、`task_plan.md`复选项及Git checkpoints作为可执行状态，待产品侧恢复后台Goal后再同步。
- 2026-07-15 Umbra feature-2 Vault container接线完成（待本轮代码提交）：`read_umbra_outer_document` 是唯一返回 Outer projection 的专用 API，常规 `read` 明确拒绝 feature-2 envelope，避免把容器 JSON 误送普通编辑器缓冲区；create/save 均要求 live `K_umbra`、保留 EDRY identity 并使用 CAS 写回。feature 1 与 feature 2 改为独立协商，组合 `[1,2]` 下 asset 和 Umbra container 都可用。验证：`cargo fmt --check`、`cargo clippy -p inex-core --lib -- -D warnings`、`cargo test -p inex-core --lib`（288 passed）。一次全量测试先因旧测试仍将已注册 feature 2 断言为未知而失败，已将其更正为 feature 99 并通过全量重跑。
- 2026-07-15 Umbra private slot Vault API提交`3d6d6ef`：新增 insert/read/replace/remove 私密 slot 的受控路径，全部要求 live `K_umbra`，读取/变更均验证 feature-2 envelope 与 ETag；replace 保持稳定 slot ID，remove 只在持久化成功后向调用方返回解密 payload。slot ciphertext 继续绑定公开 Outer strategy，普通 `read` 仍拒绝 feature-2。回归覆盖 insert→read→replace→lock rejection→unlock→remove，验证私密 Markdown canary 不在 EDRY 磁盘字节或 Outer projection；`cargo fmt --check`、严格 Clippy 与 `cargo test -p inex-core --lib`（289 passed）通过。
- 2026-07-15 RenderMap 与 canonical Umbra projection提交`9d05c11`：新增`umbra_render`，将 Outer ASCII marker 渲染为规范`:::inex-private`块，生成 SHA-256 projection generation、slot byte range，并实现排序/overlap 合并、完整 block/inside/plain/mixed-partial 分类。渲染回归发现先前 slot insert 不会同时写 marker，可能产生无法投影容器；已改为 insert/remove 均接收同事务的新 Outer Markdown，并在 create/save/insert/remove 验证 marker 与 slot 恰好一一对应。失败不会落盘部分状态。验证：fmt、严格 Clippy、Umbra 定向14项及`cargo test -p inex-core --lib`（291 passed）。
- 2026-07-15 RenderMap plain-to-Outer mapping提交`6ad745f`：RenderMap新增逐段投影/Outer byte-range对照，纯文本选区只能映射至单一一对一 Outer segment，跨私密 fence 自动拒绝。这为后续多选从后向前替换为marker并创建slot提供了不依赖编辑器解析存储容器的安全坐标基础；核心全量291项通过。
- 2026-07-14 raw-index production接线提交`b4ab8cf`（`feat(import): validate raw Git indexes`）：同一次secure read形成raw semantics与control binding，source config/Git全部经过bound runner，raw/`ls-files -s`/HEAD三方全等；`FSMN`、未知extension、entry flags与same-inode byte drift均有fail-closed回归。独立复审GO；raw 13/13、repository-import 14/14、Linux/Windows GNU Clippy/check、rustdoc、fmt与diff-check通过。
- 2026-07-14 durable publication recovery规范提交`3fd797e`（`docs(import): specify durable publication recovery`）：冻结`INEXPUB\0` marker v2、九段candidate seal、统一identity scheme、held-marker排除、initial publisher held lock、existing-only no-create guard、fresh/live分流、reserved mutation barrier与acknowledgement gap。两轮独立复审在修正initial lock、`FSMN`、pre/post-move crash wording后最终GO；明确仍未实现，当前legacy-marker demo不因此升级为GA。
- 2026-07-14 提交`b4ab8cf`后的完整`cargo test -p inex-git --all-targets --all-features`为192 passed、0 failed、12 ignored（214.63s）；先前偶发`RecoveryConflict`的既有v5 live-index fault test本轮正常通过。新raw/index/import路径定向27项、Linux/Windows GNU静态门禁亦全部通过。
- 2026-07-14 publication终态规范增量提交`3a7c622`（`docs(import): freeze reconcile terminal states`）：冻结reserved namespace八态分类、existing-only cleanup精确tuple、dry-run六态、complete nonduplicated output及stdout/stderr acknowledgement边界；三轮独立复审最终GO，未把不可取消文件系统调用或stdout backpressure伪装成有界可用性。
- 2026-07-14 publication identity提交`f14e7ff`（`feat(core): add publication identity projections`）：Linux、Windows modern与Windows legacy均只保留一个canonical primary scheme；modern query错误不降级，只有成功返回全零FileId128才进入legacy且legacy index必须非零。角色捕获/路径/同树校验统一使用该策略；9/9定向及完整core门禁通过，原生NTFS/ReFS仍为运行证据门禁。
- 2026-07-14 marker codec提交`3fd7434`（`feat(core): add publication marker v2 codec`）：实现`INEXPUB\0` canonical v2 wire、172..998字节边界、1024字节绝对读取上限、SHA-256、domain/portable child-name/opaque seal校验；输入API显式区分三个目录identity和一个marker-file identity，编译失败doctest禁止角色互换。14/14定向、doc-test及跨目标静态门禁通过。
- 2026-07-14 existing-only publication lock提交`339b554`（`feat(core): add existing-only publication lock`）：严格只打开既有零字节`.vault-local/mutation.lock`，不create/mkdir/truncate/chmod/recovery；Linux使用no-follow/nonblocking `flock`，Windows使用read-only handle与fail-immediate `LockFileEx`；pre/post/revalidate重复绑定root/local/lock identity、同mount、single-link/ADS及held path，支持整根rename后重验。独立复审GO（0 blocker/0 major/1已处理文档分类minor）；missing三态明确锁定为`NotFound -> Io`，完整core 242/242、doc-test、pedantic Clippy、rustdoc、Windows GNU check/clippy/no-run、fmt/diff全部PASS。原生Windows busy/drop/rename与same-UID advisory race仍OPEN。
- 2026-07-14 reserved publication mutation barrier提交`bf15316`（`feat(core): block mutations during repository publication`）：`.vault-local`只读有界分类冻结Absent/Legacy/ReservedConflict/V2Invalid/V2Exact五态；guard在锁前及已绑定锁后、任何staging/pending-rebind recovery前重复检查。竞态复审修复既有lock/local被chmod及open后路径消失/重绑混淆，single-link属性与path binding分离；reconcile/manual-audit经core、Vault、daemon和VS Code专用RPC错误完整保留。独立复审GO（0 blocker/0 major/0 minor），core单线程稳定复跑245/245+1 doctest，VS Code typecheck/RPC定向通过；一次并行core全测中的既有锁竞争用例失败后精确复跑及单线程全套均通过，未把首次失败隐藏或计为绿灯。
- 2026-07-14 candidate seal encoder提交`5aae576`（`feat(import): add candidate seal v1 encoder`）：实现`INEXCS1\0`前缀、九个有序count/length-framed sections、big-endian整数、typed identity/role、路径/计数/68 MiB边界、跨段引用防御检查与增量SHA-256，不缓存完整production stream或target body。独立审计另行重建完整1419-byte fixture，得到冻结digest=`2dc5f249cb215a172bc304c89bfa25457f8d25497b83c78159068e518c8d8210`，结论为encoder checkpoint GO（0 blocker/0 major/1非阻断边界测试债务）；明确exact physical/Git inventory、真实body streaming、held-marker排除及live/fresh collector尚未接线，不能宣称candidate seal生产恢复能力已完成。
- 2026-07-14 下一实现切片冻结为marker-free target-only physical collector：完整递归root/worktree/`.git`/`.vault-local`，只接受exact single-link zero-byte `mutation.lock`，任何v1/v2/alias/unknown marker或额外private entry均失败且零跳过；输出section 1/9 owned typed evidence供同一live/fresh层复用。当前不混入marker创建、held-marker排除、CLI或reconcile，以免把ownership capability与物理证据揉成不可审计的大提交。
- 2026-07-14 marker-free物理collector提交`239f9f2`（`feat(import): collect marker-free candidate evidence`）：section 1包含root及完整worktree/`.git`/`.vault-local`并按UTF-8 bytes严格排序，section 9复用同一exact empty single-link `mutation.lock` identity；读前、逐64 KiB chunk及读后均执行68 MiB checked bound，root要求supported local filesystem，所有目录最终identity/ADS重验。marker/alias/额外private state保留且零修改失败，显式单一scheme投影任一不可用即fail closed。两轮审计GO（0 blocker/0 major；最终2项为后续接线/原生Windows边界）；5/5定向、`inex-git`完整202 passed/0 failed/12 ignored（215.19s）、native/Windows GNU Clippy、Windows no-run、rustdoc、fmt/diff均PASS。
- 2026-07-14 target raw-index提交`e5744ce`（`feat(import): bind target raw index evidence`）：保留source 64 MiB/100,000不变，新增target 68 MiB/100,003 profile；同一次secure held `.git/index`读取形成raw map、identity、size和SHA-256，Git语义探针后再与完整`.git` inventory的唯一index记录四元绑定，并要求raw/`ls-files`/expected三方全等。独立终审GO（0 blocker/0 major/2后续矩阵项）；raw 14/14、真实target漂移、native/Windows GNU Clippy、rustdoc、Windows no-run及完整`inex-git` 204 passed/0 failed/12 ignored（1685.47s）全部PASS。仍明确OPEN：真实secure-read 68 MiB exact/+1、held-lock index ABA、原生Windows，以及下一切片移除合法大target仍会触发的64 MiB `ls-files`/`ls-tree`输出瓶颈。
- 2026-07-14 target direct-audit提交`80af987`（`feat(import): stream target Git audit`）：target构造与独立audit不再调用`ls-files`、`ls-tree`或`cat-file --batch-all-objects`；同一raw index与tracked entry直接一一比对，canonical tree/root commit本地构造，exact loose-object路径集合拒绝额外reachable/unreachable对象，并用单个`cat-file --batch`以16 KiB块对实际body做typed SHA-1与raw SHA-256。`.git`和`.vault-local`常规文件统一68 MiB上限，Git spy证明三类大输出在target路径不可用。窄scope独立终审GO；完整`inex-git`为207 passed/0 failed/12 ignored（215.31s），repository-import 28/28、raw-index 16/16及native/Windows静态门禁全绿。该提交是可逆中间检查点，明确不关闭spec全进程256 MiB canonical-path驻留、全部tree body streaming、fresh sections 2–8 assembler、held-lock authority、same-UID/后代持pipe与原生Windows门禁。
- 2026-07-14 target audit内存收敛提交`604624e`（`refactor(import): bound target audit memory`）：新增target-only raw-index borrowed-path visitor，v2/v3直接比较expected slice，v4/IEOT只在借用前一路径上验证canonical strip/suffix/block边界并仅返回index version与OID；repository audit在Git inventory前显式释放summary/path refs。legacy canonical tree不再累计保存全部raw body，而是逐棵计算typed OID、size与SHA-256后立即释放。独立只读复审GO，冻结blob为`96cc1383…`/`289e94ed…`；raw-index 15/15、repository-import 18/18、native与Windows GNU/MSVC pedantic Clippy、Windows GNU no-run、rustdoc、fmt/diff全部通过。fresh assembler与全局路径驻留仍保持OPEN。
- 2026-07-14 section-1 indexed-view首版尚未提交：实现稳定physical record ID、borrowed view、record-ID bitset及exact rewalk，13/13定向和三目标静态门禁通过；但独立复审NO-GO。两个阻断分别为secure hash后通过`File::open(path)`做ADS复验会先跟随攻击者链接，以及递归累计`PathBuf`/`String`连同每层`SecureSourceDirectory.path`会在section-1恰好保留256 MiB路径时越过全进程硬上限。当前修复固定为held `SecureSourceFile` ADS/binding验证，以及只传parent record ID、借用basename、child directory只持parent fd/name；修复与新增竞态/驻留测试通过复审前不得提交或计为完成。
- 2026-07-14 section-1 exact revalidation修复提交`75f754e`（`refactor(import): revalidate physical evidence in place`）：稳定`PhysicalRecordId`/borrowed view不复制path或identity；最终遍历只传parent ID并用iterator虚拟比较`parent + '/' + basename`，记录ID bitset、count与checked path sum证明精确集合。core的secure child不再保存累计root-to-child `PathBuf`，file/directory ADS均在held handle上执行binding→query→binding；真实symlink/FIFO替换在1秒测试边界内拒绝。首轮两个blocker修复后的独立终审GO；candidate 14/14、core 246/246、native与Windows GNU/MSVC check/clippy、fmt/diff通过。该GO只关闭最终exact revalidation，初始collector的临时path副本及完整fresh assembler仍OPEN。
- 2026-07-14 portable case-fold fingerprint提交`3aa0a0c`（`feat(core): stream portable case-fold fingerprints`）：以固定大小Unicode 17状态机执行lower→upper→lower、canonical decomposition/CCC replay/NFC composition，返回定长fingerprint而不保留folded path；16K nonstarter、全Unicode scalar oracle及边界语料通过，独立复审GO（0 blocker/0 major，1项非阻断多scalar组合覆盖债务）。core 249项、native与Windows GNU/MSVC check/clippy、fmt/diff全部PASS。
- 2026-07-14 section-1 direct collector提交`865937d`（`refactor(import): collect physical evidence directly`）：held descriptor DFS把每条canonical `String`只构造一次并直接移入最终record，checked ledger绑定exact retained path bytes；定长portable fingerprint完成全路径、父前缀与`.git`/`.vault-local`别名拒绝，随后释放fingerprint并原地排序/构造父图。旧`Vec<NamespaceSeal>`、owned `CaseFoldKey`集合和二次private scan已删除，返回前执行whole-root exact revalidation；非Linux显式fail closed。冻结blob=`6570c2b…`、candidate-only diff SHA-256=`2c134143…`经独立终审GO（0 blocker/0 major/0 minor）；主线程复跑19/19、native与Windows GNU/MSVC check/clippy、fmt/diff全部PASS。该提交只关闭section 1初始采集峰值，fresh sections 2–8与持锁authority仍OPEN。
- 2026-07-14 fresh worktree切片提交`f003c64`（`feat(import): assemble fresh worktree evidence`）：sections 2/4/5只保留physical ID/class/OID/tree摘要并永久绑定同一manifest；raw index直接比较借用path，单一held root逐级打开并在stream后反向复验全部ancestor，blob以64 KiB零化buffer计算typed SHA-1/raw SHA-256，tree用fixed ID edges与Git slash-order两遍hash而不构造body。主线程发现并撤销首轮GO：`.gitattributes`/`.gitignore`只存在未绑定canonical bytes；最终以同一section-1 size/SHA256绑定`TARGET_ATTRIBUTES`/`TARGET_IGNORE`并增加同长度篡改负测，复审GO（0/0/0）。定向8/8；该切片仍不认证`vault.json`语义或绑定held index/control authority。
- 2026-07-14 fresh Git切片提交`21d0cee`（`feat(import): assemble fresh Git evidence`）：sections 3/6/7/8实现strict parentless root commit parser、exact `blob∪tree∪commit`、loose-object/fanout/control双向图和不留body的typed SHA-1/raw SHA-256 verifier。首轮复审因aggregate可跨manifest重投影而NO-GO；最终改为字段private的`FreshGitManifest<'physical>`、parser-only root evidence与无manifest参数projection，并补跨manifest、pack/alternates/unknown、68 MiB exact/+1及wrong raw SHA测试，复审GO（0/0/0），定向9/9。held `cat-file`进程、config/index runtime binding与proof token仍OPEN。
- 2026-07-14 两切片合并后主线程执行单线程完整`cargo test -p inex-git --lib -- --test-threads=1`：239 passed、0 failed、12 ignored，1685.32s；作者门禁曾遇到一次既有force-kill child启动`ENOENT`并隔离复跑通过，本次权威全套未复现。随后native、Windows GNU、Windows MSVC all-target/all-feature check与pedantic Clippy、rustdoc warnings-as-errors、fmt和diff-check全部PASS。
- 2026-07-14 纯内容九段aggregate提交`779693e`（`feat(import): aggregate fresh candidate content`）：tracked/tree/git永久绑定同一physical manifest，Git object union由opaque tracked/tree/root重新推导，九段只投影一次并立即计算seal；不持锁、不创建marker且不授予publication authority。独立复审GO（0 blocker/0 major/1百万对象峰值RSS minor），定向4/4及三目标静态门禁通过。
- 2026-07-14 held-control/runtime切片提交`52d7500`（`feat(import): bind fresh runtime candidate evidence`）：生产tracked API删除裸raw-index参数，固定从同一held root读取`.git/index`；index/config snapshot以manifest引用和pointer identity防跨manifest重绑，exact EOF+1分支真实覆盖且extra buffer zeroize。`FreshRuntimeObjectProof`只有在exact sorted object union逐项16 KiB batch验证、finish/EOF与二次root binding后构造，aggregate不再接受未运行的Git manifest。两路独立复审最终GO；单独60/60候选测试通过。
- 2026-07-14 authenticated vault/config首个冻结版本被独立复审判NO-GO：即使执行`git config --file - --no-includes --null --list`并从held snapshot写stdin，Git在runner root仍自动发现并两次打开路径`.git/config`。通用`run_without_prefix`已删除，改为固定六参数`run_isolated_stdin_config`并在`env_clear`后显式设置`GIT_DIR`为空设备；功能回归证明malformed路径config使非隔离控制失败，而隔离调用只解析valid stdin并成功。
- 2026-07-14 修复后的authenticated authority提交`fb58808`（`feat(import): authenticate candidate vault configuration`）：同一physical/held/Vault/runner root下，held `vault.json` identity/size/EOF/SHA-256必须同时匹配physical record和authenticated `Vault::config_etag()`；held config只能进入隔离stdin parser，返回值只保留manifest品牌、两个opaque ID及DocumentsOnly/OpaqueAssetsV1 profile，不保留password/key/path/body/output。复审GO（0 blocker/0 major/1既有process-tree availability minor），authority 4/4通过。
- 2026-07-14 主线程从修复后源码重新执行完整单线程`cargo test -p inex-git --lib -- --test-threads=1`：263 passed、0 failed、12 ignored，1689.04s；此前并行偶发的既有live-index fault test本轮通过。native、Windows GNU/MSVC all-target/all-feature check与pedantic Clippy、rustdoc warnings-as-errors、fmt、diff-check全部PASS；两个源码提交后工作树clean，branch领先origin 58且未push。
- 2026-07-14 下一生产接线冻结为owned `InitialCandidateAuthority`：构造器必须先取得exact existing-only mutation lock，再在同一锁窗口内部生成tracked/tree/Git/runtime/vault authority与content seal、执行最终whole-tree exact revalidation，并把lock保留在不可Clone/Copy返回值中。CLI当前在Git构造前drop freshly audited Vault，需延长其生命周期；fresh reconcile另需target-only held ref/root-commit bootstrap，不能复用process-local initial token。
- 2026-07-14 held initial authority提交`3205a49`（`feat(import): hold initial candidate authority`）：marker-free physical与held root先绑定，再取得exact existing-only mutation lock；Git discovery、tracked/tree/root/Git/runtime、authenticated vault/config和candidate seal全部在同一持锁scope内部创建，post-runtime hook后依次重验held root、lock及whole-tree exact，返回值继续拥有physical/root/seal/fixed commit evidence/lock且不可Clone/Copy。它不接收预制proof、不创建marker、不move、不调用v1 publisher，非Linux在接触目标前fail closed。独立终审GO（0 blocker/0 major/1继承的same-UID/descendant-pipe minor）；authority 11/11、candidate 101/101、native与Windows GNU/MSVC静态门禁全绿。
- 2026-07-14 CLI生命周期只读审计确认：当前fresh unlock后确实逐Markdown/asset做size/SHA/exact source bytes审计，但在Git target创建前立即drop `Vault`。最小后继是不可Clone的`IndependentlyAuditedVault { vault, warnings }`，顺序改为build vault→Git target→fresh unlock/full audit→held authority；password应由execute取得zeroizing owner并在authority形成后立即drop。旧`atomic_publish_directory_no_replace_checked`固定v1 marker且会重新取普通锁，不能与持锁v2 authority串联，必须由后续v2 publisher整体替换。
- 2026-07-14 CLI audited owner提交`88e2837`（`refactor(import): retain audited vault authority`）：`execute`按值接管`Zeroizing<Vec<u8>>`，顺序固定为build vault→Git init/显式audit/durable→单次fresh unlock→exact Directory/Markdown/Asset logical inventory→逐envelope与source size/SHA/exact bytes比对；不可Clone的`IndependentlyAuditedVault`保留同一Vault与warnings，password随后立即drop。当前为保持demo行为在旧v1 publisher前显式消费owner，且源码契约禁止v2调用；未来v2必须替换而非包裹旧publisher。独立复审GO（0 blocker/0 major/1无法安全窥视Vec drop的动态覆盖minor）；CLI全测试、真实repository import 4/4、workspace/native/Windows GNU/MSVC静态门禁全绿。
- 2026-07-14 v2 consuming publisher只读设计冻结六个线性状态：InitialAuthority→StagingAuditedClaim→PublishedWithMarker→PublicationDurableWithMarker→PublishedClean，unlink已生效但sync/clean失败单独进入PostUnlinkAbsentIndeterminate且禁止重建marker。当前明确阻断是core尚无descriptor-relative create-new+retained v2 marker handle、held-existing opener和publication-specific exact removal outcome，inex-git尚无只排除exact held marker identity的marker-aware全量collector/fresh reconciler；旧v1 publisher不能复用。下一实现必须先补安全held marker primitives，再做marker-aware audit，不能直接接CLI move。
- 2026-07-14 用户再次明确要求调整并继续使用Goal；后台仍返回原长期Goal且status=`paused`，第四次以精确repository-migration objective调用`create_goal`仍因unfinished旧Goal被拒绝，接口没有objective edit/resume。未伪造complete/blocked；根`task_plan.md`继续承载收敛后的可执行Goal，Git实现照常推进。
- 2026-07-14 held publication marker core提交`347b4cd`（`feat(core): retain publication marker authority`）：Linux-only `HeldPublicationMarkerV2`按值消费`ExistingVaultMutationLock`与held root，锁为最后析构字段；held `.vault-local` fd上使用`openat2` create-new/no-follow/no-xdev，严格0600/single-link/same-mount，canonical bounded双读与exact length/identity，file/local/root handle durability，完整reserved-prefix inventory及whole-root rename后重验。existing opener只读且零cleanup/move；Windows能力不暴露并保持静态编译。独立终审GO（0 blocker/0 major/2测试补强minor），聚焦5/5、codec14/14、rustdoc、native及Windows GNU/MSVC静态门禁通过。
- 2026-07-14 主线程完整core首轮为253/254：新marker全部通过，唯一失败是2016起既有`os_lock_serializes_competing_etag_commits`，实际一条成功、另一条在首次`.vault-local`出现时保守返回pre-lock非Conflict。精确测试在相同时序下可复现，确认不是held owner泄锁。独立测试提交`70fc0b2`先建立/释放稳定lock namespace，使该用例只测OS-lock串行；随后精确50/50、完整254/254、pedantic Clippy、fmt/diff全部PASS。
- 2026-07-14 marker-aware物理层提交`5d9e686`（`feat(import): audit held publication marker trees`）：Linux collector只在exact `.vault-local/import-publish-marker-v2`上descriptor-open single-link file并要求identity等于同一`HeldPublicationMarkerV2`，marker只计一个遍历work item，不进入section 1/9、retained record/path预算或`PhysicalRecordId`。wrapper借用完整held authority、拥有current-path-bound同root fd view且不能抽取owned manifest；整根rename后在destination重新绑定，返回后可对同一manifest brand执行最终marker-aware exact。首轮独立终审发现缺少同brand最终复验API并判1 major，窄修复后终审GO（0 blocker/0 major/0 minor）；candidate 27/27、core held 5/5、workspace全测、native Clippy/fmt与Windows GNU/MSVC静态门禁通过。
- 2026-07-14 fresh root-commit bootstrap提交`4b8477d`（`feat(import): bootstrap fresh target root commit`）：fixed-size Git control shape、held canonical config与held main ref先绑定同一marker-free physical brand，再由root-identity guard只允许512-byte `git cat-file commit <lowercase-sha1>`读取；canonical parentless commit重新计算typed OID并要求精确等于main ref。首轮独立审计发现config Git/I/O错误被降格及缺少命令窗口内root rename覆盖；引入内部双通道错误后，fresh collector精确保留scrubbed `Io`/`GitCommandFailed`，initial wrapper恢复旧语义，完整rename-window回归通过。终审GO（0 blocker/0 major/0 minor），candidate Git 22/22、config 9/9、native/Windows GNU/MSVC、Clippy、rustdoc、fmt与diff-check全绿；主线程冻结哈希复核及bootstrap 7/7通过。
- 2026-07-14 marker-aware fresh九段审计提交`aea7d6b`（`feat(import): audit fresh held-marker candidates`）：借用同一`HeldPublicationMarkerV2`，只调用一次marker-aware physical collector，在单一scope内重建root commit、tracked/index/tree、exact Git control/object union、16 KiB runtime object proof与candidate seal；释放全部语义证据后由同一wrapper执行最终whole-tree exact，之后只做marker seal常量时间内存比较。返回不可Clone/Copy的88-byte固定摘要，只含scheme/publication-id、seal、根OID和目标计数，无路径、body、句柄、锁、marker或borrow；所有失败保留marker且零move/unlink/cleanup。首轮独立审计仅发现publication-id组合负测缺口，补“新非零ID+旧正确seal”后两路终审均GO（0/0/0）；focused 9/9、native Clippy/rustdoc/fmt、Windows GNU/MSVC check全绿。
- 2026-07-14 fresh main-ref提交`01effef`（`feat(import): bind fresh target main ref`）：同一held physical snapshot只接受exact `.git/refs/heads/main` regular file、40位lowercase SHA-1与单LF，拒绝zero/uppercase/CRLF/非法hex/长度漂移/identity与ancestor rebind；不可Clone的返回值只暴露pointer-brand与20-byte OID，不暴露record ID/body/path。callback后同inode同长度rewrite明确留给外层whole-manifest exact。独立终审GO（0/0/0），focused 17/17及native、Windows GNU/MSVC静态门禁全绿。
- 2026-07-14 Git control shape提交`7b4da74`（`feat(import): preflight fresh Git control shape`）：单一classifier冻结4 fixed files、6 structural directories、empty hooks与lowercase loose-object图，在任何repository-aware Git命令前拒绝alternates、pack、commondir、extra refs/hooks/logs/modules等状态；existing exact scan复用同一classifier并追加main-ref/object union语义。首版因`Vec<(OID,RecordId)>`在百万上限额外驻留约32 MiB被独立审计判1 major；最终proof仅manifest引用、count与256-bit fanout，单OID用54-byte栈path二分，复审GO（0/0/0），candidate Git 14/14及三目标静态门禁通过。
- 2026-07-14 fresh target config提交`8bd6d31`（`feat(import): validate fresh target config`）：从initial-only authority抽出不接受Vault/password的manifest-branded config evidence，唯一复用held config snapshot、isolated stdin-only Git parser、canonical validator与installed driver command；initial authority组合该proof后再认证vault.json/profile。首版fresh函数错误调用marker-free whole-tree exact，会拒绝合法v2 marker并被主线程判major；修复为held/root/runner前后闭合，最终全树由外层`HeldMarkerPhysicalManifest`封口，真实marker组合回归通过。独立终审GO（0/0/0），focused 8/8、native与Windows GNU/MSVC静态门禁全绿。
- 2026-07-14 第五次按用户的新迁移/恢复objective调用`create_goal`仍被paused但unfinished旧Goal拒绝；随后`get_goal`确认旧objective与`status=paused`未变，接口仍无edit/resume。任务可继续实质推进，故不满足blocked条件，也未伪造complete；根计划与Git检查点继续作为调整后Goal的执行真源。
- 2026-07-14 publication-specific unlink core提交`afc9132`（`feat(core): retain post-unlink publication authority`）：Linux-only `HeldPublicationMarkerV2`按值消费exact destination unlink，删除前后重复证明destination角色与staging absent；old-present返回可重试Held，exact absent转为保留原inode fd、immutable claim、root/local/common-parent descriptors及同一mutation lock的Synced/Unsynced owner，replacement/indeterminate转为无forward-action terminal owner。所有publication fault均禁止generic pathname parent sync，唯一durability barrier是held `.vault-local` fd的binding→sync→binding→absence复验；unsynced只能重试该屏障，不能重建marker或二次unlink。独立终审最终GO（0 blocker/0 major/0 minor）；当前core 265/265+doctest 2/2、held 13/13、post-unlink 2/2、generic remove回归、pedantic Clippy、rustdoc、fmt/diff及Windows GNU/MSVC check全部PASS。hostile same-UID最终check→pathname-unlink竞态与clean-audit高层borrow封口仍按计划保持OPEN。
- 2026-07-14 destination-absence core提交`4f9b074`（`feat(core): bind marker claims to absent destinations`）：v2 create在create-new前由held common-parent descriptor执行binding→exact-child lookup→binding，并由两次完整pre-marker authority复验包夹；held owner新增staging-only借用检查，创建后目标出现不会消费marker/lock。普通file/dir固定为conflict，symlink/hardlink/cross-mount等固定fail-closed为I/O，所有foreign entry保持不变；absence明确只是bounded observation，最终仍需recheck与no-replace move。独立终审GO（0/0/0），core 268/268+doctest 2/2、held 16/16、Clippy、rustdoc、fmt/diff及Windows GNU/MSVC全绿。
- 2026-07-14 Initial staging claim提交`88eab2f`（`feat(import): consume initial candidate claims`）：held-lock初审同时冻结worktree/Markdown/asset/Git-object四项计数；transition只接受audited common-parent identity与destination child，严格验证`.inex-import-staging-`+32 lowercase hex及reserved destination前缀，按值消费Initial authority写入canonical v2 marker。旧marker-free大manifest在fresh复审前显式drop；fresh九段摘要与初始context、seal、root OID及四类计数逐项相等后，再做descriptor-relative destination observation。core返回Held后的任何失败均进入boxed terminal owner，保留原marker与同一lock且无cleanup/提取API。独立终审GO（0/0/0）；完整inex-git 322 passed/12 ignored/0 failed、Initial 18/18、Fresh 9/9、seal golden不变、Linux Clippy/rustdoc/fmt/diff与Windows GNU/MSVC静态检查全绿。
- 2026-07-14 published-role gate提交`597301c`（`feat(core): validate published marker roles`）：借用式`require_published_at`只在current basename等于marker destination时，执行两轮held common-parent descriptor上的staging缺失观察并以最终完整marker/root/local/lock revalidation收尾；无sync/move/unlink/create/cleanup/recovery，也不暴露句柄或把absence描述为reservation。独立终审GO（0 blocker/0 major/0 minor）；core 268/268、doctest 2/2、Clippy、rustdoc、fmt/diff及Windows GNU/MSVC静态检查全绿。
- 2026-07-14 fused Fresh core opener提交`2e84b4f`（`feat(core): fuse existing publication claim opening`）：Linux从同一held descriptor链打开destination root、`.vault-local`和exact zero-byte/single-link `mutation.lock`，在同一fd上完成identity/ADS/same-mount前后重验与nonblocking持锁，再消费lock/root打开canonical v2 marker并证明destination角色；不接受caller identities且零create/chmod/recovery/sync/move/unlink。非Linux统一返回`Unsupported`且成功类型不可构造；I/O错误只保留`ErrorKind`，Debug/Display/source均不泄漏。独立终审GO（0/0/0）；core 273/273、doctest 2/2、opener 5/5、Linux与Windows GNU/MSVC Clippy、rustdoc、fmt/diff全绿。
- 2026-07-14 Fresh consuming owner提交`3a8661c`（`feat(import): consume fresh publication claims`）：输入仅含destination root、外层common-parent identity与exact child；fused open后依次验证repository domain、共享staging grammar、destination exact/reserved policy、common-parent、published role、完整fresh九段audit及最终published role。所有post-open失败进入marker-last terminal owner并持续持同一lock；成功形成Initial/Fresh未来共用的`PublishedWithMarker`，无move/sync/unlink/cleanup能力。独立终审GO（0 blocker/0 major/0 required minor）；Fresh 4/4、Initial 18/18、Linux Clippy/rustdoc、Windows GNU/MSVC Clippy、fmt/diff全绿；hostile same-UID race与更完整负测矩阵仍留后续门禁。
- 2026-07-14 held publication durability提交`0e89e32`（`feat(core): synchronize held publication directories`）：单一borrowed方法严格执行published-role gate→held root fd sync→role gate→held common-parent binding/sync/binding→final role gate；不调用旧staging pathname binding、不暴露raw/拆分sync能力，也不move/unlink/create/cleanup/recovery。失败保留原marker/lock且可重试；文档明确所有检查只是bounded observation，不排除non-cooperating same-UID swap-and-restore。独立终审GO（0/0/0）；focused 3/3、core 276/276、doctest 2/2、Linux与Windows GNU/MSVC Clippy、rustdoc、fmt/diff全绿。
- 2026-07-14 Initial publication提交`5060856`（`feat(import): publish initial candidate claims`）：按值消费`StagingAuditedClaim`，只从held marker派生destination；critical callback按destination absent→fresh九段audit→七字段摘要对账→destination absent执行，verified no-replace成功后再按destination role→fresh→七字段→role汇入私有`VerifiedInitialMove` token与共享`PublishedWithMarker`。generic `ParentSyncStatus`明确丢弃；只有exact `NotMoved`经额外复审形成consuming retry owner，其余冲突/不确定/I/O均保留同一marker/lock进入无forward API terminal。首轮终审发现generic preflight可在callback前返回而0-call被误分类，修复为保留`DestinationExists`/`InvalidPaths`/`Io(ErrorKind)`/`Indeterminate`，仅0-call `Ok`/`NotMoved`或多次callback判契约异常。最终独立终审GO（0/0/0）；Initial 31/31、publication 13/13、Fresh 9/9与authority 4/4、Linux/Windows GNU/MSVC Clippy、rustdoc、fmt/diff全绿。
- 2026-07-14 publication durability transition提交`984e52b`（`feat(import): confirm publication durability`）：`PublishedWithMarker::synchronize`只调用core的held root/common-parent单一同步原语，随后无论sync成功或失败都统一执行destination role→fresh九段audit→共享七字段摘要对账→destination role。只有`Ok+review`形成marker-last `PublicationDurableWithMarker`；`Err+review`把原始marker错误立即降为fixed kind/`Io(ErrorKind)`并形成仅可consuming retry的owner；任一review失败进入无forward API terminal。Fresh与Initial两条入口共享同一后半状态，summary comparator上移为单一实现；Durable尚不暴露unlink/owned marker/parts。测试冻结claim后的canonical marker bytes与file identity，并在success/retry/terminal owner存活时复验不变。独立终审GO（0/0/0）；publication 9/9、Initial 31/31、Fresh 9/9、Linux/Windows GNU/MSVC Clippy、rustdoc、fmt/diff全绿。
- 2026-07-14 durable-only marker cleanup提交`c3dd202`（`feat(import): classify publication marker cleanup`）：只有`PublicationDurableWithMarker::unlink_marker`可消费core exact unlink；调用前执行完整published review，失败时driver零调用。`NotRemoved`还需再次role→fresh→七字段→role才恢复Durable；removed+parent-synced只形成`CleanAuditPending`，unsynced只形成可consuming retry parent sync的`ParentSyncPending`，replacement/indeterminate保留Held或core terminal authority进入无forward API terminal。core unlink五态与parent-sync四态穷尽映射且不暴露裸core outcome；marker已删除仍不宣称clean/success，也未接CLI。独立终审GO（0/0/0）；marker-unlink 6/6、publication 15/15、Initial 31/31、Fresh 9/9、Linux/Windows GNU/MSVC Clippy、rustdoc、fmt/diff全绿。
- 2026-07-14 marker-free clean publication audit提交`0b366e1`（`feat(import): audit clean published candidates`）：以`SyncedPostUnlinkPublicationMarkerV2`派生lifetime-bound held-root wrapper，按absence/Forbidden collection/baseline/exact rewalk/seal/absence顺序重建九段证据；`CleanAuditPending`只可消费为`PublishedClean`、保留同一authority的Retryable或Terminal，且不暴露unlink/sync/parts能力。补充等长正文改写、marker replacement保留、retained seal mismatch及root rebind真实竞态测试。独立终审GO（0 blocker/0 major/0 minor）；主线程复跑Fresh 12/12、Publication 22/22、Manifest 27/27、Initial 31/31，Linux Clippy/rustdoc、Windows GNU/MSVC静态门禁、fmt与diff-check通过。旧v1 publisher整体替换和CLI接线仍未完成。
- 2026-07-14 initial v2 production接线提交`b34691c`（`feat(import): replace initial publisher with v2`）：新增唯一高层transaction driver，按Initial authority→v2 claim→verified no-replace move→held durability→durable-only unlink→parent-sync retry→marker-free clean audit串联私有typestate；同进程retry固定最多3次，不重建marker或重新取锁。CLI repository import已删除旧v1 publisher调用，成功与失败均以opaque owner把同一mutation lock保留到stdout终态写入并flush后才释放；成功计数与root OID只取最终target audit。真实进程证明2个Markdown+3个附件形成单一parentless密文提交、打印OID等于目标HEAD且v1/v2 marker均不存在。完整门禁：CLI 43/43及全部进程测试通过，`inex-git` 363 passed/0 failed/12 ignored（1850.29s），Linux Clippy/rustdoc、Windows GNU/MSVC Clippy、fmt/diff-check全部PASS。fresh existing-only CLI早期分流和独立reconcile输出仍未完成，下一切片不得误复用creation输出。
- 2026-07-14 fresh existing transaction提交`25bd9b2`（`feat(import): reconcile existing v2 candidates`）：公开target-only高层入口只接受destination/common-parent identity/child name，从fused existing claim直接复用durability→unlink→parent-sync→clean-audit后半驱动；不接受source、password、Vault、KDF、TargetRepository或caller seal。真实fixture从保留canonical v2 marker的已发布root完成对账，验证最终四类计数/root OID、marker删除，以及success owner存活期间lock busy、drop后释放。首轮编译因测试fixture的`pub(super)`只开放到兄弟模块之外而失败，改为仅`cfg(test)`下crate可见后重跑通过；transaction 4/4、publication authority 22/22、Linux Clippy/rustdoc、Windows GNU/MSVC Clippy、fmt/diff-check全部PASS。CLI早期分类/输出与dry-run read-only preview仍OPEN。
- 2026-07-14 fresh read-only preview提交`8ec4dd7`（`feat(import): preview existing v2 candidates`）：公开preview入口与real reconcile共享fused open+完整fresh target audit，但只复制固定计数/root OID后释放owner，源码契约禁止durability/sync/unlink/clean-audit。真实fixture证明preview后canonical v2 marker字节与identity不变且lock已释放。首轮两次定向失败均为新增函数改变源码切片后测试误把后续preview文档中的`source`纳入reconcile扫描，调整边界后5/5通过；Linux Clippy/rustdoc、Windows GNU/MSVC Clippy、fmt/diff-check全部PASS。下一步是CLI path-first dispatch、冻结终态输出和进程级零source/password/KDF证据。
- 2026-07-14 后端`get_goal`现已恢复为`active`，但仍是原始长期objective且接口没有编辑active objective的能力；未伪造complete/blocked。当前可执行阶段Goal继续以根`task_plan.md`为准：安全初始化现有Markdown/Git目录、保留源历史、形成全新密文仓库并交付可安装VS Code闭环。
- 2026-07-14 CLI existing-only接线首轮定向测试两次因静态源码契约边界失效而失败：新增`execute_reconcile`使旧`execute→build_staging_vault`切片提前截断，临时test-only `plan` wrapper又使production源码split截断。最终删除wrapper、所有测试直接调用真实`dispatch`，并把两个源码契约切片改为明确函数边界；未放宽产品断言。
- 2026-07-14 首轮strict Clippy依次发现两个large-enum variant、冻结表/契约测试超100行、boxed fixture类型不匹配；Windows交叉Clippy又发现Linux-only资源常量未cfg。修复为只box大型linear owner/plan、对纯冻结表使用窄理由、测试显式解box并把资源常量限制到Linux，随后Linux与Windows GNU/MSVC均全绿。
- 2026-07-14 三轮独立审查推动CLI路径边界收紧：canonicalize前后捕获并复验原始/规范目录identity；existing dispatch在reserved namespace分类前以held source root、descriptor-relative directory-only walker检查destination parent/root是否物理位于source树（含稳定bind alias），1,000,000项/256层有界，普通文件/hardlink/symlink不打开；non-v2输出前同时复验parent、destination identity和namespace，同分类目录替换降级`reserved-inspection-indeterminate`且两边canary不变。inode ABA及分类后hostile同UID换绑仍保留为GA门禁，不宣称descriptor-bound CAS。
- 2026-07-14 提交`d9dc345`（`feat(import): route existing targets to reconcile`）完成path-first dispatch、reserved namespace六态、exact-v2 preview/reconcile选择、十一行冻结失败tuple、独立成功输出与4 KiB单块write+flush acknowledgement。existing分支在source Git planning、password、KDF与creation输出前返回；real success/failure owner跨stdout flush保持mutation lock，dry-run返回authority-free快照。
- 2026-07-14 `d9dc345`最终门禁：CLI单元48/48、真实repository-import进程5/5、inex-git candidate transaction 5/5；Linux all-target/all-feature warnings-as-errors Clippy、Rustdoc，Windows GNU/MSVC warnings-as-errors Clippy、rustfmt与diff-check全部PASS。测试覆盖全部namespace/failure映射、preview/reconciled完整golden、4097-byte拒绝、writer一次write/flush、source nested identity、非目录跳过及dispatch后same-class destination replacement。真实CLI进程级exact-v2成功fixture仍由底层真实lifecycle+CLI静态编排+golden组合覆盖，最终Linux强杀/hostile race与原生Windows矩阵继续OPEN。
- 2026-07-14 当前active后端Goal无法原位改写objective，因此没有伪造complete/blocked；阶段Goal继续由根`task_plan.md`收窄为“既有Markdown/Git目录安全初始化+可安装VS Code体验”，并持续使用planning-with-files/Git推进。
- 2026-07-14 VS Code初始化提交`14b4f18`（`feat(vscode): initialize from Markdown workspaces`）：locked welcome/命令改为Initialize语义，单一local workspace成为source默认值，Explorer本地文件夹右键可直接传入source；fresh目标先确认只导入clean tracked HEAD、图片/附件与单个新密文root commit且旧历史不复制，existing real target只在显式modal后交给CLI exact-v2 fail-closed对账。成功后仍只提供Open New Vault并要求显式unlock，原生Explorer CRUD不冒充Inex加密CRUD。
- 2026-07-14 独立复审发现并闭合Task极快退出丢事件、同步`executeTask`异常订阅泄漏、TaskEnd/ProcessEnd顺序、existing-target password-env模式切换、copy-import章节误写repository reconcile、create/reconcile统一提示错误声称当前source HEAD等问题。最终抽出`processTask.ts`三事件状态机并新增4个乱序/异常测试；`INEX_PASSWORD_STDIN`保持无条件拒绝，完成提示只声明target已初始化或对账审计，不臆测reconcile的source。
- 2026-07-14 VS Code最终门禁：TypeScript、45/45 Node tests、production/integration bundle、真实本机Extension Host feature-1 import→asset preview→CRUD→backup/recovery→residue audit全部PASS；release artifact工具30/30、JSON、CLI help、diff-check通过。两路独立终审均GO。真实folder picker、双口令TTY、Open New Vault鼠标链与persistent-profile残留仍须在本次最终VSIX上人工执行，未以底层CLI integration冒充UI自动化。
- 2026-07-14 release锁图自`5aae576`后实际为78个Cargo组件/149份license text，旧测试仍固定77/147；仅同步精确断言并以独立提交`d784009`（`test(release): sync locked license graph counts`）落地，30/30复绿。下一步必须从clean当前提交重建release CLI/daemon/VSIX，旧`7fb83ec` demo与旧`target/release`不可复用或重标。
- 2026-07-15 用户新增Umbra私密标注系统设计。仓库此前不存在`docs/prd-umbra-mode.md`或任何Umbra/私密slot实现，故新建PRD并把它加入active Goal/Phase 6：标签、profile、kind、私密正文和时间必须在K_umbra内；Outer投影、Outer索引、editor设置、日志和异常均不得泄漏。下一实现顺序先冻结storage/RPC/兼容契约，再进入core与两个编辑器，不能直接只做QuickPick界面。
## 2026-07-15 — Umbra 独立密码槽核心起步

- 已按用户冻结的 v1 语义提交 `f96f656`：新增 `umbra_keyslot`，随机 256-bit `K_umbra` 不由密码直接充当数据密钥；唯一 `.inex/keyslots/umbra-default.inex-keyslot` JSON 使用固定 Argon2id 3/256 MiB/parallelism 1 与 XChaCha20-Poly1305 包装。
- slot AAD 绑定 vault ID、canonical slot path、slot ID、key ID 和版本；错误口令、跨 vault 移植和被改写 slot 均统一失败，不返回私密数据。`UmbraKey` 使用现有 libsodium protected allocation，drop 即清理。
- 已实现“已解锁会话中重设密码”：新 salt/nonce/KEK 仅重新包装同一个内存 `K_umbra`，无须旧密码、不会重加密私密内容；真实 256 MiB KDF 测试确认旧密码失效、新密码解包得到同一数据密钥。
- `.inex` 已成为 tree 的 root 保留目录，atomic writer 只允许该单一 canonical keyslot 作为额外受控目标。feature 2 目前仅保留编号，尚未对现有 EDRY reader 宣称支持，待 v2 document container 同步接入。
- 验证：`cargo clippy -p inex-core --all-targets -- -D warnings` 与 `cargo test -p inex-core --lib`（279/279）通过。

## 2026-07-15 — Umbra 私密标注原子包裹

- 提交 `ee77855`（`feat(umbra): apply private annotations atomically`）：Vault 新增 `apply_private_annotation`，先以 caller 的 ETag、完整投影和 `OwnedRenderMap` 重建/比对当前 authenticated state；只接受规范化后的纯文本选区，按倒序将每个选区替换为独立 opaque marker，并在同一 ETag 条件保存内写入对应的 K_umbra slot。
- 新测试覆盖两段非重叠 Markdown 多选、每 slot 共用 kind/tags、Outer 仍可见普通段、私密正文/tag ID 不出现在密文文件可读面、陈旧 ETag 与完整私密块选择均零写入。`cargo test -p inex-core --lib` 292/292、`cargo clippy -p inex-core --lib -- -D warnings`、`cargo fmt` 和 `git diff --check` 全部通过。
- 下一切片：将此核心事务暴露为 daemon 的 session-bound RPC（客户端不自行计算/持久化 private payload），然后实现 VS Code QuickPick、命令与可配置 keybindings；Sublime 与 Neovim 继续保持后序。

## 2026-07-15 — Umbra daemon 会话入口

- 提交 `f2660b3`（`feat(daemon): expose Umbra session controls`）：协议新增 `umbraV1` capability 和 `umbra.status`、`umbra.initialize`、`umbra.unlock`、`umbra.lock`、`umbra.enable`、`umbra.document.open`。Umbra 密码只由 zeroizing 参数读取；公开 feature-2 启用仍要求 live K_umbra；投影读取返回 base64 Markdown、ETag 与完整 RenderMap。
- daemon 错误映射现覆盖 Umbra keyslot/config/document/render 错误：锁定/错误 Umbra 密码只给通用认证失败，stale RenderMap 给 ETag conflict，结构损坏给 integrity failure，绝不输出 slot/tag/正文。
- 服务级回归覆盖 Outer 解锁→Umbra 初始化→feature-2 启用→投影读取→Umbra 锁定拒绝→再次解锁。`cargo test -p inex-daemon --lib` 71/71、严格 Clippy、fmt 和 diff-check 全通过。下一步接入严格 annotation apply RPC，再开始 VS Code picker。

## 2026-07-15 — Umbra 标注 RPC

- 提交 `9bd5297`（`feat(daemon): apply Umbra annotations over RPC`）：新增 `umbra.annotation.apply`；请求包含 ETag、base64 projection、完整 RenderMap、多选 byte ranges、kind/tag IDs/Outer strategy 和 mergeAdjacent。新增受限 object-array/sensitive-string-array 参数提取器，所有未消费或无效嵌套 JSON 在 drop 时递归清理。
- handler 在交给 `Vault::apply_private_annotation` 前只做 schema/resource 验证；核心仍负责 projection/RenderMap/ETag 三重一致性、private boundary 分类和单次条件保存。成功后返回刚提交的 ETag、metadata、投影与 RenderMap；stale map 映射 ETag conflict、非法范围映射 invalid params、损坏容器映射 integrity failure。
- 服务级 RPC 用真实返回的 projection/RenderMap 包裹选区，并验证 disk 上没有正文或 tag canary。`cargo test -p inex-daemon --lib` 71/71、严格 Clippy、fmt、diff-check 全通过。下一优先级进入 VS Code 选择器/命令与可配置 keybindings。

## 2026-07-15 — VS Code Umbra Sidecar Client

- 提交 `b58bffd`（`feat(vscode): add typed Umbra sidecar client`）：扩展侧新增 capability-gated Umbra status/init/unlock/lock/enable/open/apply API、严格 `RenderMap`/range/spec 序列化和响应解析。投影字节长度必须匹配 RenderMap，固定 32-byte generation、严格字段集、canonical ETag、逻辑路径和 durability 均在进入 UI 前验证。
- 新增 2 项 parser 回归；`pnpm --dir editors/vscode check` 与测试 47/47 通过。下一步为 CustomEditor 保留并上报 webview 选区、实现多选 QuickPick 及普通/快速标注命令；该 UI 尚未宣称可用。

## 2026-07-15 — VS Code Webview 选区桥接

- 提交 `058fb61`（`feat(vscode): capture verified webview selections`）：textarea 选区以 UTF-8 byte offsets 连同完整编辑内容发送；host 先同步内容，再验证范围并关联当前 document/session。锁定、dispose 会主动丢弃缓存选区，协议错误会恢复 host 内容而非保留 client 坐标。
- `pnpm --dir editors/vscode check` 和 47/47 测试通过。下一步将当前 CustomEditor document/选区暴露给命令，并实现 stateful multi-select QuickPick；此提交尚未将 Umbra projection 替换进普通 feature-2 打开路径。

## 2026-07-15 — VS Code Active Selection Authority

- 提交 `52a9e6a`（`feat(vscode): expose active verified editor selection`）：CustomEditor 通过 webview view-state 维护 active document，只在 document 仍属当前 Vault session、仍被 provider 持有且有已验证选区时向命令返回 selection authority；dispose 自动清理 active 引用。
- `pnpm --dir editors/vscode check` 通过。下一步实现 QuickPick 规格选择与将该 authority 接到 Umbra projection/apply 路径；当前 feature-2 文档尚不能用普通 open/save 路径编辑，保持 fail-closed。

## 2026-07-15 — VS Code 私密标注选择器状态

- 提交 `8aab1d2`（`feat(vscode): add private annotation picker state`）：纯 TypeScript picker state 明确 kind/Outer 为单选、tag ID 只接受 catalog 中值并排序、Cover 只在 cover mode 有且不能为空。该模块直接产生 sidecar 的 `PrivateAnnotationSpec`，不会把 tag label 当作稳定 ID。
- 新增 2 项状态/cover 回归；`pnpm --dir editors/vscode check` 和 49/49 测试通过。下一步将 encrypted Umbra catalog 暴露给 daemon/extension，再用 VS Code multi-select QuickPick 驱动此状态并把已有 webview selection 应用于 feature-2 投影。

## 2026-07-15 — Umbra profile cover 与 remove RPC 回归

- 提交 `b75f9ed`（`fix(umbra): validate profile cover annotations`）：VS Code 对 profile 的 `outer: cover` 强制收集非空公开 cover text，不再信任 `promptForCover` 是否被旧配置错误关闭；因此不会把结构无效的 Cover 请求交给 daemon。
- daemon 生命周期测试现以 apply 响应给出的 ETag、projection 和 RenderMap 的 exact private-slot 范围调用 `umbra.annotation.remove`，断言恢复原投影且不再有 private slot。首轮误用 RPC RenderMap 的 `projectionStartByte`/`projectionEndByte` 字段而失败；实际协议字段为 `startByte`/`endByte`，已按 canonical response 修正后通过。
- 验证：`cargo fmt --check`、targeted daemon lifecycle 1/1、`pnpm --dir editors/vscode check`、VS Code tests 50/50 通过。

## 2026-07-15 — VS Code 真实 Markdown paragraph 空选区

- 提交 `f34e0dc`（`feat(vscode): target Markdown paragraphs for annotations`）：将空选区默认目标从单行近似改为光标所在的连续非空 Markdown 行；空白行仍拒绝，range 不含行终止符。纯函数独立于 VS Code host，便于直接回归 Unicode UTF-8 buffer 的 byte-range 语义。
- PRD 的 MVP 状态同步为真实 paragraph 行为。验证：`git diff --check`、`pnpm --dir editors/vscode check`、tests 51/51、`pnpm --dir editors/vscode build` 均通过。

## 2026-07-15 — Umbra daemon 全量复验

- 在上述 RPC 回归并入后，`cargo test -p inex-daemon --lib` 为 71/71 通过，`cargo clippy -p inex-daemon --all-targets -- -D warnings` 通过；工作树保持 clean。下一项仍是将编辑器本地的 toggle/unwrap 交互偏好落实为配置，而非把快捷键语义写死在 extension 代码中。

## 2026-07-15 — VS Code 私密标注本地偏好

- 提交 `3ad47a5`（`feat(vscode): configure private annotation interactions`）：新增 window-local `inex.privateAnnotation.noSelectionTarget`（paragraph/line/reject）与 `confirmBeforeUnwrap`。前者只影响临时 snapshot 的 selection range，后者同时控制 toggle 与显式 remove 的确认；配置解析严格回退默认值，绝不存储私密标签、profile 或正文。
- `headingSection`、multi-cursor 和记忆上次 spec 仍未暴露为设置，避免出现仅有表面配置、却未能满足 selection 原子性或锁定清理语义的路径。PRD 已同步当前能力边界。
- 验证：package JSON、`git diff --check`、`pnpm --dir editors/vscode check`、tests 53/53、构建均通过。

## 2026-07-15 — 私密标注 metadata edit 核心与 daemon

- 提交 `aefd789`（`feat(umbra): edit private annotation metadata atomically`）：新增 Vault `edit_private_annotation`。它先重认证当前 ETag/完整 projection/RenderMap，再只接受单一 private block 内的非空 selection；解密原 payload，保留 Markdown、slot ID 与 created time，更新 kind、tag IDs、updated time 和 Outer 策略后一次性重加密保存。plain/complete/mixed/stale 不会触发写入。
- 提交 `860227d`（`feat(daemon): edit private annotations over RPC`）：协议增加 `umbra.annotation.edit`，handler 沿用严格 JSON 资源限制与 apply/remove 的 response shape。生命周期回归现在是 apply → edit（block/tag/placeholder）→ remove，remove 只消费 edit 返回的 ETag/projection/RenderMap。
- 首轮测试错误地将零长度 cursor 送入 core，但 `TextRange` 故意禁止空范围；已改为在 private block 内使用一字节 marker 范围。验证：core 295/295、core strict Clippy；daemon 71/71、daemon strict Clippy、fmt/diff-check 全通过。

## 2026-07-15 — VS Code 原位编辑私密标注

- 提交 `57487c4`（`feat(vscode): edit private annotations in place`）：新增 `inex.editPrivateAnnotation`、sidecar `umbra.annotation.edit` client 与 canonical private-block parser。命令只以当前 active Umbra projection 的 RenderMap 确定单一 slot；零长度 cursor 规范为 block 开头的安全 ASCII marker byte，非空 selection 必须完整位于 block 内且不能是 complete block。
- Picker 会预选当前 kind、catalog 中可解析的 tag IDs（含当前引用的 archived tag）和 Outer mode；Cover 仍重新要求公开文字。客户端不推导或传入 slot ID，daemon 保留 ID/private Markdown 并重新认证所有提交输入。
- 验证：`git diff --check`、`pnpm --dir editors/vscode check`、tests 55/55、build 通过。PRD 已同步。

## 2026-07-15 — VS Code chooser 快捷键别名

- 提交 `175d865`（`feat(vscode): add private annotation chooser alias`）：通过 package keybinding contribution 新增 `Ctrl+Alt+H` → `inex.choosePrivateAnnotation`，与 Ctrl+Alt+/、Ctrl+Alt+Shift+/ 一样可由用户普通 keybindings 覆盖；没有加入任何 raw key handling。
- `Ctrl+Alt+O` 尚未贡献：它需要一个独立的 Quick Redact/保存/退出 Umbra 事务，不能错误复用“锁定整个 Vault”。验证：JSON parse、VS Code check、55/55 测试通过。

## 2026-07-15 — 加密私密标签目录核心管理

- 提交 `1298641`（`feat(umbra): manage encrypted private tag catalog`）：`UmbraConfigV1` 新增 create/rename/archive/reorder。稳定 tag ID 不会在 rename/reorder 中变化；archive 只影响 picker 可见性，不删除历史 document/profile 引用。Vault 包装器每次均 load 已认证 config、变更、再用 session CAS 原子加密保存。
- config validation 现拒绝 duplicate tag/profile IDs、非 canonical catalog 顺序、profile/default 对不存在 tag 的引用、未知 default profile，及 `outer: cover` 与 `promptForCover` 不一致的 profile。这样管理命令无法产生“可解密、但不可用”的共享目录。
- 验证：tag mutation 单测、Vault ciphertext-only catalog 测试、严格 core Clippy、fmt/diff-check 通过。下一步接 daemon RPC；VS Code/Sublime 仍不得直接写 `.inex/config.umbra.inex`。

## 2026-07-15 — 加密私密标签 daemon RPC

- 提交 `f46d2ff`（`feat(daemon): manage encrypted private tags over RPC`）：新增 `umbra.tag.create`、`rename`、`archive`、`reorder`。tag ID、label、description、aliases 和排序列表均由 zeroizing 参数提取器受限读取；handler 不构造 config 文件，只委托 Vault 的 authenticated catalog transaction。
- daemon 生命周期回归覆盖创建→重命名→归档→重排→仅 Umbra 已解锁的 config 读取；全量 daemon 71/71 与严格 Clippy/fmt/diff-check 通过。下一步在 VS Code 增加管理命令，并为 Sublime 复用相同 RPC。

## 2026-07-15 — VS Code 加密标签 RPC Client

- 提交 `ea6d44a`（`feat(vscode): add encrypted tag management RPC client`）：sidecar 提供 create/rename/archive/reorder typed methods。调用前验证 canonical stable ID、UTF-8 文本长度、alias 数量、safe sort order 和完整无重复 reorder 列表；RPC acknowledgement 仍走严格 parser。
- VS Code check 与 55/55 tests 通过。下一步抽取 Umbra session 准备逻辑后接入 `Inex: Manage Private Tags` UI；客户端不缓存、也不直接写加密 catalog。

## 2026-07-15 — VS Code 私密标签管理 UI

- 提交 `a94ce38`（`feat(vscode): manage encrypted private tags`）：抽取 `ensureUmbraReady`，annotation 和 tag 管理共享 vault unlock、不可恢复初始化警告、Umbra password、enable 与 session-epoch 检查。`Inex: Manage Private Tags` 可创建、重命名、归档 tag；每个 mutation 后重新向 daemon 读取 catalog。
- 创建流程的 display label 与 stable ID 都经 sensitive input，第二次输入取消也会在 finally 中丢弃第一次的 label；UI 不缓存 catalog、不写 `.inex`。reorder/profile 管理未伪装为已完成。
- 验证：`git diff --check`、VS Code check、55/55 tests、build 通过；PRD 与计划同步。

## 2026-07-15 — VS Code 私密标签重排

- 提交 `c8b6f10`（`feat(vscode): reorder encrypted private tags`）：新增 `Inex: Reorder Private Tags`，选择当前 tag 后可移动到 first/previous/next/last。UI 从 daemon 刚读回的完整 catalog 产生 exact ID permutation，再调用 `umbra.tag.reorder` 并 reload。
- 修正管理器原本的普通 QuickPick：任何展示私密 tag label/description 的选择器均改用 sensitive QuickPick，在 Umbra 锁定时清空 items 并关闭；后续位置动作不显示 tag label。验证：VS Code check、55/55 tests、build、diff-check 通过。

## 2026-07-15 — 加密 annotation profile 核心管理

- 提交 `4594d6b`（`feat(umbra): manage encrypted annotation profiles`）：`UmbraConfigV1`/Vault 新增 create/edit/remove profile。edit 必须以同一 stable profile ID 回写，create/edit 都重新验证 encrypted tag references、kind/Outer/Cover prompt 语义；remove 会在同一 config 事务中清掉 matching default profile ID。
- 核心 profile mutation 与 catalog/canary 回归、严格 core Clippy、fmt/diff-check 通过。下一步为 daemon RPC，编辑器仍不能直接改 `.inex/config.umbra.inex`。

## 2026-07-15 — 加密 annotation profile daemon RPC

- 提交 `657f697`（`feat(daemon): manage encrypted annotation profiles`）：新增 `umbra.profile.create/edit/remove`。profile id/label/kind/tag IDs/Outer 通过 strict sensitive nested object 解析；daemon 把 stable-ID/引用/cover 语义检查和加密写入全部委托 core。
- lifecycle 回归在同一 Umbra session 内完成 create→edit（comment/drop 到 block/cover）→config get→remove，full daemon 71/71、严格 Clippy、fmt/diff-check 通过。下一步 VS Code typed client/UI。

## 2026-07-15 — Sublime Umbra 投影与标注 RPC 边界

- 提交 `e93a1a9`、`f788818`、`b027052` 先后加入 `umbra.document.open`、RenderMap shape/range 边界；本轮将这些检查收敛为 canonical parser，并新增 apply/edit/remove 客户端接口。generation 必须是 canonical 32-byte base64url，slot ID 唯一且 slot/outer ranges 有序、不重叠、投影长度精确一致。
- 所有标注 mutation 只序列化同一 authenticated projection、ETag 和完整 RenderMap；返回内容亦需重新验证 feature-2 metadata、durability 与 RenderMap 后才交给 Sublime host。annotation spec 只接受 block/comment、规范排序去重 tag ID 和与 cover mode 一致的公开 cover text。
- 验证：`PYTHONPATH=editors/sublime python3 -m unittest discover -s editors/sublime/tests -v` 为 85/85 通过、1 项平台跳过；`python3 -m py_compile`、`git diff --check` 通过。下一步在 scratch-buffer 生命周期中接入 Umbra projection 与 stateful picker，绝不将 catalog 标签写入普通设置。

## 2026-07-15 — VS Code 最新导入路径与发布基线复验

- 当前 `repositoryImport.ts` 已实际支持 absent create 与 exact existing-v2 target reconciliation：既有目标必须经 modal confirmation，且交互明确说明 target-only reconcile 不应索取密码；`INEX_PASSWORD_STDIN` 仍在 extension 边界无条件拒绝。release smoke 的 CLI usage 已为 `<destination-vault>`，不是旧的 `<new-vault>`。
- 验证：`pnpm --dir editors/vscode check && pnpm --dir editors/vscode test && pnpm --dir editors/vscode build` 全部通过，测试为 57/57。发布工具必须从仓库根目录以 `PYTHONPATH=scripts python3 -m unittest discover -s scripts/tests -p 'test_*release*.py' -v` 运行；省略 PYTHONPATH 的首次启动仅发生模块导入错误，未作为产品回归。
- 正确启动的 release tests 为 58/61；3 项依赖 Linux pidfd/subreaper descendant-control 的 lifecycle gate 在当前容器以 `Linux pidfd descendant control is unavailable` fail closed。该宿主缺少 required capability，不能把当前机的结果升级为 release evidence；后续需在具备 pidfd gate 的 clean release host 重新跑 package/audit/smoke。
- 本机在 isolated `CARGO_TARGET_DIR=target/current-demo-HEAD/native-target` 成功生成最新 `inex`/`inexd`，但 `package_release.py` 按设计拒绝其 xlings ELF interpreter（`/home/horeb/.xlings/subos/default/lib/ld-linux-x86-64.so.2`），不是 portable Linux release artifact。不得绕过 audit；需要使用 system GCC/glibc release host 重建后再 package/audit/smoke。

## 2026-07-15 — Sublime 独立 Umbra keyslot 会话

- 提交 `5069253`（`feat(sublime): manage independent Umbra keyslot`）：strict client 增加 `umbra.initialize`、`umbra.unlock`、`umbra.enable` 与 `umbra.lock`。初始化/解锁只发送当前 Outer session 和一次密码；lock 仅要求 `{ok: true, unlocked: false}`，不会锁定 Outer vault。
- 认证响应要求 initialized/unlocked 逻辑一致，所有 status、durability、精确字段形状和密码长度均在 host 前验证；不一致或异常协议响应终止 sidecar session。验证：定向 RPC 26/26、Python compile、diff-check 通过。下一步将此会话接入 Sublime command/UI 并在锁定时清空 picker state。

## 2026-07-15 — Sublime Umbra 解锁与锁定命令

- 提交 `cae72cf`（`feat(sublime): expose Umbra unlock and lock commands`）：新增命令 palette 项。Outer 尚未解锁时拒绝 Umbra 操作；读取 status 后，已有 slot 走独立密码解锁，未初始化时显示冻结的不可恢复警告并经确认后初始化。
- 每个异步阶段重查 client/generation；密码只在 worker 局部引用，完成后续期 authenticated Outer idle deadline。`Inex: Lock Umbra Private Mode` 只调用 `umbra.lock`，不会执行 vault lock 或 scrub 普通 Outer buffer。验证：Sublime 86/86、1 项 pidfd platform skip、Python compile/JSON/diff-check 通过。

## 2026-07-15 — Sublime 私密标注 stateful picker 基础

- 提交 `5eeb657`（`feat(sublime): add private annotation picker state`）：无 Sublime API 依赖的 picker state 以加密 catalog 的 tag ID/label 构造 repeated-panel items；kind 与 Outer 保持单选，tag 可多选，spec 固定规范排序 tag IDs，并在 cover mode 强制非空公开 cover text。
- 已选的 archived tag 仍展示，未选 archived tag 不进入默认 picker。`clear()` 主动清空 tags 和 label，给 lock/cancel/dispose 接线使用。验证：state + Python 3.8 syntax 12/12、compile、diff-check 通过；下一步接入 command 后必须在锁定回调清空 live picker。

## 2026-07-15 — Sublime annotation profile picker state

- 提交 `7b7624e`（`feat(sublime): apply encrypted annotation profiles`）：picker state 接受 daemon 已验证的完整 profile，原子替换 kind/tag IDs/Outer mode；严格校验 profile key set、stable ID/label、catalog tag references 和 `cover ↔ promptForCover` 语义。
- Profile 只提供 metadata，不能提供公开实例 cover text；当 outer=cover 时仍由 `spec()` 强制单独输入。验证：picker 3/3、compile、diff-check 通过。

## 2026-07-15 — Sublime repeated private annotation Quick Panel

- 提交 `fed948e`（`feat(sublime): show stateful private annotation picker`）：`_show_annotation_picker` 将 state 映射到重复 `show_quick_panel`，每次 kind/tag/Outer 点击都重开面板；Done 产出 canonical spec，Cover 只在 Done 后经公开 input panel 取得实例文字。
- live state 由专用内存列表持有；取消、Outer lock 与 Umbra lock 都调用 clear 并隐藏 overlay，避免锁后保留私密 tag label。验证：完整 Sublime 89/89、1 项 pidfd platform skip、compile/diff-check 通过。下一步将 authenticated Umbra projection 与 selection transaction 接入该 callback。

## 2026-07-15 — Sublime Umbra feature-2 conversion client

- 提交 `91f7d7a`（`feat(sublime): convert documents to Umbra containers`）：strict RPC client 新增 `umbra.document.convert`，以当前 document ETag CAS 请求 feature-2 upgrade，并只接受 exact `{etag, metadata, durability}` response。后续真实 daemon 回归修正了早期说明中的混淆：feature-2 由 authenticated `required_features=[2]` 表达，`metadata.flags` 仍只允许普通内容 flags 0/1。
- 这使后续 UI 可在 conversion 后重新经 `umbra.document.open` 获取 canonical projection/RenderMap，不能把原 normal buffer 或旧 ETag 当作私密容器状态。验证：RPC 27/27、compile、diff-check 通过。

## 2026-07-15 — Sublime authenticated Umbra projection model

- 提交 `d5036fc`（`feat(sublime): model authenticated Umbra projections`）：`ManagedDocument` 显式支持无 ordinary RPC handle 的 Umbra projection；普通 document 仍必须有 handle，Umbra document 反而拒绝 normal handle，避免 close/lock 路径误发 `document.close`。
- `replace_umbra_projection` 在 daemon mutation 成功后一次性替换 plaintext、ETag 和 RenderMap，更新 model 保存版本并清零旧 projection；close 丢弃 RenderMap。验证：model 19/19、compile、diff-check 通过。

## 2026-07-15 — Sublime normal-to-Umbra model transition

- 提交 `bdf365b`（`feat(sublime): transition clean documents into Umbra`）：仅 clean、open、normal managed document 可 transition 到 Umbra；方法先从 model 取出 normal handle，再以 authenticated projection 安装 Umbra identity，调用方随后才可关闭旧 normal handle。
- dirty、locked、closed 或已 Umbra document 一律拒绝并 wipe incoming projection，避免用户未保存的普通修改被 conversion 覆盖。验证：model 20/20、diff-check 通过；下一步是 UI worker 的 convert→open→transition→close-handle sequencing。

## 2026-07-15 — Sublime active document Umbra conversion

- 提交 `4a30a99`（`feat(sublime): enter active documents into Umbra mode`）：`Inex: Enter Umbra Mode for Active Document` 要求 clean normal managed buffer 与已解锁 Umbra，按 convert ETag CAS → authenticated projection open → main-thread client/model identity recheck → model transition → close old normal handle 顺序执行。
- conversion 已成功但 projection/transition 任一步失败时立即执行 vault lock/scrub；不会继续暴露可保存的旧 normal buffer。成功时使用 daemon projection 替换 scratch view、清空 undo stack，并保留 Outer session。验证：完整 Sublime 92/92、1 项 pidfd platform skip、compile/JSON/diff-check 通过。

## 2026-07-15 — Sublime private annotation apply command

- 提交 `950c692`（`feat(sublime): apply private annotations from projections`）：`Inex: Choose Private Annotation` 仅接受 clean active Umbra projection 的一个或多个显式 selection，使用 UTF-8 byte offsets，加载已解锁 encrypted catalog，再以完整 current projection/ETag/RenderMap 调用 daemon apply。
- apply response 仅在 Outer client、Outer generation、独立 Umbra generation、document identity、ETag/RenderMap 均未变化时安装；Umbra lock 期间完成的旧 callback 无法回写私密 projection。成功后清空 undo stack并采用 daemon projection，不推导 slot/marker。验证：完整 Sublime 92/92、1 项 pidfd platform skip、compile/JSON/diff-check 通过。

## 2026-07-15 — Sublime private annotation removal

- 新增 `Inex: Remove Private Annotation`。命令只接受 clean active Umbra projection 的明确 selection，并在确认后把主线程捕获的 UTF-8 projection 副本、ETag 和完整 RenderMap 交给 `umbra.annotation.remove`；daemon 是唯一判定完整 private block/slot 的一方，客户端不读取或推导 slot ID。
- 同时修正 apply 的 worker 所有权：主线程在弹出 picker 前复制并验证 projection，RPC worker 只消费该副本；picker cancel、成功提交及 worker finally 都会清零对应 bytearray。验证：完整 Sublime 92/92（1 项 pidfd platform skip）、Python compile、`Main.sublime-commands` JSON 和 `git diff --check` 通过。
- Neovim 已作为正式但最后优先级的 Lua 插件 MVP 写入 active goal/计划：仅在 CLI/daemon、VS Code 与本轮 Sublime 范围稳定后开始，复用同一 `inexd` JSON-RPC 与 Outer/Umbra 生命周期，不创建第二套密码学或容器实现。

## 2026-07-15 — Sublime private annotation metadata edit

- 新增 `Inex: Edit Private Annotation`。命令只接受一条位于 RenderMap 私密块内部（不是完整块）的 selection；空 cursor 以该 block 首个可认证非空 byte 作为 daemon `umbra.annotation.edit` 的 proof。完整 block 继续只属于 remove 流程。
- picker 从 canonical visible fence header 读取 kind/tag IDs/Outer mode 作为预选值；header 不含 slot ID 传递路径，tag IDs 仍必须存在于已解锁 encrypted catalog，最终 mutation 始终发送 projection/ETag/完整 RenderMap 并只安装 daemon 回包。投影副本在 cancel、session 变化和 RPC finally 中清零。验证：94/94 Sublime tests（1 项 pidfd platform skip）、Python compile、JSON 与 diff-check 通过。

## 2026-07-15 — Sublime comment-like annotation toggle and package inclusion

- 新增 `Inex: Toggle Private Annotation`：complete private blocks 复用 remove 的确认；一条 block 内 cursor/selection 复用 edit；无 private 交叉的明确普通多选复用 chooser；partial/mixed private selection 或空普通 cursor 均拒绝，不在客户端推断 slot identity。Linux `Default (Linux).sublime-keymap` 贡献 Ctrl+Alt+/、Ctrl+Alt+Shift+/、Ctrl+Alt+H，用户可在自己的 keymap 重绑。
- 修正 release source 清单：`inex_annotation.py` 与 Linux keymap 现在会进入 Sublime archive，避免源码可用而安装包缺模块。验证：Sublime 94/94（1 项 pidfd platform skip）。release unittest 为 58/61，3 项 lifecycle 进程门禁因本机缺少 Linux pidfd/subreaper fail closed；未将其计作发布通过。

## 2026-07-15 — Sublime encrypted annotation profile shortcuts

- 新增 `InexApplyPrivateAnnotationProfileCommand(profile_id)`，只接受 stable-ID 形状的 normal Sublime command argument；worker 从已解锁 daemon config 读取 profile，再由 state 校验 kind/tags/Outer 语义。profile 不可用或 catalog 矛盾均在 daemon mutation 前拒绝。
- drop/placeholder profile 立即发出 authenticated apply；cover 只在本次实例操作中询问公开 cover text。cancel、无效 cover、失效 session 与 worker finally 都清零 captured projection。Linux default keymap 增加 Ctrl+Alt+1/2/3 的 `private-comment`、`relationship-comment`、`family-comment` 示例。验证：Sublime 94/94（1 项 pidfd platform skip）、compile、JSON、diff-check 通过。

## 2026-07-15 — Sublime encrypted tag/profile mutation RPC

- strict client 新增 `umbra.tag.create/rename/archive/reorder` 和 `umbra.profile.create/edit/remove/setDefault` 的 authenticated wrappers；stable IDs、UTF-8 限额、sort order、tag sequence canonicalization、cover prompt 语义与 exact `{ok:true}` acknowledgement 都在 host 前验证，异常协议结果终止 sidecar session。
- 管理 UI 尚未接线，因而插件仍不会直接读取或写入 `.inex/config.umbra.inex`。验证：Sublime 95/95（1 项 pidfd platform skip）、Python compile 与 diff-check 通过。

## 2026-07-15 — Sublime encrypted catalog schema hardening

- `umbra.config.get` 不再只验证 ID 存在：client 现在在私密 label 接触 host UI 前验证 tag 全字段、description/alias 限额、sort order、唯一 stable IDs、profile tag 引用/cover prompt、default kind/tag/profile 引用与 canonical tag ID order。异常响应按 terminal protocol violation 处理。
- 新增合法 catalog、重复 tag、悬空 profile tag、重复 default tag 和悬空 default profile 回归。验证：Sublime 96/96（1 项 pidfd platform skip）、Python compile、diff-check 通过。

## 2026-07-15 — Sublime private tag management UI

- 新增 `Inex: Manage Private Tags` repeated Quick Panel：create 依次采集 label/stable ID，rename 与 archive 选择 encrypted catalog tag，reorder 以 first/previous/next/last 生成完整 ID permutation。每个操作调用 strict daemon RPC，成功后重新 load catalog；插件不合成或写入 config ciphertext。
- UI 只在 live Umbra generation 中呈现；Umbra lock 的既有 `hide_overlay` 关闭面板，旧 generation 回调不会继续 mutation。验证：Sublime 96/96（1 项 pidfd platform skip）、Python compile、commands JSON、diff-check 通过。

## 2026-07-15 — Sublime annotation profile management UI

- 新增 `Inex: Manage Private Annotation Profiles` repeated panel：create 采集 label/stable ID，edit 保留 ID 但可更新 label/kind/tags/Outer，remove 经确认，set default 可选择 profile 或明确清空。所有动作经 strict daemon profile RPC，成功后重新 load encrypted catalog。
- profile 专用 picker 复用多标签 state，但只传 kind/tag IDs/Outer/`promptForCover` metadata；不会向用户索取、缓存或写入一次性公开 cover text。验证：Sublime 96/96（1 项 pidfd platform skip）、compile、commands JSON、diff-check 通过。

## 2026-07-15 — CLI/daemon and VS Code main-delivery regression

- 在完成 Sublime experimental 增量后，重新运行主交付质量门：`cargo test --workspace --locked` 通过；`cargo fmt --all -- --check` 与 `cargo clippy --workspace --all-targets --locked -- -D warnings` 通过。VS Code `pnpm check && test && build` 通过，Node tests 为 57/57，产出 `dist/extension.js`。
- 本机发布 lifecycle 仍不能因此视为完成：其 Linux pidfd/subreaper descendant-control prerequisite 缺失时应继续 fail closed。当前工作树 clean，下一步优先针对可安装 artifact 与主客户端集成门禁，而非把该环境限制降级。

## 2026-07-15 — 当前 Linux x64 artifact construction and structure audit

- 在独立 `--no-local` clean checkout（origin 固定为 canonical Git URL）中，以显式 `/usr/bin/gcc` 构建当前 `739b9f0` 的 `inex`/`inexd`；两者 ELF interpreter 都是标准 `/lib64/ld-linux-x86-64.so.2`。该 checkout 内以 lockfile offline 安装 VS Code/vsce deps 并生成 production bundle，然后 `package_release.py` 成功构建 Linux x64 Rust ZIP、Sublime ZIP 与 VSIX。
- `audit_release_artifacts.py` 通过：artifact hashes 为 Rust `9892df55…`、Sublime `caa35300…`、VSIX `738effbc…`、SHA256SUMS `63d501ab…`；共享 CLI `4dbd6433…`、sidecar `f0f50b06…`，source 绑定 clean commit `739b9f0`。报告明确仍不覆盖签名/发布、独立法律审查或 native runtime/install/editor behavior；pidfd lifecycle gate 仍未通过本机环境。

## 2026-07-15 — Current candidate isolated VSIX install and bundled-runtime smoke

- 在同一 standalone checkout 中执行 `smoke_release_artifacts.py`，传入系统 `/usr/bin/code`。脚本对当前 `739b9f0` Linux x64 candidate 的 portable archives、隔离 extensions directory 内 VSIX 安装、installed layout/executable modes 和 bundled CLI/daemon runtime probes 返回 `packageSmoke: passed`。
- 这是当前精确 artifact 的本地 install/bundled-runtime evidence，补上 structure audit 不运行 executable 的边界；仍不覆盖持久 profile、Extension Host CRUD/recovery、pidfd lifecycle、签名、跨平台和独立可重复构建。

## 2026-07-15 — Real repository-import gate failure reported by user

- 用户以已安装 `739b9f0` Linux x64 VSIX 的 bundled CLI 对 `/home/horeb/_code/_blog`（324 tracked entries、307 Markdown、17 assets、最大 asset 25,074,521 bytes）执行真实导入。首次因 `.git/FETCH_HEAD`/`.git/gk/config` 在导入中变化而按设计 fail closed；停止自动 Git fetch 后第二次进入候选密文 Git 构建/审计并以 `GitCandidateFailed` 终止，最终 destination 未发布、staging retained。
- 此问题暴露此前 artifact 门禁只覆盖 fixture、dry-run、package install/runtime smoke，未以真实规模仓库进行最终全流程验收。不得再把该 VSIX 表述为已验证的可用 repository-import demo。已在 Phase 7 新增“真实规模 Git 仓库副本全流程 import/reopen/residue”作为每个候选 VSIX 的硬门禁；当前优先复现并修复该 candidate audit failure。
- 已从 `_blog` 创建只读隔离 clone，以已安装 VSIX 的 bundled CLI 复现同一 `TargetAuditFailed`，排除用户目录、口令和 VS Code 任务包装因素。候选的初始 raw-index audit 失败；失败后对保留候选执行 Git path list 的独立 parser 复核可通过，因此下一步必须捕获 audit 当时的 exact index bytes/control manifest，不能根据事后被 Git 读取可能更新的 index 推断原因。一次“目录分隔符排序”假设已被独立 Git 顺序对比否定并完全撤回，未进入产品代码。

## 2026-07-15 — Real-repository import regression fixed and verified

- 根因是 CLI 在 `tracked_target_paths` 中依赖 `PathBuf` 的组件排序；Git index 则要求 canonical slash-path 的原始 UTF-8 byte order。真实仓库同时含 `means.md` 与 `means/…`，使第 308 个 target raw-index entry 与预期次序不一致，候选 audit fail closed。现在显式按 canonical path bytes 排序，并加入回归测试。
- 以 `/home/horeb/_code/_blog` 的独立只读 clone、debug CLI 重跑完整导入：324 tracked source entries（307 Markdown、17 assets、Markdown 3,549,648 bytes、assets 46,643,446 bytes、最大 asset 25,074,521 bytes）全部成功；结果为 published vault、无 parent Git root `9aa15ca…`、307 密文 Markdown、17 密文 assets、candidate vault/Git object audit passed、source revalidated/preserved。
- 随后由新 CLI process 执行 locked `verify`（7 dirs/307 docs/17 assets）、password-protected `search`（0 matches）和 `git fsck --full --strict`；目标没有 `.md`/`.png`/`.jpg` 明文文件名，非密文文件扫描未命中测试内容。该证据只覆盖当前修复源码 CLI；VSIX 必须在该 commit 打包并重跑同一门禁后才能交付用户安装。

## 2026-07-15 — Fixed Linux x64 VSIX package and exact bundled CLI gate

- 在 standalone clean clone（commit `ff41eb3`、canonical origin、无额外 worktree）中用 `/usr/bin/gcc` 显式重建 native pair，严格 package/audit 与 isolated VS Code install/bundled-runtime smoke 均通过。新 VSIX：`target/release-artifacts/ff41eb3-linux-x64/inex-vscode-0.1.0-linux-x64.vsix`，SHA-256 `fe3ff42f1944101e7901a9c204c4038776384d2d08ce084c5f39c36cbc9f434d`。
- 从该 VSIX 解出其 bundled `inex`，对独立 `_blog` clone 再跑 exact package-binary repository import；307 encrypted Markdown/17 encrypted assets、candidate vault/Git object audits、source revalidation、whole-root publication与parentless Git root均通过。随后同一包内 CLI 的 locked verify（7/307/17）、fresh password search（0 match）、无 `.md`/`.png`/`.jpg` 明文文件名与 `git fsck --full --strict`均通过。

## 2026-07-15 — Neovim encrypted annotation-profile picker

- 新增 `:InexChoosePrivateAnnotationProfile startByte endByte` 与 `:InexApplyPrivateAnnotationProfile startByte endByte profileId`。两者只从 live `umbra.config.get` 的已验证响应读取 profile；picker 结束、取消或 cover prompt callback 完成后释放 config/spec/cover 临时引用，不写入 options、globals、shada 或 module cache。
- cover profile 只在本次操作中通过 `vim.ui.input` 取得公开 cover text，再走现有 daemon-authenticated apply；非 cover profile 直接复用已验证 kind/tag IDs/outer。Neovim clean headless runtime load check 通过。自定义 kind/tag 多选 picker 与宿主 residue gate 仍未完成。

## 2026-07-15 — Neovim custom private-annotation picker

- 新增 `:InexChoosePrivateAnnotation startByte endByte` 的 stateful `vim.ui.select` picker：kind 与 Outer 为单选，非 archived encrypted tags 可重复切换多选，Apply 才构造 canonical sorted tag IDs 并调用既有 authenticated daemon mutation；cover 仍只在一次 `vim.ui.input` 中获取公开文本。取消、完成或 cover callback 后均丢弃 config/state/spec 引用。clean headless runtime load check 通过。

## 2026-07-15 — Neovim final-priority Lua transport skeleton

- 新增 `editors/neovim` runtime plugin。Lua `rpc` 模块只启动 absolute regular `inexd`、使用 bounded Content-Length JSON-RPC framing、绑定 pending request callbacks，并在 stdout/protocol/process failure 时清理；插件提供 `:InexStart`、`:InexStatus`、`:InexStop`，`system.hello` 发送 frozen `client/clientVersion/protocolMajor` 参数。
- 以本机 Neovim 0.12 headless 和当前 system-GCC `inexd` 做真实 start→hello→status→stop smoke，两次返回 `Inex sidecar is ready`。该切片不处理密码、明文 buffer、Outer/Umbra 或 `.inex` 文件；这些必须通过后续同一 authenticated session/RenderMap API 实现，并先完成 Neovim host residue gate。

## 2026-07-15 — Neovim Outer read-only buffer skeleton

- Neovim 插件新增 `:InexUnlock`/`:InexLock`/`:InexOpen`。unlock 只发送 `vault.unlock` 给 daemon；open 只接受普通 feature 0/1 Markdown response，创建 unlisted scratch buffer，禁用 swap/undo persistence/modeline、设为 wipe-on-hide 和只读，并在 BufWipeout/lock 时关闭 daemon document handle。feature-2/Umbra response 明确拒绝。
- headless regression 首次暴露 Lua lexical-scope bug（`HELLO_PARAMS` 在 helper 定义后声明而被解析为 global nil）；移动声明后真实 `inexd` handshake 再次通过。此 slice 不实现保存或可编辑 buffer，且 `inputsecret`/cmdline、shada、LSP、第三方插件仍是未闭合宿主残留边界。

## 2026-07-15 — Neovim reproducible RPC smoke

- 新增 `editors/neovim/tests/headless_smoke.lua`。测试从 `INEX_SIDECAR` 取得绝对 binary，启动 transport、发送 exact frozen `system.hello`、验证 `inexd`/protocol major，并在 3 秒 bounded wait 内 shutdown；README 记录 exact headless invocation。
- 验证：以当前 system-GCC `inexd` 运行该 smoke 成功。该测试只覆盖 sidecar framing/lifecycle，不证明 password input、vault projection 或 Neovim plaintext-residue 安全。

## 2026-07-15 — Neovim authenticated Umbra projection transition

- Neovim 现在可在 Outer+Umbra live session 中用 `:InexEnableUmbra` 协商 feature-2，使用 `:InexConvertUmbra` 对当前 clean ordinary buffer 执行 daemon ETag CAS conversion，再由 `umbra.document.open` 读取 daemon 生成的 projection。`:InexOpenUmbra` 只显示既有 feature-2 projection；所有 `inex-umbra://` buffer 均为只读 nofile、unlisted、no-swap/no-undo/modeline disabled，并在 Umbra/Outer lock 或 stop 时 wipe。
- transition 按 convert → authenticated projection open → local identity recheck → close normal handle/buffer 顺序；convert 成功后的 projection response、状态或 buffer identity 有任何失败会主动 Outer lock/scrub，绝不把已转换容器继续当普通 buffer 保存。Neovim 不持有密码、KEK、`K_umbra`、slot cipher 或 RenderMap cache。
- 真实 daemon lifecycle 回归通过（新临时 vault：initialize/unlock Umbra、Outer document save/tree/search/mkdir、Outer relock、Umbra enable/convert/projection、Umbra lock wipe）。同时修正 Sublime 的协议校验：feature-2 是 header `required_features=[2]`，并非 `metadata.flags=2`；Umbra RPC metadata 现正确只接受内容 flags 0/1。验证：Sublime 96/96（1 项 pidfd/subreaper skip）、Neovim headless lifecycle、`git diff --check` 通过。

## 2026-07-15 — Neovim authenticated private annotation mutation

- Neovim private projection 现只在本地临时持有 daemon 返回的 ETag/RenderMap；`apply_private_annotation` 与 `remove_private_annotation` 将当前 projection、ETag、完整 RenderMap 和严格 byte ranges 原样交给 daemon，成功后只整体采用 daemon 新 projection。没有任何 Lua marker/slot 推导路径；lock/stop 仍 delete buffer 并丢弃 map。
- 真实 lifecycle 已覆盖 convert → apply（空 tag list、comment/drop）→ complete-range remove → 还原原始 Umbra projection → Umbra lock wipe。回归首次发现 daemon 对 annotation/profile 的 `tagIds` 错误要求至少一项，已改为与 PRD 和 core 相符的零或多项并由 daemon 71/71 单测覆盖。
- 提供临时可调用命令 `:InexApplyPrivateAnnotation startByte endByte` / `:InexRemovePrivateAnnotation startByte endByte`，默认 spec 为 comment/no-tags/drop；Lua API 供后续视觉选择和 picker 复用。Neovim 的 `nargs` 不接受数值 `2`，因此命令使用 `nargs="*"` 后在 callback 内严格验证两个参数；load check 与真实 lifecycle 均通过。

## 2026-07-15 — Neovim visual private-annotation toggle

- 新增 `:InexTogglePrivateAnnotation`，不提供硬编码 keymap，因而用户可按普通 Neovim mapping 机制绑定。它将一个 visual range 转成 UTF-8 byte range：plain range 使用 default comment/no-tags/drop 调用 apply；精确等于 RenderMap private range 时先确认再调用 remove；任何 partial private overlap 在 RPC 前 fail closed。
- headless lifecycle 覆盖 visual plain apply 与 linewise complete-block confirm/remove，最终恢复原 Umbra projection。该回归先暴露 visual mark API 的坐标差异：`nvim_buf_get_mark` 给出 1-based row / 0-based byte column，且 fenced private block 的末尾换行只能用 linewise visual range 完整表达；现已分别转换并验证。

## 2026-07-15 — Neovim private-annotation edit route

- `toggle_private_annotation` 现在将单一 RenderMap private block 内的非空 visual range 路由到 `umbra.annotation.edit`；完整 block 仍只会确认后 remove，partial crossing 继续拒绝。新增显式 `:InexEditPrivateAnnotation startByte endByte` 默认-spec 命令，供正常 mapping 或后续 picker 调用。
- 真实 headless lifecycle 已覆盖 apply → in-block edit（comment/drop 改为 block/placeholder）→ complete block remove；每一步只采用 daemon 新 projection/RenderMap。标签/Profile picker 仍未实现。

## 2026-07-15 — Neovim encrypted Umbra catalog boundary

- 新增 `load_umbra_annotation_config(callback)`：仅 Umbra live session 可调用，严格验证 tag/profile/default 的 exact shape、ID、tag canonical order、cross-reference 与 cover prompt 语义，随后把临时 config 交给 callback；不写入 Neovim settings 或 module cache。
- 真实 lifecycle 覆盖 enable 后 catalog read，并继续通过 convert/apply/edit/remove/lock 路径。下一步才允许用这个 transient callback 形成可清除的 picker UI。

## 2026-07-15 — Neovim encrypted default annotation

- `InexApplyDefaultPrivateAnnotation` 只在 live `umbra.config.get` callback 内读取 encrypted defaults 并构造 one-shot apply spec；默认 tag IDs/profile 语义不进入 editor-local configuration。UI picker 仍待实现。

## 2026-07-15 — Neovim custom picker regression and documentation

- 新增无 daemon 的 headless state-machine regression：模拟 live encrypted catalog 后依次选择两个 active tags、block、placeholder、Apply；断言 tag IDs canonical sort、archived tag 不显示、selection 不变，并覆盖取消不触发 mutation。该测试只替换 UI/RPC 边界，验证真实 picker 的选择状态与最终 one-shot spec，不将 catalog 写入 Neovim state。
- README 现记录 `:InexChoosePrivateAnnotation startByte endByte`，并删除“尚无 annotation/tag/profile UI”的过期表述；明确仍未实现 tag/profile 管理 UI 和宿主残留 gate。

## 2026-07-15 — VS Code current-source integration revalidation

- 当前源码运行 `pnpm --dir editors/vscode check` 与 `pnpm --dir editors/vscode test`：TypeScript 通过、57/57 单测通过。随后运行真实本机 Extension Host `pnpm --dir editors/vscode test:extension:local`，重新构建 extension、integration suite、CLI/daemon，并在隔离 Xvfb/VS Code profile 下通过 feature-1 repository import、asset preview、CRUD、backup/recovery 与 residue audit。
- 该证据不替代最终 VSIX 的人工 folder picker、隐藏终端双口令、Open New Vault 鼠标路径和 persistent-profile release gate；计划中的该项继续保持未完成，避免将 headless Extension Host 冒充真实交互验收。

## 2026-07-15 — Unix Git process-group containment

- repository-import 的普通 Git plumbing 与 `cat-file --batch` 均以独立 Unix process group 启动；timeout、oversized output、protocol mismatch 和 Drop 路径通过 safe rustix `kill_process_group` 先终止该组，再回收 direct child/reader。stdout acquisition 失败也会先执行同一清理，避免已启动 child 脱离所有权。
- 新增 Linux 对抗回归：shell 启动一个继承 stdout 的 background descendant，记录其 PID 后触发 `kill_and_wait`；测试确认 direct child 非成功结束且 descendant 在两秒内为 `ESRCH`。`inex-git` 全 379 单测、all-targets Clippy `-D warnings` 与 diff check 通过。
- 该闭合仅覆盖不主动逃离 dedicated group 的 Unix 后代；Windows Job、native process-tree evidence 和 hostile same-UID escape/TOCTOU 保持 GA 未完成门禁。
