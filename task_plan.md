# Inex 跨平台加密日记系统开发计划

## Goal

按照 `.agent/init_plan.md` 的架构与安全边界，优先交付“现有 Markdown Git 仓库 → 全新 Inex 密文仓库”的可安装迁移闭环：从干净且固定的 source HEAD 只读导入当前 tracked snapshot，完整加密 Markdown 与图片/附件，在同一隐藏 sibling staging root 内建立并审计全新密文 Git 根提交，再以一次 verified no-replace 整根发布暴露目标；使相对图片可在 VS Code 受控内存界面中读取，且原明文 Git 历史保持在源仓库、绝不进入目标 object database。随后交付 Umbra 私密标注系统：私密slot、标签、profile和元数据均经K_umbra加密，Outer投影、索引、设置与日志不泄漏它们。持续维护可安装编辑器体验、验证与发布准备，使磁盘仓库始终只保存密文而不产生临时明文 Markdown/附件。

## Current Phase

Phase 6 extension — 现有 Markdown Git 仓库/加密附件迁移与 Umbra 私密标注核心实现（Phase 7 发布收尾暂停但不撤销）

## Scope and Acceptance Baseline

- 真实 Git 仓库只保存 `vault.json`、目录元数据、`*.md.enc` Markdown 密文及版本化附件密文，不创建临时明文 Markdown/附件文件。
- 口令经 Argon2id 派生 KEK；随机 256-bit master key 被 KEK 包裹；文件使用派生子密钥与 XChaCha20-Poly1305 AEAD。
- 支持创建/解锁/锁定 vault、文件读写、树浏览、内存搜索、换密码、从现有 Markdown Git 工作树安全迁移当前快照、加密附件与密文 Git 合并。
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

  - [ ] 设计并实现 Umbra 私密标注系统（`docs/prd-umbra-mode.md`）
  - [x] 冻结产品交互、私密标签/profile加密边界、Outer隔离、selection原子性及MVP/延期范围
  - [x] 冻结独立K_umbra层级、唯一`umbra-default`密码槽、不可恢复语义与`.inex/config.umbra.inex`边界（`docs/spec/umbra-v1.md`）
  - [x] 实现随机K_umbra、Argon2id KEK 包装/解包、vault/path-bound AEAD、受保护内存清理，以及已解锁会话密码重包装基础（`f96f656`）
  - [ ] 将密码槽初始化/替换接入Vault会话、受控`.inex`目录创建与feature-2启用事务
  - [ ] 实现core私密slot、TagId、catalog/profile和RenderMap选择事务，并证明canary不进入磁盘Outer面
  - [ ] 扩展daemon session/RPC及VS Code QuickPick/命令/可配置keybindings
  - [ ] 扩展Sublime stateful picker、profile命令和keymap示例
  - [ ] 跑通多选、wrap/unwrap/edit、跨编辑器目录、canary/残留及Outer隔离矩阵

- [x] 实现 `.gitattributes`、locked-safe `inex merge-driver` 与已解锁 CLI 三方合并
- [x] 实现加密冲突状态、普通编辑器保存清旗与 journal 恢复流程
- [x] 实现 plaintext copy-import/dry-run、校验报告，并明确拒绝破坏性 in-place 转换
- [x] 实现 vault verify/pending recovery 报告与恢复说明，确保失败不破坏源数据
- [ ] 扩展为长期维护的 Markdown Git 仓库 tracked-snapshot 初始化；源仓库与原 `.git` 全程只读，目标必须全新
  - [x] 冻结干净 HEAD、tracked regular-file allowlist、双轮内容证明、导入期间重验、dirty/symlink/submodule拒绝与source provenance最小泄漏契约
  - [x] 冻结单暂存根事务：完整vault、附件、`.git`、无parent根提交、独立解锁/全树/对象审计及递归durability全部在同一sibling staging完成，只以一次整根no-replace publication暴露目标
  - [x] 在Linux实现repository source manifest、`openat2` secure no-follow遍历、完整`.git`控制树审计与最终source重验；非Linux当前明确fail closed
  - [x] 设计并实现独立版本化附件密文格式、portable logical asset path、bounded whole-file/后续streaming边界及认证读写
  - [x] 让tree/RPC/VS Code区分Markdown与attachment，并在受控webview中解析同vault相对图片而不写明文临时文件
    - [x] core tree/Vault/locked verify与daemon status/tree/顺序asset RPC已贯通，严格feature negotiation、64 MiB上限、单session零化缓存及private staging recovery门禁通过
    - [x] VS Code协商feature-1能力、顺序读取相对图片并在受控webview预览，关闭/锁定/编辑/隐藏时撤销URL并释放句柄，不形成普通plaintext document或临时文件
  - [x] 由独立`import-repository`完整导入Markdown与全部受支持的tracked `100644`附件，验证计数/摘要/精确源字节，物理`.git`只读审计且任何unsupported状态均整体拒绝
  - [x] 在单一staging root内初始化全新object database、形成单个initial snapshot、完成当前Linux对象/无明文审计与整根原子发布；真实728提交只保留在只读源仓库，不复制refs/objects/alternates或伪造parent
  - [x] 将完整历史加密重写保留为独立experimental后续；当前产品与文档只承诺单个加密快照，不宣称“保留历史”
  - [ ] 完成VS Code locked首次交互的最终发布门禁
    - [x] 提供Import/Unlock welcome、锁定CRUD gate、绝对CLI任务、成功后Open New Vault，并由真实Extension Host覆盖底层import→密文workspace→asset/CRUD流程
    - [x] 提供当前单工作区默认source、Explorer文件夹右键初始化、fresh HEAD快照/历史不复制确认、existing exact-v2显式对账入口与不丢快速退出事件的Task状态机（`14b4f18`）
    - [ ] 在最终VSIX上人工驱动Linux真实folder picker、任务终端双口令与Open New Vault鼠标路径，并纳入persistent-profile残留证据
  - [ ] 完成冻结GA对象证明与生产接线
    - [x] 实现strict SHA-1 raw index v2/v3/v4 parser，校验entry/extension/trailer、排序、canonical v4 varint与资源边界（`62fa0aa`）
    - [x] 从approved path/OID trie独立typed-SHA-1序列化每棵raw tree，并用单个bounded streaming `cat-file --batch`逐对象比较blob/tree/commit body与exact inventory（`d8805bd`）
    - [x] 将同一次secure-handle raw index读取接入repository import，证明raw index、`ls-files -s`与HEAD tree三方完全一致，并拒绝raw `FSMN` bitmap状态（`b4ab8cf`）
    - [ ] 以Unix进程组/Windows Job或等价机制闭合恶意Git后代持pipe、hostile same-UID TOCTOU及完整process-tree资源边界
  - [ ] 完成跨进程publication ambiguity恢复
    - [x] 冻结并独立复审generic marker v2、candidate seal v1、existing-only no-create reconcile、initial held-lock与reserved marker mutation barrier契约（`3fd797e`）
    - [x] 冻结reconcile终态、dry-run观察态、输出确认与reserved namespace分类，三轮独立复审GO（`3a7c622`）
    - [x] 实现Linux/Windows单一主scheme的目录/文件publication identity投影，禁止现代/legacy回退或重标（`f14e7ff`）
    - [x] 实现强类型角色的canonical marker v2 codec、bounded reader、digest与portable child-name校验（`3fd7434`）
    - [x] 实现existing-only、no-create/no-recovery、nonblocking held mutation lock与整根rename后revalidation（`339b554`）
    - [ ] 实现candidate seal、reserved marker classifier/barrier、claim创建/发布/reconcile生产状态机；真实SIGKILL后同命令只对账并删除exact held marker，绝不在final补建Git或触碰foreign destination
      - [x] 普通mutation在锁前/锁后识别完整reserved marker namespace，canonical v2路由reconcile，其余冲突路由manual audit；daemon/VS Code保留专用错误码（`bf15316`）
      - [x] 实现私有repository-candidate-seal-v1九段流式encoder、冻结golden digest与typed identity/role边界；exact inventory仍由collector证明（`5aae576`）
      - [x] 实现marker-free target-only物理collector，形成section 1/9的完整typed evidence并供后续live/fresh语义层复用（`239f9f2`）
      - [x] 为target增加独立68 MiB/100,003项raw SHA-1 index profile，并把同一次secure held读取的语义、identity、size与SHA-256绑定到较晚完整`.git` inventory（`e5744ce`）
      - [ ] 实现marker-free live sections 2–8：以raw index、独立canonical tree和逐对象streaming proof取代64 MiB `ls-files`/`ls-tree`/object-list大输出依赖
        - [x] 从target构造/只读audit移除`ls-files`、`ls-tree`与`--batch-all-objects`，改为raw index直连、canonical tree/commit和exact loose-object inventory下的16 KiB逐对象双哈希证明（`80af987`）
        - [x] 让target raw-index直接对section-1借用路径验证v2/v3/v4与IEOT，只保留OID摘要；legacy canonical tree逐棵计算OID/大小/SHA-256后立即释放body（`604624e`）
        - [x] 为section-1提供稳定record ID与无第二份owned path的exact streaming revalidation；首版NO-GO后改为held-file ADS、borrowed parent/child匹配与仅root持完整路径，修复复审GO（`75f754e`）
        - [x] 重构初始section-1采集本身，消除`Vec<NamespaceSeal>`、`BTreeSet<CaseFoldKey>`与最终records同时拥有路径字节的峰值，并以唯一路径清单上的借用比较完成portable collision验证（`3aa0a0c`、`865937d`）
        - [ ] 实现不依赖`TargetRepository`的fresh assembler，并以借用路径、raw-index visitor和逐棵tree摘要后释放闭合全进程同时不超过256 MiB canonical-path bytes及不缓存全部tree body的硬边界
          - [x] 以同一physical manifest的opaque ID证据实现sections 2/4/5：held blob双哈希、borrowed raw-index、canonical metadata与逐棵tree流式摘要（`f003c64`）
          - [x] 以同一physical manifest的opaque ID证据实现sections 3/6/7/8纯图：canonical root commit、exact object union与loose/control inventory、streaming object verifier（`21d0cee`）
          - [ ] 将held `.git/index`、canonical config、authenticated `vault.json`、16 KiB object batch与同一physical IDs交叉绑定，并形成可直接输入candidate seal的统一aggregate
            - [x] 生产tracked collector只从同一held root读取固定`.git/index`，snapshot永久绑定同一physical manifest，并以completed runtime object proof限制aggregate投影（`52d7500`）
            - [x] 以isolated stdin-only Git parser绑定held `.git/config`，并把held `vault.json`摘要绑定authenticated `Vault::config_etag()`与content profile（`fb58808`）
            - [ ] 在existing-only mutation lock窗口内部重新构造全部runtime/auth/content证据、最终whole-tree exact revalidation，并保持同一fresh-audited Vault生产接线
              - [x] 返回不可Clone/Copy且继续持锁的owned `InitialCandidateAuthority`；构造器内部创建全部proof且不接受锁外预制proof（`3205a49`）
              - [x] CLI以不可Clone的`IndependentlyAuditedVault`延长fresh unlock+逐envelope/source审计owner生命周期，并按值接管/尽早清零password；仍在旧v1 seam前显式消费，未错误串联v2（`88e2837`）
              - [x] core以不可Clone/Copy的`HeldPublicationMarkerV2`消费同一existing-only lock与held root，descriptor-relative create/open canonical v2 marker并持有root/local/file authority（`347b4cd`）
              - [x] 以v2 consuming publisher整体替换旧v1 publisher，复用同一held lock且禁止串联两套marker/lock（`b34691c`）
      - [ ] 实现held-marker owner、完整live/fresh九段collector、v2 claim创建/发布/reconcile状态机与终态输出
        - [x] held-marker core owner、existing opener、canonical双读、held directory sync与rename revalidation（`347b4cd`）
        - [ ] marker-aware physical/live collector只排除exact held marker identity，并重新形成完整九段candidate evidence
          - [x] 形成lifetime-bound marker-aware physical projection：只排除descriptor-open identity匹配的exact v2 marker，marker不进入section 1/9及record/path预算，并保留同brand最终exact复验（`5d9e686`）
          - [ ] 从target-only held main ref、canonical config、Git control shape preflight与bounded canonical commit读取自举fresh root-commit evidence
            - [x] descriptor-relative读取exact `refs/heads/main`，只接受40位lowercase SHA-1与单LF，并永久绑定同一physical brand（`01effef`）
            - [x] 将Git control唯一allowlist拆为fixed-size shape preflight，在任何repository-aware Git读取前拒绝pack/alternates/额外refs/hooks/control（`7b4da74`）
            - [x] 抽出不接受Vault/password的target-only canonical config evidence，initial authority复用同一实现且合法marker由外层held wrapper封口（`8bd6d31`）
            - [x] 固定root-identity guard与`cat-file commit <oid>`的512-byte bounded reader，验证canonical parentless commit的typed OID等于held main ref（`4b8477d`）
          - [x] 基于同一marker-aware physical brand重建sections 2–8、runtime object proof与candidate aggregate，并与marker claim seal逐项对账（`aea7d6b`）
        - [ ] publication-specific exact unlink outcome与Initial/Fresh consuming typestate
          - [x] core以consuming outcome区分old-present、exact-absent+held-parent-synced、exact-absent+unsynced、replacement与indeterminate；所有分支保留原marker fd及同一lock，post owner禁止重建/二次unlink（`afc9132`）
          - [x] core在marker create-new前及held staging claim期间以common-parent descriptor观察destination absent；链接类与不确定状态一律fail closed，且明确absence不构成名称预留（`4f9b074`）
          - [x] Initial authority按值创建v2 marker、释放旧大manifest后执行marker-aware fresh复审，并逐项对账context/seal/root OID及四类计数；所有post-marker失败保留同一owner/lock（`88eab2f`）
          - [x] Fresh existing-only opener进入同一PublishedWithMarker后半状态链
            - [x] core借用式published-role gate只接受destination角色、descriptor-relative staging缺失及最终完整authority重验，不把有界观察冒充reservation/durability（`597301c`）
            - [x] core fused existing-only opener从同一descriptor链捕获root/local/zero-byte lock、nonblocking持锁并打开exact canonical v2 marker；零create/recovery且不接受caller identities（`2e84b4f`）
            - [x] inex-git验证repository domain/staging grammar/destination policy，执行fresh九段审计并返回marker/lock最后析构的PublishedWithMarker owner（`3a8661c`）
          - [x] core以单一borrowed原语按held root fd→held common-parent fd建立durability barrier，三轮published-role gate包夹且不信任pathname sync（`0e89e32`）
          - [x] Initial经critical fresh复审与verified no-replace整根move汇入同一PublishedWithMarker；只有exact NotMoved复审后可重试（`5060856`）
          - [x] PublishedWithMarker经held durability+fresh复审进入PublicationDurableWithMarker，只有durable owner可消费exact unlink（`984e52b`）
          - [x] marker unlink后的sync retry与marker-free clean audit形成PublishedClean/terminal输出，并整体替换旧v1 publisher（`b34691c`）
            - [x] 只有PublicationDurableWithMarker可消费exact unlink；五态结果及parent-sync四态映射为pending/retry/terminal且不返回裸core authority（`c3dd202`）
            - [x] 以Synced post-unlink held-root authority执行marker-free clean九段audit并形成PublishedClean或可重试/terminal owner（`0b366e1`）
        - [x] 将fresh existing-only exact-v2入口接入CLI早期路由与独立`repository-reconcile`终态输出；不得先重做source Git plan、提示口令或运行KDF（`d9dc345`）
  - [ ] 完成repository import构造/durability/publication每一边界的Linux force-kill、hostile same-UID source/target race、artifact-bound residue与原生Windows矩阵
- **Status:** in_progress（用户实测驱动的迁移/附件扩展；原Markdown-only实现仍保持已验证基线）

### Phase 7: 跨平台验证、打包与发布准备

- [ ] 跑通格式、性质、RPC、编辑器、Git、Unicode/长路径/换行的验证矩阵
- [x] 闭合 init plan 的 creation-time Argon2id 校准：v1 固定 64 MiB/parallelism 1，有界选择 ops 以目标 250–750 ms；显式 fixture 参数不漂移，RPC creation cap 与 password rewrap 不降级
- [ ] 在所有原生发布目标复验 Argon2id 计时/资源行为；每个平台固定保留三次 fresh-process observation，不重试或挑选结果，并按 `target-window`、`minimum-above-window`、`interior-above-window`、`maximum-above-window`、`maximum-below-window` 五类 outcome 精确记录 selector 返回值；不得把单次测量窗口表述为端到端 SLA，也不得由 fallback 推断未测 ops 不可能进入窗口
  - [x] 提供无参数、CLI-only 的 `inex kdf-calibration-info`，从 production `OnceLock` 投影选中参数、决策观测、测量数与 outcome；确定性测试覆盖窗口边界、五类 outcome（含四类 fallback）、噪声/未测候选，真实进程测试证明不解析 password/query 且不写持久 product state
  - [x] 实现 Linux 原生 package evidence harness 与 CI 路径：严格四文件 snapshot/audit、CLI/daemon digest 和两次 runtime-info probe、三次无重试 fresh calibration attempt、外部资源观测、零普通文件残留与 canonical JSON；Windows 在 suspended-before-Job、Job-empty barrier 与 NTFS ADS 闭合前 fail closed
  - [ ] 从严格审计的最终 package 在 Linux x64、Linux arm64、Windows x64 MSVC、Windows arm64 MSVC 原生宿主各采集三次外部 canonical evidence；Wine、交叉编译与仿真不计入原生门禁
    - [x] Linux x64：clean `eeca0bc` A/B artifact 逐字节一致；外部 0600 report 固定三次 fresh-process `target-window`，均选择 ops 16/64 MiB/parallelism 1，canonical validator 通过
    - [ ] Linux arm64 原生宿主
    - [ ] Windows x64 MSVC 原生宿主；先闭合 suspended-before-Job、Job-empty barrier 与 NTFS ADS
    - [ ] Windows arm64 MSVC 原生宿主；先闭合 suspended-before-Job、Job-empty barrier 与 NTFS ADS
- [x] 闭合 binding Git rename/modify 源码契约：detected 形态、split 两侧 rename、精确 tree provenance、v2/v3 journal 与恢复负测均通过
- [ ] 在原生支持平台复验 Git rename/power-loss，并在 GA 前保留“禁止并行 Git porcelain”边界或实现真正的 index CAS
  - [x] 实现 alternate-index candidate、Inex 自持真实 `.git/index.lock`、old/candidate digest 绑定与 create-only journal v4
  - [x] 用真实临时 Git 仓库覆盖 foreign lock、并行 porcelain、marker/candidate/published crash states 与 SHA-1/SHA-256
  - [x] 用真实 Linux 子 test + OS force-kill 覆盖 core atomic verified-stage/lock/replace/post-commit 四个边界，只接受完整 old/new ciphertext
  - [x] 修复并复审 Git v4 candidate 创建前的 durable pre-lock intent：orphan staging、foreign ownership、Windows exact-name 与 link/reparse 全部 fail closed
  - [x] 闭合 candidate/initial/final ownership receipt 之间的强杀自动恢复源码路径；不可归属的未发布 scratch 仍保留供人工审计
    - [x] 设计并实现 v5 immutable candidate bundle：只在未发布 scratch 完成 Git mutation、final digest 与完整 payload，再以 verified no-replace directory move 一次性发布；partial scratch 保留但不阻塞，active namespace 不再暴露多文件 receipt gap
      - [x] 抽取跨平台 verified no-replace directory move，并冻结 audit-path/public API；Linux 与 Windows GNU/Wine 定向门禁通过
      - [x] 定义 strict canonical v5 manifest、exact two-file inventory、stable/scratch namespace 与 `RecoveryStatus`；明确 inventory 验证不替代真实 Git stage-map/expected-old/transaction 语义验证
      - [x] 将 immutable stable bundle 接入 v5 marker/journal/index recovery 源码路径
        - [x] 在 scratch 完成 alternate-index mutation、完整语义验证并一次性发布 immutable stable bundle
        - [x] 冻结 manifest transaction reference、canonical `INEXIDX5` marker、strict stable journal 与 fresh-process Git 语义 loader；v1-v4 读取/恢复兼容保持不变
        - [x] 从 immutable bundle 生成 token-derived publish staging，并支持 fresh-process 重新形成 held bundle/publish proofs；partial scratch 保留不阻塞，foreign/link/rebind/live drift fail closed
        - [x] 严格只读分类真实 `.git/index.lock` 的 absent/exact marker/exact candidate/foreign 状态；candidate 枚举不替代 stage-map/live-old/worktree授权
        - [x] 获取真实 `.git/index.lock` v5 marker：随机 retained scratch、verified no-replace move、双 parent durability、fresh reclassification 与所有失败态保留
        - [x] 发布 v5 durable journal：fresh held marker、三 payload 双授权、随机 retained scratch、no-replace/reconciliation、双目录 durability 与四态 fresh recovery
        - [x] 完成 post-journal worktree/index 前滚、ExactFinal/LaterUnrelated 分类与 live-index identity 绑定；SHA-1/SHA-256 三 payload、故障注入、native/Windows GNU 门禁及双路独立复审通过
        - [x] 完成 bundle retire/cleanup receipt 七态状态机：held proof、relocated classifier、逐边durability/identity协调、SHA-1/SHA-256三payload与双路独立复审均通过
        - [x] 完成 production writer 接线：三payload真实入口统一走single-guard v5 disk-classified driver，旧v4手工tail结构性移除，private composite hooks与双路复审通过
  - [ ] 完成端到端 OS force-kill recovery 原生证据；Linux/Windows 分别绑定，强杀证据不冒充 power-loss
    - [x] Linux native：SHA-1/SHA-256 × InPlace/DetectedRename/SplitRename 六分片精确230-case真实强杀矩阵通过
    - [ ] Windows native：
      - [x] 在 core Windows 平台层枚举并 fail-closed 拒绝全部 v5 transaction owner 的 NTFS ADS，接入 initial/held/critical move/delete 重验证
        - [x] 实现handle-bound `FileStreamInfo` core原语、严格bounded parser、Linux/unsupported语义、Windows native测试源码与Windows GNU/Wine结构门禁，并经独立复审确认无代码阻断项
        - [x] 接入v5 full/manifest-only/empty bundle、journal/receipt与每个move/delete临界重验证
          - [x] full/manifest-only/empty inventory、stable inventory连续持有及journal/receipt held proof已接线，Linux v5回归与Windows GNU静态门禁通过
          - [x] 补齐publish staging、marker/candidate `index.lock`与completed live index的held ADS proof，避免named stream随move/replace传播或被静默删除
          - [x] 补齐stable→cleanup、worktree split边界、真实journal→receipt、ReceiptOnly及transient/index owner的Windows-only对抗测试
      - [ ] 在原生NTFS/ReFS执行file/directory与v5七态ADS对抗矩阵；Wine unsupported fail-closed不替代该门禁
      - [ ] 绑定 Job Object suspended-before-assignment、active-process-zero 与句柄释放证据
        - [x] 实现 Rust force-kill `ChildGuard` Windows Job Object 源码路径并通过 Windows 静态/编译门禁及独立安全复审
        - [ ] 在原生 Windows 运行 Job 进程树、归零与句柄释放对抗测试
      - [ ] 在原生 NTFS/ReFS 宿主运行同一 230-case 矩阵
  - [ ] 原生 Windows NTFS/ReFS 复验 replace/write-through/power-loss，并由绑定证据决定是否取消 no-parallel-Git 边界
- [x] 配置 Linux/Windows x64/arm64 CI、Rust 二进制、VSIX 与 Sublime 包产物
- [ ] 获取两次 hosted CI 失败的权威 job/step 日志，修复真实根因并完成绿色重跑
  - [x] 绑定最新run `29233324592`/source `b9ad906`的全部job、step与日志，归并为4个独立根因
  - [x] 修复v5合法no-ancestor add/add身份验证回归，并让CLI测试区分预期unresolved与operational error
  - [x] 将Sublime 61项Python 3.8产品测试与23项Python 3.13.14 Build4200 runner测试分层；Windows固定可用的3.8.10 x64
  - [x] 将libsodium MSVC输入从mutable stable URL迁到版本化1.0.22 release资产，并补齐locked crate source pair，保留四文件SHA-256与双minisign验证
  - [ ] 推送修复checkpoint并取得当前提交的全绿hosted CI结果
- [ ] 在最终候选上执行 package workflow 四目标矩阵并保留绑定产物/证据
- [x] 完成 threat model、用户指南、安全配置、迁移/升级与故障恢复文档
- [ ] 审计磁盘明文残留、日志秘密、依赖许可与发布清单
  - [x] 将 target-bound Cargo graph、固定四 workspace member、精确许可策略/checksum、许可文本摘要与 libsodium 声明绑定到严格 `THIRD_PARTY_LICENSES.json`
  - [x] 严格验证三包共享 inventory/sidecar，并为 package/lifecycle evidence 定义 canonical report v1 与动态秘密自扫描
  - [x] 从 clean `40ff728` checkpoint 重建 Linux x64 三包，复验 audit/smoke/lifecycle 并另做 RPC/CLI/Git 负路径秘密 drill；该历史包不含后续 core/Git 变更
  - [x] Sublime Build 4200 residue runner 改用真实 masked zenity，口令仅从 stdin 注入并纳入全根动态扫描；正常与 plugin-host kill 两路均零磁盘命中
  - [x] 将 Sublime Build 4200 runner 从 source/debug smoke 升级为 strict packaged baseline：私有四文件 snapshot/seal、包内 CLI/daemon、原样 package tree、normal/crash 两路与外部 canonical evidence；该增量不得被表述为完整 persistent-profile matrix
    - [x] 经独立 mutation 复核补齐 canonical Rust/Sublime manifest、完整 installed inventory、`SHA256SUMS` 与 crash fingerprint 交叉绑定，并从 clean successor harness 重跑两路证据
  - [x] 在同一已安装隔离 Build 4200 profile/package 上完成 full-application SIGKILL/restart schema v4：subreaper/pidfd closure、零 root-bound process/mount、解锁前两秒全 view 扫描、同一密文重开与零 residue 均通过
  - [ ] 继续覆盖 keyboard/menu Save/Save As/Save All、export/clipboard/macro、draft matching/stale/corrupt、project/non-project、其他 application/idle/daemon kill、CRUD 负路径与真实用户 persistent profile
  - [ ] VS Code persistent-profile UI 自动化仍缺可靠可观测 driver；已撤销无法触发 extension activation 的 X11 原型，不以坐标猜测形成证据
  - [ ] 在所有原生目标重复许可/残留证据并完成独立法务、签名与发布渠道审查
- [x] 在 clean `40ff728` checkpoint 上用 system GCC 完成两次逐字节一致的 Linux x64 package/audit/native-dependency/VSIX-install smoke
- [x] 从独立 standalone clean clone 对 `40ff728` 历史 artifact 完成 import/password/Git-bundle/tree-copy restore/frozen-v1/residue lifecycle drill
- [x] 从包含通用非自指包内文档的最终 source checkpoint 重建三包并重跑 strict audit/native smoke/lifecycle；当前 Linux x64 artifacts 绑定 `5aa0b8c`，`fd543f4` 只保留为前一工程证据
- [x] 将最终 commit/hash/lifecycle 只写入不参与 package input 的外部 evidence 与 planning successor；artifact source 保持 `5aa0b8c`，不 relabel 为后续证据提交
- [x] 从 clean `eeca0bc` 以 Node 22.23.1/Rust 1.97.0/system GCC 完成两次逐字节一致的 Linux x64 package/audit/native-dependency/exact VS Code 1.125.0 smoke，并采集三次原生 KDF external evidence
- [x] 从第三个 standalone clean `eeca0bc` harness clone 对同一最终 artifact 重跑完整 lifecycle；旧 `5aa0b8c` lifecycle 不继承到新 CLI/package checkpoint
- [x] 从 standalone clean `bd2b58e` 以 Node 22.23.1/Rust 1.97.0/system GCC 构建当前 Linux x64 pre-alpha engineering demo；23/23 VS Code 测试、strict package/audit/native-dependency、SHA256SUMS、冻结 VS Code 1.125.0 smoke 与本机 1.128.0 隔离安装均通过。该单次构建不替代 A/B reproducibility、完整 lifecycle、签名或发布批准
- [x] 从 standalone clean `7fb83ec` 以Node 26.3.1、Rust 1.97.0、`/usr/bin/gcc` 13.3.0重建含repository-import与双binary VSIX的Linux x64 engineering demo；strict三包audit、shared CLI/sidecar、native dependency、SHA256SUMS与VS Code 1.128.0隔离安装/打包CLI+daemon smoke通过。该单次构建不替代Node 22 A/B reproducibility、真实打包VSIX UI/persistent-profile lifecycle、签名或发布批准
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
| v1 Argon2id 校准固定 64 MiB、parallelism 1，只在 ops 3–20 内选择 | parallelism 1 位于 init plan 建议的 1–4 范围；250–750 ms 被落实为固定公开 dummy 输入的一次 monotonic-clock 决策观测首选窗口，而不是 unlock/init/import/RPC/password 操作或完整命令的 SLA |
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
| 现有仓库迁移使用 `import-repository` 当前 tracked snapshot，而非复制/连接原 `.git` | 目标必须是全新密文 object database 和单个无 parent 的 initial commit；源仓库的明文历史、refs、remotes、objects 与备份仍由用户独立保管，完整历史重写另列 experimental |
| Opaque asset 注册 vault/EDRY required feature `1` 与 plaintext kind `2` | 附件必须与 Markdown 共享认证路径和碰撞域，却不能放宽 Markdown 的 16 MiB/UTF-8语义；未知旧客户端在 KDF 前拒绝 feature-1 vault，避免静默遗漏 |
| 附件 v1 使用 whole-file AEAD，单文件 64 MiB、总导入 4 GiB | 可覆盖真实25 MiB图片并保持完整认证后才返回明文；streaming/random access需要新的required feature，不能在v1暗中改变格式 |
| Repository import 只接受 Git 2.36+、SHA-1、clean HEAD、stage-zero `100644` tracked files | 以双轮HEAD/index/raw blob/worktree证明和完整no-follow `.git`控制树审计形成只读边界；symlink/submodule/split/sparse/LFS/filter/dirty/untracked均fail closed |
| Repository import 使用“单一 sibling staging root → 一次整根发布”，明确 supersede 旧 `intent → candidate-ready → cleanup-ready → complete` 双发布恢复记录 | vault、附件、`.git`、根提交、独立解锁/全树/对象审计与durability均在最终路径不可见时完成；发布前final必然absent，发布后final必然已含完整Git，因此无需repository专用journal、owner、外部Git staging或finalize命令 |

## Errors Encountered

| Error | Attempt | Resolution |
|-------|---------|------------|
| VS Code首次`pnpm check`发现`Uri.isUri`不存在、command参数仍为`unknown`，且`exactOptionalPropertyTypes`拒绝显式`defaultUri: undefined` | 1 | 使用真实`Uri`实例守卫，并仅在默认工作区存在时展开`defaultUri`；随后TypeScript与Node测试通过 |
| release artifact测试在production依赖图新增`unicode-normalization`后仍冻结77组件/147份license text，连续暴露78与149两个新精确值 | 2 | 只同步锁图绑定断言为78/149并提交`d784009`；完整release artifact测试30/30通过 |
| 独立复审发现Task在`executeTask`返回后才订阅结束事件、同步启动异常会泄漏订阅，且existing-target按一次`lstat`跳过password-env gate存在模式切换竞态 | 2 | 抽出start前订阅process-start/process-end/task-end的可单测状态机，所有终态析构订阅；恢复无条件拒绝`INEX_PASSWORD_STDIN`并在existing路径明确“出现口令即取消” |
| CLI path-first接线后两次production源码契约测试因函数切片边界与临时test wrapper误截断而失败 | 2 | 删除test-only wrapper，让fixture直接走真实`dispatch`；分别以`execute_reconcile`/`build_staging_vault`固定函数边界，产品断言保持不变 |
| strict Clippy发现large enum、冻结表长度、boxed fixture类型及Windows非Linux常量dead-code | 4 | 只box大型linear owner/plan，对纯冻结表使用窄理由，fixture显式解box并cfg Linux资源常量；Linux与Windows GNU/MSVC门禁复绿 |
| 独立审查发现canonicalize身份换绑、预存bind alias及non-v2同分类目录替换 | 3 | 增加前后identity采样、held directory-only source identity walk与终态parent/root/namespace复验；真实canary测试证明零mutation，hostile same-UID ABA仍保留为GA门禁 |
| `create_goal` 拒绝新的迁移objective，因为线程已有paused但unfinished的长期Goal | 5 | 不伪造complete/blocked；把可执行细化Goal写入根`task_plan.md`并继续Git开发，待产品侧恢复/替换后端Goal |
| 完整core回归中的既有OS-lock竞争测试偶发得到一条成功和一条pre-lock fail-closed错误，而非预期Conflict | 2 | 在竞争前先建立并释放稳定lock namespace，让测试只测同一既有lock上的串行语义；精确50轮及完整254/254通过（`70fc0b2`） |
| raw index parser首版拒绝“有IEOT但无EOIE”的真实Git 2.43 index | 1 | 以真实Git生成的v4 index和Git格式契约确认IEOT可独立存在；放宽该组合但保持唯一extension、分区与block独立解码校验，定向测试和Windows GNU检查通过 |
| `cat-file --batch`初版在错误清理路径调用无界`Child::wait` | 1 | 改为固定2秒`try_wait`轮询并绑定reaped/finished状态；直接子进程路径闭合，恶意后代继承pipe仍保留为GA进程组/Windows Job门禁 |
| 独立对象审计后的完整`inex-git`套件一次触发既有v5 recovery时序性`RecoveryConflict` | 1 | 精确隔离复跑该test 1/1通过；不把该次完整套件写成全绿，也未把它归因于repository import，后续整套继续观察 |
| raw parser与首版publication规范把`FSMN`当作可忽略optional extension，但`CE_FSMONITOR_VALID`实际来自其EWAH bitmap且会被强制`core.fsmonitor=false`的Git探针隐藏 | 1 | 从raw allowlist彻底移除`FSMN`，增加unit与重签plan-level拒绝/诊断scrub回归，并同步source profile、seal与acceptance；独立复审GO |
| publication v2初版未要求initial publisher在move到marker清理窗口持续持有既有`mutation.lock` | 1 | 在marker-free baseline后以no-create/no-recovery API获取同一lock，跨seal/move/sync/unlink/clean audit/result持续持有；普通mutation阻断全部reserved marker prefix，最终复审GO |
| exact index-byte mutation回归首次只接受`SourceChanged`，而完整重新规划先在坏checksum处返回更严格的`UnsafeSourceControl` | 1 | 保留fail-closed产品行为；测试区分revalidate的结构不可信与read_entry的既有binding漂移，并证明恢复exact bytes后重新通过 |
| Opaque asset 收口后的 workspace rustfmt check 发现 daemon 测试中一个多行 `assert_eq!` 仅有规范格式漂移 | 1 | 运行 canonical `cargo fmt --all`，随后 workspace pedantic Clippy 与 warnings-as-errors rustdoc 全部通过 |
| Repository-import 规范的一次组合patch因上下文已变化而整体拒绝 | 1 | 确认无部分写入，按source config、journal、output和acceptance matrix拆成精确小patch并逐次`git diff --check` |
| Repository-import 命令段与Git runner的组合patch因现有换行上下文不完全匹配而拒绝 | 1 | 确认无部分写入，读取精确行后以同一语义的窄上下文patch成功替换 |
| 一次双引号`rg`模式中的反引号被shell当作命令替换并打印`HEAD`用法 | 1 | 只读且未改状态；后续含反引号模式固定使用单引号，并按精确文件范围复查结果 |
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
| KDF diagnostic real-process regression passed but pedantic Clippy rejected its 143-line test function | 1 | Split static schema and dynamic outcome validation into focused helpers, keep every assertion, and rerun the CLI/core Clippy and process gates |
| Initial cross-platform KDF harness could emit a Windows PASS despite pre-Job process execution and NTFS ADS being absent from ordinary tree snapshots | 1 | Fail closed before artifact use in Windows run/main/report validation, restrict CI evidence to Linux, and keep the two Windows native rows explicitly open until suspended Job, Job-empty, ADS enumeration, and native tests exist |
| Independent KDF harness probe modified an extracted executable after its initial hash while the report still bound the old digest | 1 | Seal both executables and all four artifact snapshot files by physical identity, metadata, and SHA-256; remove POSIX write bits and revalidate before/after every probe/attempt and before report creation |
| First full-restart v3 review found argv-only survivor detection could miss a `setsid` descendant and mis-signal an unrelated process | 1 | Replace it with confirmed subreaper adoption, stable session/descendant closure, pidfd-only signals, exact env/cwd/root/fd/exe census, and a schema-v4 report that rejects the predecessor v3 |
| First portal-safe exact restart attempt failed closed on an unverified root-bound process and left a dead `fuse.portal` mount that made `rmtree` return `ENOTCONN` | 1 | Preserve and inspect the failure root; disable portals in the fixed child environment/private D-Bus config, add bounded mountinfo gates, allow only exact dead-portal non-lazy failure cleanup, remove the proven root, then rerun all three scenarios from a clean harness |
| Git v5 preflight found a Windows canonical-vs-caller audit-path mismatch, a crate-private primitive, and a case-only wrong-case fixture that did not create a distinct stored name | 1 each | Freeze the callback on the caller path while retaining internal canonical identity checks, expose a constrained documented API, create the wrong-case member directly, and require Windows GNU/Wine targeted gates before integration |
| Combined current-checkpoint planning patch targeted an earlier progress tail and failed context verification | 1 | No partial planning write occurred; split task-plan edits from append-only progress/findings sections and anchor each patch to the actual current tail |
| First split findings append omitted the literal space in `power-loss 证据` and failed exact context matching | 1 | No partial findings write occurred; copy the exact current tail before the append-only patch and rerun `git diff --check` |
| Isolated v5 reference/marker loader passed 19 tests but non-test Clippy rejected 20 intentionally unwired items as dead code | 1 | Keep the codec slice real: return the reference and marker seals from production bundle preparation, remove premature cleanup/path helpers, and narrowly annotate only parser/loader entry points until the immediately following writer/recovery slice consumes them |
| Cleanup-helper removal patch missed rustfmt's single-line test bindings | 1 | No partial test edit occurred; inspect the exact formatted block, remove only the premature cleanup/path assertions, and retain the token-derived publish basename assertion |
| v5 journal review found locked-safe status accepted matching bundle+journal beside unrelated reserved v4 files | 1 | Require the post-stable reserved namespace to be exactly the stable journal in this schema slice; add foreign marker-staging coexistence regression, then let the later publisher replace this narrow rule with a transaction-specific physical-state inspector |
| A second read-only v5 authorization audit could not be spawned or resumed because the four-agent thread limit was already occupied | 2 | Keep the existing publish/classifier agents running; perform the bounded source audit on the main thread and do not retry until an agent slot is released |
| Cherry-picking the lock classifier after the larger publish-staging commit conflicted in the shared candidate-module import block | 1 | Combine both required imports with `apply_patch`, verify no conflict markers plus fmt/diff checks, then continue the cherry-pick without selecting either side wholesale |
| The first merged lock-boundary Clippy run rejected a 106-line test after adding empty/oversize cases | 1 | Split the new boundaries into a focused test instead of suppressing `too_many_lines`; all five lock tests and pedantic Clippy then passed |
| Windows GNU Clippy saw the Unix-only identity-swap test helper as unused | 1 | Gate the helper itself with `cfg(all(test, unix))`; keep production reading generic and rerun Windows check/clippy/no-run successfully |
| A cleanup patch mistook the shared boundary line printed by two overlapping `sed` ranges for a duplicated source line | 1 | The patch failed before writing; inspect the real file with non-overlapping ranges and make no cleanup change because the source contains only one binding |
| `origin/master` advanced concurrently to `47c6567` with reflog reason `update by push`, although this thread did not authorize or run a push | 1 | Preserve local `ea40261`, ask active agents to confirm, prohibit further pushes, and treat the remote update as external state rather than rewriting or force-updating history |
| A third parallel marker-lock implementation could not be spawned because the four-agent thread limit was occupied by the classifier and authorization audit | 1 | Keep the two higher-priority agents running and design the marker seam locally; retry delegation only after a slot is released rather than interrupting active work |
| The reused marker-lock agent created an independent worktree but relative `apply_patch` paths wrote 361 candidate lines and stale planning copies into the shared main worktree | 1 | Interrupt immediately; restore candidate/planning from committed `91153b9` through `apply_patch`, retain only the main thread's authorization diff, and require absolute worktree paths for every subagent patch |
| First payload-authorization Clippy run found one collapsible condition and four needless borrows introduced by the in-place recovery extraction | 1 | Apply the exact lint suggestions without suppressions; targeted authorization tests and pedantic Clippy then pass |
| Independent payload-authorization review could not start because classifier, marker, and existing review threads occupied the agent limit | 2 | Commit the fully green seam as an isolated reversible checkpoint; request an independent review as soon as either implementation agent finishes, before wiring journal publication |
| The first post-cherry-pick marker test command used a nonexistent `v5_index_lock_marker` filter and therefore ran zero tests | 1 | Rerun with the exact `v5_marker_lock` filter; all 7 marker tests passed, then run the unfiltered 128-test suite and native/Windows GNU gates |
| The first durable-journal targeted run blocked because fault tests held a mutation guard and then called a helper that reacquired the same non-reentrant lock | 1 | Stop only the independent-worktree test process; drop the held guard before every fresh-process inspector/recovery call or reuse the existing guard for same-process classification, then rerun sequentially |
| Durable-journal Clippy first rejected two test fixture destructures whose underscore-prefixed bindings were subsequently used | 1 | Rename the bindings to normal identifiers instead of suppressing the lint; rerun targeted tests and pedantic Clippy |
| A later durable-journal Clippy pass rejected the intentionally exhaustive fresh-entry test as too many lines | 1 | Add a narrow reasoned allow on that single test after confirming its payload/object-format/state matrix is one audit unit; rerun pedantic Clippy with warnings denied |
| The first post-journal inactive-ref matrix returned `IndexChanged` for detected rename after removing `MERGE_HEAD` | 1 | Remove active-ref checks from the post-journal old-index seam while retaining recorded commit/tree authentication and the pre-journal authorization checks; rerun SHA-1/SHA-256 worktree-prefix matrix |
| The later-unrelated alias test tried to inject uppercase `.ENC` through the product API, which correctly rejected the noncanonical path before the recovery classifier ran | 1 | Use raw Git `update-index` only in the adversarial fixture so the test can materialize the repository state that the product API is designed to prevent; rerun both object formats |
| First post-journal pedantic Clippy run rejected oversized publish helper signatures/functions and unused fault-hook/test seams | 1 | Keep the fault seam, group immutable call context or split focused audit/reconciliation helpers, then consume every hook/action in the moved/not-moved/foreign/critical-drift matrix before rerunning Clippy with warnings denied |
| A parallel audit compiled the mutable post-journal diff while three new fault actions had been added but not yet covered by two expected-state matches, producing E0004 | 1 | Treat the result only as an intermediate-edit failure, finish both exhaustive matches, and stop launching duplicate gates until the implementation agent declares a fixed snapshot |
| The first owner-error mapping command used a short test name with `--exact` and ran zero tests | 1 | Rerun with the full `tests::worktree_owner_error_mapping_preserves_only_operational_io` path and require an explicit 1/1 result |
| The expanded marker fault matrix expected an enum after deliberately corrupting the live index, but the product correctly propagated `GitCommandFailed(ReadIndex)` | 1 | Assert the operational error directly, prove replace was never called and marker/publish remain exact, then rerun the entire matrix |
| The first live-index fault matrix repeated the enum expectation after deliberately corrupting the live index | 1 | Assert `GitCommandFailed(ReadIndex)` from both mutation and inspection, prove the candidate remains at `.git/index.lock`, and rerun the full lock-to-live matrix |
| Post-journal targeted behavior passed, then the next pedantic Clippy run found eight structural/test lints: an 8-argument marker seam, by-value error mappers, a 105-line worktree dispatcher, two long fault tests, and identical match arms | 1 | Introduce an authorization context, borrow mapped errors, split per-payload worktree helpers and per-action fault assertions, combine identical arms, and rerun with warnings denied without module-level allowances |
| First full post-journal suite passed 138/141; early journal-without-marker surfaced raw open I/O, while two predecessor tests still expected the old journal-only/unwired states | 1 | Strictly classify the lock before opening a held marker and map absent/foreign to Conflict; update the two tests to the new ExactFinal/final-index/lock-absent semantics while retaining scratch preservation and direct-update hard-stop assertions, then rerun the three tests and full suite |
| Fixed post-journal commit `166c42d` passed 141/141 and Windows gates but final review returned NO-GO (2 blocker/2 major): post-classifier TOCTOU rechecks missing, final rename owner I/O remapped to Conflict, replace reconciliation skipped pre-proof on operational post errors, and in-place stage auth swallowed read-object errors | 1 | Keep the commit unmerged; add fresh post-classifier journal/lock/live identity checks and fault seams, narrow owner/stage/provenance mappings to preserve operational errors, always run pre reconciliation, rerun all native/Windows gates, and require a second fixed-commit review |
| A read-only inspection chained `rg` for a not-yet-added journal-error helper with later diff checks; no match exited 1 and skipped those later reads | 1 | Run worktree status/diff-check as a separate command, and avoid chaining optional searches ahead of required inspections |
| Fixed audit delta `ad9585c` passed 143/143 and one reviewer returned GO, but the second reviewer found a new blocker: post-classifier `candidate_matches=false` could not distinguish the classified LaterUnrelated inode from a subsequently missing or arbitrary foreign inode | 1 | Bind each completed-index classification to a held single-link live file identity, require the post-hook path to match that classified identity plus Exact/Later candidate/old rules, add delete/foreign/lock rebind faults for initial and final classification, then rerun all gates and both fixed-delta reviews |
| A production-writer read-only inspection ended with an optional `rg` for a call site that correctly had no matches, so the combined command exited 1 after the required source ranges had already printed | 1 | Treat the source reads as valid, record that v5 preparation is not yet wired, and run future optional searches separately or append `|| true` instead of using their status as a gate |
| First cleanup-receipt full suite passed 138/146; eight predecessor tests still expected the intentional pre-cleanup `recover_pending -> RecoveryConflict` hard-stop after the new state machine correctly reached Clean | 1 | Keep focused post-journal tests on `recover_bundle_v5_pending`, change true end-to-end cases to require `Ok(true)` plus exact Clean/no-namespace state, then rerun the complete suite before treating cleanup behavior as green |
| Cleanup branch reached 146/146, but independent mutable-diff audit found 4 blockers: CleanupFullJ skipped final payload re-authorization, intermediate moved-but-unsynced edges could continue on the next run, journal-move error reconciliation accepted a bytes-equal foreign receipt without original inode proof, and non-target journal/receipt capabilities were not post-bound across every edge | 1 | Reopen implementation status; require final-state authentication before stable retirement, persist or re-establish each edge durability, bind moved target and retained capability identities across every operation, preserve operational I/O, then rerun fault/static/Windows gates and fixed-commit dual review |
| Cleanup pedantic Clippy first found 5 structural lints (large enum, needless ownership, two production/test length units), then the audit repair found 3 more in owned `map_err` adapters and the durability-fence audit unit | 2 | Box the large proof variant, borrow where semantics allow, retain owned adapters required by `Result::map_err`, and use only narrow function-level reasons for single security decision tables; rerun final pedantic after all authorization/identity/fence changes |
| Fixed cleanup commit `e4ed001` passed 150/150 and native/Windows static gates, but dual exact-commit review returned NO-GO: completed reauth omitted full protected alias stage-map projection, post-operation cleanup directory/member capabilities were not continuously identity-bound, two operational I/O mappings remained collapsed, and six-edge/cross-product faults were incomplete | 1 | Preserve `e4ed001` as immutable evidence; append a fix delta with stable/relocated full completed classifiers, post-edge cleanup capability identity proofs, scrubbed operational I/O, alias/directory-rebind and complete coordinator fault matrices, then rerun every gate and both reviews |
| Main thread attempted to start a duplicate `a0b98ed` review after the implementation agent had already spawned two fixed-delta reviewers, and collaboration rejected it at the four-thread limit | 1 | Do not retry or interrupt; use the already-running `final_commit_review` and `final_delta_audit` agents, then record their exact verdicts |
| Fixed cleanup delta `a0b98ed` passed 154/154 and all native/Windows gates; one reviewer returned GO, but the second returned NO-GO because `ErrorBefore` exited before the physical-operation coordinator and `NotSynced` only rewrote a post-hook value after the real primitive likely synced, creating false six-edge coverage | 1 | Keep the delta unmerged; add private test-only physical-operation and sync-fence seams that produce real error-before/no-effect, error-after/effect, NotSynced and observable/failing fence paths, then require coordinator-state assertions, all gates, and a new dual review |
| First production-writer full suite passed 156/157; existing live-index fault test's MoveThenError case returned `RecoveryConflict` instead of the prior successful reconciliation, and an exact rerun reproduced it | 1 | Treat as a real composite-wrapper regression, compare worktree/checkpoint/critical audit ordering with the pre-wrapper path, repair without weakening the fault expectation, then rerun the exact test and full suite |
| A third force-kill execution-plan audit could not start because the implementation agent had already spawned an inspector and the security audit occupied the fourth thread slot | 1 | Keep the implementation and two higher-priority audits running; derive sharding locally or retry only after a slot releases, without interrupting active work |
| Full force-kill shard execution-plan agent could not start after two exact-review agents occupied the available collaboration capacity | 1 | Keep the higher-priority fixed-delta and full-chain reviews; derive the six direct-test-binary shard commands locally, or retry after one review completes without interrupting it |
| A new isolation-fix agent could not spawn while the exact-chain reviewer still occupied collaboration capacity | 1 | Reuse the completed original implementation thread with a follow-up task once the exact reviewer returns, preserving its worktree context instead of retrying a new spawn |
| Isolation-fix coverage command used a shortened filter that matched zero tests | 1 | Treat zero executed tests as no evidence; rerun with the full module-qualified exact path and require 1/1 before continuing |
| First isolation-fix pedantic Clippy run rejected four test-only setup destructuring lints (`match_same_arms`/`used_underscore_binding`) | 1 | Merge identical enum arms with an or-pattern, avoid using underscore-prefixed bindings, and rerun the complete native and Windows GNU pedantic gates |
| First fixed isolation/canary diff closed parent handle isolation but exact review remained NO-GO because whole-file Git metadata allowlisting let side plaintext evade raw/all-object scans | 1 | Replace short metadata-colliding side bodies with long force-kill-specific plaintext canaries and neutral branch/commit labels, remove every scan exclusion, add a metadata-append mutation regression, then rerun all gates and dual review |
| Canary repair pedantic Clippy rejected the 148-line custom InPlace fixture helper | 1 | Keep the auditable fixture construction contiguous and add one narrowly reasoned test-helper `too_many_lines` allowance; rerun native and Windows GNU all-target pedantic gates |
| Second full-chain force-kill audit remained NO-GO because full-body canaries could miss a leaked prefix, line, or middle fragment | 1 | Scan long unique fragments proven to occur in each real stage/result body and password; make raw and unreachable-object mutation regressions inject only one fragment before rerunning dual review |
| Force-kill process audit found setup-detach had no parent RAII owner and kill failure could enter an unbounded blocking wait | 1 | Install a non-panicking detached-fixture guard immediately after control load, use bounded `try_wait` polling for kill/drop paths, and prohibit recovery while a writer cannot be proven reaped |
| Git-object residue regression only created a reachable commit object | 1 | Create a fragment-only unreachable blob with `git hash-object -w`, remove its input file and all refs, then require `--batch-all-objects` scanning to reject it |
| Demo artifact recheck used the stale basename `inex-cli-0.1.0-linux-x64.zip`, so the chained inspection stopped after confirming the VSIX existed | 1 | Enumerate the release artifact directory first; use the actual paired bundle `inex-rust-0.1.0-linux-x64.zip`, then independently verify VSIX checksum and manifest |
| Packaged VSIX inspection assumed `extension/README.md`, but the audited package intentionally contains no README member | 1 | Read bundled command metadata from `extension/package.json` and usage guidance from the source `docs/user-guide.md`/`editors/vscode/README.md`; do not treat an absent optional README as package corruption |
| Isolated VSIX install emitted VS Code's Node DEP0169 warning for deprecated `url.parse()` | 1 | Record it as host CLI noise: installation and exact extension enumeration still exited 0; do not attribute the host-owned warning to Inex without a stack proving an extension callsite |
| First partial-canary/RAII hardening Clippy pass found a 101-line rename assertion and identical best-effort cleanup match arms | 1 | Extract a small repeated rename-canary assertion helper and collapse the cleanup terminal branches without widening any lint allowance; rerun the full native pedantic gate |
| First fixed hardening snapshot received one GO, but process-security review found mutation regressions could pass on any scanner operational panic | 1 | Move Git enumeration, status validation and file reads outside `catch_unwind`, prove injected fragment is present, and catch only the detector assertion before repeating dual review |
| Fixed hardening review found narrow setup-owner and guard-regression coverage gaps | 1 | Declare parent cleanup ownership before setup spawn and arm it without an unowned parse window; add durable park-ready plus Drop-path evidence and make the RAII regression exercise real unwinding |
| Second hardening Clippy pass found one collapsible nested `if let` in best-effort owner evidence cleanup | 1 | Apply the equivalent let-chain, retain the same bounded cleanup behavior, and rerun the complete native and Windows GNU pedantic gates |
| Post-matrix broad `/tmp` residue search descended into systemd-private directories and emitted expected permission errors | 1 | Restrict residue inspection to same-user top-level `inex-git-recovery-test-*` roots, then check their timestamps and `fixture-owner` descendants without traversing unrelated service sandboxes |
| Repository-import独立终审发现fresh reopen仅比较长度/摘要、Git对象只列inventory且tracked worktree缺末尾统一seal重验 | 1 | fresh unlock后重新descriptor/Git-bound读取每个源文件并逐字节比较；逐个读取commit/blob/tree对象体、blob对worktree精确比较、tree typed rehash，并在每次完整target audit末尾再次复验allowlist、identity、size和SHA-256；定向测试、Clippy及Windows GNU check通过。独立raw-tree序列化与streaming仍保留为GA门禁 |
| 发布后强杀重试审计确认随机16-byte marker与进程内`TargetRepository`无法跨进程重建exact ownership，重跑又先拒绝existing destination | 1 | 不做“看到marker就删”的危险补丁；把generic persistent publication claim/seal、existing-only reconcile guard、held-marker删除和真实SIGKILL矩阵列为独立未完成安全里程碑。当前Linux preview只承诺正常完成路径，terminal要求保留现场且禁止盲重跑 |
| 发布工具与Sublime完整unittest首次分别漏设`PYTHONPATH=scripts`和`PYTHONPATH=editors/sublime`，产生模块导入错误 | 1 each | 将两次错误启动记录为无效证据；使用显式正确模块路径重跑，发布工具86/86和Sublime 84/84全部通过。后续固定命令保留显式`PYTHONPATH` |
| 首次release构建仅设置`CC=/usr/bin/gcc`，Rust最终linker仍从PATH选择xlings并产生非portable interpreter | 1 | Strict packager在artifact形成前拒绝；使用全新target并显式设置`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`，重建后interpreter固定为`/lib64/ld-linux-x86-64.so.2` |
| Main checkout虽然clean但登记多个既有worktree，strict provenance拒绝；standalone根又无package.json且local clone origin不是canonical URL | 1 each | 不删除历史worktree；以`--no-local --single-branch`创建独立clone，分别在VS Code/vsce目录离线frozen install，仅把一次性clone origin改为canonical GitHub URL且不fetch/push。最终clean source、package/audit/smoke通过 |

## Notes

- `.agent/init_plan.md` 是产品与架构的上位约束；若实现细节与其冲突，先记录并选择不削弱安全边界的方案。
- 每完成一个阶段立即更新本文件及 `progress.md`；发现和决策持续写入 `findings.md`。
- 所有破坏性迁移默认禁用；任何 in-place 操作必须显式确认并先完成可验证备份。
- Git 作为开发容错边界：已通过门禁的阶段/垂直增量单独提交；未完成或未验证的并行改动不混入稳定提交，不改写已共享历史。
