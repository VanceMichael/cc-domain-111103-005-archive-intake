# 供应商归档包的安全解封与原子接收

研究组按月接收合作机构交付的公开统计资料包。本项目重做了本地接收流程，
使一包资料**要么以可验证状态发布，要么带着完整证据留在隔离区**，杜绝
“按磁盘顺序覆盖、留下的内容与清单审核结果不一致”的问题。

运行时只依赖 Python 3.12+ 标准库；RSA/SHA-256 验签用标准库原语实现，
不引入第三方加密库。OpenSSL 仅在离线构造测试样例时使用，测试私钥
永远不写入项目。

## 威胁模型与验收不变量

接收流水线（`app/intake.py`）的阶段顺序固定、不可调换：

0. 全局 `flock` 串行化，并把上一轮崩溃残留的暂存区整体移入 `orphaned/`；
1. **只读中央目录**，在资源预算内枚举成员并标注全部结构风险，不展开任何数据；
2. 取出 `manifest.json` / `manifest.sig`，**先验证签发身份与清单签名**；
3. 完整校验清单 schema 与路径归一化；
4. 确认清单条目与归档数据成员**严格双射**（每个条目恰好对应一个成员）；
5. 在全新暂存区逐成员**流式**解压，边读边核对长度与 SHA-256；
6. 全部成功后用 `os.replace` 原子切换发布符号链接。

由此保证：

- 签名先于解包校验，未通过验签的字节永远不会被信任或展开；
- 路径归一化后同名冲突、越出目标目录（`..`、绝对路径、盘符、反斜杠）、
  符号链接 / 特殊文件、目录成员、重复 central-directory 名称、未声明或
  缺失成员，任一命中即整包隔离，现有发布版本原封不动；
- 长度或摘要不匹配会定位到具体成员，并把该成员的实际字节作为证据保留；
- ZIP64、压缩比异常、截断中央目录、成员/总量预算都在展开前或流式过程中
  强制执行，**不会先完整展开再检查**；
- 暂存区按 attempt 新建、绝不复用；进程在任一阶段退出，恢复时旧暂存
  内容只进隔离残骸区，不会与新包拼成一个“已验收”版本；
- 发布通过相对符号链接 `current -> vNNNN` 原子切换，读取端要么看到
  完整旧版，要么看到完整新版；
- 同一包（`package_id` + 清单字节指纹）重复接收幂等；签名有效但内容
  不同（指纹不同）必然形成新版本。

## 目录布局（store root）

```
root/
  .lock                          全包串行接收的 flock
  packages/<package_id>/
    current -> v0003             原子切换的发布符号链接
    v0001/ ... v000N/            不可变已验收版本（含 RECEIPT.json）
    receipts/                    每次成功接收的收据副本
    quarantine/<attempt>/        失败尝试的原始包、问题成员证据与 QUARANTINE.json
  staging/<attempt>/             单次接收的全新暂存区，发布/隔离后即清空
  orphaned/                      崩溃残留暂存区与无法归属包的兜底隔离区
```

## 命令行

启动器 `bin/intake` 可配合 `python3 -I` 运行：`-I` 隔离模式下 cwd 与
`PYTHONPATH` 都不进入模块搜索路径，因此在不可信归档目录内执行也不会
加载其中的同名模块（如植入的 `json.py`）。

```sh
# 只读中央目录做静态检查，不落盘
python3 -I bin/intake inspect <archive.zip>

# 验收并接收（成功退出 0；隔离退出 2；参数/环境错误退出 3/4）
python3 -I bin/intake receive \
  --archive <archive.zip> \
  --store   <store-root> \
  --trust   <trust-root>

# 审计：签名身份、逐文件摘要、隔离原因与当前发布版本
python3 -I bin/intake audit --store <store-root>
python3 -I bin/intake audit --store <store-root> --package-id stats-monthly
```

资源预算可显式覆盖（默认值见 `app/zipstream.py:Budget`）：
`--max-members`、`--max-total-uncompressed`、`--max-total-compressed`、
`--max-member-uncompressed`、`--max-compression-ratio`。

## 信任库与清单签名

信任库按签发方组织，文件名是 SPKI 公钥 DER 的 SHA-256 前 16 位：

```
<trust-root>/<issuer>/<key_id>.pub
```

支持 SPKI（`BEGIN PUBLIC KEY`）与 PKCS#1（`BEGIN RSA PUBLIC KEY`）两种
PEM 封装，算法固定为 RSASSA-PKCS1-v1_5 / SHA-256，模数短于 2048 位拒收。
清单签名是对清单**原始字节**的分离签名（`manifest.sig`），验签在任何
内容校验之前完成，因此后续 schema 校验不可能绕过身份验证。

## 本地样例与测试

样例由 `tools/build_fixtures.py` 生成。测试私钥只能写到项目根之外的
目录，脚本会显式拒绝把私钥写进项目；项目内只保留公钥与公开归档。

```sh
# 一次性生成密钥与样例（私钥目录必须在项目外）
python3 -I -c "import sys; sys.path.insert(0,'.'); \
  from tools.build_fixtures import main; main()" \
  --out fixtures/intake --key-dir /tmp/intake-test-keys

# 运行全部测试（-I 隔离，显式注入项目路径）
python3 -I -c "import sys, unittest; sys.path.insert(0,'.'); \
  s=unittest.TestLoader().discover('tests', top_level_dir='.'); \
  raise SystemExit(0 if unittest.TextTestRunner(verbosity=2).run(s).wasSuccessful() else 1)"

python3 -I -m compileall -q app tests tools bin
```

样例包含两版合法签名包、一次重复交付、一个真实 ZIP64 包（4 GiB+ 成员，
磁盘占用极小），以及符号链接、路径越界、重复路径、重复保留名、未声明/
缺失成员、摘要/长度不符、错误签名、缺签名、截断目录、压缩炸弹等
恶意归档。所有样例均为人工生成的虚构公开统计资料，不代表真实机构数据。

## 运行时与不可信数据的隔离约定

- 下载与解压的归档是不可信数据：每个放进独立新目录，脚本放在 `app/`、
  `tools/`、`bin/` 等独立目录，路径通过参数传入，不从归档目录运行解释器；
- 处理不可信数据的 Python 一律用 `python3 -I`；
- `runtime/` 是本地运行产物（已在 `.gitignore`），不是可随意删除的
  样例目录；fixtures 目标目录也不会被当作临时目录清空。
