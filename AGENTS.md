# 统一用户认证组件指引

## 项目定位

本仓库对应 OpenHarmony `base/useriam/user_auth_framework`，是 `useriam` 子系统下的统一用户认证框架，包含三个模块：**用户认证**、**凭据管理**、**执行器管理**。对外通过 inner_api、NAPI、ANI（ArkTS Native Interface）、CJ（仓颉）FFI、C/NDK 暴露认证与凭据能力，向下通过 HDI 与执行器（口令/人脸/指纹等）和 TA 协同，跨设备经 dsoftbus 远程认证。

优先按这些目录定位问题：

- `services/`：Service Ability 服务端实现，包含 IPC 服务入口、核心调度（认证/录入/识别/删除调度）、上下文池、引擎与 HDI 包装、加载模式、远程连接。
- `frameworks/`：接口层实现，包含 native 客户端、执行器框架、IDL 定义、NAPI/ANI/CJ 绑定。
- `interfaces/inner_api/`：对内暴露的头文件（客户端 API + 执行器框架 API + 公共定义）。
- `common/`：共享日志、工具、计时器、系统参数、xcollie 助手。
- `sa_profile/`、`param/`、`hisysevent.yaml`、`cfi_blocklist.txt`：SA 配置、系统参数、DFX 事件定义、CFE 屏蔽列表。
- `test/`、`test/fuzztest/`：单元测试与 fuzz 目标。

### 按任务类型定位代码

| 任务类型 | 首选目录 | 关键文件 |
| --- | --- | --- |
| 修改用户认证服务入口（auth/authUser/authWidget/identify） | `services/ipc/` | `user_auth_service.h/cpp` |
| 修改凭据管理服务（增删改查、会话） | `services/ipc/` | `user_idm_service.h/cpp` |
| 修改执行器注册/反注册、信使 | `services/ipc/` | `co_auth_service.h/cpp`, `executor_messenger_service.h/cpp` |
| 修改认证调度、调度节点、资源节点池 | `services/core/` | `authentication.h`, `schedule_node.h`, `resource_node_pool.h`, `engine_state_manager.h` |
| 修改凭据录入/识别/删除核心逻辑 | `services/core/` | `enrollment.h`, `identification.h`, `deletion.h`, `credential_info_interface.h` |
| 修改上下文生命周期与各类型 context | `services/context/` | `context.h`, `context_pool.h`, `context_factory.h`, `simple_auth_context.h`, `enroll_context.h`, `widget_context.h`, `remote_auth_context.h` |
| 修改 Widget 认证 UI/参数/JSON 协议 | `services/context/` | `widget_context.h`, `widget_json.h`, `auth_widget_helper.h`, `widget_client.h` |
| 修改远程认证（跨设备） | `services/context/`、`services/core/`、`services/remote_connect/` | `remote_auth_context.h`, `remote_auth_service.h`, `remote_executor_proxy.h`, `remote_connect_manager.h`, `device_manager_util.h` |
| 修改 HDI 引擎包装 | `services/engine/` | `hdi_engine.h`, `hdi_wrapper.h`, `hdi_type_convert.h` |
| 修改服务加载/卸载策略（默认/动态） | `services/load_mode/` | `engine_load_manager.h`, `service_unload_manager.h`, `load_mode_handler.h` |
| 修改线程模型/状态机/事件分发 | `services/base/` | `thread_handler.h`, `finite_state_machine.h`, `iam_event_dispatcher.h`, `subscription.h` |
| 修改 Native 客户端实现 | `frameworks/native/client/` | `user_auth_client_impl.h/cpp`, `user_idm_client_impl.h/cpp`, `co_auth_client_impl.h/cpp`, `ipc_client_utils.h` |
| 修改执行器框架（驱动/执行器/异步命令） | `frameworks/native/executors/` | `driver.h`, `executor.h`, `driver_manager.h`, `framework_executor_callback.h` |
| 修改 IPC IDL 接口定义 | `frameworks/native/ipc/idl/` | `IUserAuth.idl`, `IUserIdm.idl`, `ICoAuth.idl`, `IExecutorMessenger.idl`, `IExecutorCallback.idl`, `UserAuthTypes.idl` 等 |
| 修改 inner_api 公共头/定义/错误码 | `interfaces/inner_api/` | `user_auth_client.h`, `user_idm_client.h`, `co_auth_client.h`, `iam_common_defines.h`（`AuthType`、`PinSubType`、`ResultCode` 枚举） |
| 修改执行器侧 inner_api 头文件 | `interfaces/inner_api/iam_executor/` | `iam_executor_iauth_executor_hdi.h`, `iam_executor_iexecute_callback.h`, `iam_executor_framework_types.h` |
| 修改 NAPI 绑定 | `frameworks/js/napi/` | `user_auth/`、`user_access_ctrl/`、`user_auth_extension/`、`user_auth_icon/` 下各绑定文件 |
| 修改 ANI（ArkTS）绑定 | `frameworks/ets/ani/` | `user_auth/` 下 `.taihe` IDL 与生成产物 |
| 修改 CJ（仓颉）FFI 绑定 | `frameworks/cj/user_auth/` | `inc/` 下 FFI 头与回调 |
| 修改日志/工具/系统参数/计时器 | `common/` | `logs/iam_logger.h`, `utils/iam_check.h`, `utils/iam_defines.h`, `utils/iam_time.h`, `utils/xcollie_helper.h`, `utils/system_param_manager.h` |
| 修改 DFX 事件 | 根目录 | `hisysevent.yaml`（domain `USERIAM_FWK`） |
| 修改 SA 配置/系统参数 | `sa_profile/`、`param/` | `default/901.json`、`921.json`、`931.json`（进程 `useriam`，SA 901/921/931，`libuserauthservice.z.so`），`param/useriam.para` |

### 嵌套指引

本仓库无 `docs/knowledge/` 目录，暂无目录级别的嵌套指引。任务级指导见下文“知识索引”中的场景路由表；后续如补充稳定背景知识，建议放入 `docs/knowledge/` 并在该表中登记。

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
# 构建整个组件（part_name 为 user_auth_framework）
./build.sh --product-name rk3568 --build-target user_auth_framework --ccache

# 单独构建并运行某个单测目标（目标名见 test/BUILD.gn 及各子目录 BUILD.gn）
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 iam_services_test
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 iam_inner_api_test
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 iam_services_core_test
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 iam_executors_test
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 iam_dynamic_test
```

测试分组定义于 `test/BUILD.gn`：`iam_unittest`（含 dynamic/executors/inner_api/services/services_core）与 `iam_fuzztest`（含 clients/executors/services）。`fuzztest/common_fuzzer/` 不是分组目标，而是各 fuzz 目标依赖的共享 `ohos_source_set` 源集（如 `attributes_fuzzer`、`dfx_fuzzer`、`userauth_service_core_fuzzer`、`userauth_services_ipc_fuzzer` 等）。动态加载相关能力受 `user_auth_framework.gni` 中 `user_auth_framework_enable_dynamic_load`、`user_auth_framework_has_ext` 等 gn 参数控制，验证动态加载相关改动时需带对应 feature。

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已提交** - 使用 `git commit -s`，多代理协作时添加 `Co-Authored-By: Agent`
2. **本地构建通过** - 执行上述构建命令
3. **相关测试通过** - 对应单元测试（及 fuzz 目标，如涉及）通过
4. **板侧验证（如适用）** - 涉及 HDI 执行器、远程认证、Widget UI、SA 加载/卸载、TA 协同的改动需提供验证证据
5. **DFX 覆盖（如适用）** - 新增/修改认证、凭据、模板变更等行为需补/对齐 `hisysevent.yaml` 事件
6. **文档更新（如适用）** - 公共 API 修改需更新注释和文档

### 如果无法运行验证

明确说明无法运行的原因，列出推荐的验证步骤供人工执行，标记需要人工验证的部分。

### 完成报告格式

报告应包含：改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（API 兼容性、安全/权限风险、IPC/IDL 兼容性、性能风险）、未完成事项。

## 知识索引

稳定背景知识建议放入 `docs/knowledge/`（当前不存在）。改动前按场景读取对应文件或定位对应目录：

### 场景与路径路由

| 场景 | 修改目录 | 关键文件 / 先读文档 |
| --- | --- | --- |
| 认证全链路：方案生成、调度节点、资源节点、执行器协同、结果评估、context 生命周期 | `services/core/`、`services/context/` | `authentication.h`、`schedule_node.h`、`resource_node.h`、`context.h`、`context_pool.h`、`engine_state_manager.h` |
| 凭据生命周期：录入/更新/删除/查询、会话、安全存储协同 | `services/core/`、`services/ipc/` | `enrollment.h`、`credential_info_interface.h`、`user_idm_database.h`、`secure_user_info_interface.h`、`user_idm_service.h` |
| Widget 认证：弹窗参数、UI 扩展、JSON 协议、回调 | `services/context/`、`services/core/` | `widget_context.h`、`widget_schedule_node.h`、`widget_json.h`、`auth_widget_helper.h`、`widget_client.h` |
| 远程认证：跨设备调度、远程执行器代理、信使、dsoftbus 连接 | `services/context/`、`services/core/`、`services/remote_connect/` | `remote_auth_context.h`、`remote_auth_service.h`、`remote_executor_proxy.h`、`remote_msg_util.h`、`remote_connect_manager.h`、`device_manager_util.h` |
| HDI 执行器协同与引擎包装 | `services/engine/`、`frameworks/native/executors/` | `hdi_engine.h`、`hdi_wrapper.h`、`hdi_type_convert.h`、`executor.h`、`driver.h`、`framework_executor_callback.h` |
| 服务加载/卸载（默认 vs 动态） | `services/load_mode/`、`sa_profile/` | `engine_load_manager.h`、`service_unload_manager.h`、`load_mode_handler.h`、`sa_profile/default/`、`sa_profile/dynamic_load/` |
| IPC 接口与序列化：新增/修改跨进程接口、`Attributes`/`Ipc*Inner` 数据结构 | `frameworks/native/ipc/idl/`、`frameworks/native/ipc/common_defines/` | 各 `*.idl`、`UserAuthTypes.idl` |
| 公共定义与错误码：`AuthType`、`PinSubType`、`ResultCode`、`AuthTrustLevel` 等 | `interfaces/inner_api/` | `iam_common_defines.h`、`user_auth_client_defines.h`、`user_idm_client_defines.h`、`co_auth_client_defines.h` |
| 多用户/账号与安全状态：`OsAccounts`、`strong_auth`、`screenlock`、`secure_user_info` | `services/core/` | `os_accounts_manager.h`、`strong_auth_status_manager.h`、`screenlock_status_listener.h`、`secure_user_info_interface.h` |
| 风险事件与可发布事件 | `services/core/` | `risk_event_manager.h`、`publish_event_adapter.h`、`event_listener_manager.h` |

### 开始编辑前

在修改代码前，按以下顺序确认：
1. 确认任务类别（服务端/客户端/IDL/绑定/DFX/配置）
2. 根据上表确定需要阅读的文件
3. 根据“项目约束”确认不违反任何约束
4. 声明：“我将修改 X，已阅读 Y 文件，遵循 Z 约束”

## 项目约束

### 性能约束

- 认证调度、context 生命周期回调、远程认证消息收发是关键路径，不要在每次调度或消息处理中增加全量扫描、字符串格式化或 INFO 日志。
- `ResourceNodePool`、`ContextPool` 的查询是高频路径，新增查询条件需避免线性全表遍历。
- 远程认证的 socket 收发（dsoftbus）不要在收包路径中做重计算或同步阻塞。

### 架构约束

- 执行器分类与认证类型归属规则要保持显式，不要把 `PIN`、`FACE`、`FINGERPRINT`、`PRIVATE_PIN`、`TUI_PIN`、`COMPANION_DEVICE`、`CUSTOM_AUTH`、`ENTERPRISE_ACCOUNT` 等规则折叠进通用路径。
- 认证流程统一经由 `ScheduleNode` + `ResourceNode` 协同，不要绕过调度节点直接驱动执行器。
- context 的创建与销毁统一经由 `ContextFactory` + `ContextPool`，不要在外部直接 new context。
- HDI 引擎协同统一经由 `services/engine/` 包装层，不要在 core/context 中直接调用 HDI 接口。
- 默认加载与动态加载策略互斥分支由 `load_mode_handler` 决定，不要在业务代码中自行判断加载模式。
- `Attributes`、`IpcAuthParamInner`、`IpcWidgetParamInner` 等跨进程数据结构需保持布局稳定（见“协议与数据格式兼容性”）。

### 编码约定

- C++ 改动优先复用附近的 `IAM_LOGD`/`IAM_LOGE`/`IAM_LOGW`/`IAM_LOGI`/`IAM_LOGF`（定义于 `common/logs/iam_logger.h`）、`IF_FALSE_LOGE_AND_RETURN`/`IF_FALSE_LOGE_AND_RETURN_VAL`（定义于 `common/utils/iam_check.h`）、`ResultCode` 枚举（`SUCCESS`/`FAIL`/`GENERAL_ERROR`/`CANCELED`/`TIMEOUT`/`INVALID_PARAMETERS`/`NOT_ENROLLED`/`IPC_ERROR`/`CHECK_PERMISSION_FAILED` 等，定义于 `interfaces/inner_api/iam_common_defines.h`）。
- 新增改动进行指针判空时，使用普通 `if` + `IAM_LOGE` + `return`，不要使用 `CHKPV`/`CHKPR`/`CHKPC` 等改变代码逻辑的宏，也不要引入新的控制流宏；`IF_FALSE_LOGE_AND_RETURN*` 是已有的不变式前置校验助手，可在周围代码已采用该写法处复用，但不用于新增指针判空。
- 日志需在 `common/logs/iam_logger.h` 的 `LogTraceFileId` 枚举中登记新的 `LOG_FILE_*` 文件 ID，便于按文件过滤。
- 新增 `ResultCode` 枚举值需评估对应用层错误码兼容性的影响（见下文）。

### 公共 API 约束

**Do not（禁止）：**
- 修改已发布的 inner_api、NAPI、ANI、CJ、C/NDK API 的签名、参数类型、返回值类型
- 修改已有 API 的错误码（`ResultCode` 枚举值与语义），除非明确标注为废弃
- 删除或重命名已有公共 API
- 修改已有 API 的行为语义（如异步变同步、阻塞变非阻塞、`AuthType`/`AuthTrustLevel` 取值语义变更）
- 修改 `AuthType`、`PinSubType`、`AuthTrustLevel`、`ResultCode` 等枚举的已有取值与顺序

**Ask before（修改前必须确认）：**
- 新增公共 API：确认是否需要 DFX 事件（`hisysevent.yaml`）、Hitrace、权限检查（`AccessTokenID`）、`apiVersion` 兼容分支
- 修改内部接口：评估是否影响跨模块/跨进程/执行器侧兼容性
- 修改错误处理逻辑：确认是否影响应用层错误码兼容性
- 新增 `AuthType`/执行器类型：确认是否影响执行器注册、方案生成、结果评估链路

### 安全与权限边界

**Do not（禁止）：**
- 绕过已有的权限检查逻辑（`AccessTokenID` 验证、`apiVersion` 范围校验、`userId` 越权校验）
- 在未验证的情况下直接使用跨进程传递的文件描述符、共享内存、socket 数据
- 将敏感输入信息（PIN 明文、`challenge`、`authToken`、`frameworkPublicKey`、模板数据、`templateIds`、用户生物特征数据）写入非安全日志
- 绕过 `authToken` 校验直接删除/修改凭据，或绕过 `strong_auth`/`secure_user_info` 状态直接放行认证
- 修改涉及多用户/多账户访问控制的逻辑，除非经过安全评审

**Ask before（修改前必须确认）：**
- 涉及 `Security::AccessToken` 相关代码的改动
- 涉及跨设备数据传输（`services/remote_connect/`、dsoftbus、`device_manager_util`）的改动
- 涉及认证结果/凭据重定向到其他应用/用户/设备的改动
- 涉及隐私数据（指纹/人脸模板、PIN、用户名、设备 SN、`authToken`）的处理与日志
- 涉及 TA（可信执行环境）协同、HDI `user_auth` 驱动接口签名的改动

### 协议与数据格式兼容性

**Do not（禁止）：**
- 修改 IDL 定义的 IPC 接口签名（`frameworks/native/ipc/idl/*.idl`，如 `IUserAuth.idl`、`IUserIdm.idl`、`ICoAuth.idl`、`IExecutorMessenger.idl`、`IExecutorCallback.idl` 等）、Parcel 序列化顺序
- 修改跨进程传递的数据结构布局（`Attributes`、`IpcAuthParamInner`、`IpcWidgetParamInner`、`ExecutorInfo`、`EnrolledInfo`、`CredentialInfo` 等的字段顺序）
- 修改已有事件的类型码、`AuthType`/`AuthTrustLevel`/`OperationType` 等取值
- 修改远程认证消息格式（`services/remote_connect/inc/remote_message.h` 的消息类型与字段顺序）

**Ask before（修改前必须确认）：**
- 新增 IPC 接口：确认是否需要跨版本兼容性处理、是否需登记到 IDL 并经 `CODEOWNERS` 指定评审人评审
- 修改事件类型/消息类型：确认是否影响执行器侧、远端设备、应用层的兼容性
- 新增 `Attributes` 字段：确认序列化兼容性

### 生成代码边界

**Do not（禁止）：**
- 直接修改 IDL 编译器生成的 C++ Proxy/Stub 代码（`frameworks/native/ipc/` 下由 `*.idl` 生成）
- 手动编辑 ANI/taihe 生成产物（`frameworks/ets/ani/` 下由 `*.taihe` 经 `taihe_ffi_gen` 生成）
- 手动编辑 CJ FFI 生成产物

**正确做法：**
- 修改 IDL 定义文件（`frameworks/native/ipc/idl/*.idl`，含 `UserAuthTypes.idl` 公共类型）
- 重新运行 IDL 编译器生成代码
- 修改 `*.taihe` IDL 定义后重新生成 ANI 产物
- 如果生成代码不满足需求，考虑调整 IDL 定义或使用回调机制（见 `CODEOWNERS`，IDL 改动需经 `@leonchan5` 评审）

### 设备操作约束

**涉及真实设备时的注意事项：**
- 不执行可能影响设备正常运行的破坏性操作（如在未授权情况下强制录入/删除凭据、强制关闭执行器、强制重置 `authToken`）
- 需要在真实设备上验证的改动（HDI 执行器协同、远程认证、Widget、TA 协同、SA 加载/卸载），必须提供板侧证据（hdc 日志、hilog、截图）
- HDI `user_auth` 驱动节点的打开/关闭、TA 调用需权限与状态检查
- 远程认证涉及对端设备时，需验证对端 `RemoteExecutorStub` 与消息编解码的兼容性
