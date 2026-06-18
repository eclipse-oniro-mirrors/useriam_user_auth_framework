/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "co_auth_service.h"

#include <cinttypes>
#include <thread>

#include "string_ex.h"

#include "device_manager_util.h"
#include "driver_state_manager.h"
#include "executor_messenger_service.h"
#include "hdi_message_callback_service.h"
#include "hdi_wrapper.h"
#include "hisysevent_adapter.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_para2str.h"
#include "ipc_common.h"
#include "iam_check.h"
#include "iam_time.h"
#include "iam_common_defines.h"
#include "ipc_skeleton.h"
#include "load_mode_handler.h"
#include "parameter.h"
#include "relative_timer.h"
#include "remote_connect_manager.h"
#include "risk_event_manager.h"
#include "service_init_manager.h"
#include "system_param_manager.h"
#include "template_cache_manager.h"
#include "remote_msg_util.h"
#include "xcollie_helper.h"

#define LOG_FILE_ID LOG_FILE_CO_AUTH_SERVICE
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(CoAuthService::GetInstance().get());
} // namespace

constexpr int32_t USERIAM_IPC_THREAD_NUM = 4;
std::shared_ptr<CoAuthService> CoAuthService::instance_ = nullptr;

std::shared_ptr<CoAuthService> CoAuthService::GetInstance()
{
    static std::recursive_mutex mutex;
    if (instance_ == nullptr) {
        std::lock_guard<std::recursive_mutex> guard(mutex);
        if (instance_ == nullptr) {
            instance_ = Common::MakeShared<CoAuthService>();
            if (instance_ == nullptr) {
                IAM_LOGE("make share failed");
            }
        }
    }
    return instance_;
}

CoAuthService::CoAuthService()
    : SystemAbility(SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR, true), CoAuthStub(true)
{
    IAM_LOGI("CoAuthService init");
}

void CoAuthService::OnStart()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    IAM_LOGI("Sa start CoAuthService");
    IPCSkeleton::SetMaxWorkThreadNum(USERIAM_IPC_THREAD_NUM);
    if (!Publish(this)) {
        IAM_LOGE("Failed to publish service");
        return;
    }

    ServiceInitManager::GetInstance().OnCoAuthServiceStart();
}

void CoAuthService::OnStop()
{
    IAM_LOGI("Sa stop CoAuthService");
    ServiceInitManager::GetInstance().OnCoAuthServiceStop();
}

void CoAuthService::SetIsReady(bool isReady)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    isReady_ = isReady;
    IAM_LOGI("Set isReady %{public}d", isReady);
}

void CoAuthService::SetAccessTokenReady(bool isReady)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    accessTokenReady_ = isReady;
    IAM_LOGI("Set accesstk ready %{public}d", isReady);
}

bool CoAuthService::IsFwkReady()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return isReady_ && accessTokenReady_;
}

void CoAuthService::AddExecutorDeathRecipient(uint64_t executorIndex, AuthType authType, ExecutorRole role,
    std::shared_ptr<IExecutorCallback> callback)
{
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    auto obj = callback->AsObject();
    IF_FALSE_LOGE_AND_RETURN(obj != nullptr);

    obj->AddDeathRecipient(new (std::nothrow) IpcCommon::PeerDeathRecipient([executorIndex, authType, role]() {
        IAM_LOGE("executorCallback is down");
        auto weakNode = ResourceNodePool::Instance().Select(executorIndex);
        auto sharedNode = weakNode.lock();
        if (sharedNode != nullptr) {
            auto result = ResourceNodePool::Instance().Delete(executorIndex);
            IAM_LOGI("delete executor %{public}s, executorIndex is ****%{public}hx authType is %{public}d "
                "executorRole is %{public}d", (result ? "succ" : "failed"), static_cast<uint16_t>(executorIndex),
                sharedNode->GetAuthType(), sharedNode->GetExecutorRole());
        }
        LoadModeHandler::GetInstance().OnExecutorUnregistered(authType, role);
        std::string executorDesc = "executor, type " + std::to_string(authType);
        UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), executorDesc);
        IAM_LOGI("executorCallback is down processed");
    }));
}

int32_t CoAuthService::ProcExecutorRegisterSuccess(std::shared_ptr<ResourceNode> &resourceNode,
    const std::shared_ptr<IExecutorCallback> &callback, std::vector<uint64_t> &templateIdList,
    std::vector<uint8_t> &fwkPublicKey)
{
    IAM_LOGI("start");
    uint64_t executorIndex = resourceNode->GetExecutorIndex();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    std::weak_ptr<ResourceNode> weakNode = resourceNode;
    IF_FALSE_LOGE_AND_RETURN_VAL(handler != nullptr, GENERAL_ERROR);
    handler->PostTask([callback, fwkPublicKey, templateIdList, weakNode, executorIndex]() {
        auto resourceNode = weakNode.lock();
        IF_FALSE_LOGE_AND_RETURN(resourceNode != nullptr);
        sptr<IExecutorMessenger> messenger = ExecutorMessengerService::GetInstance();
        callback->OnMessengerReady(messenger, fwkPublicKey, templateIdList);
        IAM_LOGI("register successful, executorType is %{public}d, executorRole is %{public}d, "
            "executorIndex is ****%{public}hx",
            resourceNode->GetAuthType(), resourceNode->GetExecutorRole(), static_cast<uint16_t>(executorIndex));
        LoadModeHandler::GetInstance().OnExecutorRegistered(resourceNode->GetAuthType(),
            resourceNode->GetExecutorRole());
        AddExecutorDeathRecipient(executorIndex, resourceNode->GetAuthType(), resourceNode->GetExecutorRole(),
            callback);
        IAM_LOGI("update template cache after register success");
        TemplateCacheManager::GetInstance().UpdateTemplateCache(resourceNode->GetAuthType());
        RiskEventManager::GetInstance().SyncRiskEvents();
    });

    return SUCCESS;
}

int32_t CoAuthService::ExecutorRegister(const IpcExecutorRegisterInfo &ipcExecutorRegisterInfo,
    const sptr<IExecutorCallback> &executorCallback, uint64_t &executorIndex)
{
    IAM_LOGI("register resource node begin");
    executorIndex = INVALID_EXECUTOR_INDEX;
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (executorCallback == nullptr) {
        IAM_LOGE("executor callback is nullptr");
        return INVALID_PARAMETERS;
    }

    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!IsFwkReady()) {
        IAM_LOGE("framework is not ready");
        return GENERAL_ERROR;
    }

    if (!IpcCommon::CheckPermission(*this, ACCESS_AUTH_RESPOOL)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> fwkPublicKey;
    ExecutorRegisterInfo executorRegisterInfo = {};
    InitExecutorRegisterInfo(ipcExecutorRegisterInfo, executorRegisterInfo);
    sptr<IExecutorCallback> tempCallBack = executorCallback;
    auto callback = Common::SptrToStdSharedPtr<IExecutorCallback>(tempCallBack);
    auto resourceNode = ResourceNode::MakeNewResource(executorRegisterInfo, callback,
        templateIdList, fwkPublicKey);
    if (resourceNode == nullptr) {
        IAM_LOGE("create resource node failed");
        return GENERAL_ERROR;
    }
    if (!ResourceNodePool::Instance().Insert(resourceNode)) {
        IAM_LOGE("insert resource node failed");
        return GENERAL_ERROR;
    }
    executorIndex = resourceNode->GetExecutorIndex();
    return ProcExecutorRegisterSuccess(resourceNode, callback, templateIdList, fwkPublicKey);
}

int32_t CoAuthService::ExecutorUnregister(uint64_t executorIndex)
{
    IAM_LOGI("delete resource node begin");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!IsFwkReady()) {
        IAM_LOGE("framework is not ready");
        return SUCCESS;
    }

    if (!IpcCommon::CheckPermission(*this, ACCESS_AUTH_RESPOOL)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    {
        auto resourceNode = ResourceNodePool::Instance().Select(executorIndex).lock();
        IF_FALSE_LOGE_AND_RETURN_VAL(resourceNode != nullptr, GENERAL_ERROR);
        LoadModeHandler::GetInstance().OnExecutorUnregistered(resourceNode->GetAuthType(),
            resourceNode->GetExecutorRole());
    }

    if (!ResourceNodePool::Instance().Delete(executorIndex)) {
        IAM_LOGE("delete resource node failed");
        return GENERAL_ERROR;
    }
    IAM_LOGI("delete resource node success, executorIndex is ****%{public}hx", static_cast<uint16_t>(executorIndex));
    return SUCCESS;
}

void CoAuthService::OnDriverStart()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    IAM_LOGI("process driver start begin");
    if (isReady_) {
        IAM_LOGI("already ready");
        return;
    }
    std::string localUdid;
    bool getLocalUdidRet = DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(localUdid);
    IF_FALSE_LOGE_AND_RETURN(getLocalUdidRet);
    auto service = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN(service != nullptr);
    int32_t initRet = service->Init(localUdid);
    IF_FALSE_LOGE_AND_RETURN(initRet == HDF_SUCCESS);
    auto callbackService = HdiMessageCallbackService::GetInstance();
    IF_FALSE_LOGE_AND_RETURN(callbackService != nullptr);
    callbackService->OnHdiConnect();
    SetIsReady(true);
    NotifyFwkReady();
    IAM_LOGI("process driver start success");
}

void CoAuthService::OnDriverStop()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    IAM_LOGE("process driver stop begin");
    if (isReady_) {
        IAM_LOGI("service is ready, clear status");
        ResourceNodePool::Instance().DeleteAll();
        UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "user_auth_hdi host");
        SetIsReady(false);
    }
    IAM_LOGI("process driver stop success");
}

int CoAuthService::Dump(int fd, const std::vector<std::u16string> &args)
{
    IAM_LOGI("start");
    if (fd < 0) {
        IAM_LOGE("invalid parameters");
        return INVALID_PARAMETERS;
    }
    std::string arg0 = (args.empty() ? "" : Str16ToStr8(args[0]));
    if (arg0.empty() || arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "      -h: command help.\n");
        dprintf(fd, "      -l: resource pool dump.\n");
        return SUCCESS;
    }
    if (arg0.compare("-l") == 0) {
        ResourceNodePool::Instance().Enumerate([fd](const std::weak_ptr<ResourceNode> &node) {
            auto nodeTmp = node.lock();
            if (nodeTmp != nullptr) {
                dprintf(fd, "ExecutorIndex is: %" PRIx64 ".\n", nodeTmp->GetExecutorIndex());
                dprintf(fd, "ExecutorType is: %s.\n", Common::AuthTypeToStr(nodeTmp->GetAuthType()));
                dprintf(fd, "ExecutorRole is: %s.\n", Common::ExecutorRoleToStr(nodeTmp->GetExecutorRole()));
            }
        });
        return SUCCESS;
    }
    IAM_LOGE("invalid option");
    dprintf(fd, "Invalid option\n");
    return GENERAL_ERROR;
}

ResultCode CoAuthService::RegisterAccessTokenListener()
{
    IAM_LOGD("start.");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (accessTokenListener_ != nullptr) {
        IAM_LOGI("accessTokenListener_ is not nullptr.");
        return SUCCESS;
    }

    accessTokenListener_ = SystemAbilityListener::Subscribe("accesstoken_service", ACCESS_TOKEN_MANAGER_SERVICE_ID,
        []() {
            auto instance = CoAuthService::GetInstance();
            if (instance == nullptr) {
                IAM_LOGE("CoAuthService instance is nullptr.");
                return;
            }
            instance->SetAccessTokenReady(true);
            instance->NotifyFwkReady();
        },
        nullptr);
    if (accessTokenListener_ == nullptr) {
        IAM_LOGE("accessTokenListener_ is nullptr.");
        return GENERAL_ERROR;
    }

    IAM_LOGI("RegisterAccessTokenListener success.");
    return SUCCESS;
}

ResultCode CoAuthService::UnRegisterAccessTokenListener()
{
    IAM_LOGD("start.");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (accessTokenListener_ == nullptr) {
        IAM_LOGI("accessTokenListener_ is nullptr.");
        return SUCCESS;
    }

    int32_t ret = SystemAbilityListener::UnSubscribe(ACCESS_TOKEN_MANAGER_SERVICE_ID, accessTokenListener_);
    if (ret != SUCCESS) {
        IAM_LOGE("UnSubscribe service fail.");
        return GENERAL_ERROR;
    }

    accessTokenListener_ = nullptr;
    IAM_LOGI("UnRegisterAccessTokenListener success.");
    return SUCCESS;
}

void CoAuthService::NotifyFwkReady()
{
    IAM_LOGD("start.");
    if (IsFwkReady()) {
        LoadModeHandler::GetInstance().OnFwkReady();
    }
}

void CoAuthService::InitExecutorRegisterInfo(const IpcExecutorRegisterInfo &ipcExecutorRegisterInfo,
    ExecutorRegisterInfo &executorRegisterInfo)
{
    executorRegisterInfo.authType = static_cast<AuthType>(ipcExecutorRegisterInfo.authType);
    executorRegisterInfo.executorRole = static_cast<ExecutorRole>(ipcExecutorRegisterInfo.executorRole);
    executorRegisterInfo.executorSensorHint = ipcExecutorRegisterInfo.executorSensorHint;
    executorRegisterInfo.executorMatcher = ipcExecutorRegisterInfo.executorMatcher;
    executorRegisterInfo.esl = static_cast<ExecutorSecureLevel>(ipcExecutorRegisterInfo.esl);
    executorRegisterInfo.maxTemplateAcl = ipcExecutorRegisterInfo.maxTemplateAcl;
    executorRegisterInfo.publicKey = ipcExecutorRegisterInfo.publicKey;
    executorRegisterInfo.deviceUdid = ipcExecutorRegisterInfo.deviceUdid;
    executorRegisterInfo.signedRemoteExecutorInfo = ipcExecutorRegisterInfo.signedRemoteExecutorInfo;
}

int32_t CoAuthService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t CoAuthService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS