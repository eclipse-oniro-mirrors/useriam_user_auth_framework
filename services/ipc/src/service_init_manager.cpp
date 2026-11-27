/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "service_init_manager.h"

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_time.h"

#include "co_auth_service.h"
#include "context_pool.h"
#include "device_manager_util.h"
#include "engine_state_manager.h"
#include "hisysevent_adapter.h"
#include "load_mode_handler.h"
#include "message_callback_service.h"
#include "os_accounts_manager.h"
#include "remote_auth_service.h"
#include "remote_connect_manager.h"
#include "resource_node_pool.h"
#include "strong_auth_status_manager.h"
#include "system_ability_definition.h"
#include "system_param_manager.h"
#include "user_auth_engine.h"
#include "user_auth_service.h"
#include "user_idm_service.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SERVICE_INIT_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr uint32_t ENGINE_READY_TASK_TIMEOUT_SEC = 100;
ServiceInitManager &ServiceInitManager::GetInstance()
{
    static ServiceInitManager instance;
    return instance;
}

ServiceInitManager::ServiceInitManager()
    : threadHandler_(ThreadHandler::GetSingleThreadInstance())
{
}

void ServiceInitManager::OnCoAuthServiceStart()
{
    IAM_LOGI("co auth service start");
    IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
    threadHandler_->PostTask([this]() { StartCoAuthServiceImpl(); });
}

void ServiceInitManager::OnCoAuthServiceStop()
{
    IAM_LOGI("co auth service stop");
    IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
    threadHandler_->PostTask([this]() { StopCoAuthServiceImpl(); });
}

void ServiceInitManager::OnUserAuthServiceStart()
{
    IAM_LOGI("user auth service start");
    IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
    threadHandler_->PostTask([this]() { StartUserAuthServiceImpl(); });
}

void ServiceInitManager::OnUserAuthServiceStop()
{
    IAM_LOGI("user auth service stop");
    IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
    threadHandler_->PostTask([this]() { StopUserAuthServiceImpl(); });
}

void ServiceInitManager::OnIdmServiceStart()
{
    IAM_LOGI("idm service start");
    IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
    threadHandler_->PostTask([this]() { StartIdmServiceImpl(); });
}

void ServiceInitManager::OnIdmServiceStop()
{
    IAM_LOGI("idm service stop");
    IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
    threadHandler_->PostTask([this]() { StopIdmServiceImpl(); });
}

void ServiceInitManager::OnEngineReady()
{
    IAM_LOGI("on engine ready");
    IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
    threadHandler_->PostTask([this]() { OnEngineReadyImpl(); }, ENGINE_READY_TASK_TIMEOUT_SEC);
}

void ServiceInitManager::OnEngineUnavailable()
{
    IAM_LOGI("on engine unavailable");
    IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
    threadHandler_->PostTask([this]() { OnEngineUnavailableImpl(); });
}

void ServiceInitManager::OnAccessTokenReady()
{
    IAM_LOGI("on access token ready");
    IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
    threadHandler_->PostTask([this]() { OnAccessTokenReadyImpl(); });
}

void ServiceInitManager::StartCoAuthServiceImpl()
{
    isCoAuthServiceStart_ = true;
    HandleServiceStart();
}

void ServiceInitManager::StartUserAuthServiceImpl()
{
    isUserAuthServiceStart_ = true;
    HandleServiceStart();
}

void ServiceInitManager::StartIdmServiceImpl()
{
    isIdmServiceStart_ = true;
    HandleServiceStart();
}

void ServiceInitManager::StopCoAuthServiceImpl()
{
    isCoAuthServiceStart_ = false;
    HandleServiceStop();
}

void ServiceInitManager::StopUserAuthServiceImpl()
{
    isUserAuthServiceStart_ = false;
    HandleServiceStop();
}

void ServiceInitManager::StopIdmServiceImpl()
{
    isIdmServiceStart_ = false;
    HandleServiceStop();
}

// 公共启动逻辑：订阅（幂等）、service ready 定时器启停、全局初始化触发、统一标记检查
void ServiceInitManager::HandleServiceStart()
{
    LoadModeHandler::GetInstance().StartSubscribe();

    bool isAllServiceStart = isCoAuthServiceStart_ && isUserAuthServiceStart_ && isIdmServiceStart_;
    if (!isAllServiceStart) {
        LoadModeHandler::GetInstance().StartCheckServiceReadyTimer();
    } else {
        LoadModeHandler::GetInstance().CancelCheckServiceReadyTimer();
        InitGlobalInstance();
    }
    CheckAllFlags();
}

// 公共停止逻辑：3 SA 全停触发反初始化
void ServiceInitManager::HandleServiceStop()
{
    if (!isCoAuthServiceStart_ && !isUserAuthServiceStart_ && !isIdmServiceStart_) {
        DeinitGlobalInstance();
    }
}

void ServiceInitManager::InitGlobalInstance()
{
    IAM_LOGI("init global instance begin");
    if (fwkReady_) {
        IAM_LOGI("already inited");
        return;
    }

    RemoteConnectionManager::GetInstance().Start();
    const bool REMOTE_AUTH_SERVICE_RESULT = RemoteAuthService::GetInstance().Start();
    (void)REMOTE_AUTH_SERVICE_RESULT;

    RegisterAccessTokenListenerImpl();

    OsAccountsManager::Instance().StartSubscribe();
    ContextPool::Instance().StartSubscribeOsAccountSaStatus();
    StrongAuthStatusManager::Instance().StartSubscribe();

    EngineStateManager::GetInstance().RegisterEngineReadyCallback([]() {
        ServiceInitManager::GetInstance().OnEngineReady();
    });
    EngineStateManager::GetInstance().RegisterEngineUnavailableCallback([]() {
        ServiceInitManager::GetInstance().OnEngineUnavailable();
    });

    EngineStateManager::GetInstance().StartSubscribe();

    fwkReady_ = true;
    IAM_LOGI("init global instance end");
    CheckAllFlags();
}

void ServiceInitManager::DeinitGlobalInstance()
{
    IAM_LOGI("deinit global instance begin");

    RemoteConnectionManager::GetInstance().Stop();
    UnRegisterAccessTokenListenerImpl();

    fwkReady_ = false;
    accessTokenReady_ = false;
    engineReady_ = false;
    IAM_LOGI("deinit global instance end");
}

void ServiceInitManager::CheckAllFlags()
{
    bool isAllReady = isCoAuthServiceStart_ && isUserAuthServiceStart_ && isIdmServiceStart_ &&
        accessTokenReady_ && fwkReady_ && engineReady_;
    IAM_LOGI("coAuth:%{public}d userAuth:%{public}d idm:%{public}d accessToken:%{public}d fwk:%{public}d "
             "engine:%{public}d allReady:%{public}d",
        isCoAuthServiceStart_, isUserAuthServiceStart_, isIdmServiceStart_, accessTokenReady_, fwkReady_,
        engineReady_, isAllReady);
    if (!isAllReady) {
        return;
    }

    PublishAllServices();
    LoadModeHandler::GetInstance().OnFwkReady();
}

void ServiceInitManager::PublishAllServices()
{
    IAM_LOGI("publish all services begin");
    auto coAuthService = CoAuthService::GetInstance();
    if (coAuthService != nullptr) {
        coAuthService->PublishSelf();
    } else {
        IAM_LOGE("co auth service is null");
    }

    auto userAuthService = UserAuthService::GetInstance();
    if (userAuthService != nullptr) {
        userAuthService->PublishSelf();
    } else {
        IAM_LOGE("user auth service is null");
    }

    auto userIdmService = UserIdmService::GetInstance();
    if (userIdmService != nullptr) {
        userIdmService->PublishSelf();
    } else {
        IAM_LOGE("user idm service is null");
    }
    IAM_LOGI("publish all services end");
}

void ServiceInitManager::OnEngineReadyImpl()
{
    IAM_LOGI("process engine ready begin");
    if (engineReady_) {
        IAM_LOGI("already ready");
        return;
    }
    std::string localUdid;
    bool getLocalUdidRet = DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(localUdid);
    IF_FALSE_LOGE_AND_RETURN(getLocalUdidRet);
    int32_t initRet = GetUserAuthEngine().Init(localUdid);
    IF_FALSE_LOGE_AND_RETURN(initRet == SUCCESS);
    auto callbackService = MessageCallbackService::GetInstance();
    IF_FALSE_LOGE_AND_RETURN(callbackService != nullptr);
    callbackService->OnEngineConnect();
    engineReady_ = true;
    IAM_LOGI("process engine ready success");
    CheckAllFlags();
}

void ServiceInitManager::OnEngineUnavailableImpl()
{
    IAM_LOGE("process engine unavailable begin");
    if (engineReady_) {
        IAM_LOGI("service is ready, clear status");
        ResourceNodePool::Instance().DeleteAll();
        UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "user_auth_hdi host");
        engineReady_ = false;
    }
    IAM_LOGI("process engine unavailable success");
}

void ServiceInitManager::OnAccessTokenReadyImpl()
{
    IAM_LOGI("access token ready");
    accessTokenReady_ = true;
    CheckAllFlags();
}

ResultCode ServiceInitManager::RegisterAccessTokenListenerImpl()
{
    IAM_LOGD("start.");
    if (accessTokenListener_ != nullptr) {
        IAM_LOGI("accessTokenListener_ is not nullptr.");
        return SUCCESS;
    }

    accessTokenListener_ = SystemAbilityListener::Subscribe("accesstoken_service", ACCESS_TOKEN_MANAGER_SERVICE_ID,
        []() {
            ServiceInitManager::GetInstance().OnAccessTokenReady();
        },
        nullptr);
    if (accessTokenListener_ == nullptr) {
        IAM_LOGE("accessTokenListener_ is nullptr.");
        return GENERAL_ERROR;
    }

    IAM_LOGI("RegisterAccessTokenListener success.");
    return SUCCESS;
}

ResultCode ServiceInitManager::UnRegisterAccessTokenListenerImpl()
{
    IAM_LOGD("start.");
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
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
