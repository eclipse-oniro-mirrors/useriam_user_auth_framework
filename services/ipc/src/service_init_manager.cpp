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
#include "iam_logger.h"

#include "co_auth_service.h"
#include "context_pool.h"
#include "driver_state_manager.h"
#include "load_mode_handler.h"
#include "os_accounts_manager.h"
#include "remote_auth_service.h"
#include "remote_connect_manager.h"
#include "strong_auth_status_manager.h"
#include "system_param_manager.h"

#define LOG_FILE_ID LOG_FILE_SERVICE_INIT_MANAGER
#define IAM_LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ServiceInitManager &ServiceInitManager::GetInstance()
{
    static ServiceInitManager instance;
    return instance;
}

void ServiceInitManager::OnIdmServiceStart()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isIdmServiceStart_ = true;
    IAM_LOGI("idm service start");
    CheckAllServiceStart();
}

void ServiceInitManager::OnIdmServiceStop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isIdmServiceStart_ = false;
    IAM_LOGI("idm service stop");
    CheckAllServiceStop();
}

void ServiceInitManager::OnCoAuthServiceStart()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isCoAuthServiceStart_ = true;
    IAM_LOGI("co auth service start");
    CheckAllServiceStart();
}

void ServiceInitManager::OnCoAuthServiceStop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isCoAuthServiceStart_ = false;
    IAM_LOGI("co auth service stop");
    CheckAllServiceStop();
}

void ServiceInitManager::OnUserAuthServiceStart()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isUserAuthServiceStart_ = true;
    IAM_LOGI("user auth service start");
    CheckAllServiceStart();
}

void ServiceInitManager::OnUserAuthServiceStop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isUserAuthServiceStart_ = false;
    IAM_LOGI("user auth service stop");
    CheckAllServiceStop();
}

void ServiceInitManager::CheckAllServiceStart()
{
    bool isAllServiceStart = isIdmServiceStart_ && isCoAuthServiceStart_ && isUserAuthServiceStart_;
    IAM_LOGI("idm service: %{public}d, coauth service: %{public}d, user authservice: %{public}d, all "
             "service start: %{public}d",
        isIdmServiceStart_, isCoAuthServiceStart_, isUserAuthServiceStart_, isAllServiceStart);

    LoadModeHandler::GetInstance().StartSubscribe();

    if (!isAllServiceStart) {
        LoadModeHandler::GetInstance().StartCheckServiceReadyTimer();
        return;
    }

    LoadModeHandler::GetInstance().CancelCheckServiceReadyTimer();

    IAM_LOGI("all service start, init global instance begin");

    RemoteConnectionManager::GetInstance().Start();
    const bool REMOTE_AUTH_SERVICE_RESULT = RemoteAuthService::GetInstance().Start();
    (void)REMOTE_AUTH_SERVICE_RESULT;

    auto coAuthService = CoAuthService::GetInstance();
    IF_FALSE_LOGE_AND_RETURN(coAuthService != nullptr);
    coAuthService->RegisterAccessTokenListener();

    OsAccountsManager::Instance().StartSubscribe();
    ContextPool::Instance().StartSubscribeOsAccountSaStatus();
    StrongAuthStatusManager::Instance().StartSubscribe();

    DriverStateManager::GetInstance().RegisterDriverStartCallback([]() {
        std::shared_ptr<CoAuthService> instance = CoAuthService::GetInstance();
        if (instance == nullptr) {
            IAM_LOGE("CoAuthService instance is null");
            return;
        }
        instance->OnDriverStart();
    });
    DriverStateManager::GetInstance().RegisterDriverStopCallback([]() {
        std::shared_ptr<CoAuthService> instance = CoAuthService::GetInstance();
        if (instance == nullptr) {
            IAM_LOGE("CoAuthService instance is null");
            return;
        }
        instance->OnDriverStop();
    });

    DriverStateManager::GetInstance().StartSubscribe();

    IAM_LOGI("all service start, init global instance end");
}

void ServiceInitManager::CheckAllServiceStop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    bool isAllServiceStop = !isIdmServiceStart_ && !isCoAuthServiceStart_ && !isUserAuthServiceStart_;
    IAM_LOGI("idm service: %{public}d, coauth service: %{public}d, user authservice: %{public}d, all "
             "service stop: %{public}d",
        isIdmServiceStart_, isCoAuthServiceStart_, isUserAuthServiceStart_, isAllServiceStop);
    if (!isAllServiceStop) {
        return;
    }

    IAM_LOGI("all service stop, destroy global instance begin");

    RemoteConnectionManager::GetInstance().Stop();

    auto coAuthService = CoAuthService::GetInstance();
    IF_FALSE_LOGE_AND_RETURN(coAuthService != nullptr);
    coAuthService->UnRegisterAccessTokenListener();

    IAM_LOGI("all service stop, destroy global instance end");
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS