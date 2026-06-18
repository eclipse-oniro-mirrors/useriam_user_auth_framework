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

#include "strong_auth_status_manager.h"

#include <singleton.h>

#include "screenlock_common.h"
#include "screenlock_inner_listener.h"
#include "screenlock_manager.h"
#include "screenlock_system_ability.h"
#include "system_ability_definition.h"
#include "system_ability.h"

#include "context_appstate_observer.h"
#include "hisysevent_adapter.h"
#include "ipc_common.h"
#include "resource_node_pool.h"
#include "risk_event_manager.h"
#include "screenlock_status_listener.h"
#include "system_ability_listener.h"
#include "user_auth_service.h"

#define LOG_FILE_ID LOG_FILE_STRONG_AUTH_STATUS_MANAGER_IMPL
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
using StrongAuthListener = ScreenLock::StrongAuthListener;
using ScreenLockManager = ScreenLock::ScreenLockManager;
using StrongAuthReasonFlags = ScreenLock::StrongAuthReasonFlags;

class UserIamStrongAuthListener : public StrongAuthListener {
public:
    using StrongAuthListener::StrongAuthListener;
    ~UserIamStrongAuthListener() override = default;

    void OnStrongAuthChanged(int32_t userId, int32_t strongAuthStatus) override;
};

class StrongAuthStatusManagerImpl final
    : public StrongAuthStatusManager, public Singleton<StrongAuthStatusManagerImpl> {
public:
    ~StrongAuthStatusManagerImpl();

    void RegisterStrongAuthListener() override;
    void UnRegisterStrongAuthListener() override;
    void StartSubscribe() override;
    bool IsScreenLockStrongAuth(int32_t userId) override;
    void SyncStrongAuthStatusForAllAccounts() override;

private:
    std::recursive_mutex mutex_;
    sptr<SystemAbilityListener> screenLockSaStatusListener_ {nullptr};
    sptr<StrongAuthListener> strongAuthListener_ {nullptr};
};

void UserIamStrongAuthListener::OnStrongAuthChanged(int32_t userId, int32_t strongAuthStatus)
{
    IAM_LOGI("strong auth state changed to %{public}d for userId %{public}d", strongAuthStatus, userId);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);

    handler->PostTask([userId, strongAuthStatus]() {
        if (strongAuthStatus != static_cast<int32_t>(StrongAuthReasonFlags::AFTER_BOOT) &&
            strongAuthStatus != static_cast<int32_t>(StrongAuthReasonFlags::NONE)) {
            ScreenLockStrongAuthTrace screenLockStrongAuthTraceInfo = {};
            screenLockStrongAuthTraceInfo.userId = userId;
            screenLockStrongAuthTraceInfo.strongAuthReason = strongAuthStatus;
            UserIam::UserAuth::ReportScreenLockStrongAuth(screenLockStrongAuthTraceInfo);
        }
        int32_t reasonFlag = static_cast<int32_t>(StrongAuthReasonFlags::NONE);
        ScreenLockManager::GetInstance()->GetStrongAuth(userId, reasonFlag);
        if (reasonFlag != static_cast<int32_t>(StrongAuthReasonFlags::SECURITY_ENHANCEMENT)) {
            IAM_LOGI("screenlock not in security enhancement");
            return;
        }
        RiskEventManager::GetInstance().HandleStrongAuthEvent(userId);
    });
}

StrongAuthStatusManagerImpl::~StrongAuthStatusManagerImpl()
{
    IAM_LOGD("start");
    UnRegisterStrongAuthListener();
}

void StrongAuthStatusManagerImpl::RegisterStrongAuthListener()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (strongAuthListener_ != nullptr) {
        return;
    }

    const int32_t ALL_USER_ID = -1;
    strongAuthListener_ =
        sptr<StrongAuthListener>(new (std::nothrow) UserIamStrongAuthListener(ALL_USER_ID));
    IF_FALSE_LOGE_AND_RETURN(strongAuthListener_ != nullptr);

    ScreenLockManager::GetInstance()->RegisterStrongAuthListener(strongAuthListener_);
    IF_FALSE_LOGE_AND_RETURN(strongAuthListener_ != nullptr);
    SyncStrongAuthStatusForAllAccounts();
}

void StrongAuthStatusManagerImpl::UnRegisterStrongAuthListener()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (strongAuthListener_ == nullptr) {
        return;
    }

    int32_t ret = ScreenLockManager::GetInstance()->UnRegisterStrongAuthListener(strongAuthListener_);
    if (ret != SUCCESS) {
        IAM_LOGE("UnRegisterStrongAuthListener fail");
    }

    strongAuthListener_ = nullptr;
}

void StrongAuthStatusManagerImpl::SyncStrongAuthStatusForAllAccounts()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto screenLockManager = ScreenLockManager::GetInstance();
    IF_FALSE_LOGE_AND_RETURN(screenLockManager != nullptr);
    IF_FALSE_LOGE_AND_RETURN(strongAuthListener_ != nullptr);

    std::vector<int32_t> userIdList;
    IpcCommon::GetAllUserId(userIdList);
    int32_t reasonFlag = static_cast<int32_t>(StrongAuthReasonFlags::NONE);
    for (int32_t &userId : userIdList) {
        screenLockManager->GetStrongAuth(userId, reasonFlag);
        strongAuthListener_->OnStrongAuthChanged(userId, reasonFlag);
        reasonFlag = static_cast<int32_t>(StrongAuthReasonFlags::NONE);
    }
}

void StrongAuthStatusManagerImpl::StartSubscribe()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (screenLockSaStatusListener_ != nullptr) {
        return;
    }
    screenLockSaStatusListener_ = SystemAbilityListener::Subscribe(
        "ScreenLockService", SCREENLOCK_SERVICE_ID,
        []() {
            StrongAuthStatusManager::Instance().RegisterStrongAuthListener();
            ScreenlockStatusListenerManager::GetInstance().RegisterCommonEventListener();
        },
        []() { StrongAuthStatusManager::Instance().UnRegisterStrongAuthListener(); });
    IF_FALSE_LOGE_AND_RETURN(screenLockSaStatusListener_ != nullptr);
}

bool StrongAuthStatusManagerImpl::IsScreenLockStrongAuth(int32_t userId)
{
    int32_t reasonFlag = static_cast<int32_t>(StrongAuthReasonFlags::NONE);
    auto screenLockManager = ScreenLockManager::GetInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(screenLockManager != nullptr, false);
    screenLockManager->GetStrongAuth(userId, reasonFlag);

    if (reasonFlag != static_cast<int32_t>(StrongAuthReasonFlags::SECURITY_ENHANCEMENT)) {
        return false;
    }
    
    return true;
}

StrongAuthStatusManager &StrongAuthStatusManager::Instance()
{
    return StrongAuthStatusManagerImpl::GetInstance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS