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

#include "screenlock_status_listener.h"

#include "common_event_subscribe_info.h"
#include "matching_skills.h"
#include "singleton.h"
#include "want.h"

#include "context_appstate_observer.h"
#include "credential_info_interface.h"
#include "risk_event_manager.h"
#include "user_idm_database.h"

#define LOG_FILE_ID LOG_FILE_SCREENLOCK_STATUS_LISTENER
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ScreenlockStatusListenerManager &ScreenlockStatusListenerManager::GetInstance()
{
    static ScreenlockStatusListenerManager instance;
    return instance;
}

ResultCode ScreenlockStatusListenerManager::RegisterCommonEventListener()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (commonEventSaStatusListener_ != nullptr) {
        return SUCCESS;
    }
    commonEventSaStatusListener_ = SystemAbilityListener::Subscribe(
        "common_event_service", COMMON_EVENT_SERVICE_ID,
        []() { ScreenlockStatusListenerManager::GetInstance().RegisterScreenLockedCallback(); },
        []() { ScreenlockStatusListenerManager::GetInstance().UnRegisterScreenLockedCallback(); });
    IF_FALSE_LOGE_AND_RETURN_VAL(commonEventSaStatusListener_ != nullptr, GENERAL_ERROR);

    return SUCCESS;
}

void ScreenlockStatusListenerManager::RegisterScreenLockedCallback()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (subscriber_ != nullptr) {
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);

    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriber = Common::MakeShared<ScreenlockStatusListener>(subscribeInfo);
    IF_FALSE_LOGE_AND_RETURN(subscriber != nullptr);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber)) {
        IAM_LOGE("SubscribeCommonEvent fail");
        return;
    }
    IF_FALSE_LOGE_AND_RETURN(subscriber != nullptr);
    subscriber_ = subscriber;
    SyncScreenlockStatus();
}

void ScreenlockStatusListenerManager::UnRegisterScreenLockedCallback()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (subscriber_ == nullptr) {
        return;
    }

    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_)) {
        IAM_LOGE("UnSubscribeCommonEvent failed");
    }
    subscriber_ = nullptr;
}

void ScreenlockStatusListenerManager::SyncScreenlockStatus()
{
    IAM_LOGI("start");
    bool screenLockState = ContextAppStateObserverManager::GetInstance().IsScreenLocked();
    if (!screenLockState) {
        IAM_LOGI("screen is not locked");
        return;
    }
    RiskEventManager::GetInstance().OnScreenLock();
}

void ScreenlockStatusListener::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    int32_t userId = data.GetWant().GetIntParam("userId", INVALID_USER_ID);
    IAM_LOGI("OnReceiveEvent %{public}s, userId = %{public}d", action.c_str(), userId);
    if (userId == INVALID_USER_ID) {
        IAM_LOGE("Event userId invalid");
        return;
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) {
        RiskEventManager::GetInstance().OnScreenLock();
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS