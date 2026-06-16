/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "context_appstate_observer.h"

#include <sstream>

#include "context_pool.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#ifdef SCREENLOCK_CLIENT_ENABLE
#include "screenlock_manager.h"
#endif
#include "system_ability_definition.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::AppExecFwk;
namespace {
    constexpr std::uint32_t CONVERT_UID_TO_USERID = 200000;
}

sptr<IAppMgr> ContextAppStateObserverManager::GetAppManagerInstance()
{
    IAM_LOGD("start");
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        IAM_LOGE("systemAbilityManager is nullptr");
        return nullptr;
    }

    sptr<IRemoteObject> object = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (object == nullptr) {
        IAM_LOGE("systemAbilityManager remote object is nullptr");
        return nullptr;
    }

    return iface_cast<IAppMgr>(object);
}

void ContextAppStateObserverManager::SubscribeAppState(const std::shared_ptr<ContextCallback> &callback,
    const uint64_t contextId)
{
    IAM_LOGD("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);

    const std::string bundleName = callback->GetCallerName();
    if (bundleName.empty()) {
        IAM_LOGE("bundleName is null");
        return;
    }

    sptr<IAppMgr> appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        IAM_LOGE("GetAppManagerInstance failed");
        return;
    }

    if (appStateObserver_ != nullptr) {
        IAM_LOGI("appStateObserver_ already exists, unsubscribe first");
        appManager->UnregisterApplicationStateObserver(appStateObserver_);
        appStateObserver_ = nullptr;
    }

    appStateObserver_ = new (std::nothrow) ContextAppStateObserver(contextId, bundleName);
    if (appStateObserver_ == nullptr) {
        IAM_LOGE("get appStateObserver failed");
        return;
    }

    std::vector<std::string> bundleNameList;
    bundleNameList.emplace_back(bundleName);
    int32_t result = appManager->RegisterApplicationStateObserver(appStateObserver_, bundleNameList);
    if (result != SUCCESS) {
        IAM_LOGE("RegistApplicationStateObserver failed");
        appStateObserver_ = nullptr;
        return;
    }

    IAM_LOGI("SubscribeAppState success, contextId:****%{public}hx, bundleName:%{public}s",
        static_cast<uint16_t>(contextId), bundleName.c_str());
    return;
}

void ContextAppStateObserverManager::UnSubscribeAppState()
{
    IAM_LOGD("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (appStateObserver_ == nullptr) {
        IAM_LOGE("appStateObserver_ is nullptr");
        return;
    }

    sptr<IAppMgr> appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        IAM_LOGE("GetAppManagerInstance failed");
        return;
    }

    int32_t result = appManager->UnregisterApplicationStateObserver(appStateObserver_);
    if (result != SUCCESS) {
        IAM_LOGE("UnregisterApplicationStateObserver failed");
        return;
    }

    appStateObserver_ = nullptr;
    IAM_LOGI("UnSubscribeAppState success");
    return;
}

ContextAppStateObserverManager &ContextAppStateObserverManager::GetInstance()
{
    static ContextAppStateObserverManager instance;
    return instance;
}

bool ContextAppStateObserverManager::IsScreenLocked()
{
#ifdef SCREENLOCK_CLIENT_ENABLE
    auto screenLockInstance = ScreenLock::ScreenLockManager::GetInstance();
    if (screenLockInstance == nullptr) {
        IAM_LOGE("screenLockInstance is null");
        return false;
    }
    bool isScreenLocked = screenLockInstance->IsScreenLocked();
    IAM_LOGI("IsScreenLocked: %{public}d", isScreenLocked);
    return isScreenLocked;
#else
    return false;
#endif
}

ContextAppStateObserver::ContextAppStateObserver(const uint64_t contextId,
    const std::string bundleName) : contextId_(contextId), bundleName_(bundleName)
{
    IAM_LOGD("start");
}

void ContextAppStateObserver::ProcAppStateChanged(int32_t userId)
{
    IAM_LOGD("start");
    auto context = ContextPool::Instance().Select(contextId_).lock();
    if (context == nullptr) {
        IAM_LOGE("context is nullptr");
        return;
    }
    if (context->GetUserId() != userId) {
        IAM_LOGI("context userId is %{public}d, appStateChanged userId is %{public}d", context->GetUserId(), userId);
        return;
    }
    if (!context->Stop()) {
        IAM_LOGE("failed to cancel enroll or auth");
        return;
    }
    return;
}

void ContextAppStateObserver::OnAppStateChanged(const AppStateData &appStateData)
{
    auto bundleName = appStateData.bundleName;
    auto state = static_cast<ApplicationState>(appStateData.state);
    int32_t userId = appStateData.uid / CONVERT_UID_TO_USERID;
    IAM_LOGI("OnAppStateChanged, contextId: ****%{public}hx, userId:%{public}d, bundleName:%{public}s, "
        "state:%{public}d", static_cast<uint16_t>(contextId_), userId, bundleName.c_str(), state);

    if (bundleName.compare(bundleName_) == 0 && state == ApplicationState::APP_STATE_BACKGROUND) {
        ProcAppStateChanged(userId);
    }
    return;
}

void ContextAppStateObserver::OnForegroundApplicationChanged(const AppStateData &appStateData)
{
    auto bundleName = appStateData.bundleName;
    auto state = static_cast<ApplicationState>(appStateData.state);
    int32_t userId = appStateData.uid / CONVERT_UID_TO_USERID;
    IAM_LOGI("OnForegroundApplicationChanged, contextId: ****%{public}hx, userId:%{public}d, bundleName:%{public}s, "
        "state:%{public}d", static_cast<uint16_t>(contextId_), userId, bundleName.c_str(), state);

    if (bundleName.compare(bundleName_) == 0 && state == ApplicationState::APP_STATE_BACKGROUND) {
        ProcAppStateChanged(userId);
    }
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
