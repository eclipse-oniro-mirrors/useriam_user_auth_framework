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

#include "driver_state_manager.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "iservice_registry.h"
#include "iservmgr_hdi.h"
#include "system_ability_definition.h"
#include "system_param_manager.h"

#include "co_auth_service.h"
#include "load_mode_handler.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_DRIVER_STATE_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
using namespace HDI;
using namespace HDI::ServiceManager::V1_0;
const char *SERVICE_NAME = "user_auth_interface_service";
class DriverManagerStatusListener : public ServStatListenerStub {
public:
    DriverManagerStatusListener() = default;
    ~DriverManagerStatusListener() override = default;

    void OnReceive(const ServiceStatus &status) override
    {
        if (status.serviceName != SERVICE_NAME) {
            return;
        }

        IAM_LOGI("receive service %{public}s status %{public}d", status.serviceName.c_str(), status.status);
        if (status.status == SERVIE_STATUS_START) {
            DriverStateManager::GetInstance().OnDriverStart();
        } else if (status.status == SERVIE_STATUS_STOP) {
            DriverStateManager::GetInstance().OnDriverStop();
        }
    }
};
} // namespace

DriverStateManager &DriverStateManager::GetInstance()
{
    static DriverStateManager instance;
    return instance;
}

void DriverStateManager::StartSubscribe()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isSubscribed_) {
        return;
    }

    if (driverManagerStatusListener_ == nullptr) {
        driverManagerStatusListener_ = SystemAbilityListener::Subscribe(
            "DriverManager", DEVICE_SERVICE_MANAGER_SA_ID,
            []() { DriverStateManager::GetInstance().OnDriverManagerAdd(); },
            []() { DriverStateManager::GetInstance().OnDriverManagerRemove(); });
        IF_FALSE_LOGE_AND_RETURN(driverManagerStatusListener_ != nullptr);
    }

    if (driverStatusListener_ == nullptr) {
        driverStatusListener_ = new (std::nothrow) DriverManagerStatusListener();
        IF_FALSE_LOGE_AND_RETURN(driverStatusListener_ != nullptr);
    }

    IAM_LOGI("success");
    isSubscribed_ = true;
}

void DriverStateManager::OnDriverManagerAdd()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("driver manager add");
    IF_FALSE_LOGE_AND_RETURN(driverStatusListener_ != nullptr);

    auto servMgr = IServiceManager::Get();
    IF_FALSE_LOGE_AND_RETURN(servMgr != nullptr);

    (void)servMgr->UnregisterServiceStatusListener(driverStatusListener_);
    int32_t ret = servMgr->RegisterServiceStatusListener(driverStatusListener_, DEVICE_CLASS_USERAUTH);
    IF_FALSE_LOGE_AND_RETURN(ret == 0);

    auto service = servMgr->GetService(SERVICE_NAME);
    if (service != nullptr) {
        OnDriverStart();
    } else {
        OnDriverStop();
    }
}

void DriverStateManager::OnDriverManagerRemove()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("driver manager remove");
    OnDriverStop();
}

void DriverStateManager::OnDriverStart()
{
    IAM_LOGI("driver start");
    std::vector<DriverUpdateCallback> startCallbacksTemp;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (isDriverRunning_.has_value() && isDriverRunning_.value()) {
            IAM_LOGI("driver already start");
            return;
        }
        isDriverRunning_ = true;
        startCallbacksTemp = startCallbacks_;
    }

    for (auto &callback : startCallbacksTemp) {
        if (callback != nullptr) {
            callback();
        }
    }

    IAM_LOGI("driver start processed");
}

void DriverStateManager::OnDriverStop()
{
    IAM_LOGI("driver stop");
    std::vector<DriverUpdateCallback> stopCallbacksTemp;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (!(isDriverRunning_.has_value() && isDriverRunning_.value())) {
            IAM_LOGI("driver already stop");
            return;
        }
        isDriverRunning_ = false;
        SystemParamManager::GetInstance().SetParam(FWK_READY_KEY, FALSE_STR);
        SystemParamManager::GetInstance().SetParam(IS_PIN_FUNCTION_READY_KEY, FALSE_STR);
        stopCallbacksTemp = stopCallbacks_;
    }

    for (const auto &callback : stopCallbacksTemp) {
        if (callback != nullptr) {
            callback();
        }
    }

    IAM_LOGI("driver stop processed");
}

void DriverStateManager::RegisterDriverStartCallback(const DriverUpdateCallback &callback)
{
    IAM_LOGI("register driver start callback");
    if (callback == nullptr) {
        IAM_LOGE("driver start callback is null");
        return;
    }

    bool triggerCallback = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        startCallbacks_.push_back(callback);
        if (isDriverRunning_.has_value() && isDriverRunning_.value()) {
            triggerCallback = true;
        }
    }

    if (triggerCallback) {
        callback();
    }
}

void DriverStateManager::RegisterDriverStopCallback(const DriverUpdateCallback &callback)
{
    IAM_LOGI("register driver stop callback");
    if (callback == nullptr) {
        IAM_LOGE("driver stop callback is null");
        return;
    }

    bool triggerCallback = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        stopCallbacks_.push_back(callback);
        if (isDriverRunning_.has_value() && !isDriverRunning_.value()) {
            triggerCallback = true;
        }
    }

    if (triggerCallback) {
        callback();
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS