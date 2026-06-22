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

#include "driver_manager.h"

#include <set>

#include "iservice_registry.h"
#include "iservmgr_hdi.h"
#include "parameter.h"
#include "system_ability_definition.h"
#include "hisysevent_adapter.h"

#include "auth_executor_mgr_status_listener.h"
#include "driver_manager_status_listener.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_time.h"

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_DRIVER_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
std::string GetParam(const std::string &key, const std::string &defaultValue)
{
    constexpr uint32_t MAX_VALUE_LEN = 128;
    char valueBuffer[MAX_VALUE_LEN] = { 0 };
    int32_t ret = GetParameter(key.c_str(), defaultValue.c_str(), valueBuffer, MAX_VALUE_LEN);
    if (ret < 0) {
        IAM_LOGE("get param failed, key %{public}s, ret %{public}d, use default value %{public}s", key.c_str(), ret,
            defaultValue.c_str());
        return defaultValue;
    }
    IAM_LOGI("get param key %{public}s value %{public}s", key.c_str(), valueBuffer);
    return std::string(valueBuffer);
}
}
using namespace HDI::ServiceManager::V1_0;
const char IAM_EVENT_KEY[] = "bootevent.useriam.fwkready";
DriverManager::DriverManager()
{
    SubscribeServiceStatus();
    SubscribeFrameworkReadyEvent();
}

int32_t DriverManager::Start(const std::map<std::string, HdiConfig> &hdiName2Config, bool hasHdi)
{
    IAM_LOGI("start");
    if (!HdiConfigIsValid(hdiName2Config)) {
        IAM_LOGE("service config is not valid");
        return USERAUTH_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    bool isFwkReady = GetParam(IAM_EVENT_KEY, "false") == "true";
    auto servMgr = IServiceManager::Get();
    IF_FALSE_LOGE_AND_RETURN_VAL(servMgr != nullptr, USERAUTH_ERROR);
    for (auto const &[hdiName, config] : hdiName2Config) {
        if (serviceName2Driver_.find(hdiName) != serviceName2Driver_.end()) {
            IAM_LOGI("%{public}s already added, skip", hdiName.c_str());
            continue;
        }
        auto driver = Common::MakeShared<Driver>(hdiName, config);
        if (driver == nullptr) {
            IAM_LOGE("MakeShared for driver %{public}s failed", hdiName.c_str());
            continue;
        }
        serviceName2Driver_[hdiName] = driver;
        if (hasHdi) {
            auto service = servMgr->GetService(hdiName.c_str());
            if (service != nullptr) {
                driver->OnHdiConnect();
            }
        } else {
            driver->OnHdiConnect();
        }
        if (isFwkReady) {
            driver->OnFrameworkReady();
        }

        IAM_LOGI("add driver %{public}s", hdiName.c_str());
    }
    IAM_LOGI("success");
    return USERAUTH_SUCCESS;
}

bool DriverManager::HdiConfigIsValid(const std::map<std::string, HdiConfig> &hdiName2Config)
{
    std::set<uint16_t> idSet;
    for (auto const &[hdiName, config] : hdiName2Config) {
        uint16_t id = config.id;
        if (idSet.find(id) != idSet.end()) {
            IAM_LOGE("duplicate hdi id %{public}hu", id);
            return false;
        }
        if (config.driver == nullptr) {
            IAM_LOGE("driver is nullptr");
            return false;
        }
        idSet.insert(id);
    }
    return true;
}

void DriverManager::SubscribeHdiDriverStatus()
{
    IAM_LOGI("start");
    auto servMgr = IServiceManager::Get();
    if (servMgr == nullptr) {
        IAM_LOGE("failed to get IServiceManager");
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (hdiServiceStatusListener_ != nullptr) {
        int32_t ret = servMgr->UnregisterServiceStatusListener(hdiServiceStatusListener_);
        hdiServiceStatusListener_ = nullptr;
        IAM_LOGI("UnregisterServiceStatusListener result %{public}d", ret);
    }

    HdiServiceStatusListener::StatusCallback callback = [](const ServiceStatus &status) {
        auto driver = DriverManager::GetInstance().GetDriverByServiceName(status.serviceName);
        if (driver == nullptr) {
            return;
        }

        IAM_LOGI("service %{public}s receive status %{public}d", status.serviceName.c_str(), status.status);
        switch (status.status) {
            case SERVIE_STATUS_START:
                IAM_LOGI("service %{public}s status change to start", status.serviceName.c_str());
                driver->OnHdiConnect();
                break;
            case SERVIE_STATUS_STOP:
                UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), status.serviceName);
                IAM_LOGI("service %{public}s status change to stop", status.serviceName.c_str());
                driver->OnHdiDisconnect();
                break;
            default:
                IAM_LOGI("service %{public}s status ignored", status.serviceName.c_str());
        }
    };

    hdiServiceStatusListener_ = sptr<HdiServiceStatusListener>(new (std::nothrow) HdiServiceStatusListener(callback));
    IF_FALSE_LOGE_AND_RETURN(hdiServiceStatusListener_ != nullptr);
#ifndef IAM_TEST_ENABLE
    int32_t ret = servMgr->RegisterServiceStatusListener(hdiServiceStatusListener_, DEVICE_CLASS_USERAUTH);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("failed to register service status listener");
        hdiServiceStatusListener_ = nullptr;
        return;
    }
#endif
    IAM_LOGI("success");
}

void DriverManager::SubscribeServiceStatus()
{
    IAM_LOGI("start");
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("failed to get SA manager");
        return;
    }

    auto driverManagerStatuslistener = DriverManagerStatusListener::GetInstance();
    IF_FALSE_LOGE_AND_RETURN(driverManagerStatuslistener != nullptr);
    int32_t ret = sam->SubscribeSystemAbility(DEVICE_SERVICE_MANAGER_SA_ID, driverManagerStatuslistener);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("failed to subscribe driver manager status");
        return;
    }

    auto authExecutorMgrStatuslistener = AuthExecutorMgrStatusListener::GetInstance();
    IF_FALSE_LOGE_AND_RETURN(authExecutorMgrStatuslistener != nullptr);
    ret = sam->SubscribeSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR,
        authExecutorMgrStatuslistener);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("failed to subscribe auto executor mgr status");
        return;
    }
    IAM_LOGI("success");
}

void DriverManager::SubscribeFrameworkReadyEvent()
{
    IAM_LOGI("start");
    auto eventCallback = [](const char *key, const char *value, void *context) {
        IAM_LOGI("receive useriam.fwkready event");
        IF_FALSE_LOGE_AND_RETURN(key != nullptr);
        IF_FALSE_LOGE_AND_RETURN(value != nullptr);
        if (strcmp(key, IAM_EVENT_KEY) != 0) {
            IAM_LOGE("event key mismatch");
            return;
        }
        if (strcmp(value, "true")) {
            IAM_LOGI("event value is not true");
            DriverManager::GetInstance().OnFrameworkDown();
        } else {
            IAM_LOGI("event value is true");
            DriverManager::GetInstance().OnFrameworkReady();
        }
    };
    int32_t ret = WatchParameter(IAM_EVENT_KEY, eventCallback, nullptr);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("WatchParameter fail");
        return;
    }
    IAM_LOGI("success");
}

void DriverManager::OnAllHdiDisconnect()
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (hdiServiceStatusListener_ == nullptr) {
        IAM_LOGE("HdiServiceStatusListener not added");
        return;
    }
    auto servMgr = IServiceManager::Get();
    if (servMgr != nullptr) {
        int32_t ret = servMgr->UnregisterServiceStatusListener(hdiServiceStatusListener_);
        IAM_LOGI("UnregisterServiceStatusListener result %{public}d", ret);
    }
    hdiServiceStatusListener_ = nullptr;
    for (auto const &pair : serviceName2Driver_) {
        if (pair.second == nullptr) {
            IAM_LOGE("pair.second is null");
            continue;
        }
        pair.second->OnHdiDisconnect();
    }
    IAM_LOGI("success");
}

void DriverManager::OnFrameworkReady()
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto const &pair : serviceName2Driver_) {
        if (pair.second == nullptr) {
            IAM_LOGE("pair.second is null");
            continue;
        }
        pair.second->OnFrameworkReady();
    }
    IAM_LOGI("success");
}

void DriverManager::OnFrameworkDown()
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto const &pair : serviceName2Driver_) {
        if (pair.second == nullptr) {
            IAM_LOGE("pair.second is null");
            continue;
        }
        pair.second->OnFrameworkDown();
    }
    IAM_LOGI("success");
}

std::shared_ptr<Driver> DriverManager::GetDriverByServiceName(const std::string &serviceName)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    auto driverIter = serviceName2Driver_.find(serviceName);
    if (driverIter == serviceName2Driver_.end()) {
        return nullptr;
    }
    return driverIter->second;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
