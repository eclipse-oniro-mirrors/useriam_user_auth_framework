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

#include "driver_load_manager.h"

#include "hisysevent_adapter.h"
#include "idevmgr_hdi.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "relative_timer.h"
#include "system_param_manager.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_DRIVER_LOAD_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
using namespace HDI::DeviceManager::V1_0;
const char *SERVICE_NAME = "user_auth_interface_service";
}

DriverLoadManager &DriverLoadManager::GetInstance()
{
    static DriverLoadManager instance;
    return instance;
}

void DriverLoadManager::StartSubscribe()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isSubscribed_) {
        return;
    }

    SystemParamManager::GetInstance().WatchParam(STOP_SA_KEY, [](const std::string &value) {
        IAM_LOGI("%{public}s changed, value %{public}s", STOP_SA_KEY, value.c_str());
        DriverLoadManager::GetInstance().OnSaStopping(value == TRUE_STR);
    });
    OnSaStopping(SystemParamManager::GetInstance().GetParam(STOP_SA_KEY, FALSE_STR) == TRUE_STR);

    IAM_LOGI("success");
    isSubscribed_ = true;
}

void DriverLoadManager::OnTimeout()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("timeout");
    timerId_ = std::nullopt;
    ProcessServiceStatus();
}

void DriverLoadManager::OnDriverStart()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("service start");
    isDriverRunning_ = true;
    ProcessServiceStatus();
}

void DriverLoadManager::OnDriverStop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("service stop");
    isDriverRunning_ = false;
    ProcessServiceStatus();
}

void DriverLoadManager::OnSaStopping(bool isStopping)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isSaStopping_ = isStopping;
    ProcessServiceStatus();
}

bool DriverLoadManager::LoadDriver()
{
    IAM_LOGI("start");
    auto devMgr = IDeviceManager::Get();
    IF_FALSE_LOGE_AND_RETURN_VAL(devMgr != nullptr, false);

    IAM_LOGI("load hdi service begin");
    int32_t loadDriverRet = devMgr->LoadDevice(SERVICE_NAME);
    if (loadDriverRet != 0) {
        IAM_LOGE("load %{public}s service failed, ret:%{public}d", SERVICE_NAME, loadDriverRet);
        SaLoadDriverFailureTrace saLoadDriverFailureTraceInfo = {};
        saLoadDriverFailureTraceInfo.errCode = loadDriverRet;
        UserIam::UserAuth::ReportSaLoadDriverFailure(saLoadDriverFailureTraceInfo);
        return false;
    }
    return true;
}

bool DriverLoadManager::UnloadDriver()
{
    IAM_LOGI("start");
    auto devMgr = IDeviceManager::Get();
    IF_FALSE_LOGE_AND_RETURN_VAL(devMgr != nullptr, false);

    if (devMgr->UnloadDevice(SERVICE_NAME) != 0) {
        IAM_LOGE("unload %{public}s service failed", SERVICE_NAME);
        return false;
    }
    return true;
}

void DriverLoadManager::ProcessServiceStatus()
{
    const uint32_t RETRY_LOAD_INTERVAL = 1000; // 1s

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    bool shouldRunning = !isSaStopping_;
    IAM_LOGI("process service %{public}s status %{public}d, isSaStopping_ %{public}d", SERVICE_NAME, isDriverRunning_,
        isSaStopping_);
    if (isDriverRunning_ != shouldRunning) {
        if (shouldRunning) {
            bool loadDriverRet = LoadDriver();
            if (loadDriverRet) {
                IAM_LOGI("load service %{public}s success", SERVICE_NAME);
                isDriverRunning_ = true;
            }
        } else {
            bool unloadDriverRet = UnloadDriver();
            if (unloadDriverRet) {
                IAM_LOGI("unload service %{public}s success", SERVICE_NAME);
                isDriverRunning_ = false;
            }
        }
    }

    if (isDriverRunning_ == shouldRunning) {
        if (timerId_ != std::nullopt) {
            RelativeTimer::GetInstance().Unregister(timerId_.value());
            timerId_ = std::nullopt;
        }
    } else {
        if (timerId_ == std::nullopt) {
            timerId_ = RelativeTimer::GetInstance().Register([this]() { OnTimeout(); }, RETRY_LOAD_INTERVAL);
            IAM_LOGI("process fail, retry after %{public}d ms", RETRY_LOAD_INTERVAL);
        }
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
