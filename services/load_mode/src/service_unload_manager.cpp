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

#include "service_unload_manager.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "relative_timer.h"
#include "system_param_manager.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SERVICE_UNLOAD_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ServiceUnloadManager &ServiceUnloadManager::GetInstance()
{
    static ServiceUnloadManager instance;
    return instance;
}

void ServiceUnloadManager::StartSubscribe()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (isSubscribed_) {
        return;
    }

    auto isPinEnrolledListener = [](const std::string &value) {
        bool isPinEnrolled = false;
        if (value == TRUE_STR) {
            isPinEnrolled = true;
        }
        ServiceUnloadManager::GetInstance().OnIsPinEnrolledChange(isPinEnrolled);
    };

    SystemParamManager::GetInstance().WatchParam(IS_PIN_ENROLLED_KEY, isPinEnrolledListener);
    bool isPinEnrolled = SystemParamManager::GetInstance().GetParam(IS_PIN_ENROLLED_KEY, FALSE_STR) == TRUE_STR;
    OnIsPinEnrolledChange(isPinEnrolled);

    auto startSaListener = [](const std::string &value) {
        bool startSa = false;
        if (value == TRUE_STR) {
            startSa = true;
        }
        ServiceUnloadManager::GetInstance().OnStartSaChange(startSa);
    };
    SystemParamManager::GetInstance().WatchParam(START_SA_KEY, startSaListener);

    bool startSa = SystemParamManager::GetInstance().GetParam(START_SA_KEY, FALSE_STR) == TRUE_STR;
    OnStartSaChange(startSa);

    auto isCredentialCheckedListener = [](const std::string &value) {
        bool isCredentialChecked = false;
        if (value == TRUE_STR) {
            isCredentialChecked = true;
        }
        ServiceUnloadManager::GetInstance().OnCredentialCheckedChange(isCredentialChecked);
    };
    SystemParamManager::GetInstance().WatchParam(IS_CREDENTIAL_CHECKED_KEY, isCredentialCheckedListener);
    bool isCredentialChecked = SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR) ==
        TRUE_STR;
    OnCredentialCheckedChange(isCredentialChecked);

    isSubscribed_ = true;
}

void ServiceUnloadManager::OnTimeout()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("timer timeout, stop sa");
    StopTimer();
    if (isPinEnrolled_) {
        IAM_LOGI("isPinEnrolled is true, not stop sa");
        return;
    }
    SystemParamManager::GetInstance().SetParamTwice(STOP_SA_KEY, FALSE_STR, TRUE_STR);
}

void ServiceUnloadManager::OnIsPinEnrolledChange(bool isPinEnrolled)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isPinEnrolled_ == isPinEnrolled) {
        return;
    }
    IAM_LOGI("isPinEnrolled change from %{public}d to %{public}d", isPinEnrolled_, isPinEnrolled);
    isPinEnrolled_ = isPinEnrolled;

    if (isPinEnrolled) {
        IAM_LOGI("isPinEnrolled is true, stop timer");
        StopTimer();
    } else {
        if (isCredentialChecked_) {
            IAM_LOGI("isPinEnrolled is false, isCredentialChecked is true, start timer");
            RestartTimer();
        } else {
            IAM_LOGI("isPinEnrolled is false, isCredentialChecked is false, not start timer");
        }
    }
}

void ServiceUnloadManager::OnStartSaChange(bool startSa)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (startSa_ == startSa) {
        return;
    }
    IAM_LOGI("startSa change from %{public}d to %{public}d", startSa_, startSa);
    startSa_ = startSa;
    if (!startSa) {
        return;
    }

    IAM_LOGI("start sa manually, start timer");
    RestartTimer();
}

void ServiceUnloadManager::RestartTimer()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const uint32_t TEN_MINUTE = 10 * 60 * 1000;
    IAM_LOGI("start timer");
    StopTimer();
    timerId_ =
        RelativeTimer::GetInstance().Register([]() { ServiceUnloadManager::GetInstance().OnTimeout(); }, TEN_MINUTE);
}

void ServiceUnloadManager::StopTimer()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (timerId_ == std::nullopt) {
        return;
    }
    IAM_LOGI("stop timer");
    RelativeTimer::GetInstance().Unregister(timerId_.value());
    timerId_ = std::nullopt;
}

void ServiceUnloadManager::OnCredentialCheckedChange(bool isCredentialChecked)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isCredentialChecked_ == isCredentialChecked) {
        return;
    }
    IAM_LOGI("isCredentialChecked change from %{public}d to %{public}d", isCredentialChecked_, isCredentialChecked);
    isCredentialChecked_ = isCredentialChecked;
}

void ServiceUnloadManager::OnFwkReady(bool &isStopSa)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isStopSa = false;
    isPinEnrolled_ = SystemParamManager::GetInstance().GetParam(IS_PIN_ENROLLED_KEY, FALSE_STR) == TRUE_STR;
    if (isPinEnrolled_) {
        IAM_LOGI("fwk ready, isPinEnrolled is true, sa should be running");
        return;
    }

    if (timerId_ != std::nullopt) {
        IAM_LOGI("fwk ready, timer is running, wait timer timeout");
        return;
    }

    IAM_LOGI("fwk ready, no pin and not manual start, stop sa");
    SystemParamManager::GetInstance().SetParamTwice(STOP_SA_KEY, FALSE_STR, TRUE_STR);
    isStopSa = true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
