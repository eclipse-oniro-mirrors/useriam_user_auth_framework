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

#include "driver.h"

#include "executor_mgr_wrapper.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_executor_iauth_driver_hdi.h"
#include "iam_executor_iauth_executor_hdi.h"
#include "relative_timer.h"
#include "system_param_manager.h"

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_DRIVER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
Driver::Driver(const std::string &serviceName, HdiConfig hdiConfig) : serviceName_(serviceName), hdiConfig_(hdiConfig)
{
}

void Driver::OnHdiConnect()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (hdiConnected_) {
        IAM_LOGI("already connected skip");
        return;
    }
    std::vector<std::shared_ptr<IAuthExecutorHdi>> executorHdiList;
    IF_FALSE_LOGE_AND_RETURN(hdiConfig_.driver != nullptr);
    hdiConfig_.driver->GetExecutorList(executorHdiList);
    IAM_LOGI("executorHdiList length is %{public}zu", executorHdiList.size());
    if (executorHdiList.empty()) {
        IAM_LOGE("executorHdiList is empty, hdiConnected fail.");
        return;
    }
    auto executorMgrWrapper = Common::MakeShared<ExecutorMgrWrapper>();
    IF_FALSE_LOGE_AND_RETURN(executorMgrWrapper != nullptr);
    hdiConnected_ = true;
    for (const auto &executorHdi : executorHdiList) {
        if (executorHdi == nullptr) {
            IAM_LOGI("executorHdi is nullptr, skip");
            continue;
        }
        auto executor = Common::MakeShared<Executor>(executorMgrWrapper, executorHdi, hdiConfig_.id);
        if (executor == nullptr) {
            IAM_LOGE("MakeShared failed");
            continue;
        }
        executorList_.push_back(executor);
        IAM_LOGI("add executor %{public}s success", executor->GetDescription());
    }

    if (isFwkReady_) {
        RegisterExecutors();
        return;
    }

    EnsureRegisterExecutors();
}

void Driver::EnsureRegisterExecutors()
{
    IAM_LOGI("start");
    if (SystemParamManager::GetInstance().GetParam(FWK_READY_KEY, FALSE_STR) == TRUE_STR) {
        IAM_LOGI("fwk ready, start register executors first");
        OnFrameworkReady();
        return;
    }

    if (checkFwkReadyTimerId_ != std::nullopt) {
        IAM_LOGI("fwk ready timer has existed, no need start again");
        return;
    }
    const uint32_t RETRY_CHECK_INTERVAL = 20000; //20s
    checkFwkReadyTimerId_ = RelativeTimer::GetInstance().Register(
        [weakSelf = std::weak_ptr<Driver>(shared_from_this())]() {
            if (SystemParamManager::GetInstance().GetParam(FWK_READY_KEY, FALSE_STR) == TRUE_STR) {
                IAM_LOGI("fwk ready, call OnFrameworkReady");
                auto self = weakSelf.lock();
                if (self != nullptr) {
                    self->OnFrameworkReady();
                }
            }
    }, RETRY_CHECK_INTERVAL, false);
}

void Driver::StopFwkReadyTimer()
{
    if (!checkFwkReadyTimerId_) {
        IAM_LOGI("fwk ready timer has stopped.");
        return;
    }

    RelativeTimer::GetInstance().Unregister(checkFwkReadyTimerId_.value());
    checkFwkReadyTimerId_ = std::nullopt;
}

void Driver::OnHdiDisconnect()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    hdiConnected_ = false;
    for (const auto &executor : executorList_) {
        if (executor == nullptr) {
            IAM_LOGE("executor is null");
            continue;
        }
        executor->OnHdiDisconnect();
    }
    executorList_.clear();

    IF_FALSE_LOGE_AND_RETURN(hdiConfig_.driver != nullptr);
    hdiConfig_.driver->OnHdiDisconnect();
    IAM_LOGI("success");
}

void Driver::OnFrameworkDown()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    StopFwkReadyTimer();
    isFwkReady_ = false;
    IF_FALSE_LOGE_AND_RETURN(hdiConfig_.driver != nullptr);
    hdiConfig_.driver->OnFrameworkDown();
    IAM_LOGI("success");
}

void Driver::OnFrameworkReady()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isFwkReady_) {
        IAM_LOGI("already fwk ready, skip");
        return;
    }
    isFwkReady_ = true;
    StopFwkReadyTimer();
    if (!hdiConnected_) {
        IAM_LOGE("hdi not connected, skip");
        return;
    }

    RegisterExecutors();
}

void Driver::RegisterExecutors()
{
    for (const auto &executor : executorList_) {
        if (executor == nullptr) {
            IAM_LOGE("executor is null");
            continue;
        }
        executor->Register();
    }
    IAM_LOGI("success");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
