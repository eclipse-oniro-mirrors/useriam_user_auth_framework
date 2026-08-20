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

#include "device_manager_listener.h"
#include "framework_ready_listener.h"
#include "executor_mgr_wrapper.h"
#include "iam_check.h"
#include "iam_executor_framework_types.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_executor_iauth_driver_hdi.h"
#include "iam_executor_iauth_executor_hdi.h"

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_DRIVER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
Driver::Driver(const std::string &serviceName, HdiConfig hdiConfig)
    : serviceName_(serviceName), hdiConfig_(hdiConfig) {}

void Driver::Init()
{
    SubscribeDeviceManagerListener();
    SubscribeFrameworkReadyListener();
}

void Driver::SubscribeDeviceManagerListener()
{
    IAM_LOGI("SubscribeDeviceManagerListener");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto weakSelf = std::weak_ptr<Driver>(shared_from_this());
    deviceManagerListener_ = Common::MakeShared<DeviceManagerListener>(
        serviceName_,
        [weakSelf]() {
            auto self = weakSelf.lock();
            if (self != nullptr) {
                self->OnHdiConnect();
            }
        },
        [weakSelf]() {
            auto self = weakSelf.lock();
            if (self != nullptr) {
                self->OnHdiDisconnect();
            }
        });
    IF_FALSE_LOGE_AND_RETURN(deviceManagerListener_ != nullptr);
    deviceManagerListener_->Subscribe();
}

void Driver::SubscribeFrameworkReadyListener()
{
    IAM_LOGI("SubscribeFrameworkReadyListener");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto weakSelf = std::weak_ptr<Driver>(shared_from_this());
    frameworkReadyListener_ = Common::MakeShared<FrameworkReadyListener>(
        [weakSelf]() {
            auto self = weakSelf.lock();
            if (self != nullptr) {
                self->OnFrameworkReady();
            }
        },
        [weakSelf]() {
            auto self = weakSelf.lock();
            if (self != nullptr) {
                self->OnFrameworkDown();
            }
        });
    IF_FALSE_LOGE_AND_RETURN(frameworkReadyListener_ != nullptr);
    frameworkReadyListener_->Subscribe();
    bool isFwkReady = SystemParamManager::GetInstance().GetParam(FWK_READY_KEY, FALSE_STR) == TRUE_STR;
    if (isFwkReady) {
        OnFrameworkReady();
    }
}

void Driver::OnHdiConnect()
{
    IAM_LOGI("Driver start");
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
        IAM_LOGI("hdi %{public}s add success", executor->GetDescription());
    }

    if (isFwkReady_) {
        RegisterExecutors();
    } else {
        IF_FALSE_LOGE_AND_RETURN(frameworkReadyListener_ != nullptr);
        frameworkReadyListener_->EnsureRegisterExecutors();
    }
}

void Driver::OnHdiDisconnect()
{
    IAM_LOGI("Driver start");
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
}

void Driver::OnFrameworkReady()
{
    IAM_LOGI("Driver start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (frameworkReadyListener_) {
        frameworkReadyListener_->StopTimer();
    }

    if (isFwkReady_) {
        IAM_LOGI("already fwk ready, skip");
        return;
    }
    isFwkReady_ = true;
    if (!hdiConnected_) {
        IAM_LOGE("hdi not connected, skip");
        return;
    }

    RegisterExecutors();
}

void Driver::OnFrameworkDown()
{
    IAM_LOGI("Driver start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (frameworkReadyListener_) {
        frameworkReadyListener_->StopTimer();
    }

    if (!isFwkReady_) {
        IAM_LOGI("already fwk down, skip");
        return;
    }
    isFwkReady_ = false;
    IF_FALSE_LOGE_AND_RETURN(hdiConfig_.driver != nullptr);
    hdiConfig_.driver->OnFrameworkDown();
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
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
