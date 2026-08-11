/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "framework_ready_listener.h"

#include "iam_check.h"
#include "iam_executor_framework_types.h"
#include "iam_logger.h"
#include "iam_time.h"
#include "relative_timer.h"
#include "hisysevent_adapter.h"
#include "system_ability_definition.h"

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_FRAMEWORK_READY_LISTENER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
FrameworkReadyListener::FrameworkReadyListener(OnReadyCallback onReady, OnDownCallback onDown)
    : onFrameworkReadyFunc_(std::move(onReady)), onFrameworkDownFunc_(std::move(onDown)) {}

FrameworkReadyListener::~FrameworkReadyListener()
{
    IAM_LOGI("framework ready destory");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (authExecutorMgrListener_) {
        int32_t ret = SystemAbilityListener::UnSubscribe(SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR,
            authExecutorMgrListener_);
        IAM_LOGI("UnSubscribe authExecutorMgr result %{public}d", ret);
        authExecutorMgrListener_ = nullptr;
    }
    if (eventCallback_) {
        int32_t ret = RemoveParameterWatcher(FWK_READY_KEY, eventCallback_, this);
        eventCallback_ = nullptr;
        IAM_LOGI("RemoveParameterWatcher ret:%{public}d", ret);
    }
    StopTimer();
}

void FrameworkReadyListener::Subscribe()
{
    IAM_LOGI("FrameworkReadyListener subscribe");
    SubscribeParameterWatcher();
    SubscribeAuthExecutorMgrStatus();
}

void FrameworkReadyListener::SubscribeParameterWatcher()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    eventCallback_ = [](const char *key, const char *value, void *context) {
        IF_FALSE_LOGE_AND_RETURN(key != nullptr);
        IF_FALSE_LOGE_AND_RETURN(value != nullptr);
        IF_FALSE_LOGE_AND_RETURN(context != nullptr);
        IF_FALSE_LOGE_AND_RETURN(strcmp(key, FWK_READY_KEY) == 0);

        auto *self = static_cast<FrameworkReadyListener *>(context);
        IF_FALSE_LOGE_AND_RETURN(self->onFrameworkDownFunc_ != nullptr);
        IF_FALSE_LOGE_AND_RETURN(self->onFrameworkReadyFunc_ != nullptr);
        if (strcmp(value, "true")) {
            self->onFrameworkDownFunc_();
        } else {
            self->onFrameworkReadyFunc_();
        }
    };
    int32_t ret = WatchParameter(FWK_READY_KEY, eventCallback_, this);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("WatchParameter fail");
        eventCallback_ = nullptr;
        return;
    }
}

void FrameworkReadyListener::SubscribeAuthExecutorMgrStatus()
{
    IAM_LOGI("subscribe auth executor mgr status");
    auto weakSelf = std::weak_ptr<FrameworkReadyListener>(shared_from_this());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    authExecutorMgrListener_ = SystemAbilityListener::Subscribe("FrameworkReadyListener",
        SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR,
        []() {},
        [weakSelf]() {
            auto self = weakSelf.lock();
            IF_FALSE_LOGE_AND_RETURN(self != nullptr);
            IAM_LOGE("auth executor mgr SA removed");
            UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "user_auth_framework");
            IF_FALSE_LOGE_AND_RETURN(self->onFrameworkDownFunc_ != nullptr);
            self->onFrameworkDownFunc_();
    });
}

void FrameworkReadyListener::StopTimer()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (checkFwkReadyTimerId_) {
        IAM_LOGI("FrameworkReadyListener stop timer");
        RelativeTimer::GetInstance().Unregister(checkFwkReadyTimerId_.value());
        checkFwkReadyTimerId_ = std::nullopt;
    }
}

void FrameworkReadyListener::EnsureRegisterExecutors()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (checkFwkReadyTimerId_ != std::nullopt) {
        IAM_LOGI("fwk ready timer has existed, no need start again");
        return;
    }
    const uint32_t RETRY_CHECK_INTERVAL = 20000;
    auto weakSelf = std::weak_ptr<FrameworkReadyListener>(shared_from_this());
    checkFwkReadyTimerId_ = RelativeTimer::GetInstance().Register(
        [weakSelf]() {
            auto self = weakSelf.lock();
            if (self == nullptr || self->onFrameworkReadyFunc_ == nullptr) {
                return;
            }
            if (SystemParamManager::GetInstance().GetParam(FWK_READY_KEY, FALSE_STR) == TRUE_STR) {
                IAM_LOGI("fwk ready, call OnFrameworkReady");
                self->onFrameworkReadyFunc_();
            }
    }, RETRY_CHECK_INTERVAL, false);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
