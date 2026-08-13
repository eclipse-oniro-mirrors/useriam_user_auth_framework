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

#include "vab_update_boot_listener.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "relative_timer.h"
#include "system_param_manager.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_VAB_UPDATE_BOOT_LISTENER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr uint32_t VAB_UPDATE_BOOT_MONITOR_INTERVAL_MS = 500;
constexpr int32_t MAX_VAB_UPDATE_BOOT_TIMER_COUNT = 40;

VabUpdateBootListener::VabUpdateBootListener(VabUpdateBootCallback cb) : callback_(cb)
{
}

VabUpdateBootListener::~VabUpdateBootListener()
{
    if (vabUpdateBootTimerId_.has_value()) {
        RelativeTimer::GetInstance().Unregister(vabUpdateBootTimerId_.value());
        vabUpdateBootTimerId_ = std::nullopt;
    }
}

std::shared_ptr<VabUpdateBootListener> VabUpdateBootListener::Start(VabUpdateBootCallback cb)
{
    IAM_LOGI("start");
    std::string vabUpdateBoot = SystemParamManager::GetInstance().GetParam(VAB_UPDATE_BOOT_KEY, "");
    if (vabUpdateBoot != "booting") {
        IAM_LOGI("vabUpdateBoot is not booting");
        return nullptr;
    }
    auto listener = Common::MakeShared<VabUpdateBootListener>(cb);
    if (listener == nullptr) {
        IAM_LOGE("listener is null");
        return nullptr;
    }
    listener->StartListen();
    return listener;
}

void VabUpdateBootListener::StartListen()
{
    IAM_LOGI("start");
    vabUpdateBootTimerId_ = RelativeTimer::GetInstance().Register(
        [weakSelf = weak_from_this()]() {
            auto sharedSelf = weakSelf.lock();
            if (sharedSelf == nullptr) {
                return;
            }
            sharedSelf->OnVabUpdateBoot();
        },
        VAB_UPDATE_BOOT_MONITOR_INTERVAL_MS,
        false);
}

void VabUpdateBootListener::HandleBootEvent()
{
    IAM_LOGI("start");
    if (vabUpdateBootTimerId_.has_value()) {
        RelativeTimer::GetInstance().Unregister(vabUpdateBootTimerId_.value());
        vabUpdateBootTimerId_ = std::nullopt;
    }

    callback_();
    callback_ = nullptr;
}

void VabUpdateBootListener::OnVabUpdateBoot()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (callback_ == nullptr) {
        IAM_LOGE("callback_ is null");
        return;
    }

    if (!isBootComplete_) {
        if (SystemParamManager::GetInstance().GetParam(BOOT_COMPLETE_KEY, FALSE_STR) != TRUE_STR) {
            return;
        }
        isBootComplete_ = true;
    }

    if (vabUpdateBootTimerCount_ > MAX_VAB_UPDATE_BOOT_TIMER_COUNT) {
        IAM_LOGE("vab update boot timer count reach limit: %{public}d", vabUpdateBootTimerCount_);
        HandleBootEvent();
        return;
    }

    vabUpdateBootTimerCount_++;
    std::string vabUpdateBoot = SystemParamManager::GetInstance().GetParam(VAB_UPDATE_BOOT_KEY, "");
    if (vabUpdateBoot == "booting") {
        return;
    }
    HandleBootEvent();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
