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

#ifndef FRAMEWORK_READY_LISTENER_H
#define FRAMEWORK_READY_LISTENER_H

#include <functional>
#include <mutex>
#include <optional>

#include "nocopyable.h"
#include "parameter.h"
#include "refbase.h"
#include "system_ability_listener.h"
#include "system_param_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class FrameworkReadyListener : public std::enable_shared_from_this<FrameworkReadyListener>, public NoCopyable {
public:
    using OnReadyCallback = std::function<void()>;
    using OnDownCallback = std::function<void()>;
    FrameworkReadyListener(OnReadyCallback onReady, OnDownCallback onDown);
    ~FrameworkReadyListener() override;

    void Subscribe();
    void StopTimer();
    void EnsureRegisterExecutors();

private:
    void SubscribeAuthExecutorMgrStatus();
    void SubscribeParameterWatcher();

    std::recursive_mutex mutex_;
    OnReadyCallback onFrameworkReadyFunc_;
    OnDownCallback onFrameworkDownFunc_;
    ParameterChgPtr eventCallback_ = {};
    sptr<SystemAbilityListener> authExecutorMgrListener_ = {};
    std::optional<int32_t> checkFwkReadyTimerId_ = std::nullopt;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // FRAMEWORK_READY_LISTENER_H