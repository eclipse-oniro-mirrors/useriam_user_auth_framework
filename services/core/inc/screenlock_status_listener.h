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

#ifndef SCREENLOCK_STATUS_LISTENER_H
#define SCREENLOCK_STATUS_LISTENER_H

#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "system_ability_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using CommonEventSubscriber = OHOS::EventFwk::CommonEventSubscriber;
using CommonEventData = OHOS::EventFwk::CommonEventData;
using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;

class ScreenlockStatusListener : public CommonEventSubscriber {
public:
    explicit ScreenlockStatusListener(const CommonEventSubscribeInfo &subscriberInfo)
        : CommonEventSubscriber(subscriberInfo) {}
    ~ScreenlockStatusListener() = default;

    void OnReceiveEvent(const CommonEventData &data) override;
};

class ScreenlockStatusListenerManager {
public:
    static ScreenlockStatusListenerManager &GetInstance();

    ResultCode RegisterCommonEventListener();

private:
    ScreenlockStatusListenerManager() = default;
    ~ScreenlockStatusListenerManager() = default;

    void RegisterScreenLockedCallback();
    void UnRegisterScreenLockedCallback();
    void SyncScreenlockStatus();

    std::shared_ptr<ScreenlockStatusListener> subscriber_ {nullptr};
    sptr<SystemAbilityListener> commonEventSaStatusListener_ {nullptr};
    std::recursive_mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // SCREENLOCK_STATUS_LISTENER_H