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

#include "event_listener_callback_service.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_FILE_ID LOG_FILE_EVENT_LISTENER_CALLBACK_SERVICE
#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t EventListenerCallbackService::OnNotifyAuthSuccessEvent(int32_t userId, int32_t authType,
    const IpcAuthSuccessEventInfo &eventInfo)
{
    auto eventListenerSet = EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().GetEventListenerSet(
        static_cast<AuthType>(authType));
    IAM_LOGI("OnNotifyAuthSuccessEvent, userId:%{public}d, authType:%{public}d, callerName:%{public}s,"
        "listenerSize:%{public}zu", userId, authType, eventInfo.callerName.c_str(), eventListenerSet.size());
    for (const auto &listener : eventListenerSet) {
        if (listener == nullptr) {
            IAM_LOGE("authListener is nullptr");
            continue;
        }
        listener->OnNotifyAuthSuccessEvent(userId, static_cast<AuthType>(authType), {eventInfo.callerName,
            eventInfo.callerType, eventInfo.isWidgetAuth});
    }
    return SUCCESS;
}

int32_t EventListenerCallbackService::OnNotifyCredChangeEvent(int32_t userId, int32_t authType, int32_t eventType,
    const IpcCredChangeEventInfo &changeInfo)
{
    auto eventListenerSet = EventListenerCallbackManager<CredChangeEventListener>::GetInstance().GetEventListenerSet(
        static_cast<AuthType>(authType));
    IAM_LOGI("OnNotifyCredChangeEvent, userId:%{public}d, authType:%{public}d, eventType:%{public}d,"
        "callerName:%{public}s, credId:%{public}u, lastCredId:%{public}u, isSilent:%{public}u, size:%{public}zu",
        userId, authType, eventType, changeInfo.callerName.c_str(), static_cast<uint16_t>(changeInfo.credentialId),
        static_cast<uint16_t>(changeInfo.lastCredentialId), changeInfo.isSilentCredChange, eventListenerSet.size());
    for (const auto &listener : eventListenerSet) {
        if (listener == nullptr) {
            IAM_LOGE("credListener is nullptr");
            continue;
        }
        listener->OnNotifyCredChangeEvent(userId, static_cast<AuthType>(authType),
            static_cast<CredChangeEventType>(eventType), {changeInfo.callerName, changeInfo.callerType,
            changeInfo.credentialId, changeInfo.lastCredentialId, changeInfo.isSilentCredChange});
    }
    return SUCCESS;
}

sptr<EventListenerCallbackService> EventListenerCallbackService::GetInstance()
{
    static sptr<EventListenerCallbackService>instance(new (std::nothrow) EventListenerCallbackService());
    if (instance == nullptr) {
        IAM_LOGE("instance is nullptr");
    }
    return instance;
}

int32_t EventListenerCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t EventListenerCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS