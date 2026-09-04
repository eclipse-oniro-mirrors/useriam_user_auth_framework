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

#include "user_recognition_callback_service.h"

#include <algorithm>
#include <exception>

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SDK"
#define LOG_FILE_ID LOG_FILE_USER_RECOGNITION_CALLBACK_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
UserRecognitionResult ConvertIpcUserRecognitionResult(const IpcUserRecognitionResult &result)
{
    UserRecognitionResult clientResult;
    clientResult.status = UserRecognitionStatusFromInt(result.status);
    clientResult.userId = result.userId;
    clientResult.userInfo = result.userInfo;
    if (result.hasAuthTrustLevel) {
        clientResult.authTrustLevel = result.authTrustLevel;
    }
    return clientResult;
}

void UserRecognitionCallbackService::AddListener(const std::shared_ptr<UserRecognitionEventListener> &listener)
{
    IF_FALSE_LOGE_AND_RETURN(listener != nullptr);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (std::find(listeners_.begin(), listeners_.end(), listener) != listeners_.end()) {
        IAM_LOGI("listener already registered, skip");
        return;
    }
    listeners_.push_back(listener);
}

void UserRecognitionCallbackService::AddListenerWithCatchUp(
    const std::shared_ptr<UserRecognitionEventListener> &listener)
{
    IF_FALSE_LOGE_AND_RETURN(listener != nullptr);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (std::find(listeners_.begin(), listeners_.end(), listener) != listeners_.end()) {
        IAM_LOGI("listener already registered, skip catch-up");
        return;
    }
    listeners_.push_back(listener);
    if (latestResult_.has_value()) {
        try {
            listener->OnUserRecognitionEvent(*latestResult_);
        } catch (const std::exception &e) {
            IAM_LOGE("catch-up OnUserRecognitionEvent threw, isolating: %{public}s", e.what());
        } catch (...) {
            IAM_LOGE("catch-up OnUserRecognitionEvent threw non-exception, isolating");
        }
    }
}

void UserRecognitionCallbackService::RemoveListener(const std::shared_ptr<UserRecognitionEventListener> &listener)
{
    IF_FALSE_LOGE_AND_RETURN(listener != nullptr);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = std::find(listeners_.begin(), listeners_.end(), listener);
    if (it == listeners_.end()) {
        IAM_LOGI("listener not found, skip");
        return;
    }
    listeners_.erase(it);
}

bool UserRecognitionCallbackService::Empty() const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return listeners_.empty();
}

int32_t UserRecognitionCallbackService::OnUserRecognitionEvent(const IpcUserRecognitionResult &result)
{
    IAM_LOGI("OnUserRecognitionEvent, status:%{public}d, userId:%{public}d", result.status, result.userId);
    if (!active_.load()) {
        IAM_LOGI("event arrived after UnRegister, dropping");
        return SUCCESS;
    }
    UserRecognitionResult clientResult = ConvertIpcUserRecognitionResult(result);
    std::vector<std::shared_ptr<UserRecognitionEventListener>> snapshot;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        latestResult_ = clientResult;
        snapshot = listeners_;
    }
    for (const auto &listener : snapshot) {
        if (listener == nullptr) {
            continue;
        }
        try {
            listener->OnUserRecognitionEvent(clientResult);
        } catch (const std::exception &e) {
            IAM_LOGE("OnUserRecognitionEvent listener threw, isolating: %{public}s", e.what());
        } catch (...) {
            IAM_LOGE("OnUserRecognitionEvent listener threw non-exception, isolating");
        }
    }
    return SUCCESS;
}

void UserRecognitionCallbackService::MarkInactive()
{
    active_.store(false);
}

void UserRecognitionCallbackService::ClearLatestResult()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    latestResult_.reset();
}

int32_t UserRecognitionCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGD("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t UserRecognitionCallbackService::CallbackExit([[maybe_unused]] uint32_t code,
    [[maybe_unused]] int32_t result)
{
    IAM_LOGD("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
