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

#ifndef IAM_USER_RECOGNITION_STATE_MANAGER_IMPL_H
#define IAM_USER_RECOGNITION_STATE_MANAGER_IMPL_H

#include <map>
#include <memory>
#include <mutex>

#include "callback_death_recipient.h"
#include "user_recognition_state_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

class UserRecognitionStateManager final : public IUserRecognitionStateManager,
                                         public std::enable_shared_from_this<UserRecognitionStateManager> {
public:
    ~UserRecognitionStateManager() override = default;
    friend std::shared_ptr<IUserRecognitionStateManager> CreateUserRecognitionStateManager();

    int32_t RegisterListener(const sptr<IUserRecognitionCallback> &listener) override;
    int32_t UnregisterListener(const sptr<IUserRecognitionCallback> &listener) override;
    void OnUserRecognitionEvent(const IpcUserRecognitionResult &result) override;
    void SetUserRecognitionResult(IpcUserRecognitionResult result) override;
    IpcUserRecognitionResult GetCachedUserRecognitionResult() override;

private:
    UserRecognitionStateManager() = default;
    static bool IsSameRecognitionResult(const IpcUserRecognitionResult &a, const IpcUserRecognitionResult &b);

    struct ListenerEntry {
        sptr<IUserRecognitionCallback> callback;
        sptr<CallbackDeathRecipient> deathRecipient;
    };

    std::recursive_mutex mutex_;
    std::map<sptr<IRemoteObject>, ListenerEntry> listenerMap_;
    IpcUserRecognitionResult cachedResult_ {};
};

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_USER_RECOGNITION_STATE_MANAGER_IMPL_H
