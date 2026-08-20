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

#ifndef USER_RECOGNITION_CALLBACK_SERVICE_H
#define USER_RECOGNITION_CALLBACK_SERVICE_H

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

#include "user_auth_client_callback.h"
#include "user_recognition_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserRecognitionCallbackService : public UserRecognitionCallbackStub {
public:
    UserRecognitionCallbackService() = default;
    ~UserRecognitionCallbackService() override = default;

    void AddListener(const std::shared_ptr<UserRecognitionEventListener> &listener);
    void AddListenerWithCatchUp(const std::shared_ptr<UserRecognitionEventListener> &listener);
    void RemoveListener(const std::shared_ptr<UserRecognitionEventListener> &listener);
    bool Empty() const;
    int32_t OnUserRecognitionEvent(const IpcUserRecognitionResult &result) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
    void MarkInactive();
    void ClearLatestResult();

private:
    mutable std::recursive_mutex mutex_;
    std::vector<std::shared_ptr<UserRecognitionEventListener>> listeners_;
    std::atomic<bool> active_ {true};
    std::optional<UserRecognitionResult> latestResult_;
};

UserRecognitionResult ConvertIpcUserRecognitionResult(const IpcUserRecognitionResult &result);
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_RECOGNITION_CALLBACK_SERVICE_H
