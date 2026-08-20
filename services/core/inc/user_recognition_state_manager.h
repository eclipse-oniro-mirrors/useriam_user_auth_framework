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

#ifndef IAM_USER_RECOGNITION_STATE_MANAGER_H
#define IAM_USER_RECOGNITION_STATE_MANAGER_H

#include <memory>

#include "iremote_object.h"
#include "user_recognition_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

class IUserRecognitionStateManager {
public:
    virtual ~IUserRecognitionStateManager() = default;
    virtual int32_t RegisterListener(int32_t callerType,
        const sptr<IUserRecognitionCallback> &listener) = 0;
    virtual int32_t UnregisterListener(const sptr<IUserRecognitionCallback> &listener) = 0;
    virtual void OnUserRecognitionEvent(const IpcUserRecognitionResult &result) = 0;
    virtual void SetUserRecognitionResult(IpcUserRecognitionResult result) = 0;
    virtual IpcUserRecognitionResult GetCachedUserRecognitionResult() = 0;
    virtual IpcUserRecognitionResult GetCachedUserRecognitionResultForCaller(int32_t callerType) = 0;
};

IUserRecognitionStateManager &GetUserRecognitionStateManager();
void SetUserRecognitionStateManager(std::shared_ptr<IUserRecognitionStateManager> manager);
std::shared_ptr<IUserRecognitionStateManager> CreateUserRecognitionStateManager();
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_USER_RECOGNITION_STATE_MANAGER_H
