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

#include "callback_manager.h"

#include <map>
#include <mutex>

#include "iam_logger.h"
#include "nocopyable.h"

#define LOG_TAG "USER_AUTH_SDK"
#define LOG_FILE_ID LOG_FILE_CALLBACK_MANAGER_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CallbackManagerImpl final : public CallbackManager, public NoCopyable {
public:
    void AddCallback(uintptr_t key, CallbackAction &action) override;
    void RemoveCallback(uintptr_t key) override;
    void OnServiceDeath() override;

private:
    friend class CallbackManager;
    CallbackManagerImpl() = default;
    ~CallbackManagerImpl() override;
};

CallbackManagerImpl::~CallbackManagerImpl()
{
    IAM_LOGD("start");
    OnServiceDeath();
}

void CallbackManagerImpl::AddCallback(uintptr_t key, CallbackAction &action)
{
    IAM_LOGD("start");
}

void CallbackManagerImpl::RemoveCallback(uintptr_t key)
{
    IAM_LOGD("start");
}

void CallbackManagerImpl::OnServiceDeath()
{
    IAM_LOGI("start");
}

CallbackManager &CallbackManager::GetInstance()
{
    static CallbackManagerImpl impl;
    return impl;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS