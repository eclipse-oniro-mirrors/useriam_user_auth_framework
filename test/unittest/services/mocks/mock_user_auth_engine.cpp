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

#include "mock_user_auth_engine.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::shared_ptr<MockUserAuthEngine> MockUserAuthEngine::Holder::Get()
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (!mock_) {
        mock_ = std::make_shared<MockUserAuthEngine>();
    }
    return mock_;
}

void MockUserAuthEngine::Holder::Reset()
{
    std::lock_guard<std::mutex> guard(mutex_);
    mock_ = nullptr;
}

IUserAuthEngine &GetUserAuthEngine()
{
    return *MockUserAuthEngine::Holder::GetInstance().Get();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
