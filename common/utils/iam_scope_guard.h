/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IAM_SCOPE_GUARD_H
#define IAM_SCOPE_GUARD_H

#include <functional>
#include <string>

#include "iam_defines.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace Common {
class IamScopeGuard : public NoCopyable {
public:
    using ExitAction = std::function<void()>;
    explicit IamScopeGuard(ExitAction &&action) : action_(std::forward<ExitAction>(action))
    {
    }
    ~IamScopeGuard() override
    {
        if (action_ != nullptr) {
            try {
                action_();
            } catch (...) {
                return;
            }
        }
    }

private:
    ExitAction action_;
};

#define ON_SCOPE_EXIT_ID(id, ...) auto exitGuard##id = OHOS::UserIam::Common::IamScopeGuard([]() { __VA_ARGS__; })

#define ON_SCOPE_EXIT(...) ON_SCOPE_EXIT_ID(__LINE__, __VA_ARGS__)
} // namespace Common
} // namespace UserIam
} // namespace OHOS

#endif // IAM_SCOPE_GUARD_H