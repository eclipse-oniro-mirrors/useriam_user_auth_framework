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

#include "context_arbitration_policy.h"

#include "iam_common_defines.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_CONTEXT_ARBITRATION_POLICY

namespace OHOS {
namespace UserIam {
namespace UserAuth {

bool ContextAdmissionPolicy::IsAuthContext(ContextType type)
{
    return type == ContextType::CONTEXT_SIMPLE_AUTH || type == ContextType::WIDGET_AUTH_CONTEXT ||
        type == ContextType::SUDO_AUTH_CONTEXT || type == ContextType::REMOTE_AUTH_CONTEXT ||
        type == ContextType::LOCAL_REMOTE_AUTH_CONTEXT;
}

bool ContextAdmissionPolicy::BearsPin(const Context &ctx)
{
    for (auto authType : ctx.GetAuthTypeList()) {
        if (authType == AuthType::PIN) {
            return true;
        }
    }
    return false;
}

bool BlockedBySudoPinContention(const Context &self, const Context &predecessor)
{
    int32_t userId = self.GetUserId();
    if (userId == INVALID_USER_ID || userId != predecessor.GetUserId()) {
        return false;
    }
    if (!ContextAdmissionPolicy::BearsPin(self) || !ContextAdmissionPolicy::BearsPin(predecessor)) {
        return false;
    }
    return self.GetAuthIntent() == AuthIntent::SUDO_PIN_AUTH ||
        predecessor.GetAuthIntent() == AuthIntent::SUDO_PIN_AUTH;
}

bool ContextAdmissionPolicy::CanStart(const Context &self,
    const std::vector<std::weak_ptr<Context>> &predecessors)
{
    if (!self.IsPrimaryContext() || !IsAuthContext(self.GetContextType())) {
        return true;
    }
    for (const auto &weakPredecessor : predecessors) {
        auto predecessor = weakPredecessor.lock();
        if (predecessor == nullptr || !predecessor->IsPrimaryContext() ||
            !IsAuthContext(predecessor->GetContextType())) {
            continue;
        }
        if (!BlockedBySudoPinContention(self, *predecessor)) {
            continue;
        }
        IAM_LOGI("context ****%{public}hx waits behind predecessor ****%{public}hx",
            static_cast<uint16_t>(self.GetContextId()),
            static_cast<uint16_t>(predecessor->GetContextId()));
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
