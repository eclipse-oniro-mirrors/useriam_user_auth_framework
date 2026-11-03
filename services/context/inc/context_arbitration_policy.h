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

#ifndef IAM_CONTEXT_ARBITRATION_POLICY_H
#define IAM_CONTEXT_ARBITRATION_POLICY_H

#include <memory>
#include <vector>

#include "context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

class ContextAdmissionPolicy {
public:
    static bool IsAuthContext(ContextType type);
    static bool BearsPin(const Context &ctx);
    static bool CanStart(const Context &self, const std::vector<std::weak_ptr<Context>> &predecessors);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CONTEXT_ARBITRATION_POLICY_H
