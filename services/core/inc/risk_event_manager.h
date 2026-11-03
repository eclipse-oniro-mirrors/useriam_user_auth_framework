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

#ifndef RISK_EVENT_MANAGER_H
#define RISK_EVENT_MANAGER_H

#include <vector>

#include "attributes.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RiskEventManager {
public:
    static RiskEventManager &GetInstance();

    void HandleStrongAuthEvent(int32_t userId);
    void SyncRiskEvents();
    void OnScreenLock();

#ifndef IAM_TEST_ENABLE
private:
#endif
    enum EventType : uint32_t {
        UNKNOWN = 0,
        SCREENLOCK_STRONG_AUTH = 1
    };

    RiskEventManager() = default;
    ~RiskEventManager() = default;

    void SetRiskEventPropertyForAuthType(int32_t userId, const AuthType authType,
        EventType event);
    ResultCode GetTemplateIdList(int32_t userId, const AuthType authType,
        std::vector<uint64_t> &templateIds);
    ResultCode GetStrongAuthExtraInfo(int32_t userId, const AuthType authType,
        std::vector<uint8_t> &extraInfo);
    ResultCode SetAttributes(int32_t userId, const AuthType authType,
        EventType event, Attributes &attributes);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // RISK_EVENT_MANAGER_H