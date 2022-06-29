/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_SERVICE_H
#define USER_AUTH_SERVICE_H

#include "user_auth_stub.h"

#include <string>
#include <system_ability.h>
#include <system_ability_definition.h>

#include "context_pool.h"
#include "resource_node_pool.h"
#include "user_idm_database.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthService : public SystemAbility, public UserAuthStub, public NoCopyable {
public:
    DECLARE_SYSTEM_ABILITY(UserAuthService);
    explicit UserAuthService(int32_t systemAbilityId, bool runOnCreate = false);
    ~UserAuthService() override = default;
    void OnStart() override;
    void OnStop() override;
    int32_t GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel) override;
    void GetProperty(std::optional<int32_t> userId, AuthType authType,
        const std::vector<Attributes::AttributeKey> &keys, sptr<GetExecutorPropertyCallback> &callback) override;
    void SetProperty(std::optional<int32_t> userId, AuthType authType, const Attributes &attributes,
        sptr<SetExecutorPropertyCallback> &callback) override;
    uint64_t AuthUser(std::optional<int32_t> userId, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, sptr<UserAuthCallback> &callback) override;
    uint64_t Identify(const std::vector<uint8_t> &challenge, AuthType authType,
        sptr<UserAuthCallback> &callback) override;
    int32_t CancelAuthOrIdentify(uint64_t contextId) override;
    int32_t GetVersion() override;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_SERVICE_H