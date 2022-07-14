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

#ifndef USER_AUTH_CLIENT_IMPL_H
#define USER_AUTH_CLIENT_IMPL_H

#include "nocopyable.h"

#include "user_auth_client.h"
#include "user_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthClientImpl final : public UserAuthClient, NoCopyable {
public:
    int32_t GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel);
    void GetProperty(int32_t userId, const GetPropertyRequest &request,
        const std::shared_ptr<GetPropCallback> &callback) override;
    void SetProperty(int32_t userId, const SetPropertyRequest &request,
        const std::shared_ptr<SetPropCallback> &callback) override;
    uint64_t BeginAuthentication(int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel atl, const std::shared_ptr<AuthenticationCallback> &callback) override;
    int32_t CancelAuthentication(uint64_t contextId) override;
    uint64_t BeginIdentification(const std::vector<uint8_t> &challenge, AuthType authType,
        const std::shared_ptr<IdentificationCallback> &callback) override;
    int32_t CancelIdentification(uint64_t contextId) override;

private:
    friend class UserAuthClient;
    UserAuthClientImpl() = default;
    ~UserAuthClientImpl() override = default;

    constexpr static uint64_t INVALID_SESSION_ID {0};
    sptr<UserAuthInterface> GetProxy();
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CLIENT_IMPL_H