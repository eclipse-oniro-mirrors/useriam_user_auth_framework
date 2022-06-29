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
#ifndef IAM_MOCK_USER_AUTH_SERVICE_H
#define IAM_MOCK_USER_AUTH_SERVICE_H

#include <gmock/gmock.h>

#include "user_auth_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserAuthService final : public UserAuthStub {
public:
    MOCK_METHOD2(GetAvailableStatus, int32_t(AuthType authType, AuthTrustLevel authTrustLevel));

    MOCK_METHOD4(GetProperty,
        void(std::optional<int32_t> userId, AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
            sptr<GetExecutorPropertyCallback> &callback));

    MOCK_METHOD4(SetProperty, void(std::optional<int32_t> userId, AuthType authType, const Attributes &attributes,
                                  sptr<SetExecutorPropertyCallback> &callback));

    MOCK_METHOD5(AuthUser, uint64_t(std::optional<int32_t> userId, const std::vector<uint8_t> &challenge,
                               AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallback> &callback));

    MOCK_METHOD3(Identify,
        uint64_t(const std::vector<uint8_t> &challenge, AuthType authType, sptr<UserAuthCallback> &callback));

    MOCK_METHOD1(CancelAuthOrIdentify, int32_t(uint64_t contextId));
    MOCK_METHOD0(GetVersion, int32_t());
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_USER_AUTH_SERVICE_H