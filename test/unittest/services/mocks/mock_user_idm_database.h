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

#ifndef IAM_MOCK_USER_IDM_DATABASE_H
#define IAM_MOCK_USER_IDM_DATABASE_H

#include <cstdint>
#include <memory>
#include <vector>

#include <gmock/gmock.h>

#include "user_idm_database.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserIdmDatabase : public UserIdmDatabase {
public:
    MOCK_METHOD2(GetSecUserInfo, int32_t(int32_t userId, std::shared_ptr<SecureUserInfoInterface> &secUserInfo));
    MOCK_METHOD3(GetCredentialInfo, int32_t(int32_t userId, AuthType authType,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos));
    MOCK_METHOD4(DeleteUser, int32_t(int32_t userId, const std::vector<uint8_t> &authToken,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos, std::vector<uint8_t> &rootSecret));
    MOCK_METHOD2(DeleteUserEnforce, int32_t(int32_t userId,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos));
    MOCK_METHOD1(GetAllExtUserInfo, int32_t(std::vector<std::shared_ptr<UserInfoInterface>> &userInfos));
    MOCK_METHOD2(GetCredentialInfoById, int32_t(uint64_t credentialId,
        std::shared_ptr<CredentialInfoInterface> &credInfo));
    MOCK_METHOD2(ClearUnavailableCredential, int32_t(int32_t userId,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_USER_IDM_DATABASE_H
