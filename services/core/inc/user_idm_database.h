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

#ifndef IAM_USER_IDM_DATABASE_H
#define IAM_USER_IDM_DATABASE_H

#include <cstdint>
#include <memory>

#include "credential_info_impl.h"
#include "iam_common_defines.h"
#include "secure_user_info_impl.h"
#include "user_info_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserIdmDatabase {
public:
    static UserIdmDatabase &Instance();
#ifdef IAM_TEST_ENABLE
    static void SetInstanceForTesting(UserIdmDatabase *instance);
    static void ResetInstanceForTesting();
#endif
    virtual int32_t GetSecUserInfo(int32_t userId, std::shared_ptr<SecureUserInfoInterface> &secUserInfo) = 0;
    virtual int32_t GetCredentialInfo(int32_t userId, AuthType authType,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos) = 0;
    virtual int32_t DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos, std::vector<uint8_t> &rootSecret) = 0;
    virtual int32_t DeleteUserEnforce(int32_t userId,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos) = 0;
    virtual int32_t GetAllExtUserInfo(std::vector<std::shared_ptr<UserInfoInterface>> &userInfos) = 0;
    virtual int32_t GetCredentialInfoById(uint64_t credentialId,
        std::shared_ptr<CredentialInfoInterface> &credInfo) = 0;
    virtual int32_t ClearUnavailableCredential(int32_t userId,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_USER_IDM_DATABASE_H