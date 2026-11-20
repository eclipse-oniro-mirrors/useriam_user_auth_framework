/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "user_idm_database_impl.h"

#include <gtest/gtest.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class UserIdmDatabaseTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void UserIdmDatabaseTest::SetUpTestCase()
{
}

void UserIdmDatabaseTest::TearDownTestCase()
{
}

void UserIdmDatabaseTest::SetUp()
{
}

void UserIdmDatabaseTest::TearDown()
{
}

HWTEST_F(UserIdmDatabaseTest, EngineUnavailableTest, TestSize.Level0)
{
    auto &database = UserIdmDatabase::Instance();
    constexpr int32_t USER_ID = 100;
    std::shared_ptr<SecureUserInfoInterface> secUserInfo = nullptr;
    EXPECT_NE(database.GetSecUserInfo(USER_ID, secUserInfo), SUCCESS);

    std::vector<std::shared_ptr<CredentialInfoInterface>> infoRet = {};
    EXPECT_NE(database.GetCredentialInfo(USER_ID, FACE, infoRet), SUCCESS);

    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::vector<std::shared_ptr<CredentialInfoInterface>> testCredInfos;
    std::vector<uint8_t> rootSecret;
    EXPECT_NE(database.DeleteUser(USER_ID, testAuthToken, testCredInfos, rootSecret), SUCCESS);

    EXPECT_NE(database.DeleteUserEnforce(USER_ID, testCredInfos), SUCCESS);

    std::vector<std::shared_ptr<UserInfoInterface>> userInfos;
    EXPECT_NE(database.GetAllExtUserInfo(userInfos), SUCCESS);

    uint64_t credentialId = 0;
    std::shared_ptr<CredentialInfoInterface> credInfo;
    EXPECT_NE(database.GetCredentialInfoById(credentialId, credInfo), SUCCESS);

    EXPECT_NE(database.ClearUnavailableCredential(USER_ID, testCredInfos), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
