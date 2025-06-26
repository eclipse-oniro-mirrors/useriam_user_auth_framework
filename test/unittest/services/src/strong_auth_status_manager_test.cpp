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

#include "strong_auth_status_manager_test.h"

#include "strong_auth_status_manager.h"

#include "iam_logger.h"
#include "securec.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void StrongAuthStatusManagerTest::SetUpTestCase()
{
}

void StrongAuthStatusManagerTest::TearDownTestCase()
{
}

void StrongAuthStatusManagerTest::SetUp()
{
}

void StrongAuthStatusManagerTest::TearDown()
{
}

HWTEST_F(StrongAuthStatusManagerTest, RegisterStrongAuthListenerTest, TestSize.Level0)
{
    EXPECT_NO_THROW(StrongAuthStatusManager::Instance().RegisterStrongAuthListener());
    EXPECT_NO_THROW(StrongAuthStatusManager::Instance().RegisterStrongAuthListener());
    EXPECT_NO_THROW(StrongAuthStatusManager::Instance().SyncStrongAuthStatusForAllAccounts());
    EXPECT_NO_THROW(StrongAuthStatusManager::Instance().UnRegisterStrongAuthListener());
    EXPECT_NO_THROW(StrongAuthStatusManager::Instance().UnRegisterStrongAuthListener());
}

HWTEST_F(StrongAuthStatusManagerTest, StartSubscribeTest, TestSize.Level0)
{
    EXPECT_NO_THROW(StrongAuthStatusManager::Instance().StartSubscribe());
    EXPECT_NO_THROW(StrongAuthStatusManager::Instance().StartSubscribe());
}

HWTEST_F(StrongAuthStatusManagerTest, IsScreenLockStrongAuthTest, TestSize.Level0)
{
    int32_t mainUserId = 100;
    int32_t inValidUserId = -1;
    EXPECT_NO_THROW(StrongAuthStatusManager::Instance().IsScreenLockStrongAuth(mainUserId));
    EXPECT_NO_THROW(StrongAuthStatusManager::Instance().IsScreenLockStrongAuth(inValidUserId));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS