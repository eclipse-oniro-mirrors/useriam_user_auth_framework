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

#include "os_accounts_manager_test.h"

#include "os_accounts_manager.h"

#include "iam_logger.h"
#include "securec.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_OS_ACCOUNTS_MANAGER_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void OsAccountsManagerTest::SetUpTestCase()
{
}

void OsAccountsManagerTest::TearDownTestCase()
{
}

void OsAccountsManagerTest::SetUp()
{
}

void OsAccountsManagerTest::TearDown()
{
}

HWTEST_F(OsAccountsManagerTest, OnOsAccountSaAddRemoveTest, TestSize.Level0)
{
    EXPECT_NO_THROW(OsAccountsManager::Instance().OnOsAccountSaAdd());
    EXPECT_NO_THROW(OsAccountsManager::Instance().OnOsAccountSaAdd());
    EXPECT_NO_THROW(OsAccountsManager::Instance().OnOsAccountSaRemove());
    EXPECT_NO_THROW(OsAccountsManager::Instance().OnOsAccountSaRemove());
}

HWTEST_F(OsAccountsManagerTest, StartSubscribeTest, TestSize.Level0)
{
    EXPECT_NO_THROW(OsAccountsManager::Instance().StartSubscribe());
    EXPECT_NO_THROW(OsAccountsManager::Instance().StartSubscribe());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS