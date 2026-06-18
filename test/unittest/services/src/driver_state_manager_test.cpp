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

#include "driver_state_manager_test.h"

#include "driver_state_manager.h"

#include "iam_logger.h"
#include "securec.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_DRIVER_STATE_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void DriverStateManagerTest::SetUpTestCase()
{
}

void DriverStateManagerTest::TearDownTestCase()
{
}

void DriverStateManagerTest::SetUp()
{
}

void DriverStateManagerTest::TearDown()
{
}

HWTEST_F(DriverStateManagerTest, StartSubscribeTest, TestSize.Level0)
{
    EXPECT_NO_THROW(DriverStateManager::GetInstance().StartSubscribe());
    EXPECT_NO_THROW(DriverStateManager::GetInstance().StartSubscribe());
}

HWTEST_F(DriverStateManagerTest, OnDriverManagerAddTest, TestSize.Level0)
{
    EXPECT_NO_THROW(DriverStateManager::GetInstance().OnDriverManagerAdd());
}

HWTEST_F(DriverStateManagerTest, OnDriverStartTest, TestSize.Level0)
{
    EXPECT_NO_THROW(DriverStateManager::GetInstance().OnDriverStart());
    EXPECT_NO_THROW(DriverStateManager::GetInstance().OnDriverStart());
}

HWTEST_F(DriverStateManagerTest, OnDriverStopTest, TestSize.Level0)
{
    EXPECT_NO_THROW(DriverStateManager::GetInstance().OnDriverStop());
    EXPECT_NO_THROW(DriverStateManager::GetInstance().OnDriverStop());
    EXPECT_NO_THROW(DriverStateManager::GetInstance().OnDriverStart());
    EXPECT_NO_THROW(DriverStateManager::GetInstance().OnDriverStart());
}

HWTEST_F(DriverStateManagerTest, RegisterDriverStartCallbackTest, TestSize.Level0)
{
    EXPECT_NO_THROW(DriverStateManager::GetInstance().RegisterDriverStartCallback(nullptr));
    EXPECT_NO_THROW(DriverStateManager::GetInstance().RegisterDriverStartCallback([]() { return; }));
}

HWTEST_F(DriverStateManagerTest, RegisterDriverStopCallbackTest, TestSize.Level0)
{
    EXPECT_NO_THROW(DriverStateManager::GetInstance().RegisterDriverStopCallback(nullptr));
    EXPECT_NO_THROW(DriverStateManager::GetInstance().RegisterDriverStopCallback([]() { return; }));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
