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

#include "system_param_manager_test.h"

#include "system_param_manager.h"

#include "iam_logger.h"
#include "securec.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SYSTEM_PARAM_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void SystemParamManagerTest::SetUpTestCase()
{
}

void SystemParamManagerTest::TearDownTestCase()
{
}

void SystemParamManagerTest::SetUp()
{
}

void SystemParamManagerTest::TearDown()
{
}

HWTEST_F(SystemParamManagerTest, SetAndGetParamTest_001, TestSize.Level0)
{
    std::string oldParamStr = SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR);
    SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR);
    SystemParamManager::GetInstance().SetParam(IS_CREDENTIAL_CHECKED_KEY, TRUE_STR);
    bool newParamVal = SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR) ==
        TRUE_STR;
    EXPECT_EQ(newParamVal, true);
    SystemParamManager::GetInstance().SetParam(IS_CREDENTIAL_CHECKED_KEY, oldParamStr);
}

HWTEST_F(SystemParamManagerTest, SetAndGetParamTest_002, TestSize.Level0)
{
    const std::string UNKNOWN_PARAM = "useriam.unknownParam";
    bool getParamVal = SystemParamManager::GetInstance().GetParam(UNKNOWN_PARAM, FALSE_STR) ==
        TRUE_STR;
    EXPECT_EQ(getParamVal, false);
    SystemParamManager::GetInstance().SetParam(UNKNOWN_PARAM, FALSE_STR);
    SystemParamManager::GetInstance().SetParam(UNKNOWN_PARAM, FALSE_STR);
}

HWTEST_F(SystemParamManagerTest, SetParamTwiceTest, TestSize.Level0)
{
    std::string oldParamStr = SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR);
    SystemParamManager::GetInstance().SetParamTwice(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR, TRUE_STR);
    bool newParamVal = SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR) ==
        TRUE_STR;
    EXPECT_EQ(newParamVal, true);
    SystemParamManager::GetInstance().SetParamTwice(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR, TRUE_STR);
    SystemParamManager::GetInstance().SetParamTwice(IS_CREDENTIAL_CHECKED_KEY, TRUE_STR, TRUE_STR);
    SystemParamManager::GetInstance().SetParam(IS_CREDENTIAL_CHECKED_KEY, oldParamStr);
}

HWTEST_F(SystemParamManagerTest, WatchParamTest_001, TestSize.Level0)
{
    SystemParamManager::GetInstance().WatchParam(IS_CREDENTIAL_CHECKED_KEY, [](const std::string &value) {
        IAM_LOGI("%{public}s changed, value %{public}s", IS_CREDENTIAL_CHECKED_KEY, value.c_str());
    });
    SystemParamManager::GetInstance().WatchParam(IS_CREDENTIAL_CHECKED_KEY, [](const std::string &value) {
        IAM_LOGI("%{public}s changed again, value %{public}s", IS_CREDENTIAL_CHECKED_KEY, value.c_str());
    });
    std::string oldParamStr = SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR);
    SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR);
    SystemParamManager::GetInstance().SetParam(IS_CREDENTIAL_CHECKED_KEY, TRUE_STR);
    bool newParamVal = SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR) ==
        TRUE_STR;
    EXPECT_EQ(newParamVal, true);
    SystemParamManager::GetInstance().SetParam(IS_CREDENTIAL_CHECKED_KEY, oldParamStr);
}

HWTEST_F(SystemParamManagerTest, WatchParamTest_002, TestSize.Level0)
{
    SystemParamManager::GetInstance().WatchParam(IS_CREDENTIAL_CHECKED_KEY, [](const std::string &value) {
        IAM_LOGI("%{public}s changed, value %{public}s", IS_CREDENTIAL_CHECKED_KEY, value.c_str());
    });
    SystemParamManager::GetInstance().WatchParam(IS_CREDENTIAL_CHECKED_KEY, [](const std::string &value) {
        IAM_LOGI("%{public}s changed, value %{public}s", IS_CREDENTIAL_CHECKED_KEY, value.c_str());
    });
    std::string oldParamStr = SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR);
    SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR);
    SystemParamManager::GetInstance().SetParam(IS_CREDENTIAL_CHECKED_KEY, TRUE_STR);
    bool newParamVal = SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR) ==
        TRUE_STR;
    EXPECT_EQ(newParamVal, true);
    SystemParamManager::GetInstance().SetParam(IS_CREDENTIAL_CHECKED_KEY, oldParamStr);
}

HWTEST_F(SystemParamManagerTest, OnParamChangeTest_001, TestSize.Level0)
{
    std::string oldParamStr = SystemParamManager::GetInstance().GetParam(IS_CREDENTIAL_CHECKED_KEY, FALSE_STR);
    EXPECT_NO_THROW(SystemParamManager::GetInstance().OnParamChange(IS_CREDENTIAL_CHECKED_KEY, TRUE_STR));
    EXPECT_NO_THROW(SystemParamManager::GetInstance().OnParamChange(IS_CREDENTIAL_CHECKED_KEY, oldParamStr));
}

HWTEST_F(SystemParamManagerTest, OnParamChangeTest_002, TestSize.Level0)
{
    const std::string UNKNOWN_PARAM_CHANGE = "useriam.unknownParamChange";
    EXPECT_NO_THROW(SystemParamManager::GetInstance().OnParamChange(UNKNOWN_PARAM_CHANGE, TRUE_STR));
    EXPECT_NO_THROW(SystemParamManager::GetInstance().OnParamChange(UNKNOWN_PARAM_CHANGE, FALSE_STR));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
 