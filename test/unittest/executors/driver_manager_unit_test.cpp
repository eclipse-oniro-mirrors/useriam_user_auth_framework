/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "iam_ptr.h"

#include "driver_manager.h"
#include "iam_executor_idriver_manager.h"
#include "mock_iauth_driver_hdi.h"
#include "mock_iauth_executor_hdi.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::UserIam::UserAuth;
class DriverManagerUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DriverManagerUnitTest::SetUpTestCase()
{
}

void DriverManagerUnitTest::TearDownTestCase()
{
}

void DriverManagerUnitTest::SetUp()
{
}

void DriverManagerUnitTest::TearDown()
{
}

HWTEST_F(DriverManagerUnitTest, DriverManagerTest_001, TestSize.Level0)
{
    std::string serviceName = "mockDriver";
    HdiConfig config = {};
    config.id = 10;
    config.driver = nullptr;
    std::map<std::string, HdiConfig> hdiName2Config;
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config, true), USERAUTH_SUCCESS);
    hdiName2Config.emplace(serviceName, config);
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config, true), USERAUTH_ERROR);
    EXPECT_EQ(DriverManager::GetInstance().GetDriverByServiceName(serviceName), nullptr);
    config.driver = Common::MakeShared<MockIAuthDriverHdi>();
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config, true), USERAUTH_ERROR);
    DriverManager::GetInstance().GetDriverByServiceName(serviceName);
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config, true), USERAUTH_ERROR);
    DriverManager::GetInstance().OnFrameworkReady();
    DriverManager::GetInstance().SubscribeHdiDriverStatus();
    DriverManager::GetInstance().OnAllHdiDisconnect();
}

HWTEST_F(DriverManagerUnitTest, DriverManagerTest_002, TestSize.Level0)
{
    std::string serviceName = "mockDriver";
    HdiConfig config = {};
    config.id = 10;
    config.driver = nullptr;
    std::map<std::string, HdiConfig> hdiName2Config;
    EXPECT_EQ(IDriverManager::Start(hdiName2Config), USERAUTH_SUCCESS);
    hdiName2Config.emplace(serviceName, config);
    EXPECT_EQ(IDriverManager::Start(hdiName2Config), USERAUTH_ERROR);
    config.driver = Common::MakeShared<MockIAuthDriverHdi>();
    EXPECT_EQ(IDriverManager::Start(hdiName2Config), USERAUTH_ERROR);
}

HWTEST_F(DriverManagerUnitTest, DriverManagerTest_003, TestSize.Level0)
{
    std::string serviceName1 = "mockDriver1";
    std::string serviceName2 = "mockDriver2";
    HdiConfig config = {};
    config.id = 10;
    config.driver = Common::MakeShared<MockIAuthDriverHdi>();
    std::map<std::string, HdiConfig> hdiName2Config;
    hdiName2Config.emplace(serviceName1, config);
    EXPECT_EQ(DriverManager::GetInstance().HdiConfigIsValid(hdiName2Config), true);
    hdiName2Config.emplace(serviceName2, config);
    EXPECT_EQ(DriverManager::GetInstance().HdiConfigIsValid(hdiName2Config), false);
    EXPECT_EQ(IDriverManager::Start(hdiName2Config), USERAUTH_ERROR);
}

HWTEST_F(DriverManagerUnitTest, DriverManagerTest_004, TestSize.Level0)
{
    std::string serviceName = "mockDriver";
    HdiConfig config = {};
    config.id = 10;
    config.driver = Common::MakeShared<MockIAuthDriverHdi>();
    std::map<std::string, HdiConfig> hdiName2Config;
    hdiName2Config.emplace(serviceName, config);
    EXPECT_EQ(DriverManager::GetInstance().HdiConfigIsValid(hdiName2Config), true);
    std::shared_ptr<Driver> mockDriver = Common::MakeShared<Driver>(serviceName, config);
    DriverManager::GetInstance().serviceName2Driver_.emplace(serviceName, mockDriver);
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config, true), USERAUTH_SUCCESS);
    EXPECT_NE(DriverManager::GetInstance().GetDriverByServiceName(serviceName), nullptr);
    DriverManager::GetInstance().OnFrameworkReady();
    DriverManager::GetInstance().SubscribeHdiDriverStatus();
    DriverManager::GetInstance().OnAllHdiDisconnect();
}

HWTEST_F(DriverManagerUnitTest, DriverManagerTest_005, TestSize.Level0)
{
    std::string serviceName = "mockDriver";
    HdiConfig config = {};
    config.id = 10;
    config.driver = Common::MakeShared<MockIAuthDriverHdi>();
    std::map<std::string, HdiConfig> hdiName2Config;
    hdiName2Config.emplace(serviceName, config);
    EXPECT_EQ(DriverManager::GetInstance().HdiConfigIsValid(hdiName2Config), true);
    DriverManager::GetInstance().serviceName2Driver_.emplace(serviceName, nullptr);
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config, true), USERAUTH_SUCCESS);
    EXPECT_NE(DriverManager::GetInstance().GetDriverByServiceName(serviceName), nullptr);
    DriverManager::GetInstance().OnFrameworkReady();
    DriverManager::GetInstance().SubscribeHdiDriverStatus();
    DriverManager::GetInstance().OnAllHdiDisconnect();
    DriverManager::GetInstance().OnAllHdiDisconnect();
}

HWTEST_F(DriverManagerUnitTest, DriverManagerTest_006, TestSize.Level0)
{
    std::string serviceName = "mockDriverwer";
    std::string serviceName1 = "mockDriverxxxxx";

    HdiConfig config = {};
    config.id = 1690;
    config.driver = Common::MakeShared<MockIAuthDriverHdi>();
    std::map<std::string, HdiConfig> hdiName2Config;
    EXPECT_EQ(IDriverManager::Start(hdiName2Config), USERAUTH_SUCCESS);
    hdiName2Config.emplace(serviceName, config);
    DriverManager::GetInstance().serviceName2Driver_.emplace(serviceName1, nullptr);
    IDriverManager::Start(hdiName2Config, true);
}

HWTEST_F(DriverManagerUnitTest, DriverManagerTest_007, TestSize.Level0)
{
    std::string serviceName = "mockDriverwer1";
    std::string serviceName1 = "mockDriverxxxxx1";

    HdiConfig config = {};
    config.id = 16900;
    config.driver = Common::MakeShared<MockIAuthDriverHdi>();
    std::map<std::string, HdiConfig> hdiName2Config;
    EXPECT_EQ(IDriverManager::Start(hdiName2Config), USERAUTH_SUCCESS);
    hdiName2Config.emplace(serviceName, config);
    DriverManager::GetInstance().serviceName2Driver_.emplace(serviceName1, nullptr);
    IDriverManager::Start(hdiName2Config, false);
}

HWTEST_F(DriverManagerUnitTest, DriverManager_OnFrameworkDownTest_001, TestSize.Level0)
{
    std::string serviceName = "mockDriver";
    HdiConfig config = {};
    config.id = 10;
    config.driver = Common::MakeShared<MockIAuthDriverHdi>();
    std::map<std::string, HdiConfig> hdiName2Config;
    hdiName2Config.emplace(serviceName, config);
    EXPECT_EQ(DriverManager::GetInstance().HdiConfigIsValid(hdiName2Config), true);
    DriverManager::GetInstance().serviceName2Driver_.emplace(serviceName, nullptr);
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config, true), USERAUTH_SUCCESS);
    config.driver->OnFrameworkDown();
    DriverManager::GetInstance().OnFrameworkDown();
    for (auto const &pair : DriverManager::GetInstance().serviceName2Driver_) {
        if (pair.second == nullptr) {
            continue;
        }
        EXPECT_EQ(pair.second->isFwkReady_, false);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
