/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "driver.h"
#include "iam_ptr.h"
#include "mock_iauth_driver_hdi.h"
#include "mock_iauth_executor_hdi.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIam;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class DriverUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DriverUnitTest::SetUpTestCase()
{
}

void DriverUnitTest::TearDownTestCase()
{
}

void DriverUnitTest::SetUp()
{
}

void DriverUnitTest::TearDown()
{
}

HWTEST_F(DriverUnitTest, Driver_OnHdiConnect_001, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    auto driverHdi = MakeShared<MockIAuthDriverHdi>();
    ASSERT_NE(driverHdi, nullptr);
    config.driver = driverHdi;
    EXPECT_CALL(*driverHdi, GetExecutorList(_))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<IAuthExecutorHdi>> &executorList) {
            auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
            ASSERT_NE(executorHdi, nullptr);
            EXPECT_CALL(*executorHdi, GetExecutorInfo(_))
                .Times(AtLeast(1))
                .WillRepeatedly([](ExecutorInfo &info) {
                    info.authType = static_cast<AuthType>(1);
                    info.executorRole = static_cast<ExecutorRole>(2);
                    info.executorSensorHint = 10;
                    info.executorMatcher = 2;
                    info.esl = static_cast<ExecutorSecureLevel>(4);
                    info.publicKey = {5, 6, 7};
                    return ResultCode::SUCCESS;
                });
            executorList.push_back(executorHdi);
        });
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnHdiConnect();
}

HWTEST_F(DriverUnitTest, Driver_OnHdiConnect_002, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    config.driver = nullptr;
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnHdiConnect();
}

HWTEST_F(DriverUnitTest, Driver_OnHdiConnect_003, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    auto driverHdi = MakeShared<MockIAuthDriverHdi>();
    ASSERT_NE(driverHdi, nullptr);
    config.driver = driverHdi;
    EXPECT_CALL(*driverHdi, GetExecutorList(_))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<IAuthExecutorHdi>> &executorList) {
            executorList.clear();
        });
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnHdiConnect();
}

HWTEST_F(DriverUnitTest, Driver_OnHdiConnect_004, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    auto driverHdi = MakeShared<MockIAuthDriverHdi>();
    ASSERT_NE(driverHdi, nullptr);
    config.driver = driverHdi;
    EXPECT_CALL(*driverHdi, GetExecutorList(_))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<IAuthExecutorHdi>> &executorList) {
            executorList.push_back(nullptr);
        });
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnHdiConnect();
}

HWTEST_F(DriverUnitTest, Driver_OnHdiConnect_CallTwice, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    auto driverHdi = MakeShared<MockIAuthDriverHdi>();
    ASSERT_NE(driverHdi, nullptr);
    config.driver = driverHdi;
    EXPECT_CALL(*driverHdi, GetExecutorList(_))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<IAuthExecutorHdi>> &executorList) {
            auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
            ASSERT_NE(executorHdi, nullptr);
            EXPECT_CALL(*executorHdi, GetExecutorInfo(_))
                .Times(AtLeast(1))
                .WillRepeatedly([](ExecutorInfo &info) {
                    info.authType = static_cast<AuthType>(1);
                    info.executorRole = static_cast<ExecutorRole>(2);
                    info.executorSensorHint = 10;
                    info.executorMatcher = 2;
                    info.esl = static_cast<ExecutorSecureLevel>(4);
                    info.publicKey = {5, 6, 7};
                    return ResultCode::SUCCESS;
                });
            executorList.push_back(executorHdi);
        });
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnHdiConnect();
    driver->OnHdiConnect();
}

HWTEST_F(DriverUnitTest, Driver_OnHdiDisconnect_001, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    auto driverHdi = MakeShared<MockIAuthDriverHdi>();
    ASSERT_NE(driverHdi, nullptr);
    config.driver = driverHdi;
    EXPECT_CALL(*driverHdi, GetExecutorList(_))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<IAuthExecutorHdi>> &executorList) {
            auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
            ASSERT_NE(executorHdi, nullptr);
            EXPECT_CALL(*executorHdi, GetExecutorInfo(_))
                .Times(AtLeast(1))
                .WillRepeatedly([](ExecutorInfo &info) {
                    info.authType = static_cast<AuthType>(1);
                    info.executorRole = static_cast<ExecutorRole>(2);
                    info.executorSensorHint = 10;
                    info.executorMatcher = 2;
                    info.esl = static_cast<ExecutorSecureLevel>(4);
                    info.publicKey = {5, 6, 7};
                    return ResultCode::SUCCESS;
                });
            executorList.push_back(executorHdi);
        });
    EXPECT_CALL(*driverHdi, OnHdiDisconnect()).Times(Exactly(1));
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnHdiConnect();
    driver->OnHdiDisconnect();
}

HWTEST_F(DriverUnitTest, Driver_OnHdiDisconnect_002, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    config.driver = nullptr;
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnHdiDisconnect();
}

HWTEST_F(DriverUnitTest, Driver_OnFrameworkReady_001, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    auto driverHdi = MakeShared<MockIAuthDriverHdi>();
    ASSERT_NE(driverHdi, nullptr);
    config.driver = driverHdi;
    EXPECT_CALL(*driverHdi, GetExecutorList(_))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<IAuthExecutorHdi>> &executorList) {
            auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
            ASSERT_NE(executorHdi, nullptr);
            EXPECT_CALL(*executorHdi, GetExecutorInfo(_))
                .Times(AtLeast(1))
                .WillRepeatedly([](ExecutorInfo &info) {
                    info.authType = static_cast<AuthType>(1);
                    info.executorRole = static_cast<ExecutorRole>(2);
                    info.executorSensorHint = 10;
                    info.executorMatcher = 2;
                    info.esl = static_cast<ExecutorSecureLevel>(4);
                    info.publicKey = {5, 6, 7};
                    return ResultCode::SUCCESS;
                });
            executorList.push_back(executorHdi);
        });
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnHdiConnect();
    driver->OnFrameworkReady();
}

HWTEST_F(DriverUnitTest, Driver_OnFrameworkReady_NotConnected, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    config.driver = MakeShared<MockIAuthDriverHdi>();
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnFrameworkReady();
}

HWTEST_F(DriverUnitTest, Driver_OnFrameworkReady_CallTwice, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    auto driverHdi = MakeShared<MockIAuthDriverHdi>();
    ASSERT_NE(driverHdi, nullptr);
    config.driver = driverHdi;
    EXPECT_CALL(*driverHdi, GetExecutorList(_))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<IAuthExecutorHdi>> &executorList) {
            auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
            ASSERT_NE(executorHdi, nullptr);
            EXPECT_CALL(*executorHdi, GetExecutorInfo(_))
                .Times(AtLeast(1))
                .WillRepeatedly([](ExecutorInfo &info) {
                    info.authType = static_cast<AuthType>(1);
                    info.executorRole = static_cast<ExecutorRole>(2);
                    info.executorSensorHint = 10;
                    info.executorMatcher = 2;
                    info.esl = static_cast<ExecutorSecureLevel>(4);
                    info.publicKey = {5, 6, 7};
                    return ResultCode::SUCCESS;
                });
            executorList.push_back(executorHdi);
        });
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnHdiConnect();
    driver->OnFrameworkReady();
    driver->OnFrameworkReady();
}

HWTEST_F(DriverUnitTest, Driver_OnFrameworkDown_001, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    auto driverHdi = MakeShared<MockIAuthDriverHdi>();
    ASSERT_NE(driverHdi, nullptr);
    config.driver = driverHdi;
    EXPECT_CALL(*driverHdi, GetExecutorList(_))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<IAuthExecutorHdi>> &executorList) {
            auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
            ASSERT_NE(executorHdi, nullptr);
            EXPECT_CALL(*executorHdi, GetExecutorInfo(_))
                .Times(AtLeast(1))
                .WillRepeatedly([](ExecutorInfo &info) {
                    info.authType = static_cast<AuthType>(1);
                    info.executorRole = static_cast<ExecutorRole>(2);
                    info.executorSensorHint = 10;
                    info.executorMatcher = 2;
                    info.esl = static_cast<ExecutorSecureLevel>(4);
                    info.publicKey = {5, 6, 7};
                    return ResultCode::SUCCESS;
                });
                executorList.push_back(executorHdi);
        });
    EXPECT_CALL(*driverHdi, OnFrameworkDown()).Times(Exactly(1));
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->Init();
    driver->OnHdiConnect();
    driver->OnFrameworkReady();
    driver->OnFrameworkDown();
}

HWTEST_F(DriverUnitTest, Driver_OnFrameworkDown_002, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    config.driver = nullptr;
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnFrameworkDown();
}

HWTEST_F(DriverUnitTest, Driver_OnHdiConnect_MultipleExecutors, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 1;
    auto driverHdi = MakeShared<MockIAuthDriverHdi>();
    ASSERT_NE(driverHdi, nullptr);
    config.driver = driverHdi;
    EXPECT_CALL(*driverHdi, GetExecutorList(_))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<IAuthExecutorHdi>> &executorList) {
            for (int i = 0; i < 3; i++) {
                auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
                ASSERT_NE(executorHdi, nullptr);
                EXPECT_CALL(*executorHdi, GetExecutorInfo(_))
                    .Times(AtLeast(1))
                    .WillRepeatedly([i](ExecutorInfo &info) {
                        info.authType = static_cast<AuthType>(i + 1);
                        info.executorRole = static_cast<ExecutorRole>(2);
                        info.executorSensorHint = 10 + i;
                        info.executorMatcher = 2;
                        info.esl = static_cast<ExecutorSecureLevel>(4);
                        info.publicKey = {5, 6, 7};
                        return ResultCode::SUCCESS;
                    });
                executorList.push_back(executorHdi);
            }
        });
    EXPECT_CALL(*driverHdi, OnHdiDisconnect()).Times(Exactly(1));
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
    driver->OnHdiConnect();
    driver->OnHdiDisconnect();
}

HWTEST_F(DriverUnitTest, Driver_Constructor, TestSize.Level0)
{
    std::string serviceName = "test_service";
    HdiConfig config = {};
    config.id = 100;
    auto driver = MakeShared<Driver>(serviceName, config);
    ASSERT_NE(driver, nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
