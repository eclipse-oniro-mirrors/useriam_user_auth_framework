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

#include "custom_command.h"
#include "iam_ptr.h"

#include "executor.h"
#include "mock_iauth_executor_hdi.h"
#include "mock_iexecutor_messenger.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIam;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CustomCommandUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CustomCommandUnitTest::SetUpTestCase()
{
}

void CustomCommandUnitTest::TearDownTestCase()
{
}

void CustomCommandUnitTest::SetUp()
{
}

void CustomCommandUnitTest::TearDown()
{
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_OnResultTest_001, TestSize.Level0)
{
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
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    command->OnResult(ResultCode::SUCCESS);
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_OnResultTest_002, TestSize.Level0)
{
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
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    command->OnResult(ResultCode::GENERAL_ERROR);
    command->OnResult(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_OnResultWithExtraInfo, TestSize.Level0)
{
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
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    std::vector<uint8_t> extraInfo = {1, 2, 3};
    command->OnResult(ResultCode::SUCCESS, extraInfo);
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_SendRequest_001, TestSize.Level0)
{
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
    EXPECT_CALL(*executorHdi, SendCommand(_, _, _))
        .Times(Exactly(1))
        .WillOnce([](PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
                      const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
            return ResultCode::SUCCESS;
        });
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_INIT_ALGORITHM);
    attr.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, {1, 2, 3});
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    ResultCode ret = command->StartProcess();
    EXPECT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_SendRequest_Fail, TestSize.Level0)
{
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
    EXPECT_CALL(*executorHdi, SendCommand(_, _, _))
        .Times(Exactly(1))
        .WillOnce([](PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
                      const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
            return ResultCode::GENERAL_ERROR;
        });
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_INIT_ALGORITHM);
    attr.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, {1, 2, 3});
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    ResultCode ret = command->StartProcess();
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_SendRequest_NoPropertyMode, TestSize.Level0)
{
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
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    ResultCode ret = command->StartProcess();
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_SendRequest_NoExtraInfo, TestSize.Level0)
{
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
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_INIT_ALGORITHM);
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    ResultCode ret = command->StartProcess();
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_GetResult_001, TestSize.Level0)
{
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
    EXPECT_CALL(*executorHdi, SendCommand(_, _, _))
        .Times(Exactly(1))
        .WillOnce([](PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
                      const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
            if (callbackObj != nullptr) {
                callbackObj->OnResult(ResultCode::SUCCESS);
            }
            return ResultCode::SUCCESS;
        });
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_INIT_ALGORITHM);
    attr.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, {1, 2, 3});
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    ResultCode startRet = command->StartProcess();
    EXPECT_EQ(startRet, ResultCode::SUCCESS);
    ResultCode resultRet = command->GetResult();
    EXPECT_EQ(resultRet, ResultCode::SUCCESS);
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_GetResult_BeforeSend, TestSize.Level0)
{
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
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    ResultCode ret = command->GetResult();
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_OnHdiDisconnect, TestSize.Level0)
{
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
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    command->OnHdiDisconnect();
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_StartProcess_ExecutorNull, TestSize.Level0)
{
    std::weak_ptr<Executor> weakExecutor;
    Attributes attr;
    auto command = Common::MakeShared<CustomCommand>(weakExecutor, attr);
    ASSERT_NE(command, nullptr);
    ResultCode ret = command->StartProcess();
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_OnAcquireInfo, TestSize.Level0)
{
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
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    command->OnAcquireInfo(1, {1, 2, 3});
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_OnMessage, TestSize.Level0)
{
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
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    command->OnMessage(1, {1, 2, 3});
}

HWTEST_F(CustomCommandUnitTest, CustomCommand_GetAuthType, TestSize.Level0)
{
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
    auto executor = Common::MakeShared<Executor>(nullptr, executorHdi, 3);
    ASSERT_NE(executor, nullptr);
    Attributes attr;
    auto command = Common::MakeShared<CustomCommand>(executor, attr);
    ASSERT_NE(command, nullptr);
    int32_t authType = command->GetAuthType();
    EXPECT_EQ(authType, static_cast<int32_t>(1));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
