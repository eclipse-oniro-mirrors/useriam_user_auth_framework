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

#include <thread>
#include <pthread.h>

#include "executor.h"
#include "framework_executor_callback.h"
#include "iam_mem.h"
#include "iam_ptr.h"

#include "mock_executor_mgr_wrapper.h"
#include "mock_iasync_command.h"
#include "mock_iauth_driver_hdi.h"
#include "mock_iauth_executor_hdi.h"
#include "mock_iexecutor_messenger.h"

#define IF_FALSE_EXPECT_FAIL_AND_RETURN_VAL(cond, retVal) \
    do {                                                  \
        if (!(cond)) {                                    \
            EXPECT_TRUE(cond);                            \
            return (retVal);                              \
        }                                                 \
    } while (0)

using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIam;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint64_t TEST_TOKEN_ID = 123;
constexpr uint64_t TEST_SCHEDULE_ID = 456;
constexpr int32_t TEST_AUTH_INTENT = 1;
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_AUTH_SCENE = AUTH_SCENE_WIDGET_AUTH_NO_DISTURB;
const std::string TEST_WIDGET_TITLE = "test_widget_title";
const std::vector<uint64_t> TEST_TEMPLATE_ID_LIST = {7, 8, 9};
const std::vector<uint8_t> TEST_EXTRA_INFO = {4, 5, 6};
constexpr bool TEST_END_AFTER_FIRST_FAIL = true;

void SetAuthCommandAttributes(Attributes &attrs)
{
    attrs.SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    attrs.SetUint64ArrayValue(Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST, TEST_TEMPLATE_ID_LIST);
    attrs.SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, TEST_TOKEN_ID);
    attrs.SetUint32Value(Attributes::ATTR_USER_ID, TEST_USER_ID);
    attrs.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, TEST_EXTRA_INFO);
    attrs.SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, TEST_END_AFTER_FIRST_FAIL);
    attrs.SetInt32Value(Attributes::ATTR_AUTH_INTENTION, TEST_AUTH_INTENT);
    attrs.SetInt32Value(Attributes::ATTR_AUTH_SCENE, TEST_AUTH_SCENE);
    attrs.SetStringValue(Attributes::ATTR_WIDGET_TITLE, TEST_WIDGET_TITLE);
}
}

class ExecutorUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ExecutorUnitTest::SetUpTestCase()
{
}

void ExecutorUnitTest::TearDownTestCase()
{
}

void ExecutorUnitTest::SetUp()
{
}

void ExecutorUnitTest::TearDown()
{
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnHdiConnectTest_001, TestSize.Level0)
{
    const uint16_t testHdiId = 5;
    const ExecutorInfo testInfo = {
        .authType = static_cast<AuthType>(1),
        .executorRole = static_cast<ExecutorRole>(2),
        .executorSensorHint = 10,
        .executorMatcher = 2,
        .esl = static_cast<ExecutorSecureLevel>(4),
        .publicKey = {5, 6, 7},
    };
    auto executorMgrWrapper = MakeShared<MockExecutorMgrWrapper>();
    ASSERT_NE(executorMgrWrapper, nullptr);
    EXPECT_CALL(*executorMgrWrapper, Register(_, _))
        .Times(Exactly(1))
        .WillOnce([&testInfo](const ExecutorInfo &info, std::shared_ptr<ExecutorRegisterCallback> callback) {
            EXPECT_TRUE(static_cast<const uint32_t>(info.executorSensorHint) ==
                        Common::CombineUint16ToUint32(testHdiId, static_cast<uint16_t>(testInfo.executorSensorHint)));
            EXPECT_EQ(info.authType, testInfo.authType);
            EXPECT_EQ(info.executorRole, testInfo.executorRole);
            EXPECT_EQ(info.executorMatcher, testInfo.executorMatcher);
            EXPECT_EQ(info.esl, testInfo.esl);
            EXPECT_EQ(info.publicKey, testInfo.publicKey);
            EXPECT_NE(callback, nullptr);
            return 0;
        });
    auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
    ASSERT_NE(executorHdi, nullptr);
    EXPECT_CALL(*executorHdi, GetExecutorInfo(_)).Times(Exactly(2)).WillRepeatedly([&testInfo](ExecutorInfo &info) {
        info.executorSensorHint = testInfo.executorSensorHint;
        info.authType = testInfo.authType;
        info.executorRole = testInfo.executorRole;
        info.executorSensorHint = testInfo.executorSensorHint;
        info.executorMatcher = testInfo.executorMatcher;
        info.esl = testInfo.esl;
        info.publicKey.assign(testInfo.publicKey.begin(), testInfo.publicKey.end());
        return ResultCode::SUCCESS;
    });
    auto executor = MakeShared<Executor>(executorMgrWrapper, executorHdi, testHdiId);
    ASSERT_NE(executor, nullptr);
    executor->Register();
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnFrameworkReadyTest_001, TestSize.Level0)
{
    const uint16_t testHdiId = 5;
    const ExecutorInfo testInfo = {
        .authType = static_cast<AuthType>(1),
        .executorRole = static_cast<ExecutorRole>(2),
        .executorSensorHint = 10,
        .executorMatcher = 2,
        .esl = static_cast<ExecutorSecureLevel>(4),
        .publicKey = {5, 6, 7},
    };
    auto executorMgrWrapper = MakeShared<MockExecutorMgrWrapper>();
    ASSERT_NE(executorMgrWrapper, nullptr);
    EXPECT_CALL(*executorMgrWrapper, Register(_, _))
        .Times(Exactly(1))
        .WillOnce([&testInfo](const ExecutorInfo &info, std::shared_ptr<ExecutorRegisterCallback> callback) {
            EXPECT_TRUE(static_cast<const uint32_t>(info.executorSensorHint) ==
                        Common::CombineUint16ToUint32(testHdiId, static_cast<uint16_t>(testInfo.executorSensorHint)));
            EXPECT_EQ(info.authType, testInfo.authType);
            EXPECT_EQ(info.executorRole, testInfo.executorRole);
            EXPECT_EQ(info.executorMatcher, testInfo.executorMatcher);
            EXPECT_EQ(info.esl, testInfo.esl);
            EXPECT_EQ(info.publicKey, testInfo.publicKey);
            EXPECT_NE(callback, nullptr);
            return 0;
        });
    auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
    ASSERT_NE(executorHdi, nullptr);
    EXPECT_CALL(*executorHdi, GetExecutorInfo(_)).Times(Exactly(2)).WillRepeatedly([&testInfo](ExecutorInfo &info) {
        info.authType = testInfo.authType;
        info.executorRole = testInfo.executorRole;
        info.executorSensorHint = testInfo.executorSensorHint;
        info.executorMatcher = testInfo.executorMatcher;
        info.esl = testInfo.esl;
        info.publicKey.assign(testInfo.publicKey.begin(), testInfo.publicKey.end());
        return ResultCode::SUCCESS;
    });
    auto executor = MakeShared<Executor>(executorMgrWrapper, executorHdi, testHdiId);
    ASSERT_NE(executor, nullptr);
    executor->Register();
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnFrameworkReadyTest_002, TestSize.Level0)
{
    const uint16_t testHdiId = 5;
    const ExecutorInfo testInfo = {
        .authType = static_cast<AuthType>(1),
        .executorRole = static_cast<ExecutorRole>(2),
        .executorSensorHint = 10,
        .executorMatcher = 2,
        .esl = static_cast<ExecutorSecureLevel>(4),
        .publicKey = {5, 6, 7},
    };
    auto executorMgrWrapper = MakeShared<MockExecutorMgrWrapper>();
    ASSERT_NE(executorMgrWrapper, nullptr);
    EXPECT_CALL(*executorMgrWrapper, Register(_, _)).Times(Exactly(0));
    auto executor = MakeShared<Executor>(executorMgrWrapper, nullptr, testHdiId);
    ASSERT_NE(executor, nullptr);
    executor->Register();
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnFrameworkReadyTest_003, TestSize.Level0)
{
    const uint16_t testHdiId = 5;
    const ExecutorInfo testInfo = {
        .authType = static_cast<AuthType>(1),
        .executorRole = static_cast<ExecutorRole>(2),
        .executorSensorHint = 10,
        .executorMatcher = 2,
        .esl = static_cast<ExecutorSecureLevel>(4),
        .publicKey = {5, 6, 7},
    };
    auto executorMgrWrapper = MakeShared<MockExecutorMgrWrapper>();
    ASSERT_NE(executorMgrWrapper, nullptr);
    EXPECT_CALL(*executorMgrWrapper, Register(_, _)).Times(Exactly(0));
    auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
    ASSERT_NE(executorHdi, nullptr);
    EXPECT_CALL(*executorHdi, GetExecutorInfo(_)).Times(Exactly(2)).WillRepeatedly([&testInfo](ExecutorInfo &info) {
        return ResultCode::GENERAL_ERROR;
    });
    auto executor = MakeShared<Executor>(executorMgrWrapper, executorHdi, testHdiId);
    ASSERT_NE(executor, nullptr);
    executor->Register();
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnFrameworkReadyTest_004, TestSize.Level0)
{
    const uint16_t testHdiId = 5;
    const ExecutorInfo testInfo = {
        .authType = static_cast<AuthType>(1),
        .executorRole = static_cast<ExecutorRole>(2),
        .executorSensorHint = 10,
        .executorMatcher = 2,
        .esl = static_cast<ExecutorSecureLevel>(4),
        .publicKey = {5, 6, 7},
    };
    auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
    ASSERT_NE(executorHdi, nullptr);
    EXPECT_CALL(*executorHdi, GetExecutorInfo(_)).Times(Exactly(2)).WillRepeatedly([&testInfo](ExecutorInfo &info) {
        info.executorSensorHint = testInfo.executorSensorHint;
        info.authType = testInfo.authType;
        info.executorRole = testInfo.executorRole;
        info.executorMatcher = testInfo.executorMatcher;
        info.esl = testInfo.esl;
        info.publicKey.assign(testInfo.publicKey.begin(), testInfo.publicKey.end());
        return ResultCode::SUCCESS;
    });
    auto executor = MakeShared<Executor>(nullptr, executorHdi, testHdiId);
    ASSERT_NE(executor, nullptr);
    executor->Register();
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_CommandTest_001, TestSize.Level0)
{
    const uint16_t testHdiId = 5;
    auto executor = MakeShared<Executor>(nullptr, nullptr, testHdiId);
    ASSERT_NE(executor, nullptr);
    auto command1 = MakeShared<MockIAsyncCommand>();
    ASSERT_NE(command1, nullptr);
    EXPECT_CALL(*command1, OnHdiDisconnect()).Times(Exactly(1));
    auto command2 = MakeShared<MockIAsyncCommand>();
    ASSERT_NE(command2, nullptr);
    EXPECT_CALL(*command2, OnHdiDisconnect()).Times(Exactly(0));
    auto command3 = MakeShared<MockIAsyncCommand>();
    ASSERT_NE(command3, nullptr);
    EXPECT_CALL(*command3, OnHdiDisconnect()).Times(Exactly(1));
    executor->AddCommand(command1);
    executor->AddCommand(command1);
    executor->AddCommand(command2);
    executor->AddCommand(command3);
    executor->RemoveCommand(command2);
    executor->RemoveCommand(command3);
    executor->RemoveCommand(command3);
    executor->AddCommand(command3);
    executor->OnHdiDisconnect();
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_GetExecutorHdiTest_001, TestSize.Level0)
{
    const uint16_t testHdiId = 5;
    const uint64_t testExecutorId = 10;
    auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
    ASSERT_NE(executorHdi, nullptr);
    EXPECT_CALL(*executorHdi, GetExecutorInfo(_)).Times(Exactly(1)).WillOnce([&testExecutorId](ExecutorInfo &info) {
        return ResultCode::SUCCESS;
    });
    auto executor = MakeShared<Executor>(nullptr, executorHdi, testHdiId);
    ASSERT_NE(executor, nullptr);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_GetDescriptionTest_001, TestSize.Level0)
{
    const uint16_t testHdiId = 5;
    const uint64_t testExecutorId = 10;
    auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
    ASSERT_NE(executorHdi, nullptr);
    EXPECT_CALL(*executorHdi, GetExecutorInfo(_)).Times(Exactly(1)).WillOnce([&testExecutorId](ExecutorInfo &info) {
        info.executorSensorHint = testExecutorId;
        info.executorRole = COLLECTOR;
        info.authType = PIN;
        return ResultCode::SUCCESS;
    });
    auto executor = MakeShared<Executor>(nullptr, executorHdi, testHdiId);
    ASSERT_NE(executor, nullptr);
    const string correctDescription = "Executor(Id:0x0005000a, role:1, authType:1)";
    const char *description = executor->GetDescription();
    ASSERT_NE(description, nullptr);
    ASSERT_PRED2([](const char *toTest, const char *correct) { return strcmp(toTest, correct) == 0; }, description,
        correctDescription.c_str());
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_GetDescriptionTest_002, TestSize.Level0)
{
    const uint16_t testHdiId = 5;
    auto executor = MakeShared<Executor>(nullptr, nullptr, testHdiId);
    ASSERT_NE(executor, nullptr);
    const string correctDescription = "";
    const char *description = executor->GetDescription();
    ASSERT_NE(description, nullptr);
    ASSERT_PRED2([](const char *toTest, const char *correct) { return strcmp(toTest, correct) == 0; }, description,
        correctDescription.c_str());
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_GetDescriptionTest_003, TestSize.Level0)
{
    const uint16_t testHdiId = 5;
    auto executorHdi = MakeShared<MockIAuthExecutorHdi>();
    ASSERT_NE(executorHdi, nullptr);
    EXPECT_CALL(*executorHdi, GetExecutorInfo(_)).Times(Exactly(1)).WillOnce([](ExecutorInfo &info) {
        return ResultCode::GENERAL_ERROR;
    });
    auto executor = MakeShared<Executor>(nullptr, executorHdi, testHdiId);
    ASSERT_NE(executor, nullptr);
    const string correctDescription = "";
    const char *description = executor->GetDescription();
    ASSERT_NE(description, nullptr);
    ASSERT_PRED2([](const char *toTest, const char *correct) { return strcmp(toTest, correct) == 0; }, description,
        correctDescription.c_str());
}

namespace {
int32_t GetExecutorAndMockStub(shared_ptr<Executor> &executor, shared_ptr<ExecutorRegisterCallback> &executorCallback,
    shared_ptr<MockIAuthExecutorHdi> &mockExecutorHdi, std::shared_ptr<MockIExecutorMessenger> &mockMessenger)
{
    static const uint16_t testHdiId = 1;
    static std::vector<uint8_t> testPublicKey = {2, 3, 4, 5, 6};
    static std::vector<uint64_t> testTemplateIdList = {7, 8, 9, 10, 11};

    auto executorMgrWrapper = MakeShared<MockExecutorMgrWrapper>();
    IF_FALSE_EXPECT_FAIL_AND_RETURN_VAL(executorMgrWrapper != nullptr, ResultCode::GENERAL_ERROR);
    EXPECT_CALL(*executorMgrWrapper, Register(_, _))
        .Times(Exactly(1))
        .WillOnce([&executorCallback, &mockMessenger](const ExecutorInfo &info,
            std::shared_ptr<ExecutorRegisterCallback> callback) {
            EXPECT_NE(callback, nullptr);
            executorCallback = callback;
            auto messenger = MakeShared<MockIExecutorMessenger>();
            EXPECT_NE(messenger, nullptr);
            mockMessenger = messenger;
            executorCallback->OnMessengerReady(messenger, testPublicKey, testTemplateIdList);
            return 0;
        });

    mockExecutorHdi = MakeShared<MockIAuthExecutorHdi>();
    IF_FALSE_EXPECT_FAIL_AND_RETURN_VAL(mockExecutorHdi != nullptr, ResultCode::GENERAL_ERROR);
    EXPECT_CALL(*mockExecutorHdi, GetExecutorInfo(_)).Times(Exactly(2)).WillRepeatedly([](ExecutorInfo &info) {
        return ResultCode::SUCCESS;
    });
    EXPECT_CALL(*mockExecutorHdi, OnRegisterFinish(_, _, _))
        .Times(Exactly(1))
        .WillRepeatedly([](const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &frameworkPublicKey,
                            const std::vector<uint8_t> &extraInfo) {
            EXPECT_EQ(templateIdList, testTemplateIdList);
            EXPECT_EQ(frameworkPublicKey, testPublicKey);
            return ResultCode::SUCCESS;
        });

    executor = MakeShared<Executor>(executorMgrWrapper, mockExecutorHdi, testHdiId);
    IF_FALSE_EXPECT_FAIL_AND_RETURN_VAL(executor != nullptr, ResultCode::GENERAL_ERROR);
    executor->Register();

    IF_FALSE_EXPECT_FAIL_AND_RETURN_VAL(executorCallback != nullptr, ResultCode::GENERAL_ERROR);
    IF_FALSE_EXPECT_FAIL_AND_RETURN_VAL(mockMessenger != nullptr, ResultCode::GENERAL_ERROR);
    return ResultCode::SUCCESS;
}
} // namespace

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_CommonErrorTest_001, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    Attributes attr;
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, attr);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_CommonErrorTest_002, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    // Error: auth schedule mode not set
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_CommonErrorTest_003, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;
    static const uint32_t invalidScheduleMode = 78;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    // Error: invalid auth schedule mode
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, invalidScheduleMode);
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_ExecutorDisconnectTest_001, TestSize.Level0)
{
    static const int32_t testUserId = 100;
    static const uint64_t testTokenId = 123;
    static const uint64_t testScheduleId = 456;
    static const std::vector<uint8_t> testExtraInfo = {4, 5, 6};
    static const std::vector<uint8_t> testCallbackExtraInfo = {};

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Enroll(_, _, _))
        .Times(Exactly(2))
        .WillRepeatedly(
            [](uint64_t scheduleId, const EnrollParam &param,
                const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) { return ResultCode::SUCCESS; });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _))
        .Times(Exactly(2))
        .WillRepeatedly(
            [](uint64_t scheduleId, int32_t resultCode, const Attributes &finalResult) {
                EXPECT_EQ(scheduleId, testScheduleId);
                EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
                std::vector<uint8_t> extraInfo;
                EXPECT_EQ(finalResult.GetUint8ArrayValue(Attributes::ATTR_RESULT, extraInfo), true);
                EXPECT_EQ(extraInfo, testCallbackExtraInfo);
                return ResultCode::SUCCESS;
            });

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, ENROLL);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, testTokenId);
    commandAttrs->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, testExtraInfo);
    commandAttrs->SetUint32Value(Attributes::ATTR_USER_ID, testUserId);
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
    // Error: Simulate hdi disconnect
    executor->OnHdiDisconnect();
    executor->OnHdiDisconnect();
    executor->OnHdiDisconnect();
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_EnrollTest_001, TestSize.Level0)
{
    static const int32_t testUserId = 100;
    static const uint64_t testTokenId = 123;
    static const uint64_t testScheduleId = 456;
    static const std::vector<uint8_t> testExtraInfo = {4, 5, 6};

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback = nullptr;
    EXPECT_CALL(*mockExecutorHdi, Enroll(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&cmdCallback](uint64_t scheduleId, const EnrollParam &param,
                      const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
            EXPECT_EQ(scheduleId, testScheduleId);
            EXPECT_EQ(param.tokenId, testTokenId);
            EXPECT_EQ(param.extraInfo, testExtraInfo);
            cmdCallback = callbackObj;
            return ResultCode::SUCCESS;
        });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, ENROLL);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, testTokenId);
    commandAttrs->SetUint8ArrayValue(Attributes::AttributeKey::ATTR_EXTRA_INFO, testExtraInfo);
    commandAttrs->SetUint32Value(Attributes::ATTR_USER_ID, testUserId);
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_EnrollTest_002, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Enroll(_, _, _)).Times(Exactly(0));

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, ENROLL);
    // Error: missing Attributes::AttributeKey::ATTR_CALLER_UID
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_EnrollTest_003, TestSize.Level0)
{
    static const uint64_t testCallUid = 123;
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Enroll(_, _, _)).Times(Exactly(0));

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, ENROLL);
    commandAttrs->SetUint64Value(Attributes::AttributeKey::ATTR_CALLER_UID, testCallUid);
    // Error: Executor is disconnected
    executor->OnHdiDisconnect();
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthTest_001, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback = nullptr;
    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _))
        .Times(Exactly(1))
        .WillOnce(
            [&cmdCallback](
                uint64_t scheduleId, const AuthenticateParam &param,
                const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
                EXPECT_EQ(scheduleId, TEST_SCHEDULE_ID);
                EXPECT_EQ(param.tokenId, TEST_TOKEN_ID);
                EXPECT_EQ(param.templateIdList, TEST_TEMPLATE_ID_LIST);
                EXPECT_EQ(param.extraInfo, TEST_EXTRA_INFO);
                EXPECT_EQ(param.endAfterFirstFail, TEST_END_AFTER_FIRST_FAIL);
                EXPECT_EQ(param.authIntent, TEST_AUTH_INTENT);
                EXPECT_EQ(param.userId, TEST_USER_ID);
                EXPECT_EQ(param.authScene, static_cast<AuthScene>(TEST_AUTH_SCENE));
                EXPECT_EQ(param.title, TEST_WIDGET_TITLE);
                cmdCallback = callbackObj;
                return ResultCode::SUCCESS;
            });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    SetAuthCommandAttributes(*commandAttrs);
    ret = executorCallback->OnBeginExecute(TEST_SCHEDULE_ID, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthTest_002, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _)).Times(Exactly(0));

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    // Error: missing Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthTest_003, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;
    static const std::vector<uint64_t> testTemplateIdList = {7, 8, 9};

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _)).Times(Exactly(0));

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    commandAttrs->SetUint64ArrayValue(Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST, testTemplateIdList);
    // Error: missing Attributes::AttributeKey::ATTR_CALLER_UID
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthTest_004, TestSize.Level0)
{
    static const uint64_t testCallUid = 123;
    static const uint64_t testScheduleId = 456;
    static const std::vector<uint64_t> testTemplateIdList = {7, 8, 9};

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _)).Times(Exactly(0));

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    commandAttrs->SetUint64ArrayValue(Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST, testTemplateIdList);
    commandAttrs->SetUint64Value(Attributes::AttributeKey::ATTR_CALLER_UID, testCallUid);
    // Error: Executor is disconnected
    executor->OnHdiDisconnect();
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthTest_005, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback = nullptr;
    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _))
        .Times(Exactly(1))
        .WillOnce(
            [&cmdCallback](
                uint64_t scheduleId, const AuthenticateParam &param,
                const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
                EXPECT_EQ(scheduleId, TEST_SCHEDULE_ID);
                EXPECT_EQ(param.tokenId, TEST_TOKEN_ID);
                EXPECT_EQ(param.templateIdList, TEST_TEMPLATE_ID_LIST);
                EXPECT_EQ(param.extraInfo, TEST_EXTRA_INFO);
                EXPECT_EQ(param.endAfterFirstFail, TEST_END_AFTER_FIRST_FAIL);
                EXPECT_EQ(param.authIntent, TEST_AUTH_INTENT);
                EXPECT_EQ(param.userId, TEST_USER_ID);
                EXPECT_EQ(param.authScene, AUTH_SCENE_DEFAULT);
                EXPECT_EQ(param.title, "");
                cmdCallback = callbackObj;
                return ResultCode::SUCCESS;
            });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    commandAttrs->SetUint64ArrayValue(Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST, TEST_TEMPLATE_ID_LIST);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, TEST_TOKEN_ID);
    commandAttrs->SetUint32Value(Attributes::ATTR_USER_ID, TEST_USER_ID);
    commandAttrs->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, TEST_EXTRA_INFO);
    commandAttrs->SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, TEST_END_AFTER_FIRST_FAIL);
    commandAttrs->SetInt32Value(Attributes::ATTR_AUTH_INTENTION, TEST_AUTH_INTENT);
    ret = executorCallback->OnBeginExecute(TEST_SCHEDULE_ID, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthTest_006, TestSize.Level0)
{
    constexpr int32_t customAuthScene = AUTH_SCENE_WIDGET_AUTH_NO_DISTURB;
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback = nullptr;
    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _))
        .Times(Exactly(1))
        .WillOnce(
            [&cmdCallback, customAuthScene](
                uint64_t scheduleId, const AuthenticateParam &param,
                const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
                EXPECT_EQ(scheduleId, TEST_SCHEDULE_ID);
                EXPECT_EQ(param.tokenId, TEST_TOKEN_ID);
                EXPECT_EQ(param.templateIdList, TEST_TEMPLATE_ID_LIST);
                EXPECT_EQ(param.extraInfo, TEST_EXTRA_INFO);
                EXPECT_EQ(param.endAfterFirstFail, TEST_END_AFTER_FIRST_FAIL);
                EXPECT_EQ(param.authIntent, TEST_AUTH_INTENT);
                EXPECT_EQ(param.userId, TEST_USER_ID);
                EXPECT_EQ(param.authScene, static_cast<AuthScene>(customAuthScene));
                EXPECT_EQ(param.title, "");
                cmdCallback = callbackObj;
                return ResultCode::SUCCESS;
            });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    commandAttrs->SetUint64ArrayValue(Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST, TEST_TEMPLATE_ID_LIST);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, TEST_TOKEN_ID);
    commandAttrs->SetUint32Value(Attributes::ATTR_USER_ID, TEST_USER_ID);
    commandAttrs->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, TEST_EXTRA_INFO);
    commandAttrs->SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, TEST_END_AFTER_FIRST_FAIL);
    commandAttrs->SetInt32Value(Attributes::ATTR_AUTH_INTENTION, TEST_AUTH_INTENT);
    commandAttrs->SetInt32Value(Attributes::ATTR_AUTH_SCENE, customAuthScene);
    ret = executorCallback->OnBeginExecute(TEST_SCHEDULE_ID, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthTest_007, TestSize.Level0)
{
    const std::string customTitle = "custom_widget_title";
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback = nullptr;
    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _))
        .Times(Exactly(1))
        .WillOnce(
            [&cmdCallback, customTitle](
                uint64_t scheduleId, const AuthenticateParam &param,
                const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
                EXPECT_EQ(scheduleId, TEST_SCHEDULE_ID);
                EXPECT_EQ(param.tokenId, TEST_TOKEN_ID);
                EXPECT_EQ(param.templateIdList, TEST_TEMPLATE_ID_LIST);
                EXPECT_EQ(param.extraInfo, TEST_EXTRA_INFO);
                EXPECT_EQ(param.endAfterFirstFail, TEST_END_AFTER_FIRST_FAIL);
                EXPECT_EQ(param.authIntent, TEST_AUTH_INTENT);
                EXPECT_EQ(param.userId, TEST_USER_ID);
                EXPECT_EQ(param.authScene, AUTH_SCENE_DEFAULT);
                EXPECT_EQ(param.title, customTitle);
                cmdCallback = callbackObj;
                return ResultCode::SUCCESS;
            });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    commandAttrs->SetUint64ArrayValue(Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST, TEST_TEMPLATE_ID_LIST);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, TEST_TOKEN_ID);
    commandAttrs->SetUint32Value(Attributes::ATTR_USER_ID, TEST_USER_ID);
    commandAttrs->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, TEST_EXTRA_INFO);
    commandAttrs->SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, TEST_END_AFTER_FIRST_FAIL);
    commandAttrs->SetInt32Value(Attributes::ATTR_AUTH_INTENTION, TEST_AUTH_INTENT);
    commandAttrs->SetStringValue(Attributes::ATTR_WIDGET_TITLE, customTitle);
    ret = executorCallback->OnBeginExecute(TEST_SCHEDULE_ID, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_IdentifyTest_001, TestSize.Level0)
{
    static const uint64_t testTokenId = 123;
    static const uint64_t testScheduleId = 456;
    static const std::vector<uint8_t> testExtraInfo = {4, 5, 6};

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback = nullptr;
    EXPECT_CALL(*mockExecutorHdi, Identify(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&cmdCallback](uint64_t scheduleId, const IdentifyParam &param,
                      const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
            EXPECT_EQ(scheduleId, testScheduleId);
            EXPECT_EQ(param.tokenId, testTokenId);
            EXPECT_EQ(param.extraInfo, testExtraInfo);
            cmdCallback = callbackObj;
            return ResultCode::SUCCESS;
        });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, IDENTIFY);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, testTokenId);
    commandAttrs->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, testExtraInfo);
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_IdentifyTest_002, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Identify(_, _, _)).Times(Exactly(0));

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, IDENTIFY);
    // Error: missing Attributes::AttributeKey::ATTR_CALLER_UID
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_IdentifyTest_003, TestSize.Level0)
{
    static const uint64_t testCallUid = 123;
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Identify(_, _, _)).Times(Exactly(0));

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, IDENTIFY);
    commandAttrs->SetUint64Value(Attributes::AttributeKey::ATTR_CALLER_UID, testCallUid);
    // Error: Executor is disconnected
    executor->OnHdiDisconnect();
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AbandonTest_001, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Identify(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, ABANDON);
    executor->OnHdiDisconnect();
    ret = executorCallback->OnBeginExecute(testScheduleId, uselessPublicKey, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnEndExecute_Success, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Cancel(_)).Times(Exactly(1)).WillOnce([](uint64_t scheduleId) {
        EXPECT_EQ(scheduleId, testScheduleId);
        return ResultCode::SUCCESS;
    });

    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    ret = executorCallback->OnEndExecute(testScheduleId, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnEndExecute_ErrorTest_001, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Cancel(_)).Times(Exactly(1)).WillOnce([](uint64_t scheduleId) {
        EXPECT_EQ(scheduleId, testScheduleId);
        // Error: return error
        return ResultCode::GENERAL_ERROR;
    });

    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    ret = executorCallback->OnEndExecute(testScheduleId, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnEndExecute_ErrorTest_002, TestSize.Level0)
{
    static const uint64_t testScheduleId = 456;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Cancel(_)).Times(Exactly(0));

    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    // Error: Executor is disconnected
    executor->OnHdiDisconnect();
    ret = executorCallback->OnEndExecute(testScheduleId, *commandAttrs);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnEndExecute_ErrorTest_003, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnGetPropertyTest_001, TestSize.Level0)
{
    static const vector<uint64_t> testTemplateIds = { 1, 2, 3 };
    static const vector<uint32_t> testKeys = { 100021, 100010, 100009, 100035, 100036 };
    static const int32_t testFreezingTime = 456;
    static const int32_t testRemainTimes = 789;
    static const int32_t testAuthSubType = 101112;
    string testEnrollmentProgress = "abc";
    string testSensorInfo = "efg";

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, GetProperty(_, _, _))
        .Times(Exactly(1))
        .WillOnce([testEnrollmentProgress, testSensorInfo](const std::vector<uint64_t> &templateIdList,
            const std::vector<Attributes::AttributeKey> &keys, Property &property) {
            EXPECT_EQ(templateIdList, testTemplateIds);
            property.lockoutDuration = testFreezingTime;
            property.remainAttempts = testRemainTimes;
            property.authSubType = testAuthSubType;
            property.enrollmentProgress = testEnrollmentProgress;
            property.sensorInfo = testSensorInfo;
            return ResultCode::SUCCESS;
        });

    auto conditions = MakeShared<Attributes>();
    ASSERT_NE(conditions, nullptr);
    conditions->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    conditions->SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, testTemplateIds);
    conditions->SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, testKeys);
    auto values = MakeShared<Attributes>();
    ASSERT_NE(values, nullptr);
    ret = executorCallback->OnGetProperty(*conditions, *values);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
    int32_t pinAuthSubType;
    ASSERT_EQ(values->GetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, pinAuthSubType), true);
    ASSERT_EQ(pinAuthSubType, testAuthSubType);
    int32_t freezingTime;
    ASSERT_EQ(values->GetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime), true);
    ASSERT_EQ(freezingTime, testFreezingTime);
    int32_t remainTimes;
    ASSERT_EQ(values->GetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainTimes), true);
    ASSERT_EQ(remainTimes, testRemainTimes);
    string sensorInfo = "efg";
    ASSERT_EQ(values->GetStringValue(Attributes::ATTR_SENSOR_INFO, sensorInfo), true);
    ASSERT_EQ(sensorInfo, testSensorInfo);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnGetPropertyTest_002, TestSize.Level0)
{
    static const uint64_t testTemplateId = 123;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, GetProperty(_, _, _)).Times(Exactly(0));

    auto conditions = MakeShared<Attributes>();
    ASSERT_NE(conditions, nullptr);
    // Error: missing ATTR_PROPERTY_MODE
    conditions->SetUint64Value(Attributes::ATTR_TEMPLATE_ID, testTemplateId);
    auto values = MakeShared<Attributes>();
    ASSERT_NE(values, nullptr);
    ret = executorCallback->OnGetProperty(*conditions, *values);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnGetPropertyTest_003, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, GetProperty(_, _, _)).Times(Exactly(0));

    auto conditions = MakeShared<Attributes>();
    ASSERT_NE(conditions, nullptr);
    conditions->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    // Error: missing ATTR_TEMPLATE_ID
    auto values = MakeShared<Attributes>();
    ASSERT_NE(values, nullptr);
    ret = executorCallback->OnGetProperty(*conditions, *values);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnGetPropertyTest_004, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, GetProperty(_, _, _)).Times(Exactly(0));

    auto conditions = MakeShared<Attributes>();
    ASSERT_NE(conditions, nullptr);
    conditions->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    // Error: missing ATTR_TEMPLATE_ID
    auto values = MakeShared<Attributes>();
    ASSERT_NE(values, nullptr);
    ret = executorCallback->OnGetProperty(*conditions, *values);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnGetPropertyTest_005, TestSize.Level0)
{
    static const uint64_t testTemplateId = 123;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, GetProperty(_, _, _)).Times(Exactly(0));

    auto conditions = MakeShared<Attributes>();
    ASSERT_NE(conditions, nullptr);
    // Error: invalid ATTR_PROPERTY_MODE
    conditions->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET + 1);
    conditions->SetUint64Value(Attributes::ATTR_TEMPLATE_ID, testTemplateId);
    auto values = MakeShared<Attributes>();
    ASSERT_NE(values, nullptr);
    ret = executorCallback->OnGetProperty(*conditions, *values);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
    // Error: invalid ATTR_PROPERTY_MODE
    conditions->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET - 1);
    conditions->SetUint64Value(Attributes::ATTR_TEMPLATE_ID, testTemplateId);
    ret = executorCallback->OnGetProperty(*conditions, *values);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnGetPropertyTest_006, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, GetProperty(_, _, _)).Times(Exactly(0));

    // Error: conditions is nullptr
    auto values = MakeShared<Attributes>();
    ASSERT_NE(values, nullptr);
    ret = executorCallback->OnGetProperty(*values, *values);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnGetPropertyTest_007, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, GetProperty(_, _, _)).Times(Exactly(0));

    auto conditions = MakeShared<Attributes>();
    ASSERT_NE(conditions, nullptr);
    conditions->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);

    Attributes attr;
    ret = executorCallback->OnGetProperty(*conditions, attr);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnGetPropertyTest_008, TestSize.Level0)
{
    static const vector<uint64_t> testTemplateIds = { 1, 2, 3 };
    static const vector<uint32_t> testKeys = { 100021, 100010, 100009, 100035, 100036, 100084, 100092, 100093 };

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, GetProperty(_, _, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint64_t> &templateIdList,
            const std::vector<Attributes::AttributeKey> &keys, Property &property) {
            EXPECT_EQ(templateIdList, testTemplateIds);
            return ResultCode::GENERAL_ERROR;
        });

    auto conditions = MakeShared<Attributes>();
    ASSERT_NE(conditions, nullptr);
    conditions->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    conditions->SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, testTemplateIds);
    conditions->SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, testKeys);
    auto values = MakeShared<Attributes>();
    ASSERT_NE(values, nullptr);
    ret = executorCallback->OnGetProperty(*conditions, *values);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnGetPropertyTest_009, TestSize.Level0)
{
    static const vector<uint64_t> testTemplateIds = { 1, 2, 3 };
    static const vector<uint32_t> testKeys = { 100021, 100010, 100009, 100035, 100036, 100084, 100092, 100093 };
    static const int32_t testFreezingTime = 456;
    static const int32_t testAuthSubType = 101112;
    static const int32_t testRemainTimes = 789;
    string testEnrollmentProgress = "abc";
    string testSensorInfo = "efg";

    shared_ptr<Executor> executor;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, GetProperty(_, _, _))
        .Times(Exactly(1))
        .WillOnce([testEnrollmentProgress, testSensorInfo](const std::vector<uint64_t> &templateIdList,
            const std::vector<Attributes::AttributeKey> &keys, Property &property) {
            EXPECT_EQ(templateIdList, testTemplateIds);
            property.lockoutDuration = testFreezingTime;
            property.remainAttempts = testRemainTimes;
            property.authSubType = testAuthSubType;
            property.sensorInfo = testSensorInfo;
            property.enrollmentProgress = testEnrollmentProgress;
            return ResultCode::SUCCESS;
        });

    auto conditions = MakeShared<Attributes>();
    ASSERT_NE(conditions, nullptr);
    conditions->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    conditions->SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, testTemplateIds);
    conditions->SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, testKeys);
    auto values = MakeShared<Attributes>();
    ASSERT_NE(values, nullptr);
    executorCallback->OnGetProperty(*conditions, *values);
}


HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_General, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
    Attributes attr;
    Attributes results;
    ret = executorCallback->OnSetProperty(attr, results);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_DeleteTemplateTest_001, TestSize.Level0)
{
    static const uint64_t testTemplateId = 123;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Delete(_))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint64_t> &templateIdList) {
            EXPECT_EQ(templateIdList.size(), static_cast<size_t>(1));
            EXPECT_EQ(templateIdList[0], testTemplateId);
            return ResultCode::SUCCESS;
        });

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_DEL);
    property->SetUint64Value(Attributes::ATTR_TEMPLATE_ID, testTemplateId);
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_DeleteTemplateTest_002, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Delete(_)).Times(Exactly(0));

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_DEL);
    // Error: missing template id
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_DeleteTemplateTest_003, TestSize.Level0)
{
    static const uint64_t testTemplateId = 123;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Delete(_)).Times(Exactly(0));

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_DEL);
    property->SetUint64Value(Attributes::ATTR_TEMPLATE_ID, testTemplateId);
    // Error: Executor is disconnected
    executor->OnHdiDisconnect();
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_DeleteTemplateTest_004, TestSize.Level0)
{
    static const uint64_t testTemplateId = 123;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, Delete(_))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint64_t> &templateIdList) {
            EXPECT_EQ(templateIdList.size(), static_cast<size_t>(1));
            EXPECT_EQ(templateIdList[0], testTemplateId);
            // Error: return error
            return ResultCode::GENERAL_ERROR;
        });

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_DEL);
    property->SetUint64Value(Attributes::ATTR_TEMPLATE_ID, testTemplateId);
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_CustomCommandTest_001, TestSize.Level0)
{
    static const int32_t testCommandId = 123;
    static const std::vector<uint8_t> testExtraInfo = {4, 5, 6};
    static std::thread t;
    static std::string threadName = "executor_unit_test";

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, SendCommand(_, _, _))
        .Times(Exactly(2))
        .WillOnce([](UserAuth::PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
                      const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
            EXPECT_EQ(static_cast<int32_t>(commandId), testCommandId);
            EXPECT_EQ(extraInfo, testExtraInfo);
            callbackObj->OnResult(ResultCode::SUCCESS, {});
            return ResultCode::SUCCESS;
        })
        .WillOnce([](UserAuth::PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
                      const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
            EXPECT_EQ(static_cast<int32_t>(commandId), testCommandId);
            EXPECT_EQ(extraInfo, testExtraInfo);
            t = std::thread([callbackObj] {
                pthread_setname_np(pthread_self(), threadName.c_str());
                const int32_t sleepTime = 500;
                std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
                callbackObj->OnResult(ResultCode::SUCCESS, {});
            });
            return ResultCode::SUCCESS;
        });

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, testCommandId);
    property->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, testExtraInfo);
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
    t.join();
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_CustomCommandTest_002, TestSize.Level0)
{
    static const int32_t testCommandId = 123;
    static const std::vector<uint8_t> testExtraInfo = {4, 5, 6};

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, SendCommand(_, _, _))
        .Times(Exactly(1))
        .WillOnce([](UserAuth::PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
                      const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
            EXPECT_EQ(static_cast<int32_t>(commandId), testCommandId);
            EXPECT_EQ(extraInfo, testExtraInfo);
            // Error: OnResult not invoked
            return ResultCode::SUCCESS;
        });

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, testCommandId);
    property->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, testExtraInfo);
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::TIMEOUT);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_CustomCommandTest_003, TestSize.Level0)
{
    static const int32_t testCommandId = 123;
    static const std::vector<uint8_t> testExtraInfo = {4, 5, 6};

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, SendCommand(_, _, _))
        .Times(Exactly(1))
        .WillOnce([](UserAuth::PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
                      const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
            EXPECT_EQ(static_cast<int32_t>(commandId), testCommandId);
            EXPECT_EQ(extraInfo, testExtraInfo);
            // Error: OnResult NOT_SUPPORT
            callbackObj->OnResult(ResultCode::TYPE_NOT_SUPPORT, {});
            return ResultCode::SUCCESS;
        });

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, testCommandId);
    property->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, testExtraInfo);
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::TYPE_NOT_SUPPORT);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_CustomCommandTest_004, TestSize.Level0)
{
    static const int32_t testCommandId = 123;
    static const std::vector<uint8_t> testExtraInfo = {4, 5, 6};

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, SendCommand(_, _, _))
        .Times(Exactly(1))
        .WillOnce([](UserAuth::PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
                      const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
            EXPECT_EQ(static_cast<int32_t>(commandId), testCommandId);
            EXPECT_EQ(extraInfo, testExtraInfo);
            // Error: return error
            return ResultCode::TYPE_NOT_SUPPORT;
        });

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, testCommandId);
    property->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, testExtraInfo);
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::TYPE_NOT_SUPPORT);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_CustomCommandTest_005, TestSize.Level0)
{
    static const int32_t testCommandId = 123;

    shared_ptr<Executor> executor;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, SendCommand(_, _, _)).Times(Exactly(0));

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, testCommandId);
    // Error: ATTR_EXTRA_INFO not set
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_ProcessSetCachedTemplatesTest_001, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, SendCommand(_, _, _)).Times(Exactly(0));

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_SET_CACHED_TEMPLATES);
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_ProcessNotifyExecutorReadyTest_001, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, SendCommand(_, _, _)).Times(Exactly(0));

    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    property->SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_NOTIFY_COLLECTOR_READY);
    Attributes results;
    ret = executorCallback->OnSetProperty(*property, results);
    ASSERT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnSetProperty_OnSendDataTest_001, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    EXPECT_CALL(*mockExecutorHdi, SendCommand(_, _, _)).Times(Exactly(0));
    static const std::vector<uint8_t> extraInfo = {4, 5, 6};
    auto property = MakeShared<Attributes>();
    ASSERT_NE(property, nullptr);
    int32_t value1 = 1;
    uint64_t scheduleId = 1;
    property->SetInt32Value(Attributes::ATTR_SRC_ROLE, value1);
    property->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    executorCallback->OnSendData(scheduleId, *property);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthWithoutAuthScene_001, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback;
    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _))
        .WillOnce([&cmdCallback](uint64_t scheduleId, const AuthenticateParam &param,
            const shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
                EXPECT_EQ(param.authScene, AuthScene::AUTH_SCENE_DEFAULT);
                cmdCallback = callbackObj;
                return ResultCode::SUCCESS;
            });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    commandAttrs->SetUint64ArrayValue(Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST, TEST_TEMPLATE_ID_LIST);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, TEST_TOKEN_ID);
    commandAttrs->SetUint32Value(Attributes::ATTR_USER_ID, TEST_USER_ID);
    commandAttrs->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, TEST_EXTRA_INFO);
    commandAttrs->SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, TEST_END_AFTER_FIRST_FAIL);
    commandAttrs->SetInt32Value(Attributes::ATTR_AUTH_INTENTION, TEST_AUTH_INTENT);
    commandAttrs->SetStringValue(Attributes::ATTR_WIDGET_TITLE, TEST_WIDGET_TITLE);
    ret = executorCallback->OnBeginExecute(TEST_SCHEDULE_ID, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthWithoutTitle_001, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback;
    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _))
        .WillOnce([&cmdCallback](uint64_t scheduleId, const AuthenticateParam &param,
            const shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
                EXPECT_EQ(param.authScene, static_cast<AuthScene>(TEST_AUTH_SCENE));
                EXPECT_EQ(param.title, "");
                cmdCallback = callbackObj;
                return ResultCode::SUCCESS;
            });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    commandAttrs->SetUint64ArrayValue(Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST, TEST_TEMPLATE_ID_LIST);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, TEST_TOKEN_ID);
    commandAttrs->SetUint32Value(Attributes::ATTR_USER_ID, TEST_USER_ID);
    commandAttrs->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, TEST_EXTRA_INFO);
    commandAttrs->SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, TEST_END_AFTER_FIRST_FAIL);
    commandAttrs->SetInt32Value(Attributes::ATTR_AUTH_INTENTION, TEST_AUTH_INTENT);
    commandAttrs->SetInt32Value(Attributes::ATTR_AUTH_SCENE, TEST_AUTH_SCENE);
    ret = executorCallback->OnBeginExecute(TEST_SCHEDULE_ID, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthWithoutAuthScene_002, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback;
    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _))
        .WillOnce([&cmdCallback](uint64_t scheduleId, const AuthenticateParam &param,
            const shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
                EXPECT_EQ(param.authScene, AuthScene::AUTH_SCENE_DEFAULT);
                EXPECT_EQ(param.title, TEST_WIDGET_TITLE);
                cmdCallback = callbackObj;
                return ResultCode::SUCCESS;
            });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    commandAttrs->SetUint64ArrayValue(Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST, TEST_TEMPLATE_ID_LIST);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, TEST_TOKEN_ID);
    commandAttrs->SetUint32Value(Attributes::ATTR_USER_ID, TEST_USER_ID);
    commandAttrs->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, TEST_EXTRA_INFO);
    commandAttrs->SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, TEST_END_AFTER_FIRST_FAIL);
    commandAttrs->SetInt32Value(Attributes::ATTR_AUTH_INTENTION, TEST_AUTH_INTENT);
    commandAttrs->SetStringValue(Attributes::ATTR_WIDGET_TITLE, TEST_WIDGET_TITLE);
    ret = executorCallback->OnBeginExecute(TEST_SCHEDULE_ID, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthWithoutBothAttributes_001, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback;
    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _))
        .WillOnce([&cmdCallback](uint64_t scheduleId, const AuthenticateParam &param,
            const shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
                EXPECT_EQ(param.authScene, AuthScene::AUTH_SCENE_DEFAULT);
                EXPECT_EQ(param.title, "");
                cmdCallback = callbackObj;
                return ResultCode::SUCCESS;
            });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_SCHEDULE_MODE, AUTH);
    commandAttrs->SetUint64ArrayValue(Attributes::AttributeKey::ATTR_TEMPLATE_ID_LIST, TEST_TEMPLATE_ID_LIST);
    commandAttrs->SetUint32Value(Attributes::AttributeKey::ATTR_ACCESS_TOKEN_ID, TEST_TOKEN_ID);
    commandAttrs->SetUint32Value(Attributes::ATTR_USER_ID, TEST_USER_ID);
    commandAttrs->SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, TEST_EXTRA_INFO);
    commandAttrs->SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, TEST_END_AFTER_FIRST_FAIL);
    commandAttrs->SetInt32Value(Attributes::ATTR_AUTH_INTENTION, TEST_AUTH_INTENT);
    ret = executorCallback->OnBeginExecute(TEST_SCHEDULE_ID, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(ExecutorUnitTest, UserAuthExecutor_OnBeginExecute_AuthWithBothAttributes_001, TestSize.Level0)
{
    shared_ptr<Executor> executor;
    shared_ptr<MockIAuthExecutorHdi> mockExecutorHdi;
    shared_ptr<ExecutorRegisterCallback> executorCallback;
    shared_ptr<MockIExecutorMessenger> mockMessenger;
    int32_t ret = GetExecutorAndMockStub(executor, executorCallback, mockExecutorHdi, mockMessenger);
    ASSERT_EQ(ret, ResultCode::SUCCESS);

    shared_ptr<UserAuth::IExecuteCallback> cmdCallback;
    EXPECT_CALL(*mockExecutorHdi, Authenticate(_, _, _))
        .WillOnce([&cmdCallback](uint64_t scheduleId, const AuthenticateParam &param,
            const shared_ptr<UserAuth::IExecuteCallback> &callbackObj) {
                EXPECT_EQ(param.authScene, static_cast<AuthScene>(TEST_AUTH_SCENE));
                EXPECT_EQ(param.title, TEST_WIDGET_TITLE);
                cmdCallback = callbackObj;
                return ResultCode::SUCCESS;
            });

    EXPECT_CALL(*mockMessenger, SendData(_, _, _)).Times(Exactly(0));
    EXPECT_CALL(*mockMessenger, Finish(_, _, _)).Times(Exactly(0));

    vector<uint8_t> uselessPublicKey;
    auto commandAttrs = MakeShared<Attributes>();
    ASSERT_NE(commandAttrs, nullptr);
    SetAuthCommandAttributes(*commandAttrs);
    ret = executorCallback->OnBeginExecute(TEST_SCHEDULE_ID, uselessPublicKey, *commandAttrs);
    ASSERT_NE(cmdCallback, nullptr);
    ASSERT_EQ(ret, ResultCode::SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
