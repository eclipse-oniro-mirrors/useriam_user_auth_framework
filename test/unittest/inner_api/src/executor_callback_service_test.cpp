/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "executor_callback_service_test.h"

#include "executor_callback_service.h"
#include "iam_ptr.h"
#include "mock_executor_register_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ExecutorCallbackServiceTest::SetUpTestCase()
{
}

void ExecutorCallbackServiceTest::TearDownTestCase()
{
}

void ExecutorCallbackServiceTest::SetUp()
{
}

void ExecutorCallbackServiceTest::TearDown()
{
}

HWTEST_F(ExecutorCallbackServiceTest, ExecutorCallbackServiceTestOnMessengerReady001, TestSize.Level0)
{
    sptr<IExecutorMessenger> testMessenger(nullptr);
    std::vector<uint8_t> testPublicKey = {1, 2, 3, 4};
    std::vector<uint64_t> testTemplateIdList = {12, 13, 14, 15};

    std::shared_ptr<ExecutorRegisterCallback> testCallback = nullptr;
    auto service = Common::MakeShared<ExecutorCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    service->OnMessengerReady(testMessenger, testPublicKey, testTemplateIdList);
}

HWTEST_F(ExecutorCallbackServiceTest, ExecutorCallbackServiceTestOnMessengerReady002, TestSize.Level0)
{
    sptr<IExecutorMessenger> testMessenger(nullptr);
    std::vector<uint8_t> testPublicKey = {1, 2, 3, 4};
    std::vector<uint64_t> testTemplateIdList = {12, 13, 14, 15};

    auto testCallback = Common::MakeShared<MockExecutorRegisterCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnMessengerReady(_, _, _)).Times(1);
    ON_CALL(*testCallback, OnMessengerReady)
        .WillByDefault(
            [&testPublicKey, &testTemplateIdList](
            const std::shared_ptr<ExecutorMessenger> &messenger, const std::vector<uint8_t> &publicKey,
            const std::vector<uint64_t> &templateIdList) {
                EXPECT_NE(messenger, nullptr);
                EXPECT_THAT(publicKey, ElementsAreArray(testPublicKey));
                EXPECT_THAT(templateIdList, ElementsAreArray(testTemplateIdList));
            }
        );
    auto service = Common::MakeShared<ExecutorCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    service->OnMessengerReady(testMessenger, testPublicKey, testTemplateIdList);
}

HWTEST_F(ExecutorCallbackServiceTest, ExecutorCallbackServiceTestOnBeginExecute001, TestSize.Level0)
{
    uint64_t testScheduleId = 57875;
    std::vector<uint8_t> testPublicKey = {1, 2, 3, 4};
    Attributes testCommand;

    std::shared_ptr<ExecutorRegisterCallback> testCallback = nullptr;
    auto service = Common::MakeShared<ExecutorCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    int32_t result = service->OnBeginExecute(testScheduleId, testPublicKey, testCommand.Serialize());
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(ExecutorCallbackServiceTest, ExecutorCallbackServiceTestOnBeginExecute002, TestSize.Level0)
{
    uint64_t testScheduleId = 57875;
    std::vector<uint8_t> testPublicKey = {1, 2, 3, 4};
    Attributes testCommand;

    auto testCallback = Common::MakeShared<MockExecutorRegisterCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnBeginExecute(_, _, _)).Times(1);
    ON_CALL(*testCallback, OnBeginExecute)
        .WillByDefault(
            [&testScheduleId, &testPublicKey](uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
                const Attributes &commandAttrs) {
                EXPECT_EQ(scheduleId, testScheduleId);
                EXPECT_THAT(publicKey, ElementsAreArray(testPublicKey));
                return SUCCESS;
            }
        );
    auto service = Common::MakeShared<ExecutorCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    int32_t result = service->OnBeginExecute(testScheduleId, testPublicKey, testCommand.Serialize());
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(ExecutorCallbackServiceTest, ExecutorCallbackServiceTestOnEndExecute001, TestSize.Level0)
{
    uint64_t testScheduleId = 57875;
    Attributes testCommand;

    std::shared_ptr<ExecutorRegisterCallback> testCallback = nullptr;
    auto service = Common::MakeShared<ExecutorCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    int32_t result = service->OnEndExecute(testScheduleId, testCommand.Serialize());
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(ExecutorCallbackServiceTest, ExecutorCallbackServiceTestOnEndExecute002, TestSize.Level0)
{
    uint64_t testScheduleId = 57875;
    Attributes testCommand;

    auto testCallback = Common::MakeShared<MockExecutorRegisterCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnEndExecute(_, _)).Times(1);
    ON_CALL(*testCallback, OnEndExecute)
        .WillByDefault(
            [&testScheduleId](uint64_t scheduleId, const Attributes &commandAttrs) {
                EXPECT_EQ(scheduleId, testScheduleId);
                return SUCCESS;
            }
        );
    auto service = Common::MakeShared<ExecutorCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    int32_t result = service->OnEndExecute(testScheduleId, testCommand.Serialize());
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(ExecutorCallbackServiceTest, ExecutorCallbackServiceTestOnSetProperty001, TestSize.Level0)
{
    Attributes testProperties;

    std::shared_ptr<ExecutorRegisterCallback> testCallback = nullptr;
    auto service = Common::MakeShared<ExecutorCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    std::vector<uint8_t> values;
    int32_t result = service->OnSetProperty(testProperties.Serialize(), values);
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(ExecutorCallbackServiceTest, ExecutorCallbackServiceTestOnSetProperty002, TestSize.Level0)
{
    Attributes testProperties;

    auto testCallback = Common::MakeShared<MockExecutorRegisterCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnSetProperty(_, _)).Times(1);
    ON_CALL(*testCallback, OnSetProperty)
        .WillByDefault(
            [](const Attributes &properties, Attributes &results) {
                return SUCCESS;
            }
        );
    auto service = Common::MakeShared<ExecutorCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    std::vector<uint8_t> values;
    int32_t result = service->OnSetProperty(testProperties.Serialize(), values);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(ExecutorCallbackServiceTest, ExecutorCallbackServiceTestOnGetProperty001, TestSize.Level0)
{
    Attributes testCondition;
    std::vector<uint8_t> testValues;

    std::shared_ptr<ExecutorRegisterCallback> testCallback = nullptr;
    auto service = Common::MakeShared<ExecutorCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    int32_t result = service->OnGetProperty(testCondition.Serialize(), testValues);
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(ExecutorCallbackServiceTest, ExecutorCallbackServiceTestOnGetProperty002, TestSize.Level0)
{
    Attributes testCondition;
    std::vector<uint8_t> testValues;
    int32_t testCode = 544857;

    auto testCallback = Common::MakeShared<MockExecutorRegisterCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetProperty(_, _)).Times(1);
    ON_CALL(*testCallback, OnGetProperty)
        .WillByDefault(
            [&testCode](const Attributes &conditions, Attributes &results) {
                EXPECT_TRUE(results.SetInt32Value(Attributes::ATTR_RESULT_CODE, testCode));
                return SUCCESS;
            }
        );
    auto service = Common::MakeShared<ExecutorCallbackService>(testCallback);
    EXPECT_NE(service, nullptr);
    int32_t result = service->OnGetProperty(testCondition.Serialize(), testValues);
    EXPECT_EQ(result, SUCCESS);
    int32_t code = 0;
    Attributes attribute(testValues);
    EXPECT_TRUE(attribute.GetInt32Value(Attributes::ATTR_RESULT_CODE, code));
    EXPECT_EQ(code, testCode);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS