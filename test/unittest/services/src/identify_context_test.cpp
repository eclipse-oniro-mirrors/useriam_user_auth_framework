/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "identify_context.h"

#include "mock_context.h"
#include "mock_identification.h"
#include "mock_schedule_node.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IdentifyContextTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void IdentifyContextTest::SetUpTestCase()
{
}

void IdentifyContextTest::TearDownTestCase()
{
}

void IdentifyContextTest::SetUp()
{
}

void IdentifyContextTest::TearDown()
{
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_NullHdi, TestSize.Level0)
{
    const uint64_t testContestId = 2;
    const int32_t testResultCode = 7;
    const auto finalResult = Common::MakeShared<Attributes>();
    ASSERT_NE(finalResult, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _)).Times(Exactly(1));
    // Error: identify is null
    std::shared_ptr<Identification> identify = nullptr;

    auto oriContext = Common::MakeShared<IdentifyContext>(testContestId, identify, contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<Context> context = oriContext;
    std::shared_ptr<ScheduleNodeCallback> nodeCallback = oriContext;

    ASSERT_EQ(context->Start(), false);
    ASSERT_EQ(context->Stop(), false);
    nodeCallback->OnScheduleStoped(testResultCode, finalResult);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_NullCallback, TestSize.Level0)
{
    const uint64_t testContestId = 2;
    const ExecutorRole testRole = static_cast<ExecutorRole>(3);
    const int32_t testModuleType = 4;
    const std::vector<uint8_t> testAcquireMsg = {4, 5, 6};
    const int32_t testResultCode = 7;
    const auto finalResult = Common::MakeShared<Attributes>();
    ASSERT_NE(finalResult, nullptr);

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    // Error: contextCallback is null
    std::shared_ptr<ContextCallback> contextCallback = nullptr;

    auto oriContext = Common::MakeShared<IdentifyContext>(testContestId, mockIdentify, contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<ScheduleNodeCallback> nodeCallback = oriContext;

    nodeCallback->OnScheduleStarted();
    nodeCallback->OnScheduleProcessed(testRole, testModuleType, testAcquireMsg);
    nodeCallback->OnScheduleStoped(testResultCode, finalResult);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_BasicInfo, TestSize.Level0)
{
    const uint64_t testContestId = 2;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);

    auto oriContext = Common::MakeShared<IdentifyContext>(testContestId, mockIdentify, contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<Context> context = oriContext;

    ASSERT_EQ(context->GetContextId(), testContestId);
    ASSERT_EQ(context->GetContextType(), CONTEXT_IDENTIFY);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_Start_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    EXPECT_CALL(*mockIdentify, GetLatestError()).Times(1);
    EXPECT_CALL(*mockIdentify, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: process identification start fail
            return false;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<IdentifyContext>(testContestId,
        mockIdentify, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_Start_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    EXPECT_CALL(*mockIdentify, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: scheduleNodeList size = 0
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<IdentifyContext>(testContestId,
        mockIdentify, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_Start_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    EXPECT_CALL(*mockIdentify, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: scheduleNodeList size = 2
            scheduleList.push_back(Common::MakeShared<MockScheduleNode>());
            scheduleList.push_back(Common::MakeShared<MockScheduleNode>());
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<IdentifyContext>(testContestId,
        mockIdentify, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_Start_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    EXPECT_CALL(*mockIdentify, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: schedule node start fail
            auto scheduleNode = Common::MakeShared<MockScheduleNode>();
            EXPECT_CALL(*scheduleNode, StartSchedule()).Times(Exactly(1)).WillOnce(Return(false));
            scheduleList.push_back(scheduleNode);
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<IdentifyContext>(testContestId,
        mockIdentify, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_Start_005, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const uint64_t testScheduleId = 3;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    EXPECT_CALL(*mockIdentify, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Success
            EXPECT_EQ(scheduleList.size(), 0U);
            auto scheduleNode = Common::MakeShared<MockScheduleNode>();
            EXPECT_CALL(*scheduleNode, StartSchedule()).Times(Exactly(1)).WillOnce(Return(true));
            EXPECT_CALL(*scheduleNode, GetScheduleId()).Times(Exactly(2)).WillRepeatedly(Return(testScheduleId));
            scheduleList.push_back(scheduleNode);
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<IdentifyContext>(testContestId,
        mockIdentify, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), true);
    ASSERT_EQ(context->Start(), false);
    auto node = context->GetScheduleNode(testScheduleId);
    ASSERT_NE(node, nullptr);
    node = context->GetScheduleNode(testScheduleId + 1);
    ASSERT_EQ(node, nullptr);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_Stop_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    EXPECT_CALL(*mockIdentify, Cancel()).Times(0);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(ResultCode::CANCELED, _)).Times(Exactly(1));
    std::shared_ptr<Context> context = Common::MakeShared<IdentifyContext>(testContestId,
        mockIdentify, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Stop(), true);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_Stop_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    EXPECT_CALL(*mockIdentify, Cancel()).Times(0);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(ResultCode::CANCELED, _)).Times(Exactly(1));
    std::shared_ptr<Context> context = Common::MakeShared<IdentifyContext>(testContestId,
        mockIdentify, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Stop(), true);
    ASSERT_EQ(context->Stop(), true);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_OnScheduleStarted, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<IdentifyContext>(testContestId, mockIdentify, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    nodeCallback->OnScheduleStarted();
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_OnScheduleProcessed, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    const ExecutorRole testRole = static_cast<ExecutorRole>(3);
    const int32_t testModuleType = 4;
    const std::vector<uint8_t> testAcquireMsg = {4, 5, 6};

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    auto contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnAcquireInfo(_, _, _))
        .WillOnce(
            [](ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg) {
                EXPECT_EQ(moduleType, 4);
            }
        );

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<IdentifyContext>(testContestId, mockIdentify, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);

    nodeCallback->OnScheduleProcessed(testRole, testModuleType, testAcquireMsg);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_OnScheduleStoped_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = 7;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, testResultCode);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<IdentifyContext>(testContestId, mockIdentify, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: result is null when testResultCode is not success
    std::shared_ptr<Attributes> result = nullptr;
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_OnScheduleStoped_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<IdentifyContext>(testContestId, mockIdentify, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: result is null when testResultCode is success
    std::shared_ptr<Attributes> result = nullptr;
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_OnScheduleStoped_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<IdentifyContext>(testContestId, mockIdentify, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: ATTR_RESULT_CODE is not set
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_OnScheduleStoped_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    EXPECT_CALL(*mockIdentify, GetLatestError()).Times(1);
    EXPECT_CALL(*mockIdentify, Update(_, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, Identification::IdentifyResultInfo &resultInfo) {
            EXPECT_EQ(scheduleResult, testScheduleResult);
            return false;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<IdentifyContext>(testContestId, mockIdentify, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: identify_->Update return false
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret, true);
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(IdentifyContextTest, IdentifyContextTest_OnScheduleStoped_005, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};
    static const int32_t testResultCode = 7;
    static const int32_t testUserId = 8;
    static const std::vector<uint8_t> testToken = {10, 11, 12, 13};

    std::shared_ptr<MockIdentification> mockIdentify = Common::MakeShared<MockIdentification>();
    ASSERT_NE(mockIdentify, nullptr);
    EXPECT_CALL(*mockIdentify, Update(_, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, Identification::IdentifyResultInfo &resultInfo) {
            EXPECT_EQ(scheduleResult, testScheduleResult);
            resultInfo.result = testResultCode;
            resultInfo.userId = testUserId;
            resultInfo.token = testToken;
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, testResultCode);
            uint32_t attrResultCode;
            int32_t userId;
            vector<uint8_t> signature;
            bool ret = finalResult.GetUint32Value(Attributes::ATTR_RESULT_CODE, attrResultCode);
            EXPECT_EQ(ret, true);
            ret = finalResult.GetInt32Value(Attributes::ATTR_USER_ID, userId);
            EXPECT_EQ(ret, true);
            ret = finalResult.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, signature);
            EXPECT_EQ(ret, true);

            EXPECT_EQ(resultCode, testResultCode);
            EXPECT_EQ(userId, testUserId);
            EXPECT_EQ(signature, testToken);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<IdentifyContext>(testContestId, mockIdentify, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Success
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret, true);
    nodeCallback->OnScheduleStoped(testResultCode, result);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
