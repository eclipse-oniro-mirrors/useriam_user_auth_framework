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

#include "delete_context.h"

#include "mock_context.h"
#include "mock_credential_info.h"
#include "mock_deletion.h"
#include "mock_schedule_node.h"
#include "mock_update_pin_param_info.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
class DeleteContextTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void DeleteContextTest::SetUpTestCase()
{
}

void DeleteContextTest::TearDownTestCase()
{
}

void DeleteContextTest::SetUp()
{
}

void DeleteContextTest::TearDown()
{
}

HWTEST_F(DeleteContextTest, DeleteContextTest_NullHdi, TestSize.Level0)
{
    const uint64_t testContestId = 2;
    const int32_t testResultCode = 7;
    const auto finalResult = Common::MakeShared<Attributes>();
    ASSERT_NE(finalResult, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _)).Times(Exactly(1));
    std::shared_ptr<Deletion> deletion = nullptr;

    auto oriContext = Common::MakeShared<DeleteContext>(testContestId, deletion, contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<Context> context = oriContext;
    std::shared_ptr<ScheduleNodeCallback> nodeCallback = oriContext;

    ASSERT_EQ(context->Start(), false);
    ASSERT_EQ(context->Stop(), false);
    nodeCallback->OnScheduleStoped(testResultCode, finalResult);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_NullCallback, TestSize.Level0)
{
    const uint64_t testContestId = 2;
    const ExecutorRole testRole = static_cast<ExecutorRole>(3);
    const int32_t testModuleType = 4;
    const std::vector<uint8_t> testAcquireMsg = {4, 5, 6};
    const int32_t testResultCode = 7;
    const auto finalResult = Common::MakeShared<Attributes>();
    ASSERT_NE(finalResult, nullptr);

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    std::shared_ptr<ContextCallback> contextCallback = nullptr;

    auto oriContext = Common::MakeShared<DeleteContext>(testContestId, mockDeletion,
        contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<ScheduleNodeCallback> nodeCallback = oriContext;

    nodeCallback->OnScheduleStarted();
    nodeCallback->OnScheduleProcessed(testRole, testModuleType, testAcquireMsg);
    nodeCallback->OnScheduleStoped(testResultCode, finalResult);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_BasicInfo, TestSize.Level0)
{
    const uint64_t testContestId = 2;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);

    auto oriContext = Common::MakeShared<DeleteContext>(testContestId, mockDeletion,
        contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<Context> context = oriContext;

    ASSERT_EQ(context->GetContextId(), testContestId);
    ASSERT_EQ(context->GetContextType(), CONTEXT_DELETE);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_Start_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, GetLatestError()).Times(1);
    EXPECT_CALL(*mockDeletion, Start(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
            std::shared_ptr<ScheduleNodeCallback> callback, bool &isStartSchedule,
            std::vector<EngCredentialInfo> &credentialInfos) {
            isStartSchedule = true;
            return false;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_Start_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, Start(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
            std::shared_ptr<ScheduleNodeCallback> callback, bool &isStartSchedule,
            std::vector<EngCredentialInfo> &credentialInfos) {
            isStartSchedule = true;
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_Start_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, Start(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
            std::shared_ptr<ScheduleNodeCallback> callback, bool &isStartSchedule,
            std::vector<EngCredentialInfo> &credentialInfos) {
            isStartSchedule = true;
            scheduleList.push_back(Common::MakeShared<MockScheduleNode>());
            scheduleList.push_back(Common::MakeShared<MockScheduleNode>());
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_Start_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, Start(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
            std::shared_ptr<ScheduleNodeCallback> callback, bool &isStartSchedule,
            std::vector<EngCredentialInfo> &credentialInfos) {
            isStartSchedule = true;
            auto scheduleNode = Common::MakeShared<MockScheduleNode>();
            EXPECT_NE(scheduleNode, nullptr);

            EXPECT_CALL(*scheduleNode, StartSchedule()).Times(Exactly(1)).WillOnce(Return(false));
            scheduleList.push_back(scheduleNode);
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_Start_005, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const uint64_t testScheduleId = 3;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, Start(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
            std::shared_ptr<ScheduleNodeCallback> callback, bool &isStartSchedule,
            std::vector<EngCredentialInfo> &credentialInfos) {
            isStartSchedule = true;
            EXPECT_EQ(scheduleList.size(), 0U);
            auto scheduleNode = Common::MakeShared<MockScheduleNode>();
            EXPECT_NE(scheduleNode, nullptr);
            EXPECT_CALL(*scheduleNode, StartSchedule()).Times(Exactly(1)).WillOnce(Return(true));
            EXPECT_CALL(*scheduleNode, GetScheduleId()).WillRepeatedly(Return(testScheduleId));
            scheduleList.push_back(scheduleNode);
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), true);
    ASSERT_EQ(context->Start(), false);
    auto node = context->GetScheduleNode(testScheduleId);
    ASSERT_NE(node, nullptr);
    node = context->GetScheduleNode(testScheduleId + 1);
    ASSERT_EQ(node, nullptr);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_Stop_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, Cancel()).Times(0);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(ResultCode::CANCELED, _)).Times(Exactly(1));
    std::shared_ptr<Context> context =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Stop(), true);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_Stop_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, Cancel()).Times(0);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(ResultCode::CANCELED, _)).Times(Exactly(1));
    std::shared_ptr<Context> context =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Stop(), true);
    ASSERT_EQ(context->Stop(), true);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_Stop_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, Start(_, _, _, _)).Times(1);
    ON_CALL(*mockDeletion, Start)
        .WillByDefault(
            [](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                std::shared_ptr<ScheduleNodeCallback> callback, bool &isStartSchedule,
                std::vector<EngCredentialInfo> &credentialInfos) {
                isStartSchedule = true;
                scheduleList.push_back(nullptr);
                return true;
            }
        );
    EXPECT_CALL(*mockDeletion, Cancel()).Times(Exactly(1)).WillOnce([]() {
        return true;
    });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
    ASSERT_EQ(context->Stop(), true);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_Stop_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, Start(_, _, _, _)).Times(1);
    ON_CALL(*mockDeletion, Start)
        .WillByDefault(
            [](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                std::shared_ptr<ScheduleNodeCallback> callback, bool &isStartSchedule,
                std::vector<EngCredentialInfo> &credentialInfos) {
                isStartSchedule = true;
                auto scheduleNode = Common::MakeShared<MockScheduleNode>();
                EXPECT_NE(scheduleNode, nullptr);
                EXPECT_CALL(*scheduleNode, StartSchedule()).Times(1);
                EXPECT_CALL(*scheduleNode, StopSchedule()).Times(1);
                scheduleList.push_back(scheduleNode);
                return true;
            }
        );
    EXPECT_CALL(*mockDeletion, GetLatestError()).Times(1);
    EXPECT_CALL(*mockDeletion, Cancel()).Times(Exactly(1)).WillOnce([]() {
        return false;
    });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
    ASSERT_EQ(context->Stop(), false);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_OnScheduleStarted, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    nodeCallback->OnScheduleStarted();
}

HWTEST_F(DeleteContextTest, DeleteContextTest_OnScheduleProcessed, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    const ExecutorRole testRole = static_cast<ExecutorRole>(3);
    const int32_t testModuleType = 4;
    const std::vector<uint8_t> testAcquireMsg = {4, 5, 6};

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    auto contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnAcquireInfo(_, _, _))
        .WillOnce(
            [](ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg) {
                EXPECT_EQ(moduleType, 4);
            }
        );

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    nodeCallback->OnScheduleProcessed(testRole, testModuleType, testAcquireMsg);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_OnScheduleStoped_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = 7;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, testResultCode);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: result is null when testResultCode is not success
    std::shared_ptr<Attributes> result = nullptr;
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_OnScheduleStoped_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: result is null when testResultCode is success
    std::shared_ptr<Attributes> result = nullptr;
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_OnScheduleStoped_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_OnScheduleStoped_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, GetLatestError()).Times(1);
    EXPECT_CALL(*mockDeletion, Update(_, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, std::shared_ptr<CredentialInfoInterface> &info) {
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
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret1 = result->SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, testScheduleResult);
    ASSERT_EQ(ret1, true);

    bool ret2 = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret2, true);
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_OnScheduleStoped_005, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, Update(_, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, std::shared_ptr<CredentialInfoInterface> &info) {
            EXPECT_EQ(scheduleResult, testScheduleResult);
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::SUCCESS);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret1 = result->SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, testScheduleResult);
    ASSERT_EQ(ret1, true);

    bool ret2 = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret2, true);
    nodeCallback->OnScheduleStoped(ResultCode::SUCCESS, result);
}

HWTEST_F(DeleteContextTest, DeleteContextTest_OnScheduleStoped_006, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};

    std::shared_ptr<MockDeletion> mockDeletion = Common::MakeShared<MockDeletion>();
    ASSERT_NE(mockDeletion, nullptr);
    EXPECT_CALL(*mockDeletion, Update(_, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, std::shared_ptr<CredentialInfoInterface> &info) {
            EXPECT_EQ(scheduleResult, testScheduleResult);
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _)).Times(1);

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<DeleteContext>(testContestId, mockDeletion, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret1 = result->SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, testScheduleResult);
    ASSERT_EQ(ret1, true);

    bool ret2 = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret2, true);
    nodeCallback->OnScheduleStoped(ResultCode::SUCCESS, result);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
