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

#include "executor_messenger_service_test.h"

#include "context_pool.h"
#include "executor_messenger_service.h"
#include "mock_context.h"
#include "mock_schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ExecutorMessengerServiceTest::SetUpTestCase()
{
}

void ExecutorMessengerServiceTest::TearDownTestCase()
{
}

void ExecutorMessengerServiceTest::SetUp()
{
}

void ExecutorMessengerServiceTest::TearDown()
{
}

HWTEST_F(ExecutorMessengerServiceTest, ExecutorMessengerServiceTest001, TestSize.Level0)
{
    auto service1 = ExecutorMessengerService::GetInstance();
    EXPECT_NE(service1, nullptr);
    auto service2 = ExecutorMessengerService::GetInstance();
    EXPECT_NE(service2, nullptr);
    EXPECT_EQ(service1, service2);
}

HWTEST_F(ExecutorMessengerServiceTest, ExecutorMessengerServiceTest002, TestSize.Level0)
{
    uint64_t testScheduleId1 = 1545;
    uint64_t testScheduleId2 = 1876;
    uint64_t testContextId = 78545;
    ExecutorRole testDstRole = VERIFIER;
    ResultCode testResultCode = FAIL;
    std::vector<uint8_t> testFinalResult;
    std::vector<uint8_t> testMsg = {1, 2, 3, 4};

    auto service = ExecutorMessengerService::GetInstance();
    EXPECT_NE(service, nullptr);
    
    int32_t result1 = service->SendData(testScheduleId1, testDstRole, testMsg);
    EXPECT_EQ(result1, GENERAL_ERROR);

    int32_t result2 = service->Finish(testScheduleId1, testResultCode, testFinalResult);
    EXPECT_EQ(result2, GENERAL_ERROR);

    auto scheduleNode1 = MockScheduleNode::CreateWithScheduleId(testScheduleId1);
    EXPECT_NE(scheduleNode1, nullptr);
    EXPECT_CALL(*scheduleNode1, SendMessage(_,  _)).WillRepeatedly(Return(false));
    EXPECT_CALL(*scheduleNode1, ContinueSchedule(_, _)).WillRepeatedly(Return(false));
    auto scheduleNode2 = MockScheduleNode::CreateWithScheduleId(testScheduleId2);
    EXPECT_NE(scheduleNode2, nullptr);
    EXPECT_CALL(*scheduleNode2, SendMessage(_,  _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*scheduleNode2, ContinueSchedule(_, _)).WillRepeatedly(Return(true));
    std::set<std::shared_ptr<ScheduleNode>> scheduleNodeSet;
    scheduleNodeSet.insert(scheduleNode1);
    scheduleNodeSet.insert(scheduleNode2);

    auto context = MockContext::CreateContextWithScheduleNode(testContextId, scheduleNodeSet);
    EXPECT_NE(context, nullptr);
    EXPECT_TRUE(ContextPool::Instance().Schedule(context));

    result1 = service->SendData(testScheduleId1, testDstRole, testMsg);
    EXPECT_EQ(result1, GENERAL_ERROR);
    result1 = service->SendData(testScheduleId2, testDstRole, testMsg);
    EXPECT_EQ(result1, SUCCESS);

    result2 = service->Finish(testScheduleId1, testResultCode, testFinalResult);
    EXPECT_EQ(result2, GENERAL_ERROR);
    result2 = service->Finish(testScheduleId2, testResultCode, testFinalResult);
    EXPECT_EQ(result2, SUCCESS);

    EXPECT_TRUE(ContextPool::Instance().Delete(testContextId));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS