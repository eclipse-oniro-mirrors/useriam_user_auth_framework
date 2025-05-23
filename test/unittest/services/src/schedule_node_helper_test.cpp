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

#include "schedule_node_helper_test.h"

#include "iam_ptr.h"

#include "mock_schedule_node_callback.h"
#include "mock_resource_node.h"
#include "resource_node_pool.h"
#include "schedule_node_helper.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
void ScheduleNodeHelperTest::SetUpTestCase()
{
}

void ScheduleNodeHelperTest::TearDownTestCase()
{
}

void ScheduleNodeHelperTest::SetUp()
{
}

void ScheduleNodeHelperTest::TearDown()
{
}

HWTEST_F(ScheduleNodeHelperTest, ScheduleNodeHelperTest_001, TestSize.Level0)
{
    std::vector<HdiScheduleInfo> scheduleInfoList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_NE(callback, nullptr);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleNodeList;
    ScheduleNodeHelper::NodeOptionalPara para = {};
    EXPECT_TRUE(ScheduleNodeHelper::BuildFromHdi(scheduleInfoList, callback, scheduleNodeList, para));
}

HWTEST_F(ScheduleNodeHelperTest, ScheduleNodeHelperTest_002, TestSize.Level0)
{
    std::vector<HdiScheduleInfo> scheduleInfoList;
    HdiScheduleInfo scheduleInfo = {};
    scheduleInfo.authType = HdiAuthType::FACE;
    scheduleInfo.executorMatcher = 10;
    scheduleInfo.executorIndexes.push_back(60);

    scheduleInfo.executorIndexes.push_back(90);

    scheduleInfo.scheduleId = 20;
    scheduleInfo.scheduleMode = HdiScheduleMode::AUTH;
    scheduleInfo.templateIds.push_back(30);
    scheduleInfoList.push_back(scheduleInfo);

    std::vector<std::vector<ExecutorRole>> executorRoles = {
        {COLLECTOR, COLLECTOR},
        {VERIFIER, VERIFIER},
        {ALL_IN_ONE, ALL_IN_ONE},
        {COLLECTOR, VERIFIER},
        {COLLECTOR, ALL_IN_ONE},
        {VERIFIER, COLLECTOR},
        {VERIFIER, ALL_IN_ONE},
        {ALL_IN_ONE, COLLECTOR},
        {ALL_IN_ONE, VERIFIER},
    };

    for (const auto &executorRole : executorRoles) {
        auto resourceNode1 = MockResourceNode::CreateWithExecuteIndex(60, FACE, executorRole[0]);
        EXPECT_NE(resourceNode1, nullptr);
        auto resourceNode2 = MockResourceNode::CreateWithExecuteIndex(90, FACE, executorRole[1]);
        EXPECT_NE(resourceNode2, nullptr);
        EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode1));
        EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode2));

        auto callback = Common::MakeShared<MockScheduleNodeCallback>();
        EXPECT_NE(callback, nullptr);
        std::vector<std::shared_ptr<ScheduleNode>> scheduleNodeList;
        ScheduleNodeHelper::NodeOptionalPara para = {};
        ScheduleNodeHelper::BuildFromHdi(scheduleInfoList, callback, scheduleNodeList, para);
        ResourceNodePool::Instance().DeleteAll();
    }
}

HWTEST_F(ScheduleNodeHelperTest, ScheduleNodeHelperTestScheduleInfoToExecutors_001, TestSize.Level0)
{
    HdiScheduleInfo scheduleInfo = {};
    scheduleInfo.authType = HdiAuthType::FACE;
    scheduleInfo.executorMatcher = 10;
    scheduleInfo.executorIndexes.push_back(60);
    scheduleInfo.executorMessages.push_back({6});
    scheduleInfo.scheduleId = 20;
    scheduleInfo.scheduleMode = HdiScheduleMode::AUTH;
    scheduleInfo.templateIds.push_back(30);
    std::vector<ExecutorRole> executorRole = {SCHEDULER, COLLECTOR, VERIFIER, ALL_IN_ONE};
    auto resourceNode1 = MockResourceNode::CreateWithExecuteIndex(60, FACE, executorRole[0]);
    EXPECT_NE(resourceNode1, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode1));
    std::shared_ptr<ResourceNode> collector;
    std::shared_ptr<ResourceNode> verifier;
    std::vector<uint8_t> collectorMessage;
    std::vector<uint8_t> verifierMessage;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_FALSE(ScheduleNodeHelper::ScheduleInfoToExecutors(scheduleInfo, collector, verifier, collectorMessage,
        verifierMessage));
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ScheduleNodeHelperTest, ScheduleNodeHelperTestScheduleInfoToExecutors_002, TestSize.Level0)
{
    HdiScheduleInfo scheduleInfo = {};
    scheduleInfo.authType = HdiAuthType::FACE;
    scheduleInfo.executorMatcher = 10;
    scheduleInfo.executorIndexes.push_back(60);
    scheduleInfo.executorMessages.push_back({6});
    scheduleInfo.scheduleId = 20;
    scheduleInfo.scheduleMode = HdiScheduleMode::AUTH;
    scheduleInfo.templateIds.push_back(30);
    std::vector<ExecutorRole> executorRole = {SCHEDULER, COLLECTOR, VERIFIER, ALL_IN_ONE};
    auto resourceNode1 = MockResourceNode::CreateWithExecuteIndex(60, FACE, executorRole[1]);
    EXPECT_NE(resourceNode1, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode1));
    std::shared_ptr<ResourceNode> collector;
    std::shared_ptr<ResourceNode> verifier;
    std::vector<uint8_t> collectorMessage;
    std::vector<uint8_t> verifierMessage;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_FALSE(ScheduleNodeHelper::ScheduleInfoToExecutors(scheduleInfo, collector, verifier, collectorMessage,
        verifierMessage));
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ScheduleNodeHelperTest, ScheduleNodeHelperTestScheduleInfoToExecutors_003, TestSize.Level0)
{
    HdiScheduleInfo scheduleInfo = {};
    scheduleInfo.authType = HdiAuthType::FACE;
    scheduleInfo.executorMatcher = 10;
    scheduleInfo.executorIndexes.push_back(60);
    scheduleInfo.executorMessages.push_back({6});
    scheduleInfo.scheduleId = 20;
    scheduleInfo.scheduleMode = HdiScheduleMode::AUTH;
    scheduleInfo.templateIds.push_back(30);
    std::vector<ExecutorRole> executorRole = {SCHEDULER, COLLECTOR, VERIFIER, ALL_IN_ONE};
    auto resourceNode1 = MockResourceNode::CreateWithExecuteIndex(60, FACE, executorRole[2]);
    EXPECT_NE(resourceNode1, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode1));
    std::shared_ptr<ResourceNode> collector;
    std::shared_ptr<ResourceNode> verifier;
    std::vector<uint8_t> collectorMessage;
    std::vector<uint8_t> verifierMessage;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_FALSE(ScheduleNodeHelper::ScheduleInfoToExecutors(scheduleInfo, collector, verifier, collectorMessage,
        verifierMessage));
    ResourceNodePool::Instance().DeleteAll();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
