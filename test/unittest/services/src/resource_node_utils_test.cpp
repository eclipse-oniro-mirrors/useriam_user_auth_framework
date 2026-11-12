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

#include "resource_node_utils_test.h"

#include "iam_ptr.h"
#include "mock_credential_info.h"
#include "mock_resource_node.h"
#include "resource_node_pool.h"
#include "resource_node_utils.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ResourceNodeUtilsTest::SetUpTestCase()
{
}

void ResourceNodeUtilsTest::TearDownTestCase()
{
}

void ResourceNodeUtilsTest::SetUp()
{
}

void ResourceNodeUtilsTest::TearDown()
{
}

HWTEST_F(ResourceNodeUtilsTest, NotifyExecutorToDeleteTemplates001, TestSize.Level0)
{
    std::vector<std::shared_ptr<CredentialInfoInterface>> infos;
    std::string changeReason = "DeleteTemplate";
    int32_t result = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(infos, changeReason);
    EXPECT_EQ(result, INVALID_PARAMETERS);
}

HWTEST_F(ResourceNodeUtilsTest, NotifyExecutorToDeleteTemplates002, TestSize.Level0)
{
    auto credInfo = Common::MakeShared<MockCredentialInfo>();
    EXPECT_NE(credInfo, nullptr);
    EXPECT_CALL(*credInfo, GetExecutorIndex()).WillRepeatedly(Return(10));

    std::vector<std::shared_ptr<CredentialInfoInterface>> infos;
    infos.push_back(credInfo);
    std::string changeReason = "DeleteTemplate";
    int32_t result = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(infos, changeReason);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(ResourceNodeUtilsTest, NotifyExecutorToDeleteTemplates003, TestSize.Level0)
{
    auto credInfo1 = Common::MakeShared<MockCredentialInfo>();
    EXPECT_NE(credInfo1, nullptr);
    EXPECT_CALL(*credInfo1, GetExecutorIndex()).WillRepeatedly(Return(10));
    EXPECT_CALL(*credInfo1, GetTemplateId()).WillRepeatedly(Return(20));

    auto credInfo2 = Common::MakeShared<MockCredentialInfo>();
    EXPECT_NE(credInfo2, nullptr);
    EXPECT_CALL(*credInfo2, GetExecutorIndex()).WillRepeatedly(Return(100));
    EXPECT_CALL(*credInfo2, GetTemplateId()).WillRepeatedly(Return(200));

    std::vector<std::shared_ptr<CredentialInfoInterface>> infos;
    infos.push_back(credInfo1);
    infos.push_back(credInfo2);

    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode1, nullptr);
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(10));
    EXPECT_CALL(*resourceNode1, SetProperty(_, _)).WillRepeatedly(Return(FAIL));
    auto resourceNode2 = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode2, nullptr);
    EXPECT_CALL(*resourceNode2, GetExecutorIndex()).WillRepeatedly(Return(100));
    EXPECT_CALL(*resourceNode2, SetProperty(_, _)).WillRepeatedly(Return(SUCCESS));

    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode1));
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode2));

    std::string changeReason = "DeleteTemplate";
    int32_t result = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(infos, changeReason);
    EXPECT_EQ(result, SUCCESS);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodeUtilsTest, SendMsgToExecutor001, TestSize.Level0)
{
    uint64_t testIndex = 10;
    int32_t commandId = 1250;
    std::vector<uint8_t> testMsg = {1, 2, 3, 4};

    EXPECT_NO_THROW(ResourceNodeUtils::SendMsgToExecutor(testIndex, commandId, testMsg));
}

HWTEST_F(ResourceNodeUtilsTest, SendMsgToExecutor002, TestSize.Level0)
{
    uint64_t testIndex1 = 10;
    uint64_t testIndex2 = 100;
    int32_t commandId = 1250;
    std::vector<uint8_t> testMsg = {1, 2, 3, 4};

    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode1, nullptr);
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(10));
    EXPECT_CALL(*resourceNode1, SetProperty(_, _)).WillRepeatedly(Return(FAIL));
    auto resourceNode2 = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode2, nullptr);
    EXPECT_CALL(*resourceNode2, GetExecutorIndex()).WillRepeatedly(Return(100));
    EXPECT_CALL(*resourceNode2, SetProperty(_, _)).WillRepeatedly(Return(SUCCESS));

    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode1));
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode2));

    ResourceNodeUtils::SendMsgToExecutor(testIndex1, commandId, testMsg);
    ResourceNodeUtils::SendMsgToExecutor(testIndex2, commandId, testMsg);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodeUtilsTest, SetCachedTemplates001, TestSize.Level0)
{
    const uint64_t testIndex = 10;
    std::vector<std::shared_ptr<CredentialInfoInterface>> infos;
    EXPECT_TRUE(ResourceNodePool::Instance().Select(testIndex).lock() == nullptr);
    ResourceNodeUtils::SetCachedTemplates(testIndex, infos);
}

HWTEST_F(ResourceNodeUtilsTest, SetCachedTemplates002, TestSize.Level0)
{
    const uint64_t testIndex = 10;
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(testIndex);
    EXPECT_CALL(*(static_cast<MockResourceNode *>(resourceNode.get())), SetProperty(_, _))
        .WillRepeatedly(Return(FAIL));
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto mockCredentialInfo = Common::MakeShared<MockCredentialInfo>();
    EXPECT_CALL(*mockCredentialInfo, GetTemplateId()).WillRepeatedly(Return(0));
    std::vector<std::shared_ptr<CredentialInfoInterface>> infos = { mockCredentialInfo };
    ResourceNodeUtils::SetCachedTemplates(testIndex, infos);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodeUtilsTest, SetCachedTemplates003, TestSize.Level0)
{
    const uint64_t testIndex = 10;
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(testIndex);
    EXPECT_CALL(*(static_cast<MockResourceNode *>(resourceNode.get())), SetProperty(_, _))
        .WillRepeatedly(Return(SUCCESS));
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto mockCredentialInfo = Common::MakeShared<MockCredentialInfo>();
    EXPECT_CALL(*mockCredentialInfo, GetTemplateId()).WillRepeatedly(Return(0));
    std::vector<std::shared_ptr<CredentialInfoInterface>> infos = { mockCredentialInfo };
    ResourceNodeUtils::SetCachedTemplates(testIndex, infos);
    ResourceNodePool::Instance().DeleteAll();
}

HWTEST_F(ResourceNodeUtilsTest, ClassifyCredInfoByExecutor001, TestSize.Level0)
{
    std::vector<std::shared_ptr<CredentialInfoInterface>> in = { nullptr };
    std::map<uint64_t, std::vector<std::shared_ptr<CredentialInfoInterface>>> out;
    EXPECT_EQ(ResourceNodeUtils::ClassifyCredInfoByExecutor(in, out), GENERAL_ERROR);
}

HWTEST_F(ResourceNodeUtilsTest, ClassifyCredInfoByExecutor002, TestSize.Level0)
{
    auto mockCredentialInfo = Common::MakeShared<MockCredentialInfo>();
    EXPECT_CALL(*mockCredentialInfo, GetExecutorIndex()).WillRepeatedly(Return(0));
    std::vector<std::shared_ptr<CredentialInfoInterface>> in = { mockCredentialInfo };
    std::map<uint64_t, std::vector<std::shared_ptr<CredentialInfoInterface>>> out;
    EXPECT_EQ(ResourceNodeUtils::ClassifyCredInfoByExecutor(in, out), SUCCESS);
    EXPECT_EQ(ResourceNodeUtils::ClassifyCredInfoByExecutor(in, out), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
