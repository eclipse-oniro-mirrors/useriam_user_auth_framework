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

#include "iam_ptr.h"

#include "credential_info_impl.h"
#include "delete_impl.h"
#include "resource_node_pool.h"
#include "mock_iuser_auth_interface.h"
#include "mock_resource_node.h"
#include "mock_schedule_node_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
class DeleteImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void DeleteImplTest::SetUpTestCase()
{
}

void DeleteImplTest::TearDownTestCase()
{
}

void DeleteImplTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void DeleteImplTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(DeleteImplTest, AbandonHdiError, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    DeleteImpl::DeleteParam para = {};
    para.userId = 1;
    para.credentialId = 1;
    para.tokenId = 1;
    para.token = testAuthToken;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, DeleteCredential(_, _, _, _)).WillRepeatedly(Return(1));

    auto abandon = std::make_shared<DeleteImpl>(para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    bool isCredentialDelete = false;
    std::vector<HdiCredentialInfo> credentialInfos = {};
    EXPECT_FALSE(abandon->Start(scheduleList, nullptr, isCredentialDelete, credentialInfos));
}

HWTEST_F(DeleteImplTest, AbandonHdiEmpty, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    DeleteImpl::DeleteParam para = {};
    para.userId = 1;
    para.credentialId = 1;
    para.tokenId = 1;
    para.token = testAuthToken;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, DeleteCredential(_, _, _, _)).WillRepeatedly(Return(0));

    auto abandon = std::make_shared<DeleteImpl>(para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    bool isCredentialDelete = false;
    std::vector<HdiCredentialInfo> credentialInfos = {};
    EXPECT_FALSE(abandon->Start(scheduleList, nullptr, isCredentialDelete, credentialInfos));
}

HWTEST_F(DeleteImplTest, AbandonUpdateHdiError, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    DeleteImpl::DeleteParam para = {};
    para.userId = 1;
    para.credentialId = 1;
    para.tokenId = 1;
    para.token = testAuthToken;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, UpdateAbandonResult(para.userId, _, _)).WillRepeatedly(Return(1));

    auto abandon = std::make_shared<DeleteImpl>(para);
    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    std::shared_ptr<CredentialInfoInterface> info = nullptr;
    EXPECT_FALSE(abandon->Update(scheduleResult, info));
}

HWTEST_F(DeleteImplTest, AbandonUpdateHdiSuccessful_001, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    DeleteImpl::DeleteParam para = {};
    para.userId = 1;
    para.credentialId = 1;
    para.tokenId = 1;
    para.token = testAuthToken;
    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, UpdateAbandonResult(para.userId, _, _))
        .WillRepeatedly(
            [](int32_t userId, const std::vector<uint8_t> &scheduleResult,
                std::vector<HdiCredentialInfo> &infos) {
                HdiCredentialInfo info = {
                    .credentialId = 1,
                    .executorIndex = 2,
                    .templateId = 3,
                    .authType = static_cast<HdiAuthType>(0),
                    .executorMatcher = 5,
                    .executorSensorHint = 6,
                };
                infos.push_back(info);
                return HDF_SUCCESS;
            }
        );

    auto abandon = std::make_shared<DeleteImpl>(para);
    HdiCredentialInfo oldInfo = {};
    std::shared_ptr<CredentialInfoInterface> info = std::make_shared<CredentialInfoImpl>(para.userId, oldInfo);
    EXPECT_TRUE(abandon->Update(scheduleResult, info));

    EXPECT_EQ(info->GetCredentialId(), 1U);
    EXPECT_EQ(info->GetAuthType(), static_cast<AuthType>(0));
    EXPECT_EQ(info->GetExecutorIndex(), 2U);
    EXPECT_EQ(info->GetUserId(), 1);
    EXPECT_EQ(info->GetTemplateId(), 3U);
    EXPECT_EQ(info->GetExecutorMatcher(), 5U);
    EXPECT_EQ(info->GetExecutorSensorHint(), 6U);
}

HWTEST_F(DeleteImplTest, AbandonUpdateHdiSuccessful_002, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    DeleteImpl::DeleteParam para = {};
    para.userId = 1;
    para.credentialId = 1;
    para.tokenId = 1;
    para.token = testAuthToken;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, UpdateAbandonResult(_, _, _)).WillRepeatedly(Return(0));
    auto abandon = std::make_shared<DeleteImpl>(para);

    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    std::shared_ptr<CredentialInfoInterface> info = nullptr;
    EXPECT_TRUE(abandon->Update(scheduleResult, info));
}

HWTEST_F(DeleteImplTest, DeleteImplTestStart_001, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    DeleteImpl::DeleteParam para = {};
    para.userId = 1;
    para.credentialId = 1;
    para.tokenId = 1;
    para.token = testAuthToken;
    constexpr uint64_t executorIndex = 60;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, DeleteCredential(_, _, _, _))
        .WillRepeatedly(
            [](int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
                HdiCredentialOperateResult &operateResult) {
                operateResult.operateType = HdiCredentialOperateType::CREDENTIAL_ABANDON;
                operateResult.scheduleInfo.authType = HdiAuthType::FACE;
                operateResult.scheduleInfo.executorMatcher = 10;
                operateResult.scheduleInfo.executorIndexes.push_back(60);
                std::vector<uint8_t> executorMessages;
                executorMessages.resize(1);
                operateResult.scheduleInfo.executorMessages.push_back(executorMessages);
                operateResult.scheduleInfo.scheduleId = 20;
                operateResult.scheduleInfo.scheduleMode = HdiScheduleMode::ABANDON;
                operateResult.scheduleInfo.templateIds.push_back(30);
                return HDF_SUCCESS;
            }
        );
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, FACE, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto abandon = std::make_shared<DeleteImpl>(para);
    EXPECT_NE(abandon, nullptr);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_NE(callback, nullptr);
    bool isCredentialDelete = false;
    std::vector<HdiCredentialInfo> credentialInfos = {};
    EXPECT_TRUE(abandon->Start(scheduleList, callback, isCredentialDelete, credentialInfos));
    EXPECT_TRUE(abandon->Cancel());
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
}

HWTEST_F(DeleteImplTest, DeleteImplTestStart_002, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    DeleteImpl::DeleteParam para = {};
    para.userId = 1;
    para.credentialId = 1;
    para.tokenId = 1;
    para.token = testAuthToken;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, DeleteCredential(_, _, _, _)).WillRepeatedly(Return(1));
    auto abandon = std::make_shared<DeleteImpl>(para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    bool isCredentialDelete = false;
    std::vector<HdiCredentialInfo> credentialInfos = {};
    EXPECT_FALSE(abandon->Start(scheduleList, callback, isCredentialDelete, credentialInfos));
}

HWTEST_F(DeleteImplTest, SetLatestError_001, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    DeleteImpl::DeleteParam para = {};
    para.userId = 1;
    para.credentialId = 1;
    para.tokenId = 1;
    para.token = testAuthToken;
    auto abandon = std::make_shared<DeleteImpl>(para);
    EXPECT_NO_THROW(abandon->SetLatestError(ResultCode::SUCCESS));
}

HWTEST_F(DeleteImplTest, StartSchedule_001, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    DeleteImpl::DeleteParam para = {};
    para.userId = 1;
    para.credentialId = 1;
    para.tokenId = 1;
    para.token = testAuthToken;
    auto abandon = std::make_shared<DeleteImpl>(para);
    int32_t userId = 100;
    HdiScheduleInfo info = {};
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    std::shared_ptr<ScheduleNodeCallback> callback;
    EXPECT_FALSE(abandon->StartSchedule(userId, info, scheduleList, callback));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS