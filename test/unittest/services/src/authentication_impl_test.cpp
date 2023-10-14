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

#include <memory>

#include "iam_ptr.h"

#include "authentication_impl.h"
#include "resource_node_pool.h"
#include "mock_iuser_auth_interface.h"
#include "mock_resource_node.h"
#include "mock_schedule_node_callback.h"
#include "mock_authentication.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class AuthenticationImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void AuthenticationImplTest::SetUpTestCase()
{
}

void AuthenticationImplTest::TearDownTestCase()
{
}

void AuthenticationImplTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void AuthenticationImplTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthenticationImplTest, AuthenticationHdiError, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    constexpr int32_t userId = 0x11;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginAuthenticationV1_1(contextId, _, _)).WillRepeatedly(Return(1));

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(authentication->Start(scheduleList, nullptr));
}

HWTEST_F(AuthenticationImplTest, AuthenticationHdiEmpty, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    constexpr int32_t userId = 0x11;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginAuthenticationV1_1(contextId, _, _)).WillRepeatedly(Return(0));

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(authentication->Start(scheduleList, nullptr));
}

HWTEST_F(AuthenticationImplTest, AuthenticationInvalidExecutor, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    constexpr int32_t userId = 0x11;
    constexpr int32_t executorInfoIndex = 0x100;
    constexpr int32_t scheduleId = 0x1122;

    auto fillInfoList = [](std::vector<HdiScheduleInfo> &scheduleInfos) {
        HdiExecutorInfo executorInfo;
        executorInfo.executorIndex = executorInfoIndex;

        HdiScheduleInfo scheduleInfo;

        scheduleInfo.scheduleId = scheduleId;
        scheduleInfo.templateIds = {0, 1, 2};
        scheduleInfo.authType = HdiAuthType::FACE;
        scheduleInfo.executorMatcher = 0;
        scheduleInfo.scheduleMode = HdiScheduleMode::ENROLL;
        scheduleInfo.executors.push_back(executorInfo);

        std::vector<HdiScheduleInfo> list;
        list.emplace_back(scheduleInfo);

        scheduleInfos.swap(list);
    };

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginAuthenticationV1_1(contextId, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillInfoList),
        Return(0)));

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(authentication->Start(scheduleList, nullptr));
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestUpdate001, TestSize.Level0)
{
    constexpr uint64_t contextId = 54871;
    constexpr int32_t userId = 1534;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, UpdateAuthenticationResult(_, _, _)).Times(1);
    ON_CALL(*mockHdi, UpdateAuthenticationResult)
        .WillByDefault(
            [](uint64_t contextId, const std::vector<uint8_t> &scheduleResult, HdiAuthResultInfo &info) {
                info.result = HDF_SUCCESS;
                return HDF_SUCCESS;
            }
        );

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    EXPECT_NE(authentication, nullptr);
    std::vector<uint8_t> scheduleResult;
    Authentication::AuthResultInfo info = {};
    EXPECT_TRUE(authentication->Update(scheduleResult, info));
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestUpdate002, TestSize.Level0)
{
    constexpr uint64_t contextId = 54871;
    constexpr int32_t userId = 1534;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, UpdateAuthenticationResult(_, _, _)).Times(1);
    ON_CALL(*mockHdi, UpdateAuthenticationResult)
        .WillByDefault(
            [](uint64_t contextId, const std::vector<uint8_t> &scheduleResult, HdiAuthResultInfo &info) {
                info.result = HDF_FAILURE;
                HdiExecutorSendMsg msg = {};
                msg.commandId = 10;
                msg.executorIndex = 20;
                info.msgs.push_back(msg);
                return HDF_FAILURE;
            }
        );

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    EXPECT_NE(authentication, nullptr);
    std::vector<uint8_t> scheduleResult;
    Authentication::AuthResultInfo info = {};
    EXPECT_FALSE(authentication->Update(scheduleResult, info));
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestSetEndAfterFirstFail, TestSize.Level0)
{
    constexpr uint64_t contextId = 1234;
    constexpr int32_t userId = 5678;
    AuthType authType = FACE;
    AuthTrustLevel atl = ATL3;
    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, authType, atl);
    EXPECT_NE(authentication, nullptr);
    bool endAfterFirstFail = true;
    authentication->SetEndAfterFirstFail(endAfterFirstFail);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestGetLatestError, TestSize.Level0)
{
    constexpr uint64_t contextId = 1234;
    constexpr int32_t userId = 5678;
    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    ASSERT_NE(authentication, nullptr);
    int32_t lastError = authentication->GetLatestError();
    EXPECT_EQ(ResultCode::GENERAL_ERROR, lastError);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestGetAuthExecutorMsgs, TestSize.Level0)
{
    constexpr uint64_t contextId = 1234;
    constexpr int32_t userId = 5678;
    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    ASSERT_NE(authentication, nullptr);
    auto authExecutorMsgs = authentication->GetAuthExecutorMsgs();
    EXPECT_EQ(authExecutorMsgs.size(), 0);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestStart, TestSize.Level0)
{
    constexpr uint64_t contextId = 34567;
    constexpr uint64_t userId = 25781;
    constexpr uint64_t executorIndex = 60;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CancelAuthentication(_))
        .Times(2)
        .WillOnce(Return(HDF_SUCCESS))
        .WillOnce(Return(HDF_FAILURE));
    EXPECT_CALL(*mockHdi, BeginAuthenticationV1_1(_, _, _))
        .WillRepeatedly(
            [](uint64_t contextId, const HdiAuthSolution &param, std::vector<HdiScheduleInfo> &scheduleInfos) {
                HdiScheduleInfo scheduleInfo = {};
                scheduleInfo.authType = HdiAuthType::FACE;
                scheduleInfo.executorMatcher = 10;
                HdiExecutorInfo executorInfo = {};
                executorInfo.executorIndex = 60;
                executorInfo.info.authType = HdiAuthType::FACE;
                executorInfo.info.esl = HdiExecutorSecureLevel::ESL1;
                executorInfo.info.executorMatcher = 10;
                executorInfo.info.executorRole = HdiExecutorRole::ALL_IN_ONE;
                executorInfo.info.executorSensorHint = 90;
                executorInfo.info.publicKey = {1, 2, 3, 4};
                scheduleInfo.executors.push_back(executorInfo);
                scheduleInfo.scheduleId = 20;
                scheduleInfo.scheduleMode = HdiScheduleMode::AUTH;
                scheduleInfo.templateIds.push_back(30);
                scheduleInfos.push_back(scheduleInfo);
                return HDF_SUCCESS;
            }
        );
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, FACE, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    EXPECT_NE(authentication, nullptr);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(authentication->Start(scheduleList, callback));
    EXPECT_TRUE(authentication->Cancel());

    EXPECT_TRUE(authentication->Start(scheduleList, callback));
    EXPECT_FALSE(authentication->Cancel());

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS