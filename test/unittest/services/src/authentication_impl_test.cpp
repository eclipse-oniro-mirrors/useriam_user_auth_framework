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

#include <future>
#include <memory>
#include <thread>

#include "accesstoken_kit.h"
#include "iam_ptr.h"

#include "authentication_impl.h"
#include "resource_node_pool.h"
#include "mock_user_auth_engine.h"
#include "mock_resource_node.h"
#include "mock_schedule_node_callback.h"
#include "mock_authentication.h"

constexpr int32_t TEST_USER_ID = 101;

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
    MockUserAuthEngine::Holder::GetInstance().Reset();
}

void AuthenticationImplTest::TearDown()
{
    MockUserAuthEngine::Holder::GetInstance().Reset();
}

HWTEST_F(AuthenticationImplTest, AuthenticationHdiError, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;
    auto mock = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginAuthenticationExt(contextId, _, _, _)).WillRepeatedly(Return(1));

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    EXPECT_FALSE(authentication->Start(scheduleList, acquireInfoCallback, nullptr));
}

HWTEST_F(AuthenticationImplTest, AuthenticationHdiEmpty, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;

    auto mock = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginAuthenticationExt(contextId, _, _, _)).WillRepeatedly(Return(0));

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    EXPECT_FALSE(authentication->Start(scheduleList, acquireInfoCallback, nullptr));
}

HWTEST_F(AuthenticationImplTest, AuthenticationInvalidExecutor, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;
    constexpr int32_t executorInfoIndex = 0x100;
    constexpr int32_t scheduleId = 0x1122;

    auto fillInfoList = [](std::vector<HdiScheduleInfo> &scheduleInfos) {
        HdiScheduleInfo scheduleInfo;
        scheduleInfo.scheduleId = scheduleId;
        scheduleInfo.templateIds = {0, 1, 2};
        scheduleInfo.authType = HdiAuthType::FACE;
        scheduleInfo.executorMatcher = 0;
        scheduleInfo.scheduleMode = ScheduleMode::ENROLL;
        scheduleInfo.executorIndexes.push_back(executorInfoIndex);
        std::vector<uint8_t> executorMessages;
        executorMessages.resize(1);
        scheduleInfo.executorMessages.push_back(executorMessages);
        std::vector<HdiScheduleInfo> list;
        list.emplace_back(scheduleInfo);

        scheduleInfos.swap(list);
    };

    auto mock = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginAuthenticationExt(contextId, _, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillInfoList),
        Return(0)));

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    EXPECT_FALSE(authentication->Start(scheduleList, acquireInfoCallback, nullptr));
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestUpdate001, TestSize.Level0)
{
    constexpr uint64_t contextId = 54871;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;

    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, UpdateAuthenticationResult(_, _, _, _, _)).Times(1);
    ON_CALL(*mockHdi, UpdateAuthenticationResult)
        .WillByDefault(
            [](uint64_t contextId, const std::vector<uint8_t> &scheduleResult, HdiAuthResultInfo &info,
                HdiEnrolledState &enrolledState, AcquireInfoCallback &) {
                info.result = SUCCESS;
                info.userId = TEST_USER_ID;
                info.credentialId = 1;
                return SUCCESS;
            }
        );

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    EXPECT_NE(authentication, nullptr);
    std::vector<uint8_t> scheduleResult;
    Authentication::AuthResultInfo info = {};
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    EXPECT_TRUE(authentication->Update(scheduleResult, info, acquireInfoCallback));
    EXPECT_EQ(info.userId, TEST_USER_ID);
    EXPECT_EQ(info.credentialId, 1);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestUpdate002, TestSize.Level0)
{
    constexpr uint64_t contextId = 54871;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;

    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, UpdateAuthenticationResult(_, _, _, _, _)).Times(1);
    ON_CALL(*mockHdi, UpdateAuthenticationResult)
        .WillByDefault(
            [](uint64_t contextId, const std::vector<uint8_t> &scheduleResult, HdiAuthResultInfo &info,
                HdiEnrolledState &enrolledState, AcquireInfoCallback &) {
                info.result = GENERAL_ERROR;
                HdiExecutorSendMsg msg = {};
                msg.commandId = 10;
                msg.executorIndex = 20;
                info.msgs.push_back(msg);
                return GENERAL_ERROR;
            }
        );

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    EXPECT_NE(authentication, nullptr);
    std::vector<uint8_t> scheduleResult;
    Authentication::AuthResultInfo info = {};
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    EXPECT_FALSE(authentication->Update(scheduleResult, info, acquireInfoCallback));
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestSetEndAfterFirstFail, TestSize.Level0)
{
    constexpr uint64_t contextId = 1234;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    EXPECT_NE(authentication, nullptr);
    bool endAfterFirstFail = true;
    authentication->SetEndAfterFirstFail(endAfterFirstFail);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestGetLatestError, TestSize.Level0)
{
    constexpr uint64_t contextId = 1234;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);
    int32_t lastError = authentication->GetLatestError();
    EXPECT_EQ(ResultCode::GENERAL_ERROR, lastError);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestGetAuthExecutorMsgs, TestSize.Level0)
{
    constexpr uint64_t contextId = 1234;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);
    auto authExecutorMsgs = authentication->GetAuthExecutorMsgs();
    EXPECT_EQ(authExecutorMsgs.size(), 0);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestStart, TestSize.Level0)
{
    constexpr uint64_t contextId = 34567;
    constexpr uint64_t executorIndex = 60;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;

    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    // BeginAuthenticationExt succeeds, but the schedule info carries one executorIndex
    // and no executorMessage, so ScheduleInfoToExecutors rejects it and Start fails in
    // BuildFromHdi without ever setting running_. Cancel() is gated on running_ (the
    // cancel-request latch lives in ContextPool, not in AuthenticationImpl), so it is a
    // no-op and the engine is never asked to cancel
    EXPECT_CALL(*mockHdi, CancelAuthentication(_)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _, _))
        .WillRepeatedly(
            [](uint64_t contextId, const HdiAuthParamExt &param,
                std::vector<HdiScheduleInfo> &scheduleInfos, AcquireInfoCallback &) {
                HdiScheduleInfo scheduleInfo = {};
                scheduleInfo.authType = HdiAuthType::FACE;
                scheduleInfo.executorMatcher = 10;
                scheduleInfo.executorIndexes.push_back(60);
                scheduleInfo.scheduleId = 20;
                scheduleInfo.scheduleMode = ScheduleMode::AUTH;
                scheduleInfo.templateIds.push_back(30);
                scheduleInfos.push_back(scheduleInfo);
                return SUCCESS;
            }
        );
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, FACE, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    EXPECT_NE(authentication, nullptr);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    EXPECT_NE(callback, nullptr);
    EXPECT_FALSE(authentication->Start(scheduleList, acquireInfoCallback, callback));
    EXPECT_FALSE(authentication->Cancel());

    EXPECT_FALSE(authentication->Start(scheduleList, acquireInfoCallback, callback));
    EXPECT_FALSE(authentication->Cancel());

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
}

namespace {
constexpr int32_t CANCEL_TEST_USER_ID = 0x11;
constexpr int32_t CANCEL_TEST_SDK_VERSION = 11;
constexpr uint64_t CANCEL_TEST_SCHEDULE_ID = 21;
constexpr uint64_t CANCEL_TEST_TEMPLATE_ID = 31;

// BeginAuthenticationExt blocks between the two promises so a concurrent Cancel can
// land while Start is still inside the engine call
void MockBlockingBeginAuthentication(const std::shared_ptr<MockUserAuthEngine> &mockHdi,
    uint32_t executorIndex, std::promise<void> &beginEntered, std::promise<void> &releaseBegin)
{
    ON_CALL(*mockHdi, BeginAuthenticationExt(_, _, _, _))
        .WillByDefault([&beginEntered, &releaseBegin, executorIndex](uint64_t contextId,
            const HdiAuthParamExt &param, std::vector<HdiScheduleInfo> &scheduleInfos, AcquireInfoCallback &) {
            HdiScheduleInfo scheduleInfo = {};
            scheduleInfo.authType = HdiAuthType::FACE;
            scheduleInfo.executorMatcher = 0;
            scheduleInfo.executorIndexes.push_back(executorIndex);
            scheduleInfo.scheduleId = CANCEL_TEST_SCHEDULE_ID;
            scheduleInfo.scheduleMode = ScheduleMode::AUTH;
            scheduleInfo.templateIds.push_back(CANCEL_TEST_TEMPLATE_ID);
            std::vector<uint8_t> executorMessages;
            executorMessages.resize(1);
            scheduleInfo.executorMessages.push_back(executorMessages);
            scheduleInfos.push_back(scheduleInfo);
            beginEntered.set_value();
            releaseBegin.get_future().get();
            return SUCCESS;
        });
}
} // namespace

// The cancel-request latch lives in ContextPool (cancelRequestedIds_ suppresses
// the posted start), not in AuthenticationImpl: in production Start/Cancel run
// serially on the context handler. A Cancel that lands while Start is still
// inside the engine call finds running_ unset, is a no-op, and Start completes
// normally; only a Cancel after Start returned true reaches the engine.
HWTEST_F(AuthenticationImplTest, AuthenticationImplCancelDuringStartIsNoOpUntilRunning, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234568;
    constexpr uint32_t executorIndex = 61;
    Authentication::AuthenticationPara para = {};
    para.userId = CANCEL_TEST_USER_ID;
    para.callerName = "com.ohos.test";
    para.sdkVersion = CANCEL_TEST_SDK_VERSION;
    para.authType = FACE;
    para.atl = ATL3;

    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    std::promise<void> beginEntered;
    std::promise<void> releaseBegin;
    MockBlockingBeginAuthentication(mockHdi, executorIndex, beginEntered, releaseBegin);
    EXPECT_CALL(*mockHdi, CancelAuthentication(contextId)).WillOnce(Return(SUCCESS));

    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, FACE, ALL_IN_ONE);
    ASSERT_NE(resourceNode, nullptr);
    ASSERT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    ASSERT_NE(callback, nullptr);

    std::thread starter([&authentication, &scheduleList, &acquireInfoCallback, &callback]() {
        EXPECT_TRUE(authentication->Start(scheduleList, acquireInfoCallback, callback));
    });
    beginEntered.get_future().get();
    EXPECT_FALSE(authentication->Cancel());
    releaseBegin.set_value();
    starter.join();
    EXPECT_TRUE(authentication->Cancel());
    EXPECT_FALSE(authentication->Cancel());

    ASSERT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
}

// Same contract as the engine-call case: a reentrant Cancel from inside
// ScheduleNodeHelper::BuildFromHdi still finds running_ unset, is a no-op and
// leaves no error trace; Start completes and a later Cancel reaches the engine.
HWTEST_F(AuthenticationImplTest, AuthenticationImplCancelDuringScheduleBuildIsNoOp, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234569;
    constexpr uint32_t executorIndex = 62;
    constexpr uint64_t scheduleId = 22;
    Authentication::AuthenticationPara para = {};
    para.userId = CANCEL_TEST_USER_ID;
    para.callerName = "com.ohos.test";
    para.sdkVersion = CANCEL_TEST_SDK_VERSION;
    para.authType = FACE;
    para.atl = ATL3;
    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(contextId, _, _, _))
        .WillOnce([](uint64_t, const HdiAuthParamExt &, std::vector<HdiScheduleInfo> &infos, AcquireInfoCallback &) {
            HdiScheduleInfo info = {};
            info.authType = HdiAuthType::FACE;
            info.executorIndexes = {executorIndex};
            info.scheduleId = scheduleId;
            info.scheduleMode = ScheduleMode::AUTH;
            info.templateIds = {CANCEL_TEST_TEMPLATE_ID};
            info.executorMessages = {{0}};
            infos.push_back(info);
            return SUCCESS;
        });
    EXPECT_CALL(*mockHdi, CancelAuthentication(contextId)).WillOnce(Return(SUCCESS));
    auto resource = MockResourceNode::CreateWithExecuteIndex(executorIndex, FACE, ALL_IN_ONE);
    ASSERT_NE(resource, nullptr);
    ASSERT_TRUE(ResourceNodePool::Instance().Insert(resource));
    bool canceled = false;
    EXPECT_CALL(*std::static_pointer_cast<MockResourceNode>(resource), GetExecutorRole())
        .WillRepeatedly([&]() {
            if (!canceled) {
                canceled = true;
                EXPECT_FALSE(authentication->Cancel());
            }
            return ALL_IN_ONE;
        });

    std::vector<std::shared_ptr<ScheduleNode>> schedules;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole, int32_t, const std::vector<uint8_t> &) {};
    EXPECT_TRUE(authentication->Start(schedules, acquireInfoCallback, callback));
    EXPECT_TRUE(canceled);
    EXPECT_TRUE(authentication->Cancel());
    EXPECT_FALSE(authentication->Cancel());
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplTestSetLatestError, TestSize.Level0)
{
    constexpr uint64_t contextId = 1234;
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 11;
    para.authType = FACE;
    para.atl = ATL3;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);
    authentication->SetLatestError(0);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplHdiFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = TEST_USER_ID;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 10;
    para.authType = PIN;
    para.atl = ATL2;
    para.callerType = Security::AccessToken::TOKEN_HAP;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _, _))
        .WillRepeatedly(Return(GENERAL_ERROR));

    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    EXPECT_NE(callback, nullptr);

    bool result = authentication->Start(scheduleList, acquireInfoCallback, callback);
    EXPECT_FALSE(result);
    int32_t latestError = authentication->GetLatestError();
    EXPECT_NE(latestError, ResultCode::SUCCESS);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplGetAuthParamFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = TEST_USER_ID;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 10;
    para.authType = FACE;
    para.atl = ATL2;
    para.callerType = 9999; // Invalid caller type for test

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    EngAuthParamExt param = {};
    bool result = authentication->GetAuthParam(param);
    EXPECT_FALSE(result);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplUpdateFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = TEST_USER_ID;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 10;
    para.authType = PIN;
    para.atl = ATL2;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, UpdateAuthenticationResult(_, _, _, _, _))
        .WillRepeatedly(Return(GENERAL_ERROR));

    std::vector<uint8_t> scheduleResult = {1, 2, 3, 4};
    Authentication::AuthResultInfo resultInfo = {};
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    bool result = authentication->Update(scheduleResult, resultInfo, acquireInfoCallback);
    EXPECT_FALSE(result); // Update returns false when HDI fails

    int32_t latestError = authentication->GetLatestError();
    EXPECT_EQ(latestError, GENERAL_ERROR); // latestError is set correctly
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplCancel_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = TEST_USER_ID;
    para.callerName = "com.ohos.test";
    para.sdkVersion = 10;
    para.authType = FACE;
    para.atl = ATL3;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    authentication->SetAccessTokenId(12345);
    authentication->SetChallenge({1, 2, 3, 4});
    authentication->SetEndAfterFirstFail(true);

    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CancelAuthentication(_))
        .WillRepeatedly(Return(SUCCESS));

    EXPECT_NO_THROW(authentication->Cancel());
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplGetAuthExecutorMsgs_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = TEST_USER_ID;
    para.authType = PIN;
    para.atl = ATL2;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    std::vector<Authentication::AuthExecutorMsg> msgs = authentication->GetAuthExecutorMsgs();
    EXPECT_EQ(msgs.size(), 0);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplSetExecutor_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = TEST_USER_ID;
    para.authType = FACE;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    uint32_t executorIndex = 12345;
    authentication->SetExecutor(executorIndex);
    EXPECT_NO_THROW(authentication->GetLatestError());
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplSetCollectorUdid_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = TEST_USER_ID;
    para.authType = FINGERPRINT;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    std::string collectorUdid = "test_udid_12345";
    authentication->SetCollectorUdid(collectorUdid);
    EXPECT_NO_THROW(authentication->GetLatestError());
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplEmptyScheduleList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = TEST_USER_ID;
    para.authType = PIN;
    para.atl = ATL1;
    para.callerType = Security::AccessToken::TOKEN_HAP;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    std::vector<HdiScheduleInfo> emptyInfos;

    EXPECT_CALL(*mockHdi, BeginAuthenticationExt(_, _, _, _))
        .WillOnce([&emptyInfos](uint64_t contextId, const HdiAuthParamExt &param,
            std::vector<HdiScheduleInfo> &infos, AcquireInfoCallback &) {
            infos = emptyInfos;
            return SUCCESS;
        });

    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    EXPECT_NE(callback, nullptr);

    bool result = authentication->Start(scheduleList, acquireInfoCallback, callback);
    EXPECT_FALSE(result);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplSuccessWithToken_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = TEST_USER_ID;
    para.authType = FACE;
    para.atl = ATL3;
    para.sdkVersion = 12;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);

    EXPECT_CALL(*mockHdi, UpdateAuthenticationResult(_, _, _, _, _))
        .WillOnce([](uint64_t contextId, const std::vector<uint8_t> &scheduleResult,
            HdiAuthResultInfo &info, HdiEnrolledState &enrolledState, AcquireInfoCallback &) {
            info.result = SUCCESS;
            info.token = {0x01, 0x02, 0x03, 0x04};
            info.userId = TEST_USER_ID;
            info.lockoutDuration = 0;
            info.remainAttempts = -1;
            enrolledState.credentialDigest = 12345;
            enrolledState.credentialCount = 2;
            return SUCCESS;
        });

    std::vector<uint8_t> scheduleResult = {1, 2, 3, 4};
    Authentication::AuthResultInfo resultInfo = {};
    AcquireInfoCallback acquireInfoCallback = [](ExecutorRole src, int32_t moduleType,
        const std::vector<uint8_t> &acquireMsg) {};
    bool result = authentication->Update(scheduleResult, resultInfo, acquireInfoCallback);
    EXPECT_TRUE(result);
    EXPECT_EQ(resultInfo.result, ResultCode::SUCCESS);
    EXPECT_EQ(resultInfo.token.size(), 4);
    EXPECT_EQ(resultInfo.userId, TEST_USER_ID);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplGetUserIdAndType_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = 100;
    para.authType = AuthType::PIN;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    int32_t userId = authentication->GetUserId();
    EXPECT_EQ(userId, 100);

    int32_t authType = authentication->GetAuthType();
    EXPECT_EQ(authType, AuthType::PIN);
}

HWTEST_F(AuthenticationImplTest, AuthenticationImplGetAccessTokenId_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    Authentication::AuthenticationPara para = {};
    para.userId = TEST_USER_ID;
    para.authType = FACE;

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, para);
    ASSERT_NE(authentication, nullptr);

    uint32_t tokenId = 67890;
    authentication->SetAccessTokenId(tokenId);

    uint32_t resultTokenId = authentication->GetAccessTokenId();
    EXPECT_EQ(resultTokenId, tokenId);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
