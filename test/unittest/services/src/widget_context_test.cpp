/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "widget_context.h"

#include <chrono>
#include <future>

#include "context_pool.h"
#include "iam_scope_guard.h"
#include "mock_context.h"
#include "mock_user_auth_callback.h"
#include "widget_client.h"
#include "mock_widget_schedule_node.h"
#include "mock_remote_auth_callback.h"
#include "mock_modal_callback.h"
#include "widget_schedule_node_impl.h"

#include "schedule_node_impl.h"
#include "widget_context_callback_impl.h"
#include "relative_timer.h"
#include <map>

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
auto &timer = RelativeTimer::GetInstance();
}
class WidgetContextTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void WidgetContextTest::SetUpTestCase()
{
}

void WidgetContextTest::TearDownTestCase()
{
}

void WidgetContextTest::SetUp()
{
}

void WidgetContextTest::TearDown()
{
}

std::shared_ptr<WidgetContext> CreateWidgetContext(uint64_t contextId, ContextFactory::AuthWidgetContextPara para,
    const sptr<IRemoteAuthCallback> remoteAuthCallback = nullptr)
{
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    return Common::MakeShared<WidgetContext>(contextId, para, false, contextCallback, nullptr, remoteAuthCallback);
}

HWTEST_F(WidgetContextTest, WidgetContextTestOnTerminateTimerTimeOut_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->BuildSchedule();
    EXPECT_NO_THROW(widgetContext->OnTerminateTimerTimeOut(contextId));
}

HWTEST_F(WidgetContextTest, WidgetContextTestOnTerminateTimerTimeOut_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    AuthType authType = ALL;
    widgetContext->OnAuthSuccess(authType);
    widgetContext->IsInFollowCallerList();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestStart, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_TRUE(widgetContext->Start());
    EXPECT_FALSE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestStop, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_TRUE(widgetContext->Stop());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetPreemptDecision, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);

    // the SystemUI session is single-seat and replace-only: a new widget request
    // takes over the window, any other request leaves the live session alone
    const uint64_t widgetReqContextId = 2;
    auto widgetReq = MockContext::CreateWithContextId(widgetReqContextId);
    auto widgetReqMock = std::static_pointer_cast<MockContext>(widgetReq);
    ON_CALL(*widgetReqMock, GetContextType()).WillByDefault(Return(ContextType::WIDGET_AUTH_CONTEXT));
    EXPECT_EQ(widgetContext->GetPreemptDecision(*widgetReq), PreemptDecision::STOP_NOW);

    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto primaryWidgetContext =
        Common::MakeShared<WidgetContext>(contextId, para, true, contextCallback, nullptr, nullptr);
    ON_CALL(*widgetReqMock, IsPrimaryContext()).WillByDefault(Return(true));
    EXPECT_EQ(primaryWidgetContext->GetPreemptDecision(*widgetReq), PreemptDecision::STOP_NOW);

    const uint64_t pinReqContextId = 3;
    auto pinReq = MockContext::CreateWithContextId(pinReqContextId);
    ON_CALL(*std::static_pointer_cast<MockContext>(pinReq), GetContextType())
        .WillByDefault(Return(ContextType::CONTEXT_SIMPLE_AUTH));
    EXPECT_EQ(widgetContext->GetPreemptDecision(*pinReq), PreemptDecision::KEEP_RUNNING);

    const uint64_t sudoReqContextId = 4;
    auto sudoReq = MockContext::CreateWithContextId(sudoReqContextId);
    ON_CALL(*std::static_pointer_cast<MockContext>(sudoReq), GetContextType())
        .WillByDefault(Return(ContextType::SUDO_AUTH_CONTEXT));
    EXPECT_EQ(widgetContext->GetPreemptDecision(*sudoReq), PreemptDecision::KEEP_RUNNING);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetScheduleNode, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetScheduleNode(contextId), nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetLatestError, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetLatestError(), ResultCode::GENERAL_ERROR);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetContextType, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetContextType(), WIDGET_AUTH_CONTEXT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetTokenId, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetTokenId(), (uint32_t)0);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes finalResult;
    widgetContext->OnChildAuthResult(ResultCode::SUCCESS, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 1);
    widgetContext->OnChildAuthResult(ResultCode::SUCCESS, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 1);
    finalResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 1);
    widgetContext->OnChildAuthResult(ResultCode::SUCCESS, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 1);
    finalResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 1);
    widgetContext->OnChildAuthResult(ResultCode::SUCCESS, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0005, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 1);
    finalResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 1);
    widgetContext->OnChildAuthResult(ResultCode::GENERAL_ERROR, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0006, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_AUTH_TYPE, PIN);
    widgetContext->OnChildAuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0007, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    Attributes finalResult;
    std::vector<uint8_t> token = {1, 1};
    finalResult.SetInt32Value(Attributes::ATTR_AUTH_TYPE, PIN);
    finalResult.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    widgetContext->OnChildAuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0008, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    Attributes finalResult;
    std::vector<uint8_t> token = {1, 1};
    finalResult.SetInt32Value(Attributes::ATTR_AUTH_TYPE, PIN);
    finalResult.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    finalResult.SetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, 1);
    widgetContext->OnChildAuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestLaunchWidget_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->LaunchWidget();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestLaunchWidget_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    ContextFactory::AuthProfile contextPara;
    para.authProfileMap[PIN] = contextPara;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->LaunchWidget();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestLaunchWidget_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    ContextFactory::AuthProfile authProfile;
    authProfile.sensorInfo = "1";
    para.authProfileMap[AuthType::FINGERPRINT] = authProfile;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->LaunchWidget();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndAuthAsCancel_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->EndAuthAsCancel();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndAuthAsCancel_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->SetLatestError(COMPLEXITY_CHECK_FAILED);
    widgetContext->EndAuthAsCancel();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndAuthAsNaviPin, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->EndAuthAsNaviPin();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndAuthAsWidgetParaInvalid, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->EndAuthAsWidgetParaInvalid();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestStopAuthList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::vector<AuthType> authTypeList;
    widgetContext->StopAuthList(authTypeList);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestStopAuthList_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::vector<AuthType> authTypeList = {ALL, PIN, FACE};
    widgetContext->StopAuthList(authTypeList);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestStopAuthList_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {0, 1};
    para.atl = ATL2;
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::set<AuthType> authTypeList;
    authTypeList.insert(FACE);
    authTypeList.insert(ALL);
    widgetContext->BuildSchedule();
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    std::vector<AuthType> testTypeList = {ALL, PIN, FACE};
    widgetContext->StopAuthList(testTypeList);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestSuccessAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    AuthType authType = ALL;
    widgetContext->OnAuthSuccess(authType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestSuccessAuth_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    AuthType authType = ALL;
    widgetContext->LaunchWidget();
    widgetContext->OnAuthSuccess(authType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestSuccessAuth_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {0, 1};
    para.atl = ATL2;
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::set<AuthType> authTypeList;
    authTypeList.insert(FACE);
    widgetContext->ExecuteAuthList(authTypeList, true, AuthIntent::DEFAULT);
    AuthType authType = ALL;
    widgetContext->OnAuthSuccess(authType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestSuccessAuth_004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    AuthType authType = ALL;
    widgetContext->SetLatestError(ResultCode::COMPLEXITY_CHECK_FAILED);
    widgetContext->OnAuthSuccess(authType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReloadInit, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->AuthWidgetReloadInit();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, IsValidRotate_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.orientation = 3;
    widgetRotatePara.isReload = 3;
    widgetRotatePara.needRotate = 3;
    bool isValidRotate = widgetContext->IsValidRotate(widgetRotatePara);
    EXPECT_NE(isValidRotate, false);
    widgetRotatePara.needRotate = 1;
    widgetContext->IsValidRotate(widgetRotatePara);
}

HWTEST_F(WidgetContextTest, IsValidRotate_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.orientation = 3;
    widgetRotatePara.isReload = 3;
    widgetRotatePara.needRotate = 0;
    bool isValidRotate = widgetContext->IsValidRotate(widgetRotatePara);
    EXPECT_NE(isValidRotate, false);
    widgetRotatePara.needRotate = 1;
    widgetContext->IsValidRotate(widgetRotatePara);
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 1;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 1;
    AuthType rotateAuthType = PIN;
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 2;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 1;
    AuthType rotateAuthType = FINGERPRINT;
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 3;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 1;
    AuthType rotateAuthType = FACE;
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 2;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 0;
    AuthType rotateAuthType = FACE;
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0005, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 3;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 0;
    AuthType rotateAuthType = FACE;
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0006, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 1;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 0;
    AuthType rotateAuthType = FACE;
    WidgetCmdParameters widgetCmdParameters;
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.orientation = 3;
    widgetRotatePara.isReload = 0;
    widgetRotatePara.needRotate = 0;
    widgetContext->ProcessRotatePara(widgetCmdParameters, widgetRotatePara);
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcessRotatePara, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    WidgetCmdParameters widgetCmdParameters;
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.orientation = 2;
    widgetRotatePara.isReload = 0;
    widgetRotatePara.needRotate = 1;
    widgetContext->ProcessRotatePara(widgetCmdParameters, widgetRotatePara);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetUserId, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->GetUserId();
}

HWTEST_F(WidgetContextTest, WidgetContextTestOnResult, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    std::shared_ptr<Attributes> scheduleResultAttr = Common::MakeShared<Attributes>();
    EXPECT_NE(scheduleResultAttr, nullptr);
    int32_t resultCode = 2;
    widgetContext->OnResult(resultCode, scheduleResultAttr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleFaceOrFingerPrintAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FACE);
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->IsSingleFaceOrFingerPrintAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleFaceOrFingerPrintAuth_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FINGERPRINT);
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->IsSingleFaceOrFingerPrintAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleFaceOrFingerPrintAuth_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FACE);
    para.widgetParam.navigationButtonText = "111";
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(!widgetContext->IsSingleFaceOrFingerPrintAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleFaceOrFingerPrintAuth_004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FACE);
    para.authTypeList.push_back(FINGERPRINT);
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(!widgetContext->IsSingleFaceOrFingerPrintAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsNavigationAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FACE);
    para.widgetParam.navigationButtonText = "111";
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->IsNavigationAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsNavigationAuth_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FACE);
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(!widgetContext->IsNavigationAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestSendAuthTipInfo, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    int32_t authType = FACE;
    int32_t tipCode = TIP_CODE_FAIL;
    EXPECT_NO_THROW(widgetContext->OnScheduleAuthTip(authType, tipCode));
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetAuthTipCode, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_EQ(widgetContext->GetAuthTipCode(ResultCode::TIMEOUT, 0), TIP_CODE_TIMEOUT);
    EXPECT_EQ(widgetContext->GetAuthTipCode(ResultCode::FAIL, 1), TIP_CODE_COMPARE_FAIL_WITH_FROZEN);
    EXPECT_EQ(widgetContext->GetAuthTipCode(ResultCode::FAIL, INT32_MAX), TIP_CODE_COMPARE_FAIL_WITH_FROZEN);
    EXPECT_EQ(widgetContext->GetAuthTipCode(ResultCode::FAIL, -1), TIP_CODE_FAIL);
    EXPECT_EQ(widgetContext->GetAuthTipCode(ResultCode::LOCKED, 1), TIP_CODE_TEMPORARILY_LOCKED);
    EXPECT_EQ(widgetContext->GetAuthTipCode(ResultCode::LOCKED, INT32_MAX), TIP_CODE_PERMANENTLY_LOCKED);
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    const Attributes attribute;
    EXPECT_NO_THROW(widgetContext->ProcAuthResult(ResultCode::SUCCESS, PIN, 0, attribute));
    EXPECT_NO_THROW(widgetContext->ProcAuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, PIN, 0, attribute));
    EXPECT_NO_THROW(widgetContext->ProcAuthResult(ResultCode::FAIL, PIN, 0, attribute));
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthTipInfo, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    std::vector<uint8_t> extraInfo;
    widgetContext->BuildSchedule();
    EXPECT_NO_THROW(widgetContext->ProcAuthTipInfo(USER_AUTH_TIP_SINGLE_AUTH_RESULT, PIN, extraInfo));
    EXPECT_NO_THROW(widgetContext->ProcAuthTipInfo(0, PIN, extraInfo));
}

HWTEST_F(WidgetContextTest, WidgetContextTestStopOnTerminateTimer, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_NO_THROW(widgetContext->StopOnTerminateTimer());
    widgetContext->onTerminateTimerId_ = 1;
    EXPECT_NO_THROW(widgetContext->StopOnTerminateTimer());
}

HWTEST_F(WidgetContextTest, WidgetContextTestOnTerminateTimerTimeOut, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->BuildSchedule();
    EXPECT_NO_THROW(widgetContext->OnTerminateTimerTimeOut(contextId));
}

HWTEST_F(WidgetContextTest, WidgetContextTestSetSysDialogZOrder, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    WidgetCmdParameters widgetCmdParameters = {};
    EXPECT_NO_THROW(widgetContext->SetSysDialogZOrder(widgetCmdParameters));
    widgetContext->para_.callerName = "findnetwork";
    widgetContext->para_.callerType = Security::AccessToken::TOKEN_NATIVE;
    EXPECT_NO_THROW(widgetContext->SetSysDialogZOrder(widgetCmdParameters));
}

// Unlocked screen bypasses the engine hook, so the launch is allowed regardless of
// caller identity; a denied locked-screen launch short-circuits to CANCELED via OnResult.
HWTEST_F(WidgetContextTest, WidgetContextTestIsWidgetLaunchAllowed, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.callerName = "test_caller";
    para.callerType = Security::AccessToken::TOKEN_HAP;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    bool allow = false;
    EXPECT_NO_THROW(allow = widgetContext->IsWidgetLaunchAllowed());
    EXPECT_TRUE(allow);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestConnectExtension_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;

    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    WidgetContext::WidgetRotatePara widgetRotatePara = {};
    widgetRotatePara.isReload = true;
    AuthType authType = AuthType::FACE;
    widgetContext->para_.authTypeList.emplace_back(authType);
    EXPECT_EQ(widgetContext->ConnectExtension(widgetRotatePara), true);
}

HWTEST_F(WidgetContextTest, WidgetContextTestConnectExtension_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    std::map<AuthType, ContextFactory::AuthProfile> authProfileMap;
    ContextFactory::AuthProfile authProfile;
    authProfile.remainTimes = 0;
    authProfileMap.insert(std::make_pair(FACE, authProfile));
    std::vector<AuthType> authTypeList = { FACE };
    para.authProfileMap = authProfileMap;
    para.skipLockedBiometricAuth = true;
    para.widgetParam.hasContext = true;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    WidgetContext::WidgetRotatePara widgetRotatePara = {};
    widgetRotatePara.isReload = true;
    AuthType authType = AuthType::FACE;
    widgetContext->para_.authTypeList.emplace_back(authType);
    EXPECT_EQ(widgetContext->ConnectExtension(widgetRotatePara), true);
}

HWTEST_F(WidgetContextTest, WidgetContextSkipLockedBranchTerminatesAndReleases, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    ContextFactory::AuthProfile authProfile;
    authProfile.remainTimes = 0;
    para.authProfileMap.insert(std::make_pair(FACE, authProfile));
    para.skipLockedBiometricAuth = true;
    auto widgetContext = CreateWidgetContext(contextId, para);
    ASSERT_NE(widgetContext, nullptr);
    widgetContext->para_.authTypeList.emplace_back(AuthType::FACE);
    EXPECT_EQ(widgetContext->ConnectExtension(WidgetContext::WidgetRotatePara {}), true);
    EXPECT_EQ(widgetContext->phase_, WidgetContext::Phase::RESULT_DELIVERED);
    widgetContext->OnTerminateTimerTimeOut(contextId);
    EXPECT_EQ(widgetContext->phase_, WidgetContext::Phase::RELEASED);
}

HWTEST_F(WidgetContextTest, WidgetContextTestDisconnectExtension, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->useModalApplication_ = true;
    widgetContext->DisconnectExtension();
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetContext->para_.isPinExpired = true;
    widgetContext->BuildStartCommand(widgetRotatePara);
    widgetContext->para_.callerType = 9;
    widgetContext->GetCallerName();
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthTipInfo_0001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes extraInfo;
    std::vector<uint8_t> tipInfo = {1, 2, 3};
    extraInfo.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, tipInfo);
    int32_t tipType = 0;
    int32_t authType = PIN;
    EXPECT_NO_THROW(widgetContext->OnChildAuthTip(tipType, authType, extraInfo));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthTipInfo_0002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes extraInfo;
    int32_t tipType = 1;
    int32_t authType = FACE;
    EXPECT_NO_THROW(widgetContext->OnChildAuthTip(tipType, authType, extraInfo));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthTipInfo_0003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes extraInfo;
    std::vector<uint8_t> tipInfo = {0x01, 0x02, 0x03, 0x04};
    extraInfo.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, tipInfo);
    int32_t tipType = USER_AUTH_TIP_SINGLE_AUTH_RESULT;
    int32_t authType = FINGERPRINT;
    EXPECT_NO_THROW(widgetContext->OnChildAuthTip(tipType, authType, extraInfo));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthTipInfo_0004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.skipLockedBiometricAuth = true;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes extraInfo;
    std::vector<uint8_t> tipInfo = {5, 6, 7, 8, 9};
    extraInfo.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, tipInfo);
    int32_t tipType = 2;
    int32_t authType = FACE;
    EXPECT_NO_THROW(widgetContext->OnChildAuthTip(tipType, authType, extraInfo));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestHandleAuthSuccessResult_0001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->authResultInfo_.authType = PIN;
    widgetContext->authResultInfo_.credentialDigest = 100;
    widgetContext->authResultInfo_.credentialCount = 5;
    widgetContext->authResultInfo_.resultUserId = 1000;
    Attributes attr;
    bool result = widgetContext->HandleAuthSuccessResult(attr);
    EXPECT_TRUE(result);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestHandleAuthSuccessResult_0002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->authResultInfo_.authType = FACE;
    widgetContext->authResultInfo_.token = {0x01, 0x02, 0x03, 0x04};
    widgetContext->authResultInfo_.credentialDigest = 200;
    widgetContext->authResultInfo_.credentialCount = 3;
    widgetContext->authResultInfo_.resultUserId = 2000;
    Attributes attr;
    bool result = widgetContext->HandleAuthSuccessResult(attr);
    EXPECT_TRUE(result);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestHandleAuthSuccessResult_0003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->authResultInfo_.authType = FINGERPRINT;
    widgetContext->authResultInfo_.token = {};
    widgetContext->authResultInfo_.credentialDigest = 0;
    widgetContext->authResultInfo_.credentialCount = 0;
    widgetContext->authResultInfo_.resultUserId = 0;
    Attributes attr;
    bool result = widgetContext->HandleAuthSuccessResult(attr);
    EXPECT_TRUE(result);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestHandleAuthSuccessResult_0004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->authResultInfo_.authType = ALL;
    widgetContext->authResultInfo_.token = {1, 2, 3, 4, 5, 6, 7, 8};
    widgetContext->authResultInfo_.credentialDigest = 99999999999ULL;
    widgetContext->authResultInfo_.credentialCount = 65535;
    widgetContext->authResultInfo_.resultUserId = 2147483647;
    Attributes attr;
    bool result = widgetContext->HandleAuthSuccessResult(attr);
    EXPECT_TRUE(result);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleCompanionDeviceAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleCompanionDeviceAuth_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE, AuthType::FACE};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleCompanionDeviceAuth_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestDirectAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    ContextFactory::AuthProfile authProfile;
    authProfile.pinSubType = 0;
    authProfile.sensorInfo = "";
    authProfile.remainTimes = -1;
    authProfile.freezingTime = 0;
    para.authProfileMap[AuthType::COMPANION_DEVICE] = authProfile;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestExecuteAuthListEmpty_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    EXPECT_TRUE(widgetContext->Start());
    std::set<AuthType> emptyAuthTypeList;
    widgetContext->ExecuteAuthList(emptyAuthTypeList, false, AuthIntent::DEFAULT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestCompanionDeviceSuccess_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    ContextFactory::AuthProfile authProfile;
    authProfile.pinSubType = 0;
    authProfile.sensorInfo = "";
    authProfile.remainTimes = -1;
    authProfile.freezingTime = 0;
    para.authProfileMap[AuthType::COMPANION_DEVICE] = authProfile;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    widgetContext->OnAuthSuccess(AuthType::COMPANION_DEVICE);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestCompanionDeviceFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    ContextFactory::AuthProfile authProfile;
    authProfile.pinSubType = 0;
    authProfile.sensorInfo = "";
    authProfile.remainTimes = -1;
    authProfile.freezingTime = 0;
    para.authProfileMap[AuthType::COMPANION_DEVICE] = authProfile;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    widgetContext->OnAuthFail(AuthType::COMPANION_DEVICE);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestCompanionDeviceStop_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    ContextFactory::AuthProfile authProfile;
    authProfile.pinSubType = 0;
    authProfile.sensorInfo = "";
    authProfile.remainTimes = -1;
    authProfile.freezingTime = 0;
    para.authProfileMap[AuthType::COMPANION_DEVICE] = authProfile;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    widgetContext->Stop();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestMixedAuthWithCompanionDevice_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE, AuthType::PIN};
    ContextFactory::AuthProfile authProfile;
    authProfile.pinSubType = 0;
    authProfile.sensorInfo = "";
    authProfile.remainTimes = -1;
    authProfile.freezingTime = 0;
    para.authProfileMap[AuthType::COMPANION_DEVICE] = authProfile;
    para.authProfileMap[AuthType::PIN] = authProfile;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextMixedAuthType_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE, AuthType::PIN};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextOtherAuthTypes_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::PIN};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextEmptyAuthTypeList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextDirectAuthMode_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    para.widgetParam.title = "test_title";
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextWidgetAuthMode_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE, AuthType::FINGERPRINT};
    para.widgetParam.title = "test_title";
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

namespace {
std::shared_ptr<WidgetContext> MakePooledWidget(uint64_t contextId,
    std::shared_ptr<MockContextCallback> &cbOut)
{
    ContextFactory::AuthWidgetContextPara para;
    auto callback = Common::MakeShared<MockContextCallback>();
    auto widgetContext = Common::MakeShared<WidgetContext>(contextId, para, true, callback, nullptr, nullptr);
    cbOut = callback;
    return widgetContext;
}

void DrainSerial()
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    handler->EnsureTask([]() {});
}
} // namespace

HWTEST_F(WidgetContextTest, WidgetContextEndDeliversWhileChildrenAlive, TestSize.Level0)
{
    const uint64_t contextId = 9001;
    std::shared_ptr<MockContextCallback> cb;
    auto widgetContext = MakePooledWidget(contextId, cb);
    ASSERT_NE(widgetContext, nullptr);
    ASSERT_TRUE(ContextPool::Instance().Schedule(widgetContext));
    DrainSerial();

    widgetContext->activeChildCount_ = 1;
    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    widgetContext->End(ResultCode::CANCELED);
    EXPECT_NE(ContextPool::Instance().Select(contextId).lock(), nullptr);

    widgetContext->OnChildTerminated();
    EXPECT_NE(ContextPool::Instance().Select(contextId).lock(), nullptr);

    widgetContext->ClearSchedule();
    EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);
    widgetContext->StopOnTerminateTimer();
    WidgetClient::Instance().ClearSchedule(contextId);
    DrainSerial();
}

HWTEST_F(WidgetContextTest, WidgetContextReleaseBeforeEndExitsOnLastChild, TestSize.Level0)
{
    const uint64_t contextId = 9002;
    std::shared_ptr<MockContextCallback> cb;
    auto widgetContext = MakePooledWidget(contextId, cb);
    ASSERT_NE(widgetContext, nullptr);
    ASSERT_TRUE(ContextPool::Instance().Schedule(widgetContext));
    DrainSerial();

    widgetContext->activeChildCount_ = 1;
    widgetContext->ClearSchedule();
    EXPECT_NE(ContextPool::Instance().Select(contextId).lock(), nullptr);

    // releasing without End() still owes the caller one terminal result
    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    widgetContext->OnChildTerminated();
    EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);
    WidgetClient::Instance().RemoveScheduleNode(contextId);
    DrainSerial();
}

HWTEST_F(WidgetContextTest, WidgetContextWatchdogReleasesUndeliveredEnd, TestSize.Level0)
{
    const uint64_t contextId = 9003;
    std::shared_ptr<MockContextCallback> cb;
    auto widgetContext = MakePooledWidget(contextId, cb);
    ASSERT_NE(widgetContext, nullptr);
    ASSERT_TRUE(ContextPool::Instance().Schedule(widgetContext));
    DrainSerial();

    widgetContext->activeChildCount_ = 1;
    EXPECT_CALL(*cb, OnResult(_, _)).Times(0);
    widgetContext->ClearSchedule();
    EXPECT_NE(ContextPool::Instance().Select(contextId).lock(), nullptr);

    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    widgetContext->OnTerminateTimerTimeOut(contextId);
    EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);
    widgetContext->OnChildTerminated();
    widgetContext->End(ResultCode::CANCELED);
    WidgetClient::Instance().ClearSchedule(contextId);
    DrainSerial();
}

HWTEST_F(WidgetContextTest, WidgetContextStopBeforeStartIsAbsorbing, TestSize.Level0)
{
    const uint64_t contextId = 9004;
    std::shared_ptr<MockContextCallback> cb;
    auto widgetContext = MakePooledWidget(contextId, cb);
    ASSERT_NE(widgetContext, nullptr);

    // Stop lands while the Start task is still queued: CANCELED is reported exactly once
    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    EXPECT_TRUE(widgetContext->Stop());
    EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);

    // Absorbing terminal: a duplicate stop and the queued start are both no-ops.
    EXPECT_TRUE(widgetContext->Stop());
    EXPECT_TRUE(widgetContext->Start());
    DrainSerial();
}

HWTEST_F(WidgetContextTest, WidgetContextStopAfterScheduleBeatsQueuedStart, TestSize.Level0)
{
    const uint64_t contextId = 9005;
    std::shared_ptr<MockContextCallback> cb;
    auto widgetContext = MakePooledWidget(contextId, cb);
    ASSERT_NE(widgetContext, nullptr);

    // hold the serial thread so the stop below deterministically lands before the posted Start
    std::promise<void> entered;
    std::promise<void> release;
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    Common::IamScopeGuard releaseGuard([&release]() { release.set_value(); });
    handler->PostTask([&entered, &release]() {
        entered.set_value();
        release.get_future().wait();
    });
    ASSERT_EQ(entered.get_future().wait_for(std::chrono::seconds(5)), std::future_status::ready);

    ASSERT_TRUE(ContextPool::Instance().Schedule(widgetContext));
    // the pool entry is dropped, so the queued StartIfPooled skips
    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    EXPECT_TRUE(widgetContext->Stop());
    EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);

    releaseGuard.Cancel();
    release.set_value();
    DrainSerial();
    WidgetClient::Instance().ClearSchedule(contextId);
    DrainSerial();
}

HWTEST_F(WidgetContextTest, WidgetContextLateChildResultAfterEndDoesNotRedeliver, TestSize.Level0)
{
    const uint64_t contextId = 9006;
    std::shared_ptr<MockContextCallback> cb;
    auto widgetContext = MakePooledWidget(contextId, cb);
    ASSERT_NE(widgetContext, nullptr);
    ASSERT_TRUE(ContextPool::Instance().Schedule(widgetContext));
    DrainSerial();

    auto schedule = std::make_shared<MockWidgetScheduleNode>();
    widgetContext->schedule_ = schedule;
    widgetContext->activeChildCount_ = 1;
    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    widgetContext->End(ResultCode::CANCELED);

    // the session is settled: a late child success is still processed by the
    // schedule and settles the child count, but must not produce a second result
    EXPECT_CALL(*schedule, NotifyAuthSuccess(_)).Times(1);
    Attributes finalResult;
    widgetContext->OnChildAuthResult(ResultCode::SUCCESS, AuthType::PIN, finalResult);
    EXPECT_EQ(widgetContext->activeChildCount_, 0U);
    EXPECT_NE(ContextPool::Instance().Select(contextId).lock(), nullptr);

    widgetContext->ClearSchedule();
    EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);
    widgetContext->StopOnTerminateTimer();
    WidgetClient::Instance().ClearSchedule(contextId);
    DrainSerial();
}

HWTEST_F(WidgetContextTest, WidgetContextEndIsIdempotent, TestSize.Level0)
{
    const uint64_t contextId = 9007;
    std::shared_ptr<MockContextCallback> cb;
    auto widgetContext = MakePooledWidget(contextId, cb);
    ASSERT_NE(widgetContext, nullptr);
    ASSERT_TRUE(ContextPool::Instance().Schedule(widgetContext));
    DrainSerial();

    widgetContext->activeChildCount_ = 1;
    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    widgetContext->End(ResultCode::CANCELED);
    widgetContext->End(ResultCode::SUCCESS);
    EXPECT_EQ(widgetContext->activeChildCount_, 1U);

    widgetContext->OnChildTerminated();
    widgetContext->ClearSchedule();
    EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);
    widgetContext->StopOnTerminateTimer();
    WidgetClient::Instance().ClearSchedule(contextId);
    DrainSerial();
}

HWTEST_F(WidgetContextTest, WidgetContextHandleAuthSuccessResultFailDeliversOnce, TestSize.Level0)
{
    const uint64_t contextId = 9008;
    std::shared_ptr<MockContextCallback> cb;
    auto widgetContext = MakePooledWidget(contextId, cb);
    ASSERT_NE(widgetContext, nullptr);
    ASSERT_TRUE(ContextPool::Instance().Schedule(widgetContext));
    DrainSerial();

    Attributes attr;
    for (uint32_t k = 0; k < 520; ++k) {
        attr.SetInt32Value(static_cast<Attributes::AttributeKey>(200000 + k), k);
    }
    EXPECT_CALL(*cb, OnResult(ResultCode::GENERAL_ERROR, _)).Times(1);
    EXPECT_FALSE(widgetContext->HandleAuthSuccessResult(attr));

    widgetContext->ClearSchedule();
    EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);
    WidgetClient::Instance().ClearSchedule(contextId);
    DrainSerial();
}

HWTEST_F(WidgetContextTest, WidgetContextReleasedSessionStillSettlesLateChildCount, TestSize.Level0)
{
    const uint64_t contextId = 9009;
    std::shared_ptr<MockContextCallback> cb;
    auto widgetContext = MakePooledWidget(contextId, cb);
    ASSERT_NE(widgetContext, nullptr);

    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    EXPECT_TRUE(widgetContext->Stop());
    EXPECT_EQ(widgetContext->phase_, WidgetContext::Phase::RELEASED);

    // after full release a late child result is dropped, yet the child count
    // still settles: counted-in children must always be counted out
    widgetContext->activeChildCount_ = 1;
    Attributes finalResult;
    widgetContext->OnChildAuthResult(ResultCode::SUCCESS, AuthType::PIN, finalResult);
    EXPECT_EQ(widgetContext->activeChildCount_, 0U);
    WidgetClient::Instance().ClearSchedule(contextId);
    DrainSerial();
}
namespace {
// Keep startup deterministic while exercising the real callback and pool lifecycle.
class LifecycleWidgetContext : public WidgetContext {
public:
    LifecycleWidgetContext(uint64_t id, const std::shared_ptr<ContextCallback> &callback)
        : WidgetContext(id, ContextFactory::AuthWidgetContextPara {}, true, callback, nullptr, nullptr) {}
    bool OnStart() override { return true; }
};
}

HWTEST_F(WidgetContextTest, RealResultRetainsSeatUntilUiRelease, TestSize.Level0)
{
    const uint64_t contextId = 9101;
    sptr<MockUserAuthCallback> ipcCallback = new MockUserAuthCallback();
    auto callback = ContextCallback::NewInstance(ipcCallback, TRACE_AUTH_USER_SECURITY);
    auto widget = Common::MakeShared<LifecycleWidgetContext>(contextId, callback);
    ASSERT_TRUE(ContextPool::Instance().Schedule(widget));
    DrainSerial();
    EXPECT_CALL(*ipcCallback, OnResult(SUCCESS, _)).Times(1);
    ThreadHandler::GetSingleThreadInstance()->EnsureTask([widget, contextId]() {
        widget->activeChildCount_ = 1;
        const std::vector<uint8_t> token = {1, 2, 3};
        widget->authResultInfo_.token = token;
        widget->End(SUCCESS);
        widget->OnChildTerminated();
        EXPECT_NE(ContextPool::Instance().Select(contextId).lock(), nullptr);
        EXPECT_NE(widget->onTerminateTimerId_, 0U);
        widget->ClearSchedule();
        EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);
        EXPECT_EQ(widget->onTerminateTimerId_, 0U);
        widget->ClearSchedule();
        widget->End(CANCELED);
    });
    DrainSerial();
}

HWTEST_F(WidgetContextTest, RealResultWatchdogReleasesWithoutDuplicateResult, TestSize.Level0)
{
    const uint64_t contextId = 9102;
    sptr<MockUserAuthCallback> ipcCallback = new MockUserAuthCallback();
    auto callback = ContextCallback::NewInstance(ipcCallback, TRACE_AUTH_USER_SECURITY);
    auto widget = Common::MakeShared<LifecycleWidgetContext>(contextId, callback);
    ASSERT_TRUE(ContextPool::Instance().Schedule(widget));
    DrainSerial();
    EXPECT_CALL(*ipcCallback, OnResult(SUCCESS, _)).Times(1);
    ThreadHandler::GetSingleThreadInstance()->EnsureTask([widget, contextId]() {
        widget->End(SUCCESS);
        EXPECT_NE(ContextPool::Instance().Select(contextId).lock(), nullptr);
        widget->OnTerminateTimerTimeOut(contextId);
        EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);
        widget->OnTerminateTimerTimeOut(contextId);
        widget->ClearSchedule();
    });
    DrainSerial();
}

HWTEST_F(WidgetContextTest, RealStartFailureReleasesWithoutCleaner, TestSize.Level0)
{
    const uint64_t contextId = 9103;
    sptr<MockUserAuthCallback> ipcCallback = new MockUserAuthCallback();
    auto callback = ContextCallback::NewInstance(ipcCallback, TRACE_AUTH_USER_SECURITY);
    auto widget = Common::MakeShared<LifecycleWidgetContext>(contextId, callback);
    ASSERT_TRUE(ContextPool::Instance().Schedule(widget));
    DrainSerial();
    EXPECT_CALL(*ipcCallback, OnResult(GENERAL_ERROR, _)).Times(1);
    ThreadHandler::GetSingleThreadInstance()->EnsureTask([widget, contextId]() {
        widget->OnStartFailed(GENERAL_ERROR);
        EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);
        widget->OnStartFailed(GENERAL_ERROR);
        widget->Stop();
    });
    DrainSerial();
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS