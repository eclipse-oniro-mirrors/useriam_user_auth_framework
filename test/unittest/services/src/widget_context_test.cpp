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

#include "widget_context.h"

#include <future>

#include "mock_context.h"
#include "mock_widget_schedule_node.h"
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

std::shared_ptr<WidgetContext> CreateWidgetContext(uint64_t contextId, ContextFactory::AuthWidgetContextPara para)
{
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    return Common::MakeShared<WidgetContext>(contextId, para, contextCallback, nullptr);
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
    widgetContext->SuccessAuth(authType);
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
    widgetContext->AuthResult(ResultCode::SUCCESS, 1, finalResult);
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
    widgetContext->AuthResult(ResultCode::SUCCESS, 1, finalResult);
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
    widgetContext->AuthResult(ResultCode::SUCCESS, 1, finalResult);
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
    widgetContext->AuthResult(ResultCode::SUCCESS, 1, finalResult);
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
    widgetContext->AuthResult(ResultCode::GENERAL_ERROR, 1, finalResult);
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
    widgetContext->AuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, 1, finalResult);
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
    widgetContext->AuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, 1, finalResult);
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
    widgetContext->AuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, 1, finalResult);
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
    widgetContext->SuccessAuth(authType);
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
    widgetContext->SuccessAuth(authType);
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
    widgetContext->SuccessAuth(authType);
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
    widgetContext->SuccessAuth(authType);
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
    EXPECT_NO_THROW(widgetContext->SendAuthTipInfo(authType, tipCode));
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
    EXPECT_NO_THROW(widgetContext->AuthTipInfo(tipType, authType, extraInfo));
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
    EXPECT_NO_THROW(widgetContext->AuthTipInfo(tipType, authType, extraInfo));
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
    EXPECT_NO_THROW(widgetContext->AuthTipInfo(tipType, authType, extraInfo));
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
    EXPECT_NO_THROW(widgetContext->AuthTipInfo(tipType, authType, extraInfo));
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
    widgetContext->SuccessAuth(AuthType::COMPANION_DEVICE);
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
    widgetContext->FailAuth(AuthType::COMPANION_DEVICE);
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

class TestableWidgetContext : public WidgetContext {
public:
    TestableWidgetContext(uint64_t contextId, const ContextFactory::AuthWidgetContextPara &para,
        std::shared_ptr<ContextCallback> callback, const sptr<IModalCallback> &modalCallback)
        : WidgetContext(contextId, para, callback, modalCallback) {}

    void SetSchedule(std::shared_ptr<WidgetScheduleNode> schedule)
    {
        schedule_ = schedule;
    }

    std::shared_ptr<WidgetScheduleNode> GetSchedule()
    {
        return schedule_;
    }

protected:
    bool BuildSchedule() override
    {
        if (schedule_ != nullptr) {
            return true;
        }
        schedule_ = Common::MakeShared<WidgetScheduleNodeImpl>();
        if (schedule_ == nullptr) {
            return false;
        }
        schedule_->SetCallback(shared_from_this());
        return true;
    }
};

HWTEST_F(WidgetContextTest, WidgetContextStartDirectAuthFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};

    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para, contextCallback, nullptr);
    EXPECT_NE(testableContext, nullptr);

    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    EXPECT_NE(mockSchedule, nullptr);
    EXPECT_CALL(*mockSchedule, StartDirectAuth()).WillOnce(Return(false));
    EXPECT_CALL(*mockSchedule, SetCallback(_)).Times(AnyNumber());

    testableContext->SetSchedule(mockSchedule);

    EXPECT_FALSE(testableContext->Start());

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextStartScheduleFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};

    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para, contextCallback, nullptr);
    EXPECT_NE(testableContext, nullptr);

    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    EXPECT_NE(mockSchedule, nullptr);
    EXPECT_CALL(*mockSchedule, StartSchedule()).WillOnce(Return(false));
    EXPECT_CALL(*mockSchedule, SetCallback(_)).Times(AnyNumber());

    testableContext->SetSchedule(mockSchedule);

    EXPECT_FALSE(testableContext->Start());

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextIsSingleCompanionDeviceAuthFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::PIN};

    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para, contextCallback, nullptr);
    EXPECT_NE(testableContext, nullptr);

    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    EXPECT_NE(mockSchedule, nullptr);
    EXPECT_CALL(*mockSchedule, StartSchedule()).WillOnce(Return(true));
    EXPECT_CALL(*mockSchedule, SetCallback(_)).Times(AnyNumber());

    testableContext->SetSchedule(mockSchedule);

    EXPECT_TRUE(testableContext->Start());

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAttributesGetFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes finalResult;
    widgetContext->AuthResult(ResultCode::FAIL, PIN, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAttributesGetFail_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, -1);
    finalResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, -1);
    widgetContext->AuthResult(ResultCode::LOCKED, PIN, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAttributesGetFail_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes extraInfo;
    std::vector<uint8_t> invalidTipInfo;
    extraInfo.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, invalidTipInfo);
    EXPECT_NO_THROW(widgetContext->AuthTipInfo(USER_AUTH_TIP_SINGLE_AUTH_RESULT, PIN, extraInfo));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestBuildTaskFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2, 3};
    para.atl = ATL2;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    std::set<AuthType> authTypeList = {AuthType::FACE};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestHandleAuthSuccessResultFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes attr;
    widgetContext->authResultInfo_.authType = PIN;
    widgetContext->authResultInfo_.credentialDigest = 0;
    widgetContext->authResultInfo_.credentialCount = 0;
    widgetContext->authResultInfo_.resultUserId = 0;
    bool result = widgetContext->HandleAuthSuccessResult(attr);
    EXPECT_TRUE(result);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestStopAllRunTask_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::PIN};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    widgetContext->StopAllRunTask(ResultCode::FAIL);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetCallerName_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.callerName = "test_caller";
    para.callerType = Security::AccessToken::TOKEN_HAP;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    std::string callerName = widgetContext->GetCallerName();
    EXPECT_EQ(callerName, "test_caller");
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetCallerName_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.callerName = "test_native_caller";
    para.callerType = Security::AccessToken::TOKEN_NATIVE;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    std::string callerName = widgetContext->GetCallerName();
    // TOKEN_NATIVE returns the callerName directly (not bundle name)
    EXPECT_EQ(callerName, "test_native_caller");
}

HWTEST_F(WidgetContextTest, WidgetContextTestBuildStartCommand_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::PIN, AuthType::FACE};
    ContextFactory::AuthProfile pinProfile;
    pinProfile.pinSubType = 1;
    pinProfile.remainTimes = 3;
    pinProfile.freezingTime = 30000;
    para.authProfileMap[AuthType::PIN] = pinProfile;

    ContextFactory::AuthProfile faceProfile;
    faceProfile.sensorInfo = "";
    faceProfile.remainTimes = -1;
    faceProfile.freezingTime = 0;
    para.authProfileMap[AuthType::FACE] = faceProfile;

    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.isReload = false;
    widgetRotatePara.needRotate = 0;
    widgetRotatePara.orientation = 0;
    std::string command = widgetContext->BuildStartCommand(widgetRotatePara);
    EXPECT_NE(command, "");
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcessCmdData_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    WidgetCmdParameters widgetCmdParameters;
    widgetCmdParameters.uiExtensionType = "sysDialog/userAuth";
    widgetCmdParameters.useriamCmdData.widgetContextId = contextId;
    std::string cmdData = widgetContext->ProcessCmdData(widgetCmdParameters);
    EXPECT_NE(cmdData, "");
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsValidRotate_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.orientation = 0;
    widgetRotatePara.needRotate = 0;
    widgetRotatePara.isReload = false;
    bool isValid = widgetContext->IsValidRotate(widgetRotatePara);
    EXPECT_TRUE(isValid);
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndDifferentResultCodes_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    EXPECT_NO_THROW(widgetContext->EndAuthAsCancel());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndDifferentResultCodes_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    EXPECT_NO_THROW(widgetContext->EndAuthAsNaviPin());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndDifferentResultCodes_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    EXPECT_NO_THROW(widgetContext->EndAuthAsWidgetParaInvalid());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleCompanionDeviceAuth_EmptyList_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleCompanionDeviceAuth_SizeZero_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.clear();
    para.widgetParam.title = "test_title";
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestDirectAuthWithEmptyList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {};
    ContextFactory::AuthProfile authProfile;
    authProfile.pinSubType = 0;
    authProfile.sensorInfo = "";
    authProfile.remainTimes = -1;
    authProfile.freezingTime = 0;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_SingleCompanionDevice_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = true;

    EXPECT_CALL(*mockSchedule, FailAuth(AuthType::COMPANION_DEVICE)).WillOnce(Return(true));

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::FAIL, AuthType::COMPANION_DEVICE, 0, finalResult);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_SingleCompanionDevice_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = true;

    EXPECT_CALL(*mockSchedule, FailAuth(AuthType::COMPANION_DEVICE)).WillOnce(Return(true));

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::LOCKED, AuthType::COMPANION_DEVICE, 60, finalResult);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_SingleCompanionDevice_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = true;

    EXPECT_CALL(*mockSchedule, FailAuth(AuthType::COMPANION_DEVICE)).WillOnce(Return(true));

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::TIMEOUT, AuthType::COMPANION_DEVICE, 0, finalResult);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestFailAuth_UseLatestError_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->SetLatestError(ResultCode::LOCKED);
    widgetContext->FailAuth(AuthType::FACE);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestFailAuth_UseLatestError_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FINGERPRINT};
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->SetLatestError(ResultCode::FAIL);
    widgetContext->FailAuth(AuthType::FINGERPRINT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_DirectAuthSuccess_001, TestSize.Level0)
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

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = true;

    EXPECT_CALL(*mockSchedule, SuccessAuth(AuthType::COMPANION_DEVICE)).WillOnce(Return(true));
    EXPECT_CALL(*mockSchedule, ClearSchedule()).WillOnce(Return(true));

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::SUCCESS, AuthType::COMPANION_DEVICE, 0, finalResult);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_DirectAuthFail_001, TestSize.Level0)
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

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = true;

    EXPECT_CALL(*mockSchedule, FailAuth(AuthType::COMPANION_DEVICE)).WillOnce(Return(true));
    EXPECT_CALL(*mockSchedule, ClearSchedule()).WillOnce(Return(true));

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::FAIL, AuthType::COMPANION_DEVICE, 0, finalResult);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_DirectAuthFail_002, TestSize.Level0)
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

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = true;

    EXPECT_CALL(*mockSchedule, FailAuth(AuthType::COMPANION_DEVICE)).WillOnce(Return(true));
    EXPECT_CALL(*mockSchedule, ClearSchedule()).WillOnce(Return(true));

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::LOCKED, AuthType::COMPANION_DEVICE, 60, finalResult);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_SingleFaceAuth_SetLockedError_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    para.skipLockedBiometricAuth = true;

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = false;

    EXPECT_CALL(*mockSchedule, FailAuth(AuthType::FACE)).WillOnce(Return(true));

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::FAIL, AuthType::FACE, 30, finalResult);

    EXPECT_EQ(testableContext->GetLatestError(), ResultCode::LOCKED);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_SingleFingerprintAuth_SetLockedError_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FINGERPRINT};
    para.skipLockedBiometricAuth = true;

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = false;

    EXPECT_CALL(*mockSchedule, FailAuth(AuthType::FINGERPRINT)).WillOnce(Return(true));

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::FAIL, AuthType::FINGERPRINT, 30, finalResult);

    EXPECT_EQ(testableContext->GetLatestError(), ResultCode::LOCKED);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthTipInfo_SingleFaceAuth_SetLockedError_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    para.skipLockedBiometricAuth = true;

    auto mockCallback = Common::MakeShared<MockContextCallback>();
    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para, mockCallback, nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = false;

    std::vector<uint8_t> extraInfo;
    EXPECT_CALL(*mockCallback, ParseAuthTipInfo(_, _, _, _))
        .WillOnce(Invoke([](int32_t, const std::vector<uint8_t> &, int32_t &authResult, int32_t &freezingTime) {
            authResult = ResultCode::FAIL;
            freezingTime = 30;
            return ResultCode::SUCCESS;
        }));

    EXPECT_CALL(*mockSchedule, FailAuth(AuthType::FACE)).WillOnce(Return(true));

    testableContext->ProcAuthTipInfo(USER_AUTH_TIP_SINGLE_AUTH_RESULT, AuthType::FACE, extraInfo);

    EXPECT_EQ(testableContext->GetLatestError(), ResultCode::LOCKED);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthTipInfo_SingleFingerprintAuth_SetLockedError_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FINGERPRINT};
    para.skipLockedBiometricAuth = true;

    auto mockCallback = Common::MakeShared<MockContextCallback>();
    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para, mockCallback, nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = false;

    std::vector<uint8_t> extraInfo;
    EXPECT_CALL(*mockCallback, ParseAuthTipInfo(_, _, _, _))
        .WillOnce(Invoke([](int32_t, const std::vector<uint8_t> &, int32_t &authResult, int32_t &freezingTime) {
            authResult = ResultCode::FAIL;
            freezingTime = 30;
            return ResultCode::SUCCESS;
        }));

    EXPECT_CALL(*mockSchedule, FailAuth(AuthType::FINGERPRINT)).WillOnce(Return(true));

    testableContext->ProcAuthTipInfo(USER_AUTH_TIP_SINGLE_AUTH_RESULT, AuthType::FINGERPRINT, extraInfo);

    EXPECT_EQ(testableContext->GetLatestError(), ResultCode::LOCKED);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_NonDirectAuthSuccess_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE, AuthType::PIN};

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = false;

    EXPECT_CALL(*mockSchedule, SuccessAuth(AuthType::FACE)).WillOnce(Return(true));
    EXPECT_CALL(*mockSchedule, ClearSchedule()).Times(0);

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::SUCCESS, AuthType::FACE, 0, finalResult);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_NonDirectAuthFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE, AuthType::PIN};

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = false;

    EXPECT_CALL(*mockSchedule, FailAuth(AuthType::FACE)).Times(0);
    EXPECT_CALL(*mockSchedule, ClearSchedule()).Times(0);

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::FAIL, AuthType::FACE, 0, finalResult);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult_NavigationAuth_NaviPinAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE, AuthType::PIN};
    para.skipLockedBiometricAuth = true;
    para.widgetParam.navigationButtonText = "Navigate";

    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para,
        Common::MakeShared<MockContextCallback>(), nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = false;

    EXPECT_CALL(*mockSchedule, NaviPinAuth()).WillOnce(Return(true));

    Attributes finalResult;
    testableContext->ProcAuthResult(ResultCode::FAIL, AuthType::FACE, 30, finalResult);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthTipInfo_NavigationAuth_NaviPinAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE, AuthType::PIN};
    para.skipLockedBiometricAuth = true;
    para.widgetParam.navigationButtonText = "Navigate";

    auto mockCallback = Common::MakeShared<MockContextCallback>();
    auto testableContext = Common::MakeShared<TestableWidgetContext>(contextId, para, mockCallback, nullptr);
    auto mockSchedule = Common::MakeShared<MockWidgetScheduleNode>();
    testableContext->SetSchedule(mockSchedule);
    testableContext->isDirectAuth_ = false;

    std::vector<uint8_t> extraInfo;
    EXPECT_CALL(*mockCallback, ParseAuthTipInfo(_, _, _, _))
        .WillOnce(Invoke([](int32_t, const std::vector<uint8_t> &, int32_t &authResult, int32_t &freezingTime) {
            authResult = ResultCode::FAIL;
            freezingTime = 30;
            return ResultCode::SUCCESS;
        }));

    EXPECT_CALL(*mockSchedule, NaviPinAuth()).WillOnce(Return(true));

    testableContext->ProcAuthTipInfo(USER_AUTH_TIP_SINGLE_AUTH_RESULT, AuthType::FACE, extraInfo);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS