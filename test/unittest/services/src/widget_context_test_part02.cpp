/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <future>

#include "mock_context.h"
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
class WidgetContextTestPart02 : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void WidgetContextTestPart02::SetUpTestCase()
{
}

void WidgetContextTestPart02::TearDownTestCase()
{
}

void WidgetContextTestPart02::SetUp()
{
}

void WidgetContextTestPart02::TearDown()
{
}

std::shared_ptr<WidgetContext> CreateWidgetContextPart02(uint64_t contextId,
    ContextFactory::AuthWidgetContextPara para, const sptr<IRemoteAuthCallback> remoteAuthCallback = nullptr)
{
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    return Common::MakeShared<WidgetContext>(contextId, para, contextCallback, nullptr, remoteAuthCallback);
}

class TestableWidgetContext : public WidgetContext {
public:
    TestableWidgetContext(uint64_t contextId, const ContextFactory::AuthWidgetContextPara &para,
        std::shared_ptr<ContextCallback> callback, const sptr<IModalCallback> &modalCallback)
        : WidgetContext(contextId, para, callback, modalCallback, nullptr) {}

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

HWTEST_F(WidgetContextTestPart02, WidgetContextStartDirectAuthFail_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextStartScheduleFail_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextIsSingleCompanionDeviceAuthFail_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestAttributesGetFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes finalResult;
    widgetContext->AuthResult(ResultCode::FAIL, PIN, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestAttributesGetFail_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, -1);
    finalResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, -1);
    widgetContext->AuthResult(ResultCode::LOCKED, PIN, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestAttributesGetFail_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes extraInfo;
    std::vector<uint8_t> invalidTipInfo;
    extraInfo.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, invalidTipInfo);
    EXPECT_NO_THROW(widgetContext->AuthTipInfo(USER_AUTH_TIP_SINGLE_AUTH_RESULT, PIN, extraInfo));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestBuildTaskFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2, 3};
    para.atl = ATL2;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    std::set<AuthType> authTypeList = {AuthType::FACE};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestHandleAuthSuccessResultFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestStopAllRunTask_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::PIN};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    widgetContext->StopAllRunTask(ResultCode::FAIL);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestGetCallerName_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.callerName = "test_caller";
    para.callerType = Security::AccessToken::TOKEN_HAP;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    std::string callerName = widgetContext->GetCallerName();
    EXPECT_EQ(callerName, "test_caller");
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestGetCallerName_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.callerName = "test_native_caller";
    para.callerType = Security::AccessToken::TOKEN_NATIVE;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    std::string callerName = widgetContext->GetCallerName();
    // TOKEN_NATIVE returns the callerName directly (not bundle name)
    EXPECT_EQ(callerName, "test_native_caller");
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestBuildStartCommand_001, TestSize.Level0)
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

    auto widgetContext = CreateWidgetContextPart02(contextId, para);
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcessCmdData_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    WidgetCmdParameters widgetCmdParameters;
    widgetCmdParameters.uiExtensionType = "sysDialog/userAuth";
    widgetCmdParameters.useriamCmdData.widgetContextId = contextId;
    std::string cmdData = widgetContext->ProcessCmdData(widgetCmdParameters);
    EXPECT_NE(cmdData, "");
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsValidRotate_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.orientation = 0;
    widgetRotatePara.needRotate = 0;
    widgetRotatePara.isReload = false;
    bool isValid = widgetContext->IsValidRotate(widgetRotatePara);
    EXPECT_TRUE(isValid);
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestEndDifferentResultCodes_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    EXPECT_NO_THROW(widgetContext->EndAuthAsCancel());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestEndDifferentResultCodes_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    EXPECT_NO_THROW(widgetContext->EndAuthAsNaviPin());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestEndDifferentResultCodes_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    EXPECT_NO_THROW(widgetContext->EndAuthAsWidgetParaInvalid());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsSingleCompanionDeviceAuth_EmptyList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsSingleCompanionDeviceAuth_SizeZero_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.clear();
    para.widgetParam.title = "test_title";
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestDirectAuthWithEmptyList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {};
    ContextFactory::AuthProfile authProfile;
    authProfile.pinSubType = 0;
    authProfile.sensorInfo = "";
    authProfile.remainTimes = -1;
    authProfile.freezingTime = 0;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    EXPECT_TRUE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_SingleCompanionDevice_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_SingleCompanionDevice_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_SingleCompanionDevice_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::COMPANION_DEVICE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestFailAuth_UseLatestError_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->SetLatestError(ResultCode::LOCKED);
    widgetContext->FailAuth(AuthType::FACE);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestFailAuth_UseLatestError_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FINGERPRINT};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->SetLatestError(ResultCode::FAIL);
    widgetContext->FailAuth(AuthType::FINGERPRINT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_DirectAuthSuccess_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_DirectAuthFail_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_DirectAuthFail_002, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_SingleFaceAuth_SetLockedError_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_SingleFingerprintAuth_SetLockedError_001,
    TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthTipInfo_SingleFaceAuth_SetLockedError_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthTipInfo_SingleFingerprintAuth_SetLockedError_001,
    TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_NonDirectAuthSuccess_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_NonDirectAuthFail_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthResult_NavigationAuth_NaviPinAuth_001, TestSize.Level0)
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

HWTEST_F(WidgetContextTestPart02, WidgetContextTestProcAuthTipInfo_NavigationAuth_NaviPinAuth_001, TestSize.Level0)
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

    std::vector<uint8_t> token = {};
    testableContext->SendAuthResultInfo(ResultCode::GENERAL_ERROR, PIN, token);
    testableContext->SendAuthResultInfo(ResultCode::SUCCESS, PIN, token);
}

HWTEST_F(WidgetContextTestPart02, WidgetContextCreateWithRemoteAuthCallback_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para, nullptr);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_EQ(widgetContext->remoteAuthCallback_, nullptr);
}

HWTEST_F(WidgetContextTestPart02, WidgetContextCreateWithRemoteAuthCallback_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);
    auto widgetContext = CreateWidgetContextPart02(contextId, para, mockCallback);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_NE(widgetContext->remoteAuthCallback_, nullptr);
}

HWTEST_F(WidgetContextTestPart02, WidgetContextSetRemoteAuthParam_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::PIN, AuthType::FACE};
    para.authProfileMap[AuthType::PIN] = {};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);

    WidgetParamInner widgetParam = {};
    widgetParam.title = "test title";
    widgetParam.navigationButtonText = "test navigation";
    widgetParam.windowMode = WindowModeType::DIALOG_BOX;
    widgetParam.hasContext = false;

    sptr<MockModalCallback> mockModalCallback = new (std::nothrow) MockModalCallback();
    EXPECT_NE(mockModalCallback, nullptr);

    EXPECT_TRUE(widgetContext->Start());
    EXPECT_NO_THROW(widgetContext->SetRemoteAuthParam(widgetParam, mockModalCallback));

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextSetRemoteAuthParam_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::PIN, AuthType::FACE};
    para.authProfileMap[AuthType::PIN] = {};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);

    WidgetParamInner widgetParam = {};
    widgetParam.title = "";
    widgetParam.navigationButtonText = "Navigate";
    widgetParam.windowMode = WindowModeType::DIALOG_BOX;
    widgetParam.hasContext = true;

    sptr<MockModalCallback> mockModalCallback = new (std::nothrow) MockModalCallback();
    EXPECT_NE(mockModalCallback, nullptr);

    EXPECT_TRUE(widgetContext->Start());
    EXPECT_NO_THROW(widgetContext->SetRemoteAuthParam(widgetParam, mockModalCallback));
    EXPECT_EQ(widgetContext->para_.authTypeList.size(), 2);
    EXPECT_NE(widgetContext->para_.authProfileMap.find(AuthType::PIN), widgetContext->para_.authProfileMap.end());

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextSetRemoteAuthParam_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);

    WidgetParamInner widgetParam = {};
    widgetParam.title = "test title";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    widgetParam.hasContext = false;

    sptr<MockModalCallback> mockModalCallback = new (std::nothrow) MockModalCallback();
    EXPECT_NE(mockModalCallback, nullptr);

    EXPECT_TRUE(widgetContext->Start());
    EXPECT_NO_THROW(widgetContext->SetRemoteAuthParam(widgetParam, mockModalCallback));
    EXPECT_EQ(widgetContext->para_.widgetParam.windowMode, WindowModeType::UNKNOWN_WINDOW_MODE);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextRemoteAuthCallbackOnResult_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2, 3, 4};
    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);
    auto widgetContext = CreateWidgetContextPart02(contextId, para, mockCallback);

    EXPECT_CALL(*mockCallback, OnRemoteAuthResult(_, _, _)).Times(1);

    Attributes attr;
    widgetContext->End(ResultCode::SUCCESS);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextGetRemoteAuthParam_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2, 3, 4};
    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);
    auto widgetContext = CreateWidgetContextPart02(contextId, para, mockCallback);
    widgetContext->BuildSchedule();
    EXPECT_TRUE(widgetContext->GetRemoteAuthParam());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextGetRemoteAuthParam_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2, 3, 4};
    auto widgetContext = CreateWidgetContextPart02(contextId, para, nullptr);
    widgetContext->BuildSchedule();
    EXPECT_FALSE(widgetContext->GetRemoteAuthParam());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextGetRemoteAuthParam_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2, 3, 4};
    sptr<MockRemoteAuthCallback> mockCallback = new (std::nothrow) MockRemoteAuthCallback();
    EXPECT_NE(mockCallback, nullptr);
    auto widgetContext = CreateWidgetContextPart02(contextId, para, mockCallback);
    widgetContext->BuildSchedule();
    widgetContext->OnStart();
    EXPECT_TRUE(widgetContext->GetRemoteAuthParam());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextSetRemoteAuthParam_004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::PIN};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    widgetContext->BuildSchedule();
    widgetContext->OnStart();

    WidgetParamInner widgetParam = {};
    widgetParam.title = "Remote Title";
    widgetParam.navigationButtonText = "Remote Nav";
    widgetParam.windowMode = WindowModeType::DIALOG_BOX;
    widgetParam.hasContext = true;

    sptr<MockModalCallback> mockModalCallback = new (std::nothrow) MockModalCallback();
    EXPECT_NE(mockModalCallback, nullptr);

    EXPECT_NO_THROW(widgetContext->SetRemoteAuthParam(widgetParam, mockModalCallback));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextSetRemoteAuthParam_005, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE, AuthType::FINGERPRINT};
    para.authProfileMap[AuthType::FACE] = {};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    widgetContext->BuildSchedule();
    widgetContext->OnStart();

    WidgetParamInner widgetParam = {};
    widgetParam.title = "";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    widgetParam.hasContext = false;

    sptr<MockModalCallback> mockModalCallback = nullptr;

    EXPECT_NO_THROW(widgetContext->SetRemoteAuthParam(widgetParam, mockModalCallback));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestBuildTask_Success_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2, 3};
    para.atl = ATL2;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::PIN};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestBuildTask_MultiType_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {0xAA, 0xBB};
    para.atl = ATL3;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::PIN, AuthType::FACE};
    widgetContext->ExecuteAuthList(authTypeList, true, AuthIntent::UNLOCK);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestBuildTask_AuthIntentSilent_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1};
    para.atl = ATL1;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::FACE};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::SILENT_AUTH);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestExecuteAuthList_EmptyAuthList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2};
    para.atl = ATL2;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> emptyAuthTypeList;
    widgetContext->ExecuteAuthList(emptyAuthTypeList, true, AuthIntent::DEFAULT);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestExecuteAuthList_FaceAuthType_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2, 3};
    para.atl = ATL2;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::FACE};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestExecuteAuthList_MultipleAuthTypes_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {0x01, 0x02, 0x03, 0x04};
    para.atl = ATL3;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    widgetContext->ExecuteAuthList(authTypeList, true, AuthIntent::DEFAULT);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestExecuteAuthList_EndAfterFirstFail_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2, 3, 4, 5};
    para.atl = ATL4;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::PIN, AuthType::FACE};
    widgetContext->ExecuteAuthList(authTypeList, true, AuthIntent::QUESTION_AUTH);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestExecuteAuthList_NotStart_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1};
    para.atl = ATL1;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    std::set<AuthType> authTypeList = {AuthType::PIN};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestStopAuthList_EmptyAuthList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2};
    para.atl = ATL2;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::vector<AuthType> authTypeList;
    widgetContext->StopAuthList(authTypeList);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestStopAuthList_NotInTaskList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2};
    para.atl = ATL2;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::PIN};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    std::vector<AuthType> stopTypeList = {AuthType::FACE};
    widgetContext->StopAuthList(stopTypeList);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestStopAuthList_MatchTasks_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1, 2};
    para.atl = ATL2;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::PIN, AuthType::FACE};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    std::vector<AuthType> stopTypeList = {AuthType::PIN, AuthType::FACE};
    widgetContext->StopAuthList(stopTypeList);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestStopAuthList_PartialMatch_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {1};
    para.atl = ATL1;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->BuildSchedule();
    widgetContext->Start();
    std::set<AuthType> authTypeList = {AuthType::PIN};
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    std::vector<AuthType> stopTypeList = {AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    widgetContext->StopAuthList(stopTypeList);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsInFollowCallerList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.remoteCallerName = "test_caller";
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    bool ret = false;
    EXPECT_NO_THROW(ret = widgetContext->IsInFollowCallerList());
    EXPECT_FALSE(ret);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsInFollowCallerList_RemoteCallerSet_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.remoteCallerName = "another_remote_caller";
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    bool ret = true;
    EXPECT_NO_THROW(ret = widgetContext->IsInFollowCallerList());
    EXPECT_FALSE(ret);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsSupportFollowCallerUi_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.remoteCallerName = "test_caller";
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    bool ret = true;
    EXPECT_NO_THROW(ret = widgetContext->IsSupportFollowCallerUi());
    EXPECT_FALSE(ret);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsSupportFollowCallerUi_EmptyRemoteCaller_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    bool ret = true;
    EXPECT_NO_THROW(ret = widgetContext->IsSupportFollowCallerUi());
    EXPECT_FALSE(ret);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsWidgetLaunchAllowed_HapCaller_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.callerName = "hap_caller";
    para.callerType = Security::AccessToken::TOKEN_HAP;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    bool allow = false;
    EXPECT_NO_THROW(allow = widgetContext->IsWidgetLaunchAllowed());
    EXPECT_TRUE(allow);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsWidgetLaunchAllowed_NativeCaller_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.callerName = "native_caller";
    para.callerType = Security::AccessToken::TOKEN_NATIVE;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    bool allow = false;
    EXPECT_NO_THROW(allow = widgetContext->IsWidgetLaunchAllowed());
    EXPECT_TRUE(allow);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsWidgetLaunchAllowed_EmptyCaller_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    bool allow = false;
    EXPECT_NO_THROW(allow = widgetContext->IsWidgetLaunchAllowed());
    EXPECT_TRUE(allow);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestIsWidgetLaunchAllowed_WithAppIdentifier_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.callerName = "caller_with_identifier";
    para.callerType = Security::AccessToken::TOKEN_HAP;
    para.callingAppIdentifier = "test_app_identifier";
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    bool allow = false;
    EXPECT_NO_THROW(allow = widgetContext->IsWidgetLaunchAllowed());
    EXPECT_TRUE(allow);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestInitFaceAlgo_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_NO_THROW(widgetContext->InitFaceAlgo());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestUninitFaceAlgo_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->InitFaceAlgo();
    EXPECT_NO_THROW(widgetContext->UninitFaceAlgo());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestSendFaceAlgoCommand_Init_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_NO_THROW(widgetContext->SendFaceAlgoCommand("init"));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestSendFaceAlgoCommand_Uninit_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->InitFaceAlgo();
    EXPECT_NO_THROW(widgetContext->SendFaceAlgoCommand("uninit"));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestSendFaceAlgoCommand_EmptyOperation_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_NO_THROW(widgetContext->SendFaceAlgoCommand(""));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestSendFaceAlgoCommand_NoFaceAuthType_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::PIN};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_NO_THROW(widgetContext->SendFaceAlgoCommand("init"));
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTestPart02, WidgetContextTestInitUninitFaceAlgoSequence_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList = {AuthType::FACE};
    auto widgetContext = CreateWidgetContextPart02(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_NO_THROW(widgetContext->InitFaceAlgo());
    EXPECT_NO_THROW(widgetContext->UninitFaceAlgo());
    EXPECT_NO_THROW(widgetContext->InitFaceAlgo());
    EXPECT_NO_THROW(widgetContext->UninitFaceAlgo());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
