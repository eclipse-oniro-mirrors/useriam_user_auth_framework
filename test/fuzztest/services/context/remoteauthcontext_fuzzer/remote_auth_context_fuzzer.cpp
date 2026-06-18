/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "remote_auth_context_fuzzer.h"

#include "parcel.h"

#include "dummy_authentication.h"
#include "dummy_context_pool.h"
#include "dummy_iam_callback_interface.h"
#include "dummy_executor_callback_interface.h"
#include "dummy_schedule_node_callback.h"

#include "attributes.h"
#include "context_pool.h"
#include "context_callback_impl.h"
#include "simple_auth_context.h"
#include "iam_common_defines.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "remote_auth_context.h"
#include "remote_auth_invoker_context.h"
#include "remote_iam_callback.h"
#include "context_appstate_observer.h"
#include "auth_widget_helper.h"
#include "remote_auth_service.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_REMOTE_AUTH_CONTEXT

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t OPERATION_TYPE = 1;

void FillIAttributes(Parcel &parcel, Attributes &attributes)
{
    bool fillNull = parcel.ReadBool();
    if (fillNull) {
        return;
    }

    attributes.SetUint64Value(Attributes::ATTR_TEMPLATE_ID, parcel.ReadUint64());
    attributes.SetUint64Value(Attributes::ATTR_CALLER_UID, parcel.ReadUint64());
    attributes.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, parcel.ReadUint32());
    attributes.SetUint32Value(Attributes::ATTR_MSG_TYPE, parcel.ReadUint32());
    attributes.SetUint32Value(Attributes::ATTR_REMAIN_TIMES, parcel.ReadUint32());
    attributes.SetUint32Value(Attributes::ATTR_FREEZING_TIME, parcel.ReadUint32());
    attributes.SetInt32Value(Attributes::ATTR_RESULT, parcel.ReadInt32());
    std::vector<uint64_t> templateIdList;
    FillFuzzUint64Vector(parcel, templateIdList);
    attributes.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    attributes.SetUint64ArrayValue(Attributes::ATTR_EXTRA_INFO, templateIdList);
    attributes.SetUint64Value(Attributes::ATTR_CALLER_UID, parcel.ReadUint64());
    attributes.SetUint32Value(Attributes::ATTR_SCHEDULE_MODE, parcel.ReadUint32());
}

void ContextAppStateObserverFuzzTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto contextAppStateObserver = MakeShared<ContextAppStateObserverManager>();
    auto contextCallback = MakeShared<ContextCallbackImpl>(new (std::nothrow) DummyIamCallbackInterface(),
        static_cast<OperationType>(OPERATION_TYPE));
    uint64_t contextId = parcel.ReadUint64();

    contextAppStateObserver->SubscribeAppState(contextCallback, contextId);
    std::string callerName = parcel.ReadString();
    if (callerName.empty()) {
        return;
    }
    contextCallback->SetTraceCallerName(callerName);
    contextAppStateObserver->SubscribeAppState(contextCallback, contextId);

    contextAppStateObserver->UnSubscribeAppState();

    std::string bundleName = parcel.ReadString();
    if (bundleName.empty()) {
        return;
    }
    auto contextApp = MakeShared<ContextAppStateObserver>(contextId, bundleName);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.bundleName = "com.homs.settings";

    contextApp->OnAppStateChanged(appStateData);

    contextApp->OnForegroundApplicationChanged(appStateData);

    int32_t userId = parcel.ReadInt32();
    contextApp->ProcAppStateChanged(userId);
    IAM_LOGI("end");
}

void RemoteAuthContextFuzzTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    const int32_t sdkVersion = 11;
    uint64_t newContextId = parcel.ReadUint64();
    Authentication::AuthenticationPara para = {};
    para.userId = 0x11;
    para.callerName = "com.ohos.test";
    para.sdkVersion = sdkVersion;
    para.authType = FACE;
    para.atl = ATL3;
    auto auth = MakeShared<AuthenticationImpl>(newContextId, para);
    auto contextCallback = MakeShared<ContextCallbackImpl>(new (std::nothrow) DummyIamCallbackInterface(),
        static_cast<OperationType>(OPERATION_TYPE));
    RemoteAuthContextParam param;
    param.authType = ALL;
    param.connectionName = parcel.ReadString();
    param.collectorNetworkId = parcel.ReadString();
    param.executorInfoMsg = {};
    auto remoteAuthContext = MakeShared<RemoteAuthContext>(
        newContextId, auth, param, contextCallback
    );

    remoteAuthContext->GetContextType();

    std::vector<uint8_t> msg;
    FillFuzzUint8Vector(parcel, msg);
    remoteAuthContext->SetExecutorInfoMsg(msg);
    remoteAuthContext->OnStart();
    remoteAuthContext->StartAuth();
    remoteAuthContext->StartAuthDelayed();
    remoteAuthContext->OnTimeOut();
    std::string connectionName = parcel.ReadString();
    remoteAuthContext->OnConnectStatus(connectionName, ConnectStatus::DISCONNECTED);
    remoteAuthContext->OnConnectStatus(connectionName, ConnectStatus::CONNECTED);

    IAM_LOGI("end");
}

void RemoteAuthInvokerContextFuzzTest(Parcel &parcel)
{
    IAM_LOGI("begin");

    uint64_t contextId = parcel.ReadUint64();
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    AuthParamInner authParam = {
        .userId = parcel.ReadInt32(),
        .challenge = challenge,
        .authType = static_cast<AuthType>(parcel.ReadInt32()),
        .authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32()),
    };
    auto contextCallback = MakeShared<ContextCallbackImpl>(new (std::nothrow) DummyIamCallbackInterface(),
        static_cast<OperationType>(OPERATION_TYPE));

    RemoteAuthInvokerContextParam param;
    param.connectionName = parcel.ReadString();
    param.verifierNetworkId = parcel.ReadString();
    param.collectorNetworkId = parcel.ReadString();
    param.tokenId = parcel.ReadUint32();
    param.collectorTokenId = parcel.ReadUint32();
    param.callerName = parcel.ReadString();
    param.callerType = parcel.ReadInt32();

    auto remoteAuthInvokerContext = MakeShared<RemoteAuthInvokerContext>(
        contextId, authParam, param, contextCallback
    );
    remoteAuthInvokerContext->GetContextType();
    remoteAuthInvokerContext->GetTokenId();

    std::string connectionName = parcel.ReadString();
    remoteAuthInvokerContext->OnConnectStatus(connectionName, ConnectStatus::DISCONNECTED);
    remoteAuthInvokerContext->OnConnectStatus(connectionName, ConnectStatus::CONNECTED);
    remoteAuthInvokerContext->SetVerifierContextId(contextId);
    remoteAuthInvokerContext->OnTimeOut();

    std::string srcEndPoint = parcel.ReadString();
    auto request = MakeShared<Attributes>();
    auto reply = MakeShared<Attributes>();
    request->SetUint32Value(Attributes::ATTR_MSG_TYPE, parcel.ReadUint32());
    remoteAuthInvokerContext->OnMessage(connectionName, srcEndPoint, request, reply);

    int32_t resultCode = parcel.ReadInt32();
    auto scheduleResultAttr = MakeShared<Attributes>();

    remoteAuthInvokerContext->OnResult(resultCode, scheduleResultAttr);

    remoteAuthInvokerContext->OnStart();
    remoteAuthInvokerContext->OnStop();
    Attributes extraInfo;
    FillIAttributes(parcel, extraInfo);
    remoteAuthInvokerContext->ProcAuthTipMsg(extraInfo);
    remoteAuthInvokerContext->ProcAuthResultMsg(extraInfo);
    IAM_LOGI("end");
}

void RemoteIamCallbackFuzzTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::string connectionName = parcel.ReadString();
    auto remoteCallback = MakeShared<RemoteIamCallback>(connectionName);
    int32_t result = parcel.ReadInt32();
    Attributes extraInfo;
    remoteCallback->OnResult(result, extraInfo.Serialize());

    int32_t module = parcel.ReadInt32();
    int32_t acquireInfo = parcel.ReadInt32();
    remoteCallback->OnAcquireInfo(module, acquireInfo, extraInfo.Serialize());

    remoteCallback->AsObject();
    IAM_LOGI("end");
}

void FuzzAuthWidgetHelper(Parcel &parcel)
{
    AuthParamInner authParam;
    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(ALL);
    authParam.authTypes.push_back(PIN);
    authParam.authTypes.push_back(FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    ContextFactory::AuthWidgetContextPara para;
    para.userId = MAIN_USER_ID;
    std::vector<AuthType> validType = {PIN, FACE, FINGERPRINT};
    AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para);
}

void FuzzGetUserAuthProfile(Parcel &parcel)
{
    int32_t userId = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    ContextFactory::AuthProfile profile = {};
    std::vector<uint64_t> credIds;
    FillFuzzUint64Vector(parcel, credIds);
    AuthWidgetHelper::GetUserAuthProfile(userId, authType, profile, credIds);
}

void FuzzParseAttributes(Parcel &parcel)
{
    Attributes extraInfo;
    FillIAttributes(parcel, extraInfo);
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    ContextFactory::AuthProfile profile = {};
    AuthWidgetHelper::ParseAttributes(extraInfo, authType, profile);
}

void FuzzCheckValidSolution(Parcel &parcel)
{
    int32_t userId = MAIN_USER_ID;
    std::vector<AuthType> authTypeList = {PIN, FACE, FINGERPRINT};
    AuthTrustLevel atl = ATL2;
    std::vector<AuthType> validTypeList = {PIN, FACE, FINGERPRINT};
    AuthWidgetHelper::CheckValidSolution(userId, authTypeList, atl, validTypeList);
}

void FuzzSetReuseUnlockResult(Parcel &parcel)
{
    int32_t apiVersion = parcel.ReadInt32();
    Attributes extraInfo;
    FillIAttributes(parcel, extraInfo);
    HdiReuseUnlockInfo info;
    AuthWidgetHelper::SetReuseUnlockResult(apiVersion, info, extraInfo);
}

void FuzzCheckReuseUnlockResult(Parcel &parcel)
{
    ContextFactory::AuthWidgetContextPara para;
    para.userId = MAIN_USER_ID;
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    ReuseUnlockResult reuseUnlockResult = {};
    reuseUnlockResult.isReuse = parcel.ReadBool();
    reuseUnlockResult.reuseDuration = parcel.ReadUint64();
    AuthParamInner authParam = {
        .userId = parcel.ReadInt32(),
        .challenge = challenge,
        .authType = static_cast<AuthType>(parcel.ReadInt32()),
        .authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32()),
        .reuseUnlockResult = reuseUnlockResult,
    };
    Attributes extraInfo;
    FillIAttributes(parcel, extraInfo);
    AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo);
}

using FuzzFunc = decltype(ContextAppStateObserverFuzzTest);
FuzzFunc *g_fuzzFuncs[] = {
    ContextAppStateObserverFuzzTest,
    RemoteAuthContextFuzzTest,
    RemoteAuthInvokerContextFuzzTest,
    RemoteIamCallbackFuzzTest,
    FuzzAuthWidgetHelper,
    FuzzGetUserAuthProfile,
    FuzzParseAttributes,
    FuzzCheckValidSolution,
    FuzzSetReuseUnlockResult,
    FuzzCheckReuseUnlockResult,
};

void RemoteAuthContextFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::RemoteAuthContextFuzzTest(data, size);
    return 0;
}