/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "user_auth_client_fuzzer.h"

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "modal_callback_service.h"
#include "user_auth_client_impl.h"
#include "user_auth_callback_service.h"
#include "user_auth_modal_inner_callback.h"
#include "user_auth_napi_client_impl.h"

#define LOG_TAG "USER_AUTH_SDK"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_CLIENT_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyGetPropCallback final : public GetPropCallback {
public:
    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
    }
};

class DummySetPropCallback final : public SetPropCallback {
public:
    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
    }
};

class DummyAuthenticationCallback final : public AuthenticationCallback {
public:
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(module);
        static_cast<void>(acquireInfo);
        static_cast<void>(extraInfo);
    }

    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
    }
};

class DummyIdentificationCallback final : public IdentificationCallback {
public:
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(module);
        static_cast<void>(acquireInfo);
        static_cast<void>(extraInfo);
    }

    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
    }
};

class DummyPrepareRemoteAuthCallback final : public PrepareRemoteAuthCallback {
public:
    void OnResult(int32_t result)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
    }
};

class DummyIUserAuthWidgetCallback final : public IUserAuthWidgetCallback {
public:
    void SendCommand(const std::string &cmdData)
    {
        IAM_LOGI("start");
        static_cast<void>(cmdData);
    }
};

class DummyAuthSuccessEventListener final : public AuthSuccessEventListener {
public:
    void OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, const AuthSuccessEventInfo &info) override
    {
        IAM_LOGI("start");
        static_cast<void>(userId);
        static_cast<void>(authType);
        static_cast<void>(info);
    }
};

class DummyUserAuthModalClientCallback final : public UserAuthModalClientCallback {
public:
    void SendCommand(uint64_t contextId, const std::string &cmdData)
    {
        IAM_LOGI("start");
        static_cast<void>(contextId);
        static_cast<void>(cmdData);
    }

    bool IsModalInit()
    {
        IAM_LOGI("start");
        return true;
    }

    bool IsModalDestroy()
    {
        IAM_LOGI("start");
        return false;
    }

private:
    void CancelAuthentication(uint64_t contextId, int32_t cancelReason)
    {
        IAM_LOGI("start");
        static_cast<void>(contextId);
        static_cast<void>(cancelReason);
    }
};

void FuzzClientGetEnrolledState(Parcel &parcel)
{
    IAM_LOGI("start");
    auto apiVersion = parcel.ReadInt32();
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    EnrolledState enrolledState = {};
    UserAuthClientImpl::Instance().GetEnrolledState(apiVersion, authType, enrolledState);
    IAM_LOGI("end");
}

void FuzzClientGetAvailableStatus(Parcel &parcel)
{
    IAM_LOGI("start");
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    auto atl = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    auto userId = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    auto apiVersion = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    UserAuthClientImpl::Instance().GetAvailableStatus(userId, authType, atl);
    UserAuthClientImpl::Instance().GetNorthAvailableStatus(apiVersion, authType, atl);
    UserAuthClientImpl::Instance().GetAvailableStatus(authType, atl);
    IAM_LOGI("end");
}

void FuzzClientGetProperty(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    GetPropertyRequest request = {};
    request.authType = static_cast<AuthType>(parcel.ReadInt32());
    request.keys.push_back(static_cast<Attributes::AttributeKey>(parcel.ReadUint32()));
    auto callback = Common::MakeShared<DummyGetPropCallback>();
    UserAuthClient::GetInstance().GetProperty(userId, request, callback);
    UserAuthClient::GetInstance().GetProperty(userId, request, nullptr);
    IAM_LOGI("end");
}

void FuzzClientGetAuthLockState(Parcel &parcel)
{
    IAM_LOGI("start");
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    auto callback = Common::MakeShared<DummyGetPropCallback>();
    UserAuthClientImpl::Instance().GetAuthLockState(authType, callback);
    UserAuthClientImpl::Instance().GetAuthLockState(authType, nullptr);
    IAM_LOGI("end");
}

void FuzzClientSetProperty(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    SetPropertyRequest request = {};
    request.authType = static_cast<AuthType>(parcel.ReadInt32());
    request.mode = static_cast<PropertyMode>(parcel.ReadUint32());
    auto callback = Common::MakeShared<DummySetPropCallback>();
    UserAuthClient::GetInstance().SetProperty(userId, request, callback);
    UserAuthClient::GetInstance().SetProperty(userId, request, nullptr);
    IAM_LOGI("end");
}

void FuzzClientBeginAuthentication001(Parcel &parcel)
{
    IAM_LOGI("start");
    AuthParam authParam = {};
    authParam.userId = parcel.ReadInt32();
    Common::FillFuzzUint8Vector(parcel, authParam.challenge);
    authParam.authType = static_cast<AuthType>(parcel.ReadInt32());
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    auto callback = Common::MakeShared<DummyAuthenticationCallback>();
    UserAuthClient::GetInstance().BeginAuthentication(authParam, callback);
    UserAuthClient::GetInstance().BeginAuthentication(authParam, nullptr);
    IAM_LOGI("end");
}

void FuzzClientBeginAuthentication002(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t apiVersion = parcel.ReadInt32();
    std::vector<uint8_t> challenge;
    Common::FillFuzzUint8Vector(parcel, challenge);
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    auto atl = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    auto callback = Common::MakeShared<DummyAuthenticationCallback>();
    UserAuthClientImpl::Instance().BeginNorthAuthentication(apiVersion, challenge, authType, atl, callback);
    UserAuthClientImpl::Instance().BeginNorthAuthentication(apiVersion, challenge, authType, atl, nullptr);
    IAM_LOGI("end");
}

void FuzzClientCancelAuthentication(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    UserAuthClient::GetInstance().CancelAuthentication(contextId);
    IAM_LOGI("end");
}

void FuzzClientBeginIdentification(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> challenge;
    Common::FillFuzzUint8Vector(parcel, challenge);
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    auto callback = Common::MakeShared<DummyIdentificationCallback>();
    UserAuthClient::GetInstance().BeginIdentification(challenge, authType, callback);
    UserAuthClient::GetInstance().BeginIdentification(challenge, authType, nullptr);
    IAM_LOGI("end");
}

void FuzzCancelIdentification(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t contextId = parcel.ReadUint64();
    UserAuthClient::GetInstance().CancelIdentification(contextId);
    IAM_LOGI("end");
}

void FuzzClientGetVersion(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel.ReadInt32());
    int32_t version = -1;
    UserAuthClientImpl::Instance().GetVersion(version);
    IAM_LOGI("end");
}

void FuzzClientRegistUserAuthSuccessEventListener(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);
    auto listener = Common::MakeShared<DummyAuthSuccessEventListener>();
    UserAuthClientImpl::Instance().RegistUserAuthSuccessEventListener(authTypeList, listener);
    IAM_LOGI("end");
}

void FuzzClientUnRegistUserAuthSuccessEventListener(Parcel &Parcel)
{
    IAM_LOGI("start");
    auto listener = Common::MakeShared<DummyAuthSuccessEventListener>();
    UserAuthClientImpl::Instance().UnRegistUserAuthSuccessEventListener(listener);
    IAM_LOGI("end");
}

void FuzzClientSetGlobalConfigParam(Parcel &parcel)
{
    IAM_LOGI("start");
    GlobalConfigParam param = {};
    UserAuthClientImpl::Instance().SetGlobalConfigParam(param);
    IAM_LOGI("end");
}

void FuzzClientPrepareRemoteAuth(Parcel &parcel)
{
    IAM_LOGI("start");
    std::string networkId = parcel.ReadString();
    auto callback = Common::MakeShared<DummyPrepareRemoteAuthCallback>();
    UserAuthClientImpl::Instance().PrepareRemoteAuth(networkId, callback);
    UserAuthClientImpl::Instance().PrepareRemoteAuth(networkId, nullptr);
    IAM_LOGI("end");
}

void FuzzBeginWidgetAuth(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t apiVersion = parcel.ReadInt32();
    WidgetAuthParam authParam;
    WidgetParam widgetParam;
    Common::FillFuzzUint8Vector(parcel, authParam.challenge);
    std::vector<int32_t> atList;
    parcel.ReadInt32Vector(&atList);
    for (auto at : atList) {
        authParam.authTypes.push_back(static_cast<AuthType>(at));
    }
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    widgetParam.title = parcel.ReadString();
    widgetParam.navigationButtonText = parcel.ReadString();
    widgetParam.windowMode = static_cast<WindowModeType>(parcel.ReadInt32());
    auto callback = Common::MakeShared<DummyAuthenticationCallback>();
    UserAuthClientImpl::Instance().BeginWidgetAuth(apiVersion, authParam, widgetParam, callback);
    UserAuthClientImpl::Instance().BeginWidgetAuth(authParam, widgetParam, callback);
    IAM_LOGI("end");
}

void FuzzNapiBeginWidgetAuth(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t apiVersion = parcel.ReadInt32();
    AuthParamInner authParam;
    WidgetParamNapi widgetParam;
    Common::FillFuzzUint8Vector(parcel, authParam.challenge);
    std::vector<int32_t> atList;
    parcel.ReadInt32Vector(&atList);
    for (auto at : atList) {
        authParam.authTypes.push_back(static_cast<AuthType>(at));
    }
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    widgetParam.title = parcel.ReadString();
    widgetParam.navigationButtonText = parcel.ReadString();
    widgetParam.windowMode = static_cast<WindowModeType>(parcel.ReadInt32());
    auto callback = Common::MakeShared<DummyAuthenticationCallback>();
    std::shared_ptr<UserAuthModalInnerCallback> modalCallback = Common::MakeShared<UserAuthModalInnerCallback>();
    UserAuthNapiClientImpl::Instance().BeginWidgetAuth(apiVersion, authParam, widgetParam, callback, modalCallback);
    uint64_t contextId = parcel.ReadUint64();
    int32_t cancelReason = parcel.ReadInt32();
    UserAuthNapiClientImpl::Instance().CancelAuthentication(contextId, cancelReason);
    IAM_LOGI("end");
}

void FuzzSetWidgetCallback(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t version = -1;
    auto callback = Common::MakeShared<DummyIUserAuthWidgetCallback>();
    UserAuthClientImpl::Instance().SetWidgetCallback(version, callback);
    IAM_LOGI("end");
}

void FuzzNotice(Parcel &parcel)
{
    IAM_LOGI("start");
    NoticeType noticeType = static_cast<NoticeType>(parcel.ReadInt32());
    std::string eventData = parcel.ReadString();
    UserAuthClientImpl::Instance().Notice(noticeType, eventData);
    IAM_LOGI("end");
}

auto g_UserAuthCallbackService =
    Common::MakeShared<UserAuthCallbackService>(Common::MakeShared<DummyAuthenticationCallback>());

auto g_UserAuthCallbackServiceForWait =
    Common::MakeShared<UserAuthCallbackService>(Common::MakeShared<DummyAuthenticationCallback>(),
        Common::MakeShared<DummyUserAuthModalClientCallback>());

auto g_GetPropCallbackService =
    Common::MakeShared<GetExecutorPropertyCallbackService>(Common::MakeShared<DummyGetPropCallback>());

auto g_SetPropCallbackService =
    Common::MakeShared<SetExecutorPropertyCallbackService>(Common::MakeShared<DummySetPropCallback>());

void FuzzUserAuthCallbackServiceOnResult(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t result = parcel.ReadInt32();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes extraInfo(attr);
    if (g_UserAuthCallbackService != nullptr) {
        g_UserAuthCallbackService->OnResult(result, extraInfo.Serialize());
    }
    IAM_LOGI("end");
}

void FuzzUserAuthCallbackServiceOnAcquireInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t result = parcel.ReadInt32();
    int32_t acquireInfo = parcel.ReadInt32();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes extraInfo(attr);
    if (g_UserAuthCallbackService != nullptr) {
        g_UserAuthCallbackService->OnAcquireInfo(result, acquireInfo, extraInfo.Serialize());
    }
    IAM_LOGI("end");
}

void FuzzUserAuthCallbackServiceOnAcquireInfoForWait(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t result = parcel.ReadInt32();
    int32_t acquireInfo = parcel.ReadInt32();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes extraInfo(attr);
    if (g_UserAuthCallbackServiceForWait != nullptr) {
        g_UserAuthCallbackServiceForWait->OnAcquireInfo(result, acquireInfo, extraInfo.Serialize());
    }
    IAM_LOGI("end");
}

void FuzzGetPropCallbackServiceOnPropResult(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t result = parcel.ReadInt32();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes extraInfo(attr);
    if (g_GetPropCallbackService != nullptr) {
        g_GetPropCallbackService->OnGetExecutorPropertyResult(result, extraInfo.Serialize());
    }
    IAM_LOGI("end");
}

void FuzzSetPropCallbackServiceOnPropResult(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t result = parcel.ReadInt32();
    if (g_SetPropCallbackService != nullptr) {
        g_SetPropCallbackService->OnSetExecutorPropertyResult(result);
    }
    IAM_LOGI("end");
}

void FuzzSetGlobalConfigParam(Parcel &parcel)
{
    IAM_LOGI("start");
    GlobalConfigParam param = {};
    param.value.pinExpiredPeriod = parcel.ReadUint64();
    param.type = static_cast<GlobalConfigType>(parcel.ReadInt32());
    UserAuthClientImpl::Instance().SetGlobalConfigParam(param);
    IAM_LOGI("end");
}

void FuzzQueryReusableAuthResult(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> token;
    WidgetAuthParam authParam = {};
    authParam.userId = parcel.ReadInt32();
    Common::FillFuzzUint8Vector(parcel, authParam.challenge);
    authParam.authTypes.push_back(static_cast<AuthType>(parcel.ReadInt32()));
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    authParam.reuseUnlockResult.isReuse = parcel.ReadBool();
    authParam.reuseUnlockResult.reuseMode = static_cast<ReuseMode>(parcel.ReadInt32());
    authParam.reuseUnlockResult.reuseDuration = parcel.ReadUint64();
    UserAuthClientImpl::Instance().QueryReusableAuthResult(authParam, token);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzClientGetAvailableStatus);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzClientGetAuthLockState,
    FuzzClientGetEnrolledState,
    FuzzClientGetAvailableStatus,
    FuzzClientGetProperty,
    FuzzClientSetProperty,
    FuzzClientBeginAuthentication001,
    FuzzClientBeginAuthentication002,
    FuzzClientCancelAuthentication,
    FuzzClientBeginIdentification,
    FuzzClientRegistUserAuthSuccessEventListener,
    FuzzClientUnRegistUserAuthSuccessEventListener,
    FuzzClientSetGlobalConfigParam,
    FuzzClientPrepareRemoteAuth,
    FuzzCancelIdentification,
    FuzzClientGetVersion,
    FuzzBeginWidgetAuth,
    FuzzSetWidgetCallback,
    FuzzNotice,
    FuzzUserAuthCallbackServiceOnResult,
    FuzzUserAuthCallbackServiceOnAcquireInfo,
    FuzzUserAuthCallbackServiceOnAcquireInfoForWait,
    FuzzGetPropCallbackServiceOnPropResult,
    FuzzSetPropCallbackServiceOnPropResult,
    FuzzSetGlobalConfigParam,
    FuzzNapiBeginWidgetAuth,
    FuzzQueryReusableAuthResult,
};

void UserAuthClientFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::UserAuthClientFuzzTest(data, size);
    return 0;
}