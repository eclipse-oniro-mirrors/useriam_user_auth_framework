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

#include "user_auth_service_fuzzer.h"

#include <cinttypes>
#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "user_auth_service.h"
#include "user_auth_common_defines.h"
#include "user_auth_event_listener_stub.h"
#include "dummy_iam_callback_interface.h"

#undef private

#ifdef LOG_LABEL
#undef LOG_LABEL
#endif
#define LOG_TAG "USER_AUTH_SA"

using namespace std;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyUserAuthCallback : public UserAuthCallbackInterface {
public:
    ~DummyUserAuthCallback() override = default;

    void OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo) override
    {
        IAM_LOGI("start");
        static_cast<void>(module);
        static_cast<void>(acquireInfo);
        static_cast<void>(extraInfo);
        return;
    }

    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

class DummyGetExecutorPropertyCallback : public GetExecutorPropertyCallbackInterface {
public:
    ~DummyGetExecutorPropertyCallback() override = default;

    void OnGetExecutorPropertyResult(int32_t result, const Attributes &attributes) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

class DummySetExecutorPropertyCallback : public SetExecutorPropertyCallbackInterface {
public:
    ~DummySetExecutorPropertyCallback() override = default;

    void OnSetExecutorPropertyResult(int32_t result) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

class DummyWidgetCallback : public WidgetCallbackInterface {
public:
    void SendCommand(const std::string &cmdData) override
    {
        IAM_LOGI("start");
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

class DummyAuthEventListener : public AuthEventListenerInterface {
public:
    ~DummyAuthEventListener() override = default;

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }

    void OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, int32_t callerType,
        std::string &callerName) override
    {
        IAM_LOGI("notify: userId: %{public}d, authType: %{public}d, callerName: %{public}s,"
            "callerType: %{public}d", userId, static_cast<int32_t>(authType), callerName.c_str(), callerType);
    }
};

class DummyVerifyTokenCallback : public VerifyTokenCallbackInterface {
public:
    ~DummyVerifyTokenCallback() override = default;

    void OnVerifyTokenResult(int32_t result, const Attributes &attributes) override
    {
        IAM_LOGI("start");
        return;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

UserAuthService g_userAuthService;

void FuzzGetEnrolledState(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    EnrolledState enrolledState = {};
    g_userAuthService.GetEnrolledState(apiVersion, authType, enrolledState);
    IAM_LOGI("end");
}

void FuzzGetAvailableStatusOtherScene(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = 8;
    int32_t pin = 1;
    AuthType authType = static_cast<AuthType>(pin);
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    int32_t userId = parcel.ReadInt32();
    g_userAuthService.GetAvailableStatus(apiVersion, userId, authType, authTrustLevel);
    IAM_LOGI("end");
}

void FuzzGetAvailableStatus(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    int32_t userId = parcel.ReadInt32();
    g_userAuthService.GetAvailableStatus(apiVersion, userId, authType, authTrustLevel);
    FuzzGetAvailableStatusOtherScene(parcel);
    IAM_LOGI("end");
}

void FuzzGetProperty(Parcel &parcel)
{
    IAM_LOGI("begin");
    constexpr uint32_t maxDataLen = 50;
    int32_t userId = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    std::vector<Attributes::AttributeKey> keys;
    uint32_t keysLen = parcel.ReadUint32() % maxDataLen;
    keys.reserve(keysLen);
    for (uint32_t i = 0; i < keysLen; i++) {
        keys.emplace_back(static_cast<Attributes::AttributeKey>(parcel.ReadInt32()));
    }

    sptr<GetExecutorPropertyCallbackInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<GetExecutorPropertyCallbackInterface>(new (std::nothrow) DummyGetExecutorPropertyCallback());
    }
    g_userAuthService.GetProperty(userId, authType, keys, callback);
    IAM_LOGI("end");
}

void FuzzSetProperty(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    vector<uint8_t> attributesRaw;
    FillFuzzUint8Vector(parcel, attributesRaw);
    Attributes attributes(attributesRaw);
    sptr<SetExecutorPropertyCallbackInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<SetExecutorPropertyCallbackInterface>(new (nothrow) DummySetExecutorPropertyCallback());
    }

    g_userAuthService.SetProperty(userId, authType, attributes, callback);
    IAM_LOGI("end");
}

void FuzzAuth(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    sptr<UserAuthCallbackInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<UserAuthCallbackInterface>(new (std::nothrow) DummyUserAuthCallback());
    }
    g_userAuthService.Auth(apiVersion, challenge, authType, authTrustLevel, callback);
    IAM_LOGI("end");
}

void FuzzAuthUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    sptr<UserAuthCallbackInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<UserAuthCallbackInterface>(new (nothrow) DummyUserAuthCallback());
    }
    AuthParamInner param = {
        .userId = parcel.ReadInt32(),
        .challenge = challenge,
        .authType = static_cast<AuthType>(parcel.ReadInt32()),
        .authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32()),
    };
    std::optional<RemoteAuthParam> remoteAuthParam = std::nullopt;
    g_userAuthService.AuthUser(param, remoteAuthParam, callback);
    IAM_LOGI("end");
}

void FuzzIdentify(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    sptr<UserAuthCallbackInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<UserAuthCallbackInterface>(new (nothrow) DummyUserAuthCallback());
    }
    g_userAuthService.Identify(challenge, authType, callback);
    IAM_LOGI("end");
}

void FuzzCancelAuthOrIdentify(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    int32_t cancelReason = parcel.ReadInt32();
    g_userAuthService.CancelAuthOrIdentify(contextId, cancelReason);
    IAM_LOGI("end");
}

void FuzzGetVersion(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t version = -1;
    g_userAuthService.GetVersion(version);
    IAM_LOGI("end");
}

void FuzzAuthWidget(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    AuthParamInner authParam;
    WidgetParamInner widgetParam;
    FillFuzzUint8Vector(parcel, authParam.challenge);
    std::vector<int32_t> atList;
    parcel.ReadInt32Vector(&atList);
    for (auto at : atList) {
        authParam.authTypes.push_back(static_cast<AuthType>(at));
    }
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    sptr<UserAuthCallbackInterface> callback(nullptr);
    widgetParam.title = parcel.ReadString();
    widgetParam.navigationButtonText = parcel.ReadString();
    widgetParam.windowMode = static_cast<WindowModeType>(parcel.ReadInt32());
    if (parcel.ReadBool()) {
        callback = sptr<UserAuthCallbackInterface>(new (std::nothrow) DummyUserAuthCallback());
    }
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    g_userAuthService.AuthWidget(apiVersion, authParam, widgetParam, callback, testModalCallback);
    IAM_LOGI("end");
}

void FuzzNotice(Parcel &parcel)
{
    IAM_LOGI("begin");
    NoticeType noticeType = static_cast<NoticeType>(parcel.ReadInt32());
    std::string eventData = parcel.ReadString();
    g_userAuthService.Notice(noticeType, eventData);
    IAM_LOGI("end");
}

void FuzzRegisterWidgetCallback(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t version = parcel.ReadInt32();
    sptr<WidgetCallbackInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<WidgetCallbackInterface>(new (std::nothrow) DummyWidgetCallback());
    }
    g_userAuthService.RegisterWidgetCallback(version, callback);
    IAM_LOGI("end");
}

void FuzzRegistUserAuthSuccessEventListener(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<int32_t> authType;
    std::vector<AuthType> authTypeList;
    parcel.ReadInt32Vector(&authType);
    for (const auto &iter : authType) {
        authTypeList.push_back(static_cast<AuthType>(iter));
    }

    sptr<AuthEventListenerInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<AuthEventListenerInterface>(new (std::nothrow) DummyAuthEventListener());
    }

    g_userAuthService.RegistUserAuthSuccessEventListener(authTypeList, callback);
    g_userAuthService.UnRegistUserAuthSuccessEventListener(callback);
    IAM_LOGI("end");
}

void FuzzSetGlobalConfigParam(Parcel &parcel)
{
    IAM_LOGI("start");
    GlobalConfigParam param = {};
    param.value.pinExpiredPeriod = parcel.ReadUint64();
    param.type = static_cast<GlobalConfigType>(parcel.ReadInt32());
    g_userAuthService.SetGlobalConfigParam(param);
    IAM_LOGI("end");
}

void FuzzPrepareRemoteAuth(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::string networkId = parcel.ReadString();
    sptr<UserAuthCallbackInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<UserAuthCallbackInterface>(new (nothrow) DummyUserAuthCallback());
    }
    g_userAuthService.PrepareRemoteAuth(networkId, callback);
    IAM_LOGI("end");
}

void FuzzCheckValidSolution(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    AuthParamInner authParam = {
        .userId = parcel.ReadInt32(),
        .challenge = challenge,
        .authType = static_cast<AuthType>(parcel.ReadInt32()),
        .authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32()),
    };
    WidgetParamInner widgetParam;
    widgetParam.title = parcel.ReadString();
    widgetParam.navigationButtonText = parcel.ReadString();
    widgetParam.windowMode = static_cast<WindowModeType>(parcel.ReadInt32());
    std::vector<int32_t> authType;
    std::vector<AuthType> validType;
    parcel.ReadInt32Vector(&authType);
    for (const auto &iter : authType) {
        validType.push_back(static_cast<AuthType>(iter));
    }
    g_userAuthService.CheckValidSolution(userId, authParam, widgetParam, validType);
    IAM_LOGI("end");
}


void FuzzCompleteRemoteAuthParam(Parcel &parcel)
{
    IAM_LOGI("begin");
    RemoteAuthParam remoteAuthParam = {};
    std::string localNetworkId = "1234567890123456789012345678901234567890123456789012345678901234";
    remoteAuthParam.verifierNetworkId = std::nullopt;
    g_userAuthService.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId);
    remoteAuthParam.verifierNetworkId = "123";
    remoteAuthParam.collectorNetworkId = "1234123456789012345678901234567890123456789012345678901234567890";
    g_userAuthService.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId);
    remoteAuthParam.verifierNetworkId = localNetworkId;
    g_userAuthService.CompleteRemoteAuthParam(remoteAuthParam, localNetworkId);
    IAM_LOGI("end");
}

void FuzzGetAuthContextCallback(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    sptr<UserAuthCallbackInterface> callback = sptr<UserAuthCallbackInterface>(new (nothrow) DummyUserAuthCallback);
    g_userAuthService.GetAuthContextCallback(apiVersion, authParam, widgetParam, callback);
    authParam.authTypes = {PIN, FACE, FINGERPRINT};
    ReuseUnlockResult reuseUnlockResult = {};
    reuseUnlockResult.isReuse = true;
    authParam.reuseUnlockResult = reuseUnlockResult;
    g_userAuthService.GetAuthContextCallback(apiVersion, authParam, widgetParam, callback);
    IAM_LOGI("end");
}

void FuzzInsert2ContextPool(Parcel &parcel)
{
    IAM_LOGI("begin");
    ContextFactory::AuthWidgetContextPara para = {};
    auto context = ContextFactory::CreateWidgetContext(para, nullptr);
    g_userAuthService.Insert2ContextPool(context);
    IAM_LOGI("end");
}

void FuzzCheckAuthWidgetType(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<AuthType> authType = {PIN, FACE, FINGERPRINT};
    g_userAuthService.CheckAuthWidgetType(authType);
    authType = {PIN, FACE, FINGERPRINT, RECOVERY_KEY};
    g_userAuthService.CheckAuthWidgetType(authType);
    IAM_LOGI("end");
}

void FuzzCheckSingeFaceOrFinger(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<AuthType> authType = {PIN, FACE, FINGERPRINT};
    g_userAuthService.CheckSingeFaceOrFinger(authType);
    authType = {PIN};
    g_userAuthService.CheckSingeFaceOrFinger(authType);
    authType = {FACE};
    g_userAuthService.CheckSingeFaceOrFinger(authType);
    authType = {FINGERPRINT};
    g_userAuthService.CheckSingeFaceOrFinger(authType);
    IAM_LOGI("end");
}

void FuzzAuthRemoteUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    AuthParamInner authParam = {
        .userId = INVALID_USER_ID,
        .challenge = challenge,
        .authType = static_cast<AuthType>(parcel.ReadInt32()),
        .authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32()),
    };
    Authentication::AuthenticationPara para = {};
    RemoteAuthParam remoteAuthParam = {};
    sptr<IamCallbackInterface> iamCallback = sptr<IamCallbackInterface>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    ResultCode failReason = SUCCESS;
    g_userAuthService.AuthRemoteUser(authParam, para, remoteAuthParam, contextCallback, failReason);
    authParam.authType = PIN;
    g_userAuthService.AuthRemoteUser(authParam, para, remoteAuthParam, contextCallback, failReason);
    IAM_LOGI("end");
}

void FuzzFillGetPropertyValue(Parcel &parcel)
{
    IAM_LOGI("begin");
    AuthType authType = PIN;
    std::vector<Attributes::AttributeKey> keys = {Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION};
    Attributes *values = new Attributes();
    g_userAuthService.FillGetPropertyValue(authType, keys, *values);
    authType = FACE;
    g_userAuthService.FillGetPropertyValue(authType, keys, *values);
    IAM_LOGI("end");
}

void FuzzFillGetPropertyKeys(Parcel &parcel)
{
    IAM_LOGI("begin");
    AuthType authType = PIN;
    std::vector<Attributes::AttributeKey> keys = {Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION};
    std::vector<uint32_t> uint32Keys = {parcel.ReadInt32(), parcel.ReadInt32()};
    g_userAuthService.FillGetPropertyKeys(authType, keys, uint32Keys);
    authType = FACE;
    g_userAuthService.FillGetPropertyKeys(authType, keys, uint32Keys);
    IAM_LOGI("end");
}

void FuzzStartWidgetContext(Parcel &parcel)
{
    IAM_LOGI("begin");
    sptr<IamCallbackInterface> iamCallback = sptr<IamCallbackInterface>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType = {PIN};
    ContextFactory::AuthWidgetContextPara para;
    g_userAuthService.StartWidgetContext(contextCallback, authParam, widgetParam, validType, para);
    IAM_LOGI("end");
}

void FuzzStartRemoteAuthInvokerContext(Parcel &parcel)
{
    IAM_LOGI("begin");
    AuthParamInner authParam = {};
    RemoteAuthInvokerContextParam param = {};
    sptr<IamCallbackInterface> iamCallback = sptr<IamCallbackInterface>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    g_userAuthService.StartRemoteAuthInvokerContext(authParam, param, contextCallback);
    IAM_LOGI("end");
}

void FuzzStartAuthContext(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    Authentication::AuthenticationPara para;
    sptr<IamCallbackInterface> iamCallback = sptr<IamCallbackInterface>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    g_userAuthService.StartAuthContext(apiVersion, para, contextCallback);
    IAM_LOGI("end");
}

void FuzzGetPropertyById(Parcel &parcel)
{
    IAM_LOGI("begin");
    constexpr uint32_t maxDataLen = 50;
    uint64_t credentialId = parcel.ReadUint64();
    std::vector<Attributes::AttributeKey> keys;
    uint32_t keysLen = parcel.ReadUint32() % maxDataLen;
    keys.reserve(keysLen);
    for (uint32_t i = 0; i < keysLen; i++) {
        keys.emplace_back(static_cast<Attributes::AttributeKey>(parcel.ReadInt32()));
    }

    sptr<GetExecutorPropertyCallbackInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<GetExecutorPropertyCallbackInterface>(new (std::nothrow) DummyGetExecutorPropertyCallback());
    }
    g_userAuthService.GetPropertyById(credentialId, keys, callback);
    IAM_LOGI("end");
}

void FuzzVerifyAuthToken(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t allowableDuration = parcel.ReadUint64();
    std::vector<uint8_t> tokenIn = {};
    Common::FillFuzzUint8Vector(parcel, tokenIn);
    sptr<VerifyTokenCallbackInterface> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<VerifyTokenCallbackInterface>(new (std::nothrow) DummyVerifyTokenCallback());
    }
    g_userAuthService.VerifyAuthToken(tokenIn, allowableDuration, callback);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetAvailableStatus);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzGetEnrolledState,
    FuzzGetAvailableStatus,
    FuzzGetProperty,
    FuzzSetProperty,
    FuzzAuth,
    FuzzAuthUser,
    FuzzIdentify,
    FuzzCancelAuthOrIdentify,
    FuzzGetVersion,
    FuzzAuthWidget,
    FuzzNotice,
    FuzzRegisterWidgetCallback,
    FuzzRegistUserAuthSuccessEventListener,
    FuzzSetGlobalConfigParam,
    FuzzPrepareRemoteAuth,
    FuzzCheckValidSolution,
    FuzzCompleteRemoteAuthParam,
    FuzzGetAuthContextCallback,
    FuzzInsert2ContextPool,
    FuzzCheckAuthWidgetType,
    FuzzCheckSingeFaceOrFinger,
    FuzzAuthRemoteUser,
    FuzzFillGetPropertyValue,
    FuzzFillGetPropertyKeys,
    FuzzStartWidgetContext,
    FuzzStartRemoteAuthInvokerContext,
    FuzzStartAuthContext,
    FuzzGetPropertyById,
    FuzzVerifyAuthToken,
};

void UserAuthFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs)) / sizeof(FuzzFunc *);
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::UserAuthFuzzTest(data, size);
    return 0;
}
