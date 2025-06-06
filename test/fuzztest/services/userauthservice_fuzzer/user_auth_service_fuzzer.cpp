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
#include "mock_ipc_common.h"
#include "user_auth_service.h"
#include "user_auth_common_defines.h"
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
class DummyUserAuthCallback : public IIamCallback {
public:
    ~DummyUserAuthCallback() override = default;

    int32_t OnAcquireInfo(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo) override
    {
        IAM_LOGI("start");
        static_cast<void>(module);
        static_cast<void>(acquireInfo);
        static_cast<void>(extraInfo);
        return SUCCESS;
    }

    int32_t OnResult(int32_t result, const std::vector<uint8_t> &extraInfo) override
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

class DummyGetExecutorPropertyCallback : public IGetExecutorPropertyCallback {
public:
    ~DummyGetExecutorPropertyCallback() override = default;

    int32_t OnGetExecutorPropertyResult(int32_t result, const std::vector<uint8_t> &attributes) override
    {
        IAM_LOGI("start");
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

class DummySetExecutorPropertyCallback : public ISetExecutorPropertyCallback {
public:
    ~DummySetExecutorPropertyCallback() override = default;

    int32_t OnSetExecutorPropertyResult(int32_t resultCode) override
    {
        IAM_LOGI("start");
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

class DummyWidgetCallback : public IWidgetCallback {
public:
    int32_t SendCommand(const std::string &cmdData) override
    {
        IAM_LOGI("start");
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

class DummyAuthEventListener : public IEventListenerCallback {
public:
    ~DummyAuthEventListener() override = default;

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }

    int32_t OnNotifyAuthSuccessEvent(int32_t userId, int32_t authType, int32_t callerType,
        const std::string &callerName) override
    {
        IAM_LOGI("start");
        return SUCCESS;
    }
    int32_t OnNotifyCredChangeEvent(int32_t userId, int32_t authType, int32_t eventType,
        uint64_t credentialId) override
    {
        IAM_LOGI("start");
        return SUCCESS;
    }
};

class DummyVerifyTokenCallback : public IVerifyTokenCallback {
public:
    ~DummyVerifyTokenCallback() override = default;

    int32_t OnVerifyTokenResult(int32_t result, const std::vector<uint8_t> &attributes) override
    {
        IAM_LOGI("start");
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

UserAuthService g_userAuthService;

void FuzzGetResourseNode(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_userAuthService.OnStart();
    g_userAuthService.OnStop();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    g_userAuthService.GetResourseNode(authType);
    g_userAuthService.ProcessWidgetSessionExclusive();
    uint32_t code = parcel.ReadUint32();
    int32_t result = parcel.ReadInt32();
    g_userAuthService.CallbackEnter(code);
    g_userAuthService.CallbackExit(code, result);
    IAM_LOGI("end");
}

void FuzzGetEnrolledState(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    int32_t authType = parcel.ReadInt32();
    IpcEnrolledState enrolledState = {};
    g_userAuthService.GetEnrolledState(apiVersion, authType, enrolledState);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    g_userAuthService.GetEnrolledState(apiVersion, authType, enrolledState);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzGetAvailableStatusOtherScene(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = 8;
    int32_t pin = 1;
    int32_t authTrustLevel = parcel.ReadInt32();
    int32_t userId = parcel.ReadInt32();
    g_userAuthService.GetAvailableStatus(apiVersion, userId, pin, authTrustLevel);
    g_userAuthService.GetAvailableStatus(apiVersion, pin, authTrustLevel);
    IAM_LOGI("end");
}

void FuzzGetAvailableStatus(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    int32_t authType = parcel.ReadInt32();
    int32_t authTrustLevel = parcel.ReadInt32();
    int32_t userId = parcel.ReadInt32();
    g_userAuthService.GetAvailableStatus(apiVersion, userId, authType, authTrustLevel);
    g_userAuthService.GetAvailableStatus(apiVersion, authType, authTrustLevel);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    g_userAuthService.GetAvailableStatus(apiVersion, userId, authType, authTrustLevel);
    g_userAuthService.GetAvailableStatus(apiVersion, authType, authTrustLevel);
    FuzzGetAvailableStatusOtherScene(parcel);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzGetProperty(Parcel &parcel)
{
    IAM_LOGI("begin");
    constexpr uint32_t maxDataLen = 50;
    int32_t userId = parcel.ReadInt32();
    int32_t authType = parcel.ReadInt32();
    std::vector<uint32_t> keys;
    uint32_t keysLen = parcel.ReadUint32() % maxDataLen;
    keys.reserve(keysLen);
    for (uint32_t i = 0; i < keysLen; i++) {
        keys.emplace_back(parcel.ReadUint32());
    }

    sptr<IGetExecutorPropertyCallback> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<IGetExecutorPropertyCallback>(new (std::nothrow) DummyGetExecutorPropertyCallback());
    }
    g_userAuthService.GetProperty(userId, authType, keys, callback);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    g_userAuthService.GetProperty(userId, authType, keys, callback);
    IpcCommon::DeleteAllPermission();
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
    sptr<ISetExecutorPropertyCallback> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<ISetExecutorPropertyCallback>(new (nothrow) DummySetExecutorPropertyCallback());
    }

    g_userAuthService.SetProperty(userId, authType, attributes.Serialize(), callback);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    g_userAuthService.SetProperty(userId, authType, attributes.Serialize(), callback);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzAuth(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.challenge = challenge;
    ipcAuthParamInner.authType = parcel.ReadInt32();
    ipcAuthParamInner.authTrustLevel =  parcel.ReadInt32();
    sptr<IIamCallback> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<IIamCallback>(new (std::nothrow) DummyUserAuthCallback());
    }
    uint64_t contextId = 0;
    g_userAuthService.Auth(apiVersion, ipcAuthParamInner, callback, contextId);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    g_userAuthService.Auth(apiVersion, ipcAuthParamInner, callback, contextId);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzAuthUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    sptr<IIamCallback> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<IIamCallback>(new (nothrow) DummyUserAuthCallback());
    }
    IpcAuthParamInner param = {
        .userId = parcel.ReadInt32(),
        .challenge = challenge,
        .authType = parcel.ReadInt32(),
        .authTrustLevel = parcel.ReadInt32(),
    };
    IpcRemoteAuthParam remoteAuthParam = {
        .isHasRemoteAuthParam = parcel.ReadBool(),
    };
    uint64_t contextId = 0;
    g_userAuthService.AuthUser(param, remoteAuthParam, callback, contextId);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    g_userAuthService.AuthUser(param, remoteAuthParam, callback, contextId);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzDoPrepareRemoteAuth(Parcel &parcel)
{
    IAM_LOGI("begin");
    const std::string networkId = parcel.ReadString();
    g_userAuthService.DoPrepareRemoteAuth(networkId);
    IAM_LOGI("end");
}

void FuzzIdentify(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    int32_t authType = parcel.ReadInt32();
    sptr<IIamCallback> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<IIamCallback>(new (nothrow) DummyUserAuthCallback());
    }
    uint64_t contextId = 0;
    g_userAuthService.Identify(challenge, authType, callback, contextId);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    g_userAuthService.Identify(challenge, authType, callback, contextId);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzCancelAuthOrIdentify(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    int32_t cancelReason = parcel.ReadInt32();
    g_userAuthService.CancelAuthOrIdentify(contextId, cancelReason);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    g_userAuthService.CancelAuthOrIdentify(contextId, cancelReason);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzGetVersion(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t version = -1;
    g_userAuthService.GetVersion(version);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    g_userAuthService.GetVersion(version);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzAuthWidget(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    IpcAuthParamInner authParam;
    IpcWidgetParamInner widgetParam;
    FillFuzzUint8Vector(parcel, authParam.challenge);
    std::vector<int32_t> atList;
    parcel.ReadInt32Vector(&authParam.authTypes);
    authParam.authTrustLevel = parcel.ReadInt32();
    authParam.isUserIdSpecified = true;
    sptr<IIamCallback> callback(nullptr);
    widgetParam.title = parcel.ReadString();
    widgetParam.navigationButtonText = parcel.ReadString();
    widgetParam.windowMode = parcel.ReadInt32();
    if (parcel.ReadBool()) {
        callback = sptr<IIamCallback>(new (std::nothrow) DummyUserAuthCallback());
    }
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    g_userAuthService.AuthWidget(apiVersion, authParam, widgetParam, callback, testModalCallback, contextId);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    g_userAuthService.AuthWidget(apiVersion, authParam, widgetParam, callback, testModalCallback, contextId);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzStartAuthWidget(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    AuthParamInner authParam;
    WidgetParamInner widgetParam;
    FillFuzzUint8Vector(parcel, authParam.challenge);
    std::vector<int32_t> atList;
    authParam.authType = static_cast<AuthType>(parcel.ReadInt32());
    authParam.authTypes = {PIN, FACE, FINGERPRINT};
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32());
    authParam.isUserIdSpecified = true;
    widgetParam.title = parcel.ReadString();
    widgetParam.navigationButtonText = parcel.ReadString();
    widgetParam.windowMode = static_cast<WindowModeType>(parcel.ReadInt32());
    sptr<IIamCallback> iamCallback = sptr<IIamCallback>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback =
        ContextCallback::NewInstance(iamCallback, TRACE_AUTH_USER_SECURITY);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    ContextFactory::AuthWidgetContextPara para;
    para.sdkVersion = apiVersion;
    g_userAuthService.StartAuthWidget(authParam, widgetParam, para, contextCallback, testModalCallback, contextId);
    IAM_LOGI("end");
}

void FuzzNotice(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t noticeType = parcel.ReadInt32();
    std::string eventData = parcel.ReadString();
    g_userAuthService.Notice(noticeType, eventData);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    g_userAuthService.Notice(noticeType, eventData);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    g_userAuthService.Notice(noticeType, eventData);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzRegisterWidgetCallback(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t version = parcel.ReadInt32();
    sptr<IWidgetCallback> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<IWidgetCallback>(new (std::nothrow) DummyWidgetCallback());
    }
    g_userAuthService.RegisterWidgetCallback(version, callback);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    g_userAuthService.RegisterWidgetCallback(version, callback);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    g_userAuthService.RegisterWidgetCallback(version, callback);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzRegistUserAuthSuccessEventListener(Parcel &parcel)
{
    IAM_LOGI("begin");
    sptr<IEventListenerCallback> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<IEventListenerCallback>(new (std::nothrow) DummyAuthEventListener());
    }

    g_userAuthService.RegistUserAuthSuccessEventListener(callback);
    g_userAuthService.UnRegistUserAuthSuccessEventListener(callback);
    IAM_LOGI("end");
}

void FuzzSetGlobalConfigParam(Parcel &parcel)
{
    IAM_LOGI("start");
    IpcGlobalConfigParam param = {};
    param.value.pinExpiredPeriod = parcel.ReadUint64();
    param.type = parcel.ReadInt32();
    g_userAuthService.SetGlobalConfigParam(param);
    IAM_LOGI("end");
}

void FuzzPrepareRemoteAuth(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::string networkId = parcel.ReadString();
    sptr<IIamCallback> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<IIamCallback>(new (nothrow) DummyUserAuthCallback());
    }
    g_userAuthService.PrepareRemoteAuth(networkId, callback);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    g_userAuthService.PrepareRemoteAuth(networkId, callback);
    IpcCommon::DeleteAllPermission();
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
    sptr<IIamCallback> callback = sptr<IIamCallback>(new (nothrow) DummyUserAuthCallback);
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
    auto context = ContextFactory::CreateWidgetContext(para, nullptr, nullptr);
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
        .userId = -1,
        .challenge = challenge,
        .authType = static_cast<AuthType>(parcel.ReadInt32()),
        .authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadInt32()),
    };
    Authentication::AuthenticationPara para = {};
    RemoteAuthParam remoteAuthParam = {};
    sptr<IIamCallback> iamCallback = sptr<IIamCallback>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    ResultCode failReason = SUCCESS;
    g_userAuthService.AuthRemoteUser(authParam, para, remoteAuthParam, contextCallback, failReason);
    authParam.userId = parcel.ReadInt32();
    g_userAuthService.AuthRemoteUser(authParam, para, remoteAuthParam, contextCallback, failReason);
    para.authType = PIN;
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
    sptr<IIamCallback> iamCallback = sptr<IIamCallback>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    AuthParamInner authParam = {};
    WidgetParamInner widgetParam = {};
    std::vector<AuthType> validType = {PIN};
    ContextFactory::AuthWidgetContextPara para;
    g_userAuthService.StartWidgetContext(contextCallback, authParam, widgetParam, validType, para, nullptr);
    IAM_LOGI("end");
}

void FuzzStartRemoteAuthInvokerContext(Parcel &parcel)
{
    IAM_LOGI("begin");
    AuthParamInner authParam = {};
    RemoteAuthInvokerContextParam param = {};
    sptr<IIamCallback> iamCallback = sptr<IIamCallback>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    g_userAuthService.StartRemoteAuthInvokerContext(authParam, param, contextCallback);
    IAM_LOGI("end");
}

void FuzzStartAuth(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t apiVersion = parcel.ReadInt32();
    uint64_t contextId = parcel.ReadUint64();
    Authentication::AuthenticationPara para;
    sptr<IIamCallback> iamCallback = sptr<IIamCallback>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    g_userAuthService.StartAuth(apiVersion, para, contextCallback, contextId);
    IAM_LOGI("end");
}

void FuzzGetPropertyById(Parcel &parcel)
{
    IAM_LOGI("begin");
    constexpr uint32_t maxDataLen = 50;
    uint64_t credentialId = parcel.ReadUint64();
    std::vector<uint32_t> keys;
    uint32_t keysLen = parcel.ReadUint32() % maxDataLen;
    keys.reserve(keysLen);
    for (uint32_t i = 0; i < keysLen; i++) {
        keys.emplace_back(parcel.ReadUint32());
    }

    sptr<IGetExecutorPropertyCallback> callback(nullptr);
    callback = sptr<IGetExecutorPropertyCallback>(new (std::nothrow) DummyGetExecutorPropertyCallback());
    g_userAuthService.GetPropertyById(credentialId, keys, callback);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    g_userAuthService.GetPropertyById(credentialId, keys, callback);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzVerifyAuthToken(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t allowableDuration = parcel.ReadUint64();
    std::vector<uint8_t> tokenIn = {};
    Common::FillFuzzUint8Vector(parcel, tokenIn);
    sptr<IVerifyTokenCallback> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<IVerifyTokenCallback>(new (std::nothrow) DummyVerifyTokenCallback());
    }
    g_userAuthService.VerifyAuthToken(tokenIn, allowableDuration, callback);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    g_userAuthService.VerifyAuthToken(tokenIn, allowableDuration, callback);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzGetAuthTokenAttr(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    const HdiUserAuthTokenPlain tokenPlain = {
        .version = parcel.ReadInt32(),
        .userId = parcel.ReadInt32(),
        .challenge = challenge,
        .timeInterval = parcel.ReadUint64(),
        .authTrustLevel = parcel.ReadUint32(),
        .authType = parcel.ReadInt32(),
        .tokenType = parcel.ReadInt32(),
        .secureUid = parcel.ReadUint64(),
        .enrolledId = parcel.ReadUint64(),
        .credentialId = parcel.ReadUint64()
    };
    std::vector<uint8_t> rootSecret;
    FillFuzzUint8Vector(parcel, rootSecret);
    Attributes extraInfo;
    g_userAuthService.GetAuthTokenAttr(tokenPlain, rootSecret, extraInfo);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzGetAvailableStatus);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzGetResourseNode,
    FuzzGetEnrolledState,
    FuzzGetAvailableStatus,
    FuzzGetProperty,
    FuzzSetProperty,
    FuzzAuth,
    FuzzAuthUser,
    FuzzDoPrepareRemoteAuth,
    FuzzIdentify,
    FuzzCancelAuthOrIdentify,
    FuzzGetVersion,
    FuzzAuthWidget,
    FuzzStartAuthWidget,
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
    FuzzStartAuth,
    FuzzGetPropertyById,
    FuzzVerifyAuthToken,
    FuzzGetAuthTokenAttr,
};

void UserAuthFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    for (auto fuzzFunc : g_fuzzFuncs) {
        fuzzFunc(parcel);
    }
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
