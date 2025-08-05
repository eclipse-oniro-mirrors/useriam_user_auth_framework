/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "parcel.h"

#include "attributes.h"
#include "context_callback_impl.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "dummy_iam_callback_interface.h"

#define LOG_TAG "USER_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

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

std::shared_ptr<WidgetContext> CreateWidgetContext(Parcel &parcel)
{
    uint64_t contextId = parcel.ReadUint64();
    ContextFactory::AuthWidgetContextPara para;
    para.userId = parcel.ReadInt32();
    para.sdkVersion = parcel.ReadInt32();
    para.tokenId = parcel.ReadUint32();
    FillFuzzString(parcel, para.callerName);
    FillFuzzUint8Vector(parcel, para.challenge);
    para.authTypeList.push_back(static_cast<AuthType>(parcel.ReadInt32()));
    para.atl = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    FillFuzzString(parcel, para.widgetParam.navigationButtonText);
    para.callerType = parcel.ReadInt32();
    FillFuzzString(parcel, para.callingAppID);
    para.isPinExpired = parcel.ReadBool();
    para.isOsAccountVerified = parcel.ReadBool();
    para.isBackgroundApplication = parcel.ReadBool();
    auto contextCallback = MakeShared<ContextCallbackImpl>(new (std::nothrow) DummyIamCallbackInterface(),
        static_cast<OperationType>(TRACE_AUTH_USER_ALL));
    return Common::MakeShared<WidgetContext>(contextId, para, contextCallback, nullptr);
}

void FillAttributes(Parcel &parcel, Attributes &attributes)
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

void FuzzStart(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }
    widgetContext->Start();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzStop(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }
    widgetContext->Stop();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzBuildSchedule(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }
    widgetContext->BuildSchedule();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzGetAuthContextCallback(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    sptr<IIamCallback> callback(nullptr);
    callback = sptr<IIamCallback>(new (nothrow) DummyUserAuthCallback());
    widgetContext->GetAuthContextCallback(authType, authTrustLevel, callback);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzBuildTask(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    AuthTrustLevel authTrustLevel = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    bool endAfterFirstFail = parcel.ReadBool();
    AuthIntent authIntent = static_cast<AuthIntent>(parcel.ReadInt32());
    widgetContext->BuildTask(challenge, authType, authTrustLevel, endAfterFirstFail, authIntent);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzOnStart(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    widgetContext->OnStart();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzOnStop(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    widgetContext->OnStop();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzAuthResult(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    int32_t resultCode = parcel.ReadInt32();
    int32_t authType = parcel.ReadInt32();
    Attributes attribute;
    FillAttributes(parcel, attribute);
    widgetContext->OnStart();
    widgetContext->AuthResult(resultCode, authType, attribute);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzAuthTipInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    int32_t tipType = parcel.ReadInt32();
    int32_t authType = parcel.ReadInt32();
    Attributes attribute;
    FillAttributes(parcel, attribute);
    widgetContext->OnStart();
    widgetContext->AuthTipInfo(tipType, authType, attribute);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzEndAuthAsCancel(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    widgetContext->OnStart();
    widgetContext->EndAuthAsCancel();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzEndAuthAsNaviPin(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }
    widgetContext->OnStart();
    widgetContext->EndAuthAsNaviPin();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzEndAuthAsWidgetParaInvalid(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }
    widgetContext->OnStart();
    widgetContext->EndAuthAsWidgetParaInvalid();
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzAuthWidgetReloadInit(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    widgetContext->AuthWidgetReloadInit();
    IAM_LOGI("end");
}

void FuzzAuthWidgetReload(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    uint32_t orientation = parcel.ReadUint32();
    uint32_t needRotate = parcel.ReadUint32();
    uint32_t alreadyLoad =  parcel.ReadUint32();
    AuthType rotateAuthType = static_cast<AuthType>(parcel.ReadInt32());
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    IAM_LOGI("end");
}

void FuzzIsValidRotate(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.isReload = parcel.ReadBool();
    widgetRotatePara.orientation = parcel.ReadUint32();
    widgetRotatePara.needRotate = parcel.ReadUint32();
    widgetRotatePara.alreadyLoad = parcel.ReadUint32();
    widgetRotatePara.rotateAuthType = static_cast<AuthType>(parcel.ReadInt32());
    widgetContext->IsValidRotate(widgetRotatePara);
    IAM_LOGI("end");
}

void FuzzStopAuthList(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    std::vector<AuthType> authTypeList;
    authTypeList.push_back(static_cast<AuthType>(parcel.ReadInt32()));
    widgetContext->StopAuthList(authTypeList);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzSuccessAuth(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }

    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    widgetContext->OnStart();
    widgetContext->SuccessAuth(authType);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

void FuzzConnectExtension(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.isReload = parcel.ReadBool();
    widgetRotatePara.orientation = parcel.ReadUint32();
    widgetRotatePara.needRotate = parcel.ReadUint32();
    widgetRotatePara.alreadyLoad = parcel.ReadUint32();
    widgetRotatePara.rotateAuthType = static_cast<AuthType>(parcel.ReadInt32());
    widgetContext->ConnectExtension(widgetRotatePara);
    widgetContext->DisconnectExtension();
    IAM_LOGI("end");
}

void FuzzEnd(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }
    widgetContext->OnStart();
    ResultCode resultCode = static_cast<ResultCode>(parcel.ReadInt32());
    widgetContext->End(resultCode);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});

    IAM_LOGI("end");
}

void FuzzStopAllRunTask(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto widgetContext = CreateWidgetContext(parcel);
    if (widgetContext == nullptr) {
        return;
    }
    widgetContext->OnStart();
    ResultCode resultCode = static_cast<ResultCode>(parcel.ReadInt32());
    widgetContext->StopAllRunTask(resultCode);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzStart);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzStart,
    FuzzStop,
    FuzzBuildSchedule,
    FuzzGetAuthContextCallback,
    FuzzBuildTask,
    FuzzOnStart,
    FuzzOnStop,
    FuzzAuthResult,
    FuzzAuthTipInfo,
    FuzzEndAuthAsCancel,
    FuzzEndAuthAsNaviPin,
    FuzzEndAuthAsWidgetParaInvalid,
    FuzzAuthWidgetReloadInit,
    FuzzAuthWidgetReload,
    FuzzIsValidRotate,
    FuzzStopAuthList,
    FuzzSuccessAuth,
    FuzzConnectExtension,
    FuzzEnd,
    FuzzStopAllRunTask,
};

void WidgetContextFuzzTest(const uint8_t *data, size_t size)
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
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::WidgetContextFuzzTest(data, size);
    return 0;
}
