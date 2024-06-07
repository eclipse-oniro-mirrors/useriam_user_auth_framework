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

#include "context_callback_impl_fuzzer.h"

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
constexpr uint32_t OPERATION_TYPE = 1;

auto g_ContextCallback = MakeShared<ContextCallbackImpl>(new (std::nothrow) DummyIamCallbackInterface(),
    static_cast<OperationType>(OPERATION_TYPE));

void FillOnResult(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t resultCode = parcel.ReadInt32();
    Attributes attributes;
    g_ContextCallback->OnResult(resultCode, attributes);
    IAM_LOGI("end");
}

void FillOnAcquireInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    ExecutorRole src = static_cast<ExecutorRole>(parcel.ReadInt32());
    int32_t moduleType = parcel.ReadInt32();
    std::vector<uint8_t> acquireMsg;
    FillFuzzUint8Vector(parcel, acquireMsg);
    g_ContextCallback->OnAcquireInfo(src, moduleType, acquireMsg);
    IAM_LOGI("end");
}

void FillSet(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::string callerName;
    FillFuzzString(parcel, callerName);
    g_ContextCallback->SetTraceCallerName(callerName);

    uint64_t requestContextId = parcel.ReadUint64();
    g_ContextCallback->SetTraceRequestContextId(requestContextId);

    uint64_t authContextId = parcel.ReadUint64();
    g_ContextCallback->SetTraceAuthContextId(authContextId);

    int32_t userId = parcel.ReadInt32();
    g_ContextCallback->SetTraceUserId(userId);

    int32_t remainTime = parcel.ReadInt32();
    g_ContextCallback->SetTraceRemainTime(remainTime);

    int32_t freezingTime = parcel.ReadInt32();
    g_ContextCallback->SetTraceFreezingTime(freezingTime);

    int32_t version = parcel.ReadInt32();
    g_ContextCallback->SetTraceSdkVersion(version);

    int32_t authType = parcel.ReadInt32();
    g_ContextCallback->SetTraceAuthType(authType);

    uint32_t authWidgetType = parcel.ReadUint32();
    g_ContextCallback->SetTraceAuthWidgetType(authWidgetType);

    AuthTrustLevel atl = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    g_ContextCallback->SetTraceAuthTrustLevel(atl);

    uint32_t reuseUnlockResultMode = parcel.ReadUint32();
    g_ContextCallback->SetTraceReuseUnlockResultMode(reuseUnlockResultMode);

    uint64_t reuseUnlockResultDuration = parcel.ReadUint64();
    g_ContextCallback->SetTraceReuseUnlockResultDuration(reuseUnlockResultDuration);

    g_ContextCallback->SetCleaner(nullptr);

    int32_t callerType = parcel.ReadInt32();
    g_ContextCallback->SetTraceCallerType(callerType);
    IAM_LOGI("end");
}

void FillProcessAuthResult(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t tip = parcel.ReadInt32();
    std::vector<uint8_t> extraInfo;
    FillFuzzUint8Vector(parcel, extraInfo);
    g_ContextCallback->ProcessAuthResult(tip, extraInfo);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FillOnResult);
FuzzFunc *g_fuzzFuncs[] = {
    FillOnResult,
    FillOnAcquireInfo,
    FillSet,
    FillProcessAuthResult,
};

void ContextCallbackImplFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::ContextCallbackImplFuzzTest(data, size);
    return 0;
}
