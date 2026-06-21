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

#include "remote_auth_callback_service.h"
#include "remote_auth_callback_service_fuzzer.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyRemoteAuthClientCallback final : public RemoteAuthClientCallback {
public:
    void OnGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge,
        const std::shared_ptr<SetWidgetParamClientCallback> &callback) override
    {
        IAM_LOGI("start");
        static_cast<void>(challenge);
        static_cast<void>(callback);
    }

    void OnRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t result,
        const Attributes &extraInfo) override
    {
        IAM_LOGI("start");
        static_cast<void>(challenge);
        static_cast<void>(result);
        static_cast<void>(extraInfo);
    }
};

std::shared_ptr<RemoteAuthCallbackService> CreateRemoteAuthCallbackService()
{
    std::shared_ptr<RemoteAuthClientCallback> testCallback = Common::MakeShared<DummyRemoteAuthClientCallback>();
    return Common::MakeShared<RemoteAuthCallbackService>(testCallback);
}

void FuzzOnGetRemoteAuthWidgetParam(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateRemoteAuthCallbackService();
    std::vector<uint8_t> challenge;
    Common::FillFuzzUint8Vector(parcel, challenge);
    sptr<ISetWidgetParamCallback> testSetWidgetParamCallback = nullptr;
    service->OnGetRemoteAuthWidgetParam(challenge, testSetWidgetParamCallback);
    IAM_LOGI("end");
}

void FuzzOnRemoteAuthResult(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateRemoteAuthCallbackService();
    std::vector<uint8_t> challenge;
    Common::FillFuzzUint8Vector(parcel, challenge);
    int32_t resultCode = parcel.ReadInt32();
    std::vector<uint8_t> extraInfo;
    Common::FillFuzzUint8Vector(parcel, extraInfo);
    service->OnRemoteAuthResult(challenge, resultCode, extraInfo);
    IAM_LOGI("end");
}

void FuzzCallbackEnter(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateRemoteAuthCallbackService();
    uint32_t code = parcel.ReadUint32();
    service->CallbackEnter(code);
    IAM_LOGI("end");
}

void FuzzCallbackExit(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto service = CreateRemoteAuthCallbackService();
    uint32_t code = parcel.ReadUint32();
    int32_t result = parcel.ReadInt32();
    service->CallbackExit(code, result);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzOnGetRemoteAuthWidgetParam);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzOnGetRemoteAuthWidgetParam,
    FuzzOnRemoteAuthResult,
    FuzzCallbackEnter,
    FuzzCallbackExit,
};

void RemoteAuthCallbackServiceFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::RemoteAuthCallbackServiceFuzzTest(data, size);
    return 0;
}
