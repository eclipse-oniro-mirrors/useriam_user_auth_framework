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

#include "user_access_ctrl_client_fuzzer.h"

#include "parcel.h"

#include "user_access_ctrl_client_impl.h"
#include "user_access_ctrl_callback_service.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SDK"
#define LOG_FILE_ID LOG_FILE_USER_ACCESS_CTRL_CLIENT_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyVerifyTokenCallback final : public VerifyTokenCallback {
public:
    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
    }
};


void FuzzClientVerifyAuthToken(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> tokenIn = {};
    Common::FillFuzzUint8Vector(parcel, tokenIn);
    uint64_t allowableDuration = parcel.ReadInt32();
    auto callback = Common::MakeShared<DummyVerifyTokenCallback>();
    UserAccessCtrlClient::GetInstance().VerifyAuthToken(tokenIn, allowableDuration, callback);
    UserAccessCtrlClient::GetInstance().VerifyAuthToken(tokenIn, allowableDuration, nullptr);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzClientVerifyAuthToken);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzClientVerifyAuthToken,
};

void UserAccessCtrlClientFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::UserAccessCtrlClientFuzzTest(data, size);
    return 0;
}