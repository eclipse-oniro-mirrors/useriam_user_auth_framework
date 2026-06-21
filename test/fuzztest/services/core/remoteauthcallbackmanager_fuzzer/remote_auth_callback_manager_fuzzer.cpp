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

#include "remote_auth_callback_manager_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "iam_logger.h"
#include "remote_auth_callback_manager.h"
#include "i_remote_auth_callback.h"

#define LOG_TAG "USER_AUTH_SA"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {

class DummyIRemoteAuthCallback : public IRemoteStub<IRemoteAuthCallback> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD3(OnRemoteAuthResult,
        int32_t(int32_t result, const std::vector<uint8_t> &extraInfo, const std::vector<uint8_t> &licenseInfo));
    MOCK_METHOD2(OnGetRemoteAuthWidgetParam,
        int32_t(const std::vector<uint8_t> &challenge, const sptr<ISetWidgetParamCallback> &callback));
    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

void FuzzAddRemoteAuthCallback(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint32_t tokenId = parcel.ReadUint32();
    sptr<DummyIRemoteAuthCallback> callback = nullptr;
    bool hasCallback = parcel.ReadBool();
    if (hasCallback) {
        callback = new (std::nothrow) DummyIRemoteAuthCallback();
    }
    std::string callerName = "fuzz";
    manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    manager->DelRemoteAuthCallback(tokenId);
    IAM_LOGI("end");
}

void FuzzDelRemoteAuthCallback(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint32_t tokenId = parcel.ReadUint32();
    sptr<DummyIRemoteAuthCallback> callback = new (std::nothrow) DummyIRemoteAuthCallback();
    std::string callerName = "fuzz";
    if (callback != nullptr) {
        manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    }
    manager->DelRemoteAuthCallback(tokenId);
    IAM_LOGI("end");
}

void FuzzGetRemoteAuthCallback(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint32_t tokenId = parcel.ReadUint32();
    sptr<DummyIRemoteAuthCallback> callback = new (std::nothrow) DummyIRemoteAuthCallback();
    std::string callerName = "fuzz";
    if (callback != nullptr) {
        manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    }
    auto result = manager->GetRemoteAuthCallback(tokenId);
    static_cast<void>(result);
    manager->DelRemoteAuthCallback(tokenId);
    IAM_LOGI("end");
}

void FuzzDelRemoteAuthCallbackOnRemoteDied(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint32_t tokenId = parcel.ReadUint32();
    sptr<DummyIRemoteAuthCallback> callback = new (std::nothrow) DummyIRemoteAuthCallback();
    std::string callerName = "fuzz";
    if (callback != nullptr) {
        manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    }
    bool useNullCallback = parcel.ReadBool();
    sptr<IRemoteAuthCallback> callbackToDel = useNullCallback ? nullptr : callback;
    manager->DelRemoteAuthCallbackOnRemoteDied(callbackToDel);
    manager->DelRemoteAuthCallback(tokenId);
    IAM_LOGI("end");
}

void FuzzGetCallbackDeathRecipientMap(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint32_t tokenId = parcel.ReadUint32();
    sptr<DummyIRemoteAuthCallback> callback = new (std::nothrow) DummyIRemoteAuthCallback();
    std::string callerName = "fuzz";
    if (callback != nullptr) {
        manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    }
    auto map = manager->GetCallbackDeathRecipientMap();
    static_cast<void>(map);
    manager->DelRemoteAuthCallback(tokenId);
    IAM_LOGI("end");
}

void FuzzMultipleCallbacks(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint32_t tokenId1 = parcel.ReadUint32();
    uint32_t tokenId2 = parcel.ReadUint32();
    uint32_t tokenId3 = parcel.ReadUint32();
    sptr<DummyIRemoteAuthCallback> callback1 = new (std::nothrow) DummyIRemoteAuthCallback();
    sptr<DummyIRemoteAuthCallback> callback2 = new (std::nothrow) DummyIRemoteAuthCallback();
    sptr<DummyIRemoteAuthCallback> callback3 = new (std::nothrow) DummyIRemoteAuthCallback();
    std::string callerName = "fuzz";

    if (callback1 != nullptr) {
        manager->AddRemoteAuthCallback(tokenId1, callback1, callerName);
    }
    if (callback2 != nullptr) {
        manager->AddRemoteAuthCallback(tokenId2, callback2, callerName);
    }
    if (callback3 != nullptr) {
        manager->AddRemoteAuthCallback(tokenId3, callback3, callerName);
    }

    auto result1 = manager->GetRemoteAuthCallback(tokenId1);
    auto result2 = manager->GetRemoteAuthCallback(tokenId2);
    auto result3 = manager->GetRemoteAuthCallback(tokenId3);
    static_cast<void>(result1);
    static_cast<void>(result2);
    static_cast<void>(result3);

    manager->DelRemoteAuthCallback(tokenId1);
    manager->DelRemoteAuthCallback(tokenId2);
    manager->DelRemoteAuthCallback(tokenId3);
    IAM_LOGI("end");
}

void FuzzGetRemoteAuthCallerName(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto manager = &RemoteAuthCallbackManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    uint32_t tokenId = parcel.ReadUint32();
    sptr<DummyIRemoteAuthCallback> callback = new (std::nothrow) DummyIRemoteAuthCallback();
    std::string callerName = "fuzz";
    if (callback != nullptr) {
        manager->AddRemoteAuthCallback(tokenId, callback, callerName);
    }
    auto result = manager->GetRemoteAuthCallerName(tokenId);
    static_cast<void>(result);
    manager->DelRemoteAuthCallback(tokenId);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzAddRemoteAuthCallback);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzAddRemoteAuthCallback,
    FuzzDelRemoteAuthCallback,
    FuzzGetRemoteAuthCallback,
    FuzzDelRemoteAuthCallbackOnRemoteDied,
    FuzzGetCallbackDeathRecipientMap,
    FuzzMultipleCallbacks,
    FuzzGetRemoteAuthCallerName,
};

void RemoteAuthCallbackManagerFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::RemoteAuthCallbackManagerFuzzTest(data, size);
    return 0;
}