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

#include "event_listener_callback_service.h"
#include "event_listener_callback_service_fuzzer.h"
#include "user_auth_client_impl.h"
#include "user_idm_client_impl.h"

#include "callback_manager.h"
#include "iam_fuzz_test.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SDK"
#define LOG_FILE_ID LOG_FILE_EVENT_LISTENER_CALLBACK_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
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

class DummyCredChangeEventListener final : public CredChangeEventListener {
public:
    void OnNotifyCredChangeEvent(int32_t userId, AuthType authType, CredChangeEventType eventType,
        const CredChangeEventInfo &changeInfo) override
    {
        IAM_LOGI("start");
        static_cast<void>(userId);
        static_cast<void>(authType);
        static_cast<void>(eventType);
        static_cast<void>(changeInfo);
    }
};

void FuzzAddEventListener(Parcel &parcel)
{
    IAM_LOGI("begin");
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyAuthSuccessEventListener>();
    EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().RegisterListener(authTypeList, listener);
    EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().UnRegisterListener(listener);
    EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().GetEventListenerSet(AuthType::PIN);
    IAM_LOGI("end");
}

void FuzzOnNotifyAuthSuccessEvent(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    IpcAuthSuccessEventInfo info = {};
    info.callerType = parcel.ReadInt32();
    Common::FillFuzzString(parcel, info.callerName);
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    auto subManage = EventListenerCallbackService::GetInstance();
    subManage->OnNotifyAuthSuccessEvent(userId, authType, info);

    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyAuthSuccessEventListener>();
    EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().RegisterListener(authTypeList, listener);
    subManage->OnNotifyAuthSuccessEvent(userId, authType, info);
    IAM_LOGI("end");
}

void FuzzOnNotifyCredChangeEvent(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    int32_t callerType = parcel.ReadInt32();
    IpcCredChangeEventInfo info = {};
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    auto subManage = EventListenerCallbackService::GetInstance();
    subManage->OnNotifyCredChangeEvent(userId, authType, callerType, info);

    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyCredChangeEventListener>();
    EventListenerCallbackManager<CredChangeEventListener>::GetInstance().RegisterListener(authTypeList, listener);
    subManage->OnNotifyCredChangeEvent(userId, authType, callerType, info);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzAddEventListener);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzAddEventListener,
    FuzzOnNotifyAuthSuccessEvent,
    FuzzOnNotifyCredChangeEvent,
};

void EventListenerCallbackServiceFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::EventListenerCallbackServiceFuzzTest(data, size);
    return 0;
}