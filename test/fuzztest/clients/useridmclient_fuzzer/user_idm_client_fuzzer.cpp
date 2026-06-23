/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "user_idm_client_fuzzer.h"

#include "parcel.h"

#include "user_idm_client.h"
#include "user_idm_callback_service.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SDK"
#define LOG_FILE_ID LOG_FILE_USER_IDM_CLIENT_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyUserIdmClientCallback final : public UserIdmClientCallback {
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

class DummyGetCredentialInfoCallback final : public GetCredentialInfoCallback {
public:
    void OnCredentialInfo(int32_t result, const std::vector<CredentialInfo> &infoList)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(infoList);
    }
};

class DummyGetSecUserInfoCallback final : public GetSecUserInfoCallback {
public:
    void OnSecUserInfo(int32_t result, const SecUserInfo &info)
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(info);
    }
};

class DummyCredChangeEventListener final : public CredChangeEventListener {
public:
    void OnNotifyCredChangeEvent(int32_t userId, AuthType authType, CredChangeEventType eventType,
        const CredChangeEventInfo &changeInfo)
    {
        IAM_LOGI("start");
        static_cast<void>(userId);
        static_cast<void>(authType);
        static_cast<void>(eventType);
        static_cast<void>(changeInfo);
    }
};

void FuzzClientOpenSession(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    UserIdmClient::GetInstance().OpenSession(userId);
    IAM_LOGI("end");
}

void FuzzClientCloseSession(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    UserIdmClient::GetInstance().CloseSession(userId);
    IAM_LOGI("end");
}

void FuzzClientAddCredential(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    CredentialParameters para = {};
    para.authType = static_cast<AuthType>(parcel.ReadInt32());
    Common::FillFuzzUint8Vector(parcel, para.token);
    auto callback = Common::MakeShared<DummyUserIdmClientCallback>();
    UserIdmClient::GetInstance().AddCredential(userId, para, callback);
    UserIdmClient::GetInstance().AddCredential(userId, para, nullptr);
    IAM_LOGI("end");
}

void FuzzClientUpdateCredential(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    CredentialParameters para = {};
    para.authType = static_cast<AuthType>(parcel.ReadInt32());
    Common::FillFuzzUint8Vector(parcel, para.token);
    auto callback = Common::MakeShared<DummyUserIdmClientCallback>();
    UserIdmClient::GetInstance().UpdateCredential(userId, para, callback);
    UserIdmClient::GetInstance().UpdateCredential(userId, para, nullptr);
    IAM_LOGI("end");
}

void FuzzClientCancel(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    UserIdmClient::GetInstance().Cancel(userId);
    IAM_LOGI("end");
}

void FuzzClientDeleteCredential(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    uint64_t credentialId = parcel.ReadUint64();
    std::vector<uint8_t> authToken;
    Common::FillFuzzUint8Vector(parcel, authToken);
    auto callback = Common::MakeShared<DummyUserIdmClientCallback>();
    UserIdmClient::GetInstance().DeleteCredential(userId, credentialId, authToken, callback);
    UserIdmClient::GetInstance().DeleteCredential(userId, credentialId, authToken, nullptr);
    IAM_LOGI("end");
}

void FuzzClientDeleteUser(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> authToken;
    Common::FillFuzzUint8Vector(parcel, authToken);
    auto callback = Common::MakeShared<DummyUserIdmClientCallback>();
    UserIdmClient::GetInstance().DeleteUser(userId, authToken, callback);
    UserIdmClient::GetInstance().DeleteUser(userId, authToken, nullptr);
    IAM_LOGI("end");
}

void FuzzClientEraseUser(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    auto callback = Common::MakeShared<DummyUserIdmClientCallback>();
    UserIdmClient::GetInstance().EraseUser(userId, callback);
    UserIdmClient::GetInstance().EraseUser(userId, nullptr);
    IAM_LOGI("end");
}

void FuzzClientGetCredentialInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    auto callback = Common::MakeShared<DummyGetCredentialInfoCallback>();
    UserIdmClient::GetInstance().GetCredentialInfo(userId, authType, callback);
    UserIdmClient::GetInstance().GetCredentialInfo(userId, authType, nullptr);
    IAM_LOGI("end");
}

void FuzzClientGetSecUserInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    auto callback = Common::MakeShared<DummyGetSecUserInfoCallback>();
    UserIdmClient::GetInstance().GetSecUserInfo(userId, callback);
    UserIdmClient::GetInstance().GetSecUserInfo(userId, nullptr);
    IAM_LOGI("end");
}

void FuzzClientClearRedundancyCredential(Parcel &parcel)
{
    IAM_LOGI("start");
    auto callback = Common::MakeShared<DummyUserIdmClientCallback>();
    UserIdmClient::GetInstance().ClearRedundancyCredential(callback);
    UserIdmClient::GetInstance().ClearRedundancyCredential(nullptr);
    IAM_LOGI("end");
}

void FuzzClientRegistCredChangeEventListener(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);
    auto listener = Common::MakeShared<DummyCredChangeEventListener>();
    UserIdmClient::GetInstance().RegistCredChangeEventListener(authTypeList, listener);
    IAM_LOGI("end");
}

void FuzzClientUnRegistCredChangeEventListener(Parcel &Parcel)
{
    IAM_LOGI("start");
    auto listener = Common::MakeShared<DummyCredChangeEventListener>();
    UserIdmClient::GetInstance().UnRegistCredChangeEventListener(listener);
    IAM_LOGI("end");
}

auto g_IdmCallbackService =
    Common::MakeShared<IdmCallbackService>(Common::MakeShared<DummyUserIdmClientCallback>());

auto g_IdmGetCredInfoCallbackService =
    Common::MakeShared<IdmGetCredInfoCallbackService>(Common::MakeShared<DummyGetCredentialInfoCallback>());

auto g_IdmGetSecureUserInfoCallbackService =
    Common::MakeShared<IdmGetSecureUserInfoCallbackService>(Common::MakeShared<DummyGetSecUserInfoCallback>());

void FuzzIdmCallbackServiceOnResult(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t result = parcel.ReadInt32();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes extraInfo(attr);
    if (g_IdmCallbackService != nullptr) {
        g_IdmCallbackService->OnResult(result, extraInfo.Serialize());
    }
    IAM_LOGI("end");
}

void FuzzIdmCallbackServiceOnAcquireInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t module = parcel.ReadInt32();
    int32_t acquireInfo = parcel.ReadInt32();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes extraInfo(attr);
    if (g_IdmCallbackService != nullptr) {
        g_IdmCallbackService->OnAcquireInfo(module, acquireInfo, extraInfo.Serialize());
    }
    IAM_LOGI("end");
}

void FuzzCallbackServiceOnCredentialInfos(Parcel &parcel)
{
    IAM_LOGI("start");
    IpcCredentialInfo info = {};
    info.authType = static_cast<AuthType>(parcel.ReadInt32());
    info.credentialId = parcel.ReadUint64();
    info.templateId = parcel.ReadUint64();
    info.pinType = static_cast<PinSubType>(parcel.ReadInt32());
    std::vector<IpcCredentialInfo> credInfoList = {info};
    int32_t result = parcel.ReadInt32();
    if (g_IdmGetCredInfoCallbackService != nullptr) {
        g_IdmGetCredInfoCallbackService->OnCredentialInfos(result, credInfoList);
    }
    IAM_LOGI("end");
}

void FuzzCallbackServiceOnSecureUserInfo(Parcel &parcel)
{
    IAM_LOGI("start");
    IpcSecUserInfo secUserInfo = {};
    secUserInfo.secureUid = parcel.ReadUint64();
    IpcEnrolledInfo info = {};
    info.authType = parcel.ReadInt32();
    info.enrolledId = parcel.ReadUint64();
    secUserInfo.enrolledInfo.push_back(info);
    int32_t result = parcel.ReadInt32();

    if (g_IdmGetSecureUserInfoCallbackService != nullptr) {
        g_IdmGetSecureUserInfoCallbackService->OnSecureUserInfo(result, secUserInfo);
    }
    IAM_LOGI("end");
}

void FuzzClientGetCredentialInfoSync(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t userId = parcel.ReadInt32();
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    std::vector<CredentialInfo> credentialInfoList;
    UserIdmClient::GetInstance().GetCredentialInfoSync(userId, authType, credentialInfoList);
    IAM_LOGI("end");
}


using FuzzFunc = decltype(FuzzClientOpenSession);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzClientOpenSession,
    FuzzClientCloseSession,
    FuzzClientAddCredential,
    FuzzClientUpdateCredential,
    FuzzClientCancel,
    FuzzClientDeleteCredential,
    FuzzClientDeleteUser,
    FuzzClientEraseUser,
    FuzzClientGetCredentialInfo,
    FuzzClientGetSecUserInfo,
    FuzzIdmCallbackServiceOnResult,
    FuzzIdmCallbackServiceOnAcquireInfo,
    FuzzCallbackServiceOnCredentialInfos,
    FuzzCallbackServiceOnSecureUserInfo,
    FuzzClientClearRedundancyCredential,
    FuzzClientRegistCredChangeEventListener,
    FuzzClientUnRegistCredChangeEventListener,
    FuzzClientGetCredentialInfoSync,
};

void UserIdmClientFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::UserIdmClientFuzzTest(data, size);
    return 0;
}