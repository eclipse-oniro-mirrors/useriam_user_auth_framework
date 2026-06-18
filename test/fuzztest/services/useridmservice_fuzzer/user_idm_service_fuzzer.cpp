/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "user_idm_service_fuzzer.h"

#include <cstdio>
#include "parcel.h"
#include "securec.h"

#include "iam_callback_proxy.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "mock_ipc_common.h"
#include "user_idm_service.h"
#include "dummy_iam_callback_interface.h"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_USER_IDM_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const int CMD_LEN = 19;
std::u16string cmd[] = {u"-h", u"-lc", u"-ls", u"-c", u"-c [base system]", u"-s", u"-s [SA0 SA1]", u"-s [SA] -a [-h]",
    u"-e", u"--net", u"--storage", u"-p", u"-p [pid]", u"--cpuusage [pid]", u"cified pid", u"--cpufreq", u"--mem [pid]",
    u"--zip", u"--mem-smaps pid [-v]"};

class DummyIdmGetCredentialInfoCallback : public IIdmGetCredInfoCallback {
public:
    int32_t OnCredentialInfos(int32_t result, const std::vector<IpcCredentialInfo> &credInfoList) override
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

class DummyIdmGetSecureUserInfoCallback : public IIdmGetSecureUserInfoCallback {
public:
    int32_t OnSecureUserInfo(int32_t result, const IpcSecUserInfo &secUserInfo) override
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

class DummyIdmCallback : public IIamCallback {
public:
    int32_t OnResult(int32_t result, const std::vector<uint8_t> &reqRet) override
    {
        IAM_LOGI("start");
        return SUCCESS;
    }

    int32_t OnAcquireInfo(int32_t module, int32_t acquire, const std::vector<uint8_t> &reqRet) override
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

class DummyCredChangeEventListener : public IEventListenerCallback {
public:
    ~DummyCredChangeEventListener() override = default;

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }

    int32_t OnNotifyAuthSuccessEvent(int32_t userId, int32_t authType,
        const IpcAuthSuccessEventInfo &info) override
    {
        IAM_LOGI("start");
        return SUCCESS;
    }
    int32_t OnNotifyCredChangeEvent(int32_t userId, int32_t authType, int32_t eventType,
        const IpcCredChangeEventInfo &changeInfo) override
    {
        IAM_LOGI("start");
        return SUCCESS;
    }
};

int32_t GetFuzzOptionalUserId(Parcel &parcel)
{
    if (parcel.ReadBool()) {
        return parcel.ReadInt32();
    }
    return 0;
}

sptr<IIdmGetCredInfoCallback> GetFuzzIdmGetCredentialInfoCallback(Parcel &parcel)
{
    sptr<IIdmGetCredInfoCallback> tmp(nullptr);
    if (parcel.ReadBool()) {
        tmp = sptr<IIdmGetCredInfoCallback>(new (std::nothrow) DummyIdmGetCredentialInfoCallback());
    }
    return tmp;
}

sptr<IIdmGetSecureUserInfoCallback> GetFuzzIdmGetSecureUserInfoCallback(Parcel &parcel)
{
    sptr<IIdmGetSecureUserInfoCallback> tmp(nullptr);
    if (parcel.ReadBool()) {
        tmp = sptr<IIdmGetSecureUserInfoCallback>(new (std::nothrow) DummyIdmGetSecureUserInfoCallback());
    }
    return tmp;
}

sptr<IIamCallback> GetFuzzIdmCallback(Parcel &parcel)
{
    sptr<IIamCallback> tmp(nullptr);
    if (parcel.ReadBool()) {
        tmp = sptr<IIamCallback>(new (std::nothrow) DummyIdmCallback());
    }
    return tmp;
}

UserIdmService g_userIdmService(SUBSYS_USERIAM_SYS_ABILITY_USERIDM, true);

void FuzzOpenSession(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = GetFuzzOptionalUserId(parcel);
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    g_userIdmService.OpenSession(userId, challenge);
    IAM_LOGI("end");
}

void FuzzCloseSession(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = GetFuzzOptionalUserId(parcel);
    g_userIdmService.CloseSession(userId);
    IAM_LOGI("end");
}

void FuzzGetCredentialInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = GetFuzzOptionalUserId(parcel);
    int32_t authType = parcel.ReadUint32();
    sptr<IIdmGetCredInfoCallback> callback = GetFuzzIdmGetCredentialInfoCallback(parcel);
    int32_t funcResult = SUCCESS;
    g_userIdmService.GetCredentialInfo(userId, authType, callback, funcResult);
    IAM_LOGI("end");
}

void FuzzGetCredentialInfoInner(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = GetFuzzOptionalUserId(parcel);
    auto authType = static_cast<AuthType>(parcel.ReadUint32());
    std::vector<CredentialInfo> credInfoList;
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    g_userIdmService.GetCredentialInfoInner(userId, authType, credInfoList);
    IpcCommon::DeleteAllPermission();
    IAM_LOGI("end");
}

void FuzzGetSecInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = GetFuzzOptionalUserId(parcel);
    sptr<IIdmGetSecureUserInfoCallback> callback = GetFuzzIdmGetSecureUserInfoCallback(parcel);
    g_userIdmService.GetSecInfo(userId, callback);
    IAM_LOGI("end");
}

void FuzzAddCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    IpcCredentialPara para = {};
    para.authType = parcel.ReadInt32();
    para.pinType = parcel.ReadInt32();
    FillFuzzUint8Vector(parcel, para.token);
    sptr<IIamCallback> callback = GetFuzzIdmCallback(parcel);
    g_userIdmService.AddCredential(userId, para, callback, false);
    IAM_LOGI("end");
}

void FuzzUpdateCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    IpcCredentialPara para = {};
    para.authType = parcel.ReadInt32();
    para.pinType = parcel.ReadInt32();
    FillFuzzUint8Vector(parcel, para.token);
    sptr<IIamCallback> callback = GetFuzzIdmCallback(parcel);
    g_userIdmService.UpdateCredential(userId, para, callback);
    IAM_LOGI("end");
}

void FuzzCancel(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    g_userIdmService.Cancel(userId);
    IAM_LOGI("end");
}

void FuzzEnforceDelUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    sptr<IIamCallback> callback = GetFuzzIdmCallback(parcel);
    g_userIdmService.EnforceDelUser(userId, callback);
    IAM_LOGI("end");
}

void FuzzDelUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    sptr<IIamCallback> callback = GetFuzzIdmCallback(parcel);
    g_userIdmService.DelUser(userId, authToken, callback);
    IAM_LOGI("end");
}

void FuzzDump(Parcel &parcel)
{
    IAM_LOGI("FuzzDump begin");
    std::vector<uint8_t> msg;
    Common::FillFuzzUint8Vector(parcel, msg);
    int32_t fd = parcel.ReadInt32();
    std::string fileName = to_string(fd) + ".txt";
    FILE *file = fopen(fileName.c_str(), "w");
    if (file != nullptr) {
        fd = fileno(file);
        std::vector<std::u16string> args;
        for (uint32_t i = 0; i < msg.size(); i++) {
            args.push_back(cmd[msg[i] % CMD_LEN]);
        }
        g_userIdmService.Dump(fd, args);
        fclose(file);
        remove(fileName.c_str());
    }
    IAM_LOGI("FuzzDump end");
}

void DelCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    uint64_t credentialId = parcel.ReadUint64();
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    sptr<IIamCallback> callback = GetFuzzIdmCallback(parcel);
    g_userIdmService.DelCredential(userId, credentialId, authToken, callback);
    IAM_LOGI("end");
}

void FuzzClearRedundancyCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    sptr<IIamCallback> callback = GetFuzzIdmCallback(parcel);
    g_userIdmService.ClearRedundancyCredential(callback);
    IAM_LOGI("end");
}

void FuzzClearRedundancyCredentialInner(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::string callerName = parcel.ReadString();
    int32_t callerType = parcel.ReadInt32();
    g_userIdmService.ClearRedundancyCredentialInner(callerName, callerType);
    IAM_LOGI("end");
}

void FuzzEnforceDelUserInner(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = 100;
    sptr<IIamCallback> iamCallback = sptr<IIamCallback>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> callbackForTrace =
        ContextCallback::NewInstance(iamCallback, TRACE_ENFORCE_DELETE_USER);
    std::string changeReasonTrace = parcel.ReadString();
    CredChangeEventInfo changeInfo = {};
    changeInfo.credentialId = parcel.ReadUint64();
    changeInfo.lastCredentialId = parcel.ReadUint64();
    changeInfo.callerName = parcel.ReadString();
    changeInfo.isSilentCredChange = parcel.ReadBool();
    g_userIdmService.EnforceDelUserInner(userId, callbackForTrace, changeReasonTrace, changeInfo);
    IAM_LOGI("end");
}

void FuzzCancelCurrentEnroll(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_userIdmService.CancelCurrentEnrollIfExist();
    IAM_LOGI("end");
}

void FuzzStartEnroll(Parcel &parcel)
{
    IAM_LOGI("begin");
    Enrollment::EnrollmentPara para = {};
    sptr<IIamCallback> iamCallback = sptr<IIamCallback>(new (nothrow) DummyIamCallbackInterface);
    std::shared_ptr<ContextCallback> contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    Attributes extraInfo;
    g_userIdmService.StartEnroll(para, contextCallback, extraInfo, true);
    IAM_LOGI("end");
}

void FuzzRegistCredChangeEventListener(Parcel &parcel)
{
    IAM_LOGI("begin");
    sptr<IEventListenerCallback> callback(nullptr);
    if (parcel.ReadBool()) {
        callback = sptr<IEventListenerCallback>(new (std::nothrow) DummyCredChangeEventListener());
    }

    g_userIdmService.RegistCredChangeEventListener(callback);
    g_userIdmService.UnRegistCredChangeEventListener(callback);
    IAM_LOGI("end");
}

void FuzzGetCredentialInfoSync(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    auto authType = static_cast<AuthType>(parcel.ReadInt32());
    IpcCredentialInfo info = {};
    info.authType = static_cast<AuthType>(parcel.ReadInt32());
    info.credentialId = parcel.ReadUint64();
    info.templateId = parcel.ReadUint64();
    info.pinType = static_cast<PinSubType>(parcel.ReadInt32());
    std::vector<IpcCredentialInfo> credentialInfoList = {info};
    g_userIdmService.GetCredentialInfoSync(userId, authType, credentialInfoList);
    IAM_LOGI("end");
}

void FuzzClearUnavailableCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    g_userIdmService.ClearUnavailableCredential(userId);
    IAM_LOGI("end");
}

void FuzzGetSessionInfoMasked(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    g_userIdmService.GetSessionInfoMasked(challenge);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzOpenSession);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzOpenSession,
    FuzzCloseSession,
    FuzzGetCredentialInfo,
    FuzzGetSecInfo,
    FuzzAddCredential,
    FuzzUpdateCredential,
    FuzzCancel,
    FuzzEnforceDelUser,
    FuzzDelUser,
    DelCredential,
    FuzzDump,
    FuzzClearRedundancyCredential,
    FuzzClearRedundancyCredentialInner,
    FuzzEnforceDelUserInner,
    FuzzCancelCurrentEnroll,
    FuzzStartEnroll,
    FuzzRegistCredChangeEventListener,
    FuzzGetCredentialInfoSync,
    FuzzClearUnavailableCredential,
    FuzzGetSessionInfoMasked,
    FuzzGetCredentialInfoInner
};

void UserIdmFuzzTest(const uint8_t *data, size_t size)
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
    OHOS::UserIam::UserAuth::UserIdmFuzzTest(data, size);
    return 0;
}