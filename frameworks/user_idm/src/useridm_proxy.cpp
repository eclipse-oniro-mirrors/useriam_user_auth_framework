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

#include "useridm_proxy.h"

#include <cinttypes>

#include "iam_logger.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_IDM_SDK

using namespace OHOS::UserIAM::Common;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
uint64_t UserIDMProxy::OpenSession()
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }

    uint64_t challenge = 0;
    bool ret = SendRequest(USERIDM_OPEN_SESSION, data, reply);
    if (ret) {
        challenge = reply.ReadUint64();
        IAM_LOGI("challenge = 0xXXXX%{public}04" PRIx64, MASK & challenge);
    }
    return challenge;
}

uint64_t UserIDMProxy::OpenSession(const int32_t userId)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to WriteInt32(userId)");
        return FAIL;
    }
    uint64_t challenge = 0;
    bool ret = SendRequest(USERIDM_OPEN_SESSION_BY_ID, data, reply);
    if (ret) {
        challenge = reply.ReadUint64();
        IAM_LOGI("challenge = 0xXXXX%{public}04" PRIx64, MASK & challenge);
    }
    return challenge;
}

void UserIDMProxy::CloseSession()
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }

    bool ret = SendRequest(USERIDM_CLOSE_SESSION, data, reply);
    if (ret) {
        IAM_LOGE("ret = %{public}d", ret);
    }
}

void UserIDMProxy::CloseSession(const int32_t userId)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to WriteInt32(userId)");
        return;
    }
    bool ret = SendRequest(USERIDM_CLOSE_SESSION_BY_ID, data, reply);
    IAM_LOGI("ret = %{public}d", ret);
}

int32_t UserIDMProxy::GetAuthInfo(const AuthType authType, const sptr<IGetInfoCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }

    if (!data.WriteUint32(authType)) {
        IAM_LOGE("failed to WriteUint32(authType)");
        return FAIL;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return FAIL;
    }

    int32_t result = FAIL;
    bool ret = SendRequest(USERIDM_GET_AUTH_INFO, data, reply, true);
    if (ret) {
        result = reply.ReadInt32();
        IAM_LOGI("result = %{public}d", result);
    }
    return result;
}

int32_t UserIDMProxy::GetAuthInfo(const int32_t userId, const AuthType authType, const sptr<IGetInfoCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to WriteInt32(userId)");
        return FAIL;
    }
    if (!data.WriteUint32(authType)) {
        IAM_LOGE("failed to WriteUint32(authType)");
        return FAIL;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return FAIL;
    }
    bool ret = SendRequest(USERIDM_GET_AUTH_INFO_BY_ID, data, reply, true);
    if (!ret) {
        IAM_LOGE("failed to send USERIDM_GET_AUTH_INFO_BY_ID request");
        std::vector<CredentialInfo> credInfos;
        callback->OnGetInfo(credInfos);
        return FAIL;
    }
    int32_t result = reply.ReadInt32();
    IAM_LOGI("result = %{public}d", result);
    return result;
}

int32_t UserIDMProxy::GetSecInfo(const int32_t userId, const sptr<IGetSecInfoCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to WriteInt32(userId)");
        return FAIL;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return FAIL;
    }
    bool ret = SendRequest(USERIDM_GET_SEC_INFO, data, reply, true);
    if (!ret) {
        IAM_LOGE("failed to send USERIDM_GET_SEC_INFO request");
        SecInfo secInfo = {};
        callback->OnGetSecInfo(secInfo);
        return FAIL;
    }
    int32_t result = reply.ReadInt32();
    IAM_LOGI("result = %{public}d", result);
    return result;
}

void UserIDMProxy::AddCredential(const AddCredInfo& credInfo, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }

    if (!data.WriteUint32(credInfo.authType)) {
        IAM_LOGE("failed to WriteUint32(credInfo.authType)");
        return;
    }

    if (!data.WriteUint64(credInfo.authSubType)) {
        IAM_LOGE("failed to WriteUint64(credInfo.authSubType)");
        return;
    }

    if (!data.WriteUInt8Vector(credInfo.token)) {
        IAM_LOGE("failed to WriteUInt8Vector(credInfo.token)");
        return;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return;
    }

    SendRequest(USERIDM_ADD_CREDENTIAL, data, reply, false);
}

void UserIDMProxy::AddCredential(const int32_t userId, const AddCredInfo& credInfo, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to WriteInt32(userId)");
        return;
    }
    if (!data.WriteUint32(credInfo.authType)) {
        IAM_LOGE("failed to WriteUint32(credInfo.authType)");
        return;
    }
    if (!data.WriteUint64(credInfo.authSubType)) {
        IAM_LOGE("failed to WriteUint64(credInfo.authSubType)");
        return;
    }
    if (!data.WriteUInt8Vector(credInfo.token)) {
        IAM_LOGE("failed to WriteUInt8Vector(credInfo.token)");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return;
    }
    bool ret = SendRequest(USERIDM_ADD_CREDENTIAL_BY_ID, data, reply, false);
    if (!ret) {
        IAM_LOGE("failed to send USERIDM_ADD_CREDENTIAL_BY_ID request");
        RequestResult para = {};
        callback->OnResult(FAIL, para);
    }
}

void UserIDMProxy::UpdateCredential(const AddCredInfo& credInfo, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }

    if (!data.WriteUint32(credInfo.authType)) {
        IAM_LOGE("failed to WriteUint32(credInfo.authType)");
        return;
    }

    if (!data.WriteUint64(credInfo.authSubType)) {
        IAM_LOGE("failed to WriteUint64(credInfo.authSubType)");
        return;
    }

    if (!data.WriteUInt8Vector(credInfo.token)) {
        IAM_LOGE("failed to WriteUInt8Vector(credInfo.token)");
        return;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return;
    }

    SendRequest(USERIDM_UPDATE_CREDENTIAL, data, reply, false);
}

void UserIDMProxy::UpdateCredential(const int32_t userId, const AddCredInfo& credInfo,
    const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to WriteInt32(userId)");
        return;
    }
    if (!data.WriteUint32(credInfo.authType)) {
        IAM_LOGE("failed to WriteUint32(credInfo.authType)");
        return;
    }
    if (!data.WriteUint64(credInfo.authSubType)) {
        IAM_LOGE("failed to WriteUint64(credInfo.authSubType)");
        return;
    }
    if (!data.WriteUInt8Vector(credInfo.token)) {
        IAM_LOGE("failed to WriteUInt8Vector(credInfo.token)");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return;
    }
    bool ret = SendRequest(USERIDM_UPDATE_CREDENTIAL_BY_ID, data, reply, false);
    if (!ret) {
        IAM_LOGE("failed to send USERIDM_UPDATE_CREDENTIAL_BY_ID request");
        RequestResult para = {};
        callback->OnResult(FAIL, para);
    }
}

int32_t UserIDMProxy::Cancel(const uint64_t challenge)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }

    if (!data.WriteUint64(challenge)) {
        IAM_LOGE("failed to WriteUint64(challenge)");
        return FAIL;
    }

    int32_t result = FAIL;
    bool ret = SendRequest(USERIDM_CANCEL, data, reply);
    if (ret) {
        result = reply.ReadInt32();
        IAM_LOGI("result = %{public}d", result);
    }
    return result;
}

int32_t UserIDMProxy::Cancel(const int32_t userId)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to WriteInt32(userId)");
        return FAIL;
    }
    int32_t result = FAIL;
    bool ret = SendRequest(USERIDM_CANCEL_BY_ID, data, reply);
    if (ret) {
        result = reply.ReadInt32();
        IAM_LOGI("result = %{public}d", result);
    }
    return result;
}

int32_t UserIDMProxy::EnforceDelUser(const int32_t userId, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to WriteUint32(userId)");
        return FAIL;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return FAIL;
    }
    int32_t result = FAIL;
    bool ret = SendRequest(USERIDM_ENFORCE_DELUSER, data, reply, false);
    if (!ret) {
        IAM_LOGE("failed to send USERIDM_ENFORCE_DELUSER request");
        RequestResult para = {};
        callback->OnResult(FAIL, para);
        return FAIL;
    }
    result = reply.ReadInt32();
    IAM_LOGI("result = %{public}d", result);
    return result;
}

void UserIDMProxy::DelUser(const std::vector<uint8_t> authToken, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }

    if (!data.WriteUInt8Vector(authToken)) {
        IAM_LOGE("failed to WriteUInt8Vector(authToken)");
        return;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return;
    }

    SendRequest(USERIDM_DELUSER, data, reply, false);
}

void UserIDMProxy::DelUser(const int32_t userId, std::vector<uint8_t> authToken, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to WriteUint32(userId)");
        return;
    }
    if (!data.WriteUInt8Vector(authToken)) {
        IAM_LOGE("failed to WriteUInt8Vector(authToken)");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return;
    }
    bool ret = SendRequest(USERIDM_DELUSER_BY_ID, data, reply, false);
    if (!ret) {
        IAM_LOGE("failed to send USERIDM_DELUSER_BY_ID request");
        RequestResult para = {};
        callback->OnResult(FAIL, para);
    }
}

void UserIDMProxy::DelCred(const uint64_t credentialId, const std::vector<uint8_t> authToken,
    const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }

    if (!data.WriteUint64(credentialId)) {
        IAM_LOGE("failed to WriteUint64(credentialId)");
        return;
    }

    if (!data.WriteUInt8Vector(authToken)) {
        IAM_LOGE("failed to WriteUInt8Vector(authToken)");
        return;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return;
    }

    SendRequest(USERIDM_DELCRED, data, reply, false);
}

void UserIDMProxy::DelCredential(const int32_t userId, const uint64_t credentialId,
    const std::vector<uint8_t> authToken, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to WriteUint32(userId)");
        return;
    }
    if (!data.WriteUint64(credentialId)) {
        IAM_LOGE("failed to WriteUint64(credentialId)");
        return;
    }
    if (!data.WriteUInt8Vector(authToken)) {
        IAM_LOGE("failed to WriteUInt8Vector(authToken)");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to WriteRemoteObject(callback)");
        return;
    }
    bool ret = SendRequest(USERIDM_DELCREDENTIAL, data, reply, false);
    if (!ret) {
        IAM_LOGE("failed to send USERIDM_DELCREDENTIAL request");
        RequestResult para = {};
        callback->OnResult(FAIL, para);
    }
}

bool UserIDMProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync)
{
    IAM_LOGD("SendRequest start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("failed to get remote");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    if (!isSync) {
        option.SetFlags(MessageOption::TF_ASYNC);
    }
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != SUCCESS) {
        IAM_LOGE("failed to SendRequest.result = %{public}d", result);
        return false;
    }
    return true;
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
