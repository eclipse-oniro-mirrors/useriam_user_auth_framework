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

#include "user_idm_callback_proxy.h"

#include "iam_logger.h"
#include "result_code.h"
#include "user_idm.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void IdmCallbackProxy::OnAcquireInfo(int32_t module, int32_t acquire, const Attributes &reqRet)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(IdmCallbackProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    uint64_t credentialId = 0;
    if (!reqRet.GetUint64Value(Attributes::ATTR_CREDENTIAL_ID, credentialId)) {
        IAM_LOGE("failed to get credentialId");
    }
    if (!data.WriteInt32(module)) {
        IAM_LOGE("failed to write module");
        return;
    }
    if (!data.WriteInt32(acquire)) {
        IAM_LOGE("failed to write acquire");
        return;
    }
    if (!data.WriteUint64(credentialId)) {
        IAM_LOGE("failed to write credentialId");
        return;
    }

    bool ret = SendRequest(IDM_CALLBACK_ON_ACQUIRE_INFO, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
    }
}

void IdmCallbackProxy::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    uint64_t credentialId = 0;
    if (!extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_ID, credentialId)) {
        IAM_LOGE("failed to get credentialId");
    }
    if (!data.WriteInterfaceToken(IdmCallbackProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteInt32(result)) {
        IAM_LOGE("failed to write result");
        return;
    }
    if (!data.WriteUint64(credentialId)) {
        IAM_LOGE("failed to write credentialId");
        return;
    }

    bool ret = SendRequest(IDM_CALLBACK_ON_RESULT, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
    }
}

bool IdmCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("failed to get remote");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != SUCCESS) {
        IAM_LOGE("failed to send request, result = %{public}d", result);
        return false;
    }

    IAM_LOGI("end");
    return true;
}

void IdmGetCredentialInfoProxy::OnCredentialInfos(const std::vector<std::shared_ptr<CredentialInfo>> infoList,
    const std::optional<PinSubType> pinSubType)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(IdmGetCredentialInfoProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteUint32(infoList.size())) {
        IAM_LOGE("failed to write infoList.size()");
        return;
    }
    for (const auto &info : infoList) {
        if (info == nullptr) {
            return;
        }

        if (!data.WriteUint64(info->GetCredentialId())) {
            IAM_LOGE("failed to write credentialId");
            return;
        }
        if (!data.WriteUint32(info->GetAuthType())) {
            IAM_LOGE("failed to write authType)");
            return;
        }
        if (!data.WriteUint64(pinSubType.value_or(static_cast<PinSubType>(0)))) {
            IAM_LOGE("failed to write authSubType");
            return;
        }
        if (!data.WriteUint64(info->GetTemplateId())) {
            IAM_LOGE("failed to write templateId");
            return;
        }
    }

    bool ret = SendRequest(ON_GET_INFO, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
    }
}

bool IdmGetCredentialInfoProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("failed to get remote");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != SUCCESS) {
        IAM_LOGE("failed to send request result = %{public}d", result);
        return false;
    }

    IAM_LOGI("end");
    return true;
}

void IdmGetSecureUserInfoProxy::OnSecureUserInfo(const std::shared_ptr<SecureUserInfo> info)
{
    IAM_LOGI("start");

    if (info == nullptr) {
        IAM_LOGE("info is nullptr");
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(IdmGetSecureUserInfoProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteUint64(info->GetSecUserId())) {
        IAM_LOGE("failed to write secureUid");
        return;
    }

    if (!data.WriteUint32(info->GetEnrolledInfo().size())) {
        IAM_LOGE("failed to write enrolledInfoLen");
        return;
    }

    bool ret = SendRequest(ON_GET_SEC_INFO, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
    }
}

bool IdmGetSecureUserInfoProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("failed to get remote");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != SUCCESS) {
        IAM_LOGE("failed to send request result = %{public}d", result);
        return false;
    }

    IAM_LOGI("end");
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
