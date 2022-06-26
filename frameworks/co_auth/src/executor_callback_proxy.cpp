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

#include "executor_callback_proxy.h"
#include "coauth_hilog_wrapper.h"
#include "message_parcel.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
void ExecutorCallbackProxy::OnMessengerReady(const sptr<IExecutorMessenger> &messenger,
    std::vector<uint8_t> &frameworkPublicKey, std::vector<uint64_t> &templateIds)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "ExecutorCallbackProxy OnMessengerReady");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return;
    }

    if (messenger.GetRefPtr() == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "messenger.GetRefPtr() is nullptr");
        return;
    }
    if (!data.WriteRemoteObject(messenger.GetRefPtr()->AsObject())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write RemoteObject failed");
        return;
    }
    if (!data.WriteUInt8Vector(frameworkPublicKey)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write frameworkPublicKey failed");
        return;
    }
    if (!data.WriteUInt64Vector(templateIds)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write templateIds failed");
        return;
    }
    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_MESSENGER_READY), data, reply);
    COAUTH_HILOGD(MODULE_INNERKIT, "ret = %{public}d", ret);
}

int32_t ExecutorCallbackProxy::OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
    std::shared_ptr<UserIam::UserAuth::Attributes> commandAttrs)
{
    if (commandAttrs == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "commandAttrs is nullptr");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return FAIL;
    }

    if (!data.WriteUint64(scheduleId)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write scheduleId failed");
        return FAIL;
    }
    if (!data.WriteUInt8Vector(publicKey)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write publicKey failed");
        return FAIL;
    }
    std::vector<uint8_t> buffer = commandAttrs.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write buffer failed");
        return FAIL;
    }

    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_BEGIN_EXECUTE), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "send request failed");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "read result failed");
        return FAIL;
    }
    COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", result);
    return result;
}

int32_t ExecutorCallbackProxy::OnEndExecute(uint64_t scheduleId,
    std::shared_ptr<UserIam::UserAuth::Attributes> consumerAttr)
{
    if (consumerAttr == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "consumerAttr is null");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return FAIL;
    }

    if (!data.WriteUint64(scheduleId)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write scheduleId failed");
        return FAIL;
    }

    std::vector<uint8_t> buffer  = consumerAttr.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write buffer failed");
        return FAIL;
    }

    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_END_EXECUTE), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "send request failed");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "read result failed");
        return FAIL;
    }
    COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", result);
    return result;
}

int32_t ExecutorCallbackProxy::OnSetProperty(std::shared_ptr<UserIam::UserAuth::Attributes> properties)
{
    if (properties == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "properties is null");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return FAIL;
    }
    std::vector<uint8_t> buffer  =  properties.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write buffer failed");
        return FAIL;
    }
    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_SET_PROPERTY), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "send request failed");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "read result failed");
        return FAIL;
    }
    COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", result);
    return result;
}

int32_t ExecutorCallbackProxy::OnGetProperty(std::shared_ptr<UserIam::UserAuth::Attributes> conditions,
    std::shared_ptr<UserIam::UserAuth::Attributes> values)
{
    if (conditions == nullptr || values == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "param is null");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;
    if (values == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "values is null.");
        return FAIL;
    }

    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return FAIL;
    }

    std::vector<uint8_t> buffer =  conditions.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write buffer failed");
        return FAIL;
    }

    std::vector<uint8_t> valuesReply;
    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_GET_PROPERTY), data, reply); // must sync
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "send request failed");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "read result failed");
        return FAIL;
    }
    if (!reply.ReadUInt8Vector(&valuesReply)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "read valuesReply failed");
        return FAIL;
    } else {
        values->Unpack(valuesReply);
    }
    COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", result);
    return result;
}


bool ExecutorCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "get remote failed");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        COAUTH_HILOGE(MODULE_INNERKIT, "send request failed, result = %{public}d", result);
        return false;
    }
    return true;
}
}
}
}