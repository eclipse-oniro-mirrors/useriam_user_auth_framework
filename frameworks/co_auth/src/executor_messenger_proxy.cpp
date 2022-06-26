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

#include "executor_messenger_proxy.h"

#include "iam_logger.h"
#include "message_parcel.h"

#define LOG_LABEL Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
int32_t ExecutorMessengerProxy::SendData(uint64_t scheduleId, uint64_t transNum,
    int32_t srcType, int32_t dstType, std::shared_ptr<AuthMessage> msg)
{
    if (msg == nullptr) {
        IAM_LOGE("msg is nullptr");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;
    int32_t result = 0;
    if (!data.WriteInterfaceToken(ExecutorMessengerProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }
    if (!data.WriteUint64(scheduleId)) {
        return FAIL;
    }
    if (!data.WriteUint64(transNum)) {
        return FAIL;
    }
    if (!data.WriteInt32(srcType)) {
        return FAIL;
    }
    if (!data.WriteInt32(dstType)) {
        return FAIL;
    }

    std::vector<uint8_t> buffer;
    msg->FromUint8Array(buffer);
    if (!data.WriteUInt8Vector(buffer)) {
        return FAIL;
    }
    bool ret = SendRequest(static_cast<int32_t>(IExecutorMessenger::COAUTH_SEND_DATA), data, reply);
    if (ret) {
        result = reply.ReadInt32();
        IAM_LOGI("result = %{public}d", result);
    }
    return result;
}


int32_t ExecutorMessengerProxy::Finish(uint64_t scheduleId, int32_t srcType, int32_t resultCode,
    std::shared_ptr<UserIam::UserAuth::Attributes> finalResult)
{
    if (finalResult == nullptr) {
        IAM_LOGE("finalResult is nullptr");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorMessengerProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }
    if (!data.WriteUint64(scheduleId)) {
        return FAIL;
    }
    if (!data.WriteInt32(srcType)) {
        return FAIL;
    }
    if (!data.WriteInt32(resultCode)) {
        return FAIL;
    }
    std::vector<uint8_t> buffer = finalResult->Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        return FAIL;
    }
    int32_t result = SUCCESS;
    bool ret = SendRequest(static_cast<int32_t>(IExecutorMessenger::COAUTH_FINISH), data, reply);
    if (ret) {
        result = reply.ReadInt32();
        IAM_LOGI("result = %{public}d", result);
    }
    return result;
}

bool ExecutorMessengerProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("get remote failed");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request failed, result = %{public}d", result);
        return false;
    }
    return true;
}
}
}
}