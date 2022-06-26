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

#include "query_callback_proxy.h"

#include <message_parcel.h>
#include <string_ex.h>

#include "iam_logger.h"

#define LOG_LABEL Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
void QueryCallbackProxy::OnResult(uint32_t resultCode)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(QueryCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteUint32(resultCode)) {
        IAM_LOGE("write resultCode failed");
        return;
    }
    MessageParcel reply;
    bool ret = SendRequest(static_cast<int32_t>(IQueryCallback::COAUTH_QUERY_RESULT), data, reply);
    if (ret) {
        IAM_LOGI("ret = %{public}d", ret);
    }
}

bool QueryCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
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
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS