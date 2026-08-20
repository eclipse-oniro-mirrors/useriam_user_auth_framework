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

#include "callback_death_recipient.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "thread_handler.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_CALLBACK_DEATH_RECIPIENT

namespace OHOS {
namespace UserIam {
namespace UserAuth {

sptr<CallbackDeathRecipient> CallbackDeathRecipient::Register(const sptr<IRemoteObject> &remoteObj,
    DeathCallback &&callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(remoteObj != nullptr, nullptr);
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);

    sptr<CallbackDeathRecipient> recipient(new (std::nothrow) CallbackDeathRecipient(std::move(callback)));
    IF_FALSE_LOGE_AND_RETURN_VAL(recipient != nullptr, nullptr);

    if (!remoteObj->AddDeathRecipient(recipient)) {
        IAM_LOGE("AddDeathRecipient failed");
        return nullptr;
    }
    return recipient;
}

CallbackDeathRecipient::CallbackDeathRecipient(DeathCallback &&callback) : callback_(std::move(callback))
{
}

void CallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    (void)remote;
    IAM_LOGI("remote object died, posting cleanup to resident thread");
    DeathCallback callback = callback_;
    if (callback == nullptr) {
        return;
    }
    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);

    handler->PostTask([cb = std::move(callback)]() mutable {
        if (cb != nullptr) {
            cb();
        }
    });
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
