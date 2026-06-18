/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "context_death_recipient.h"

#include <sstream>

#include "context_pool.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_FILE_ID LOG_FILE_CONTEXT_DEATH_RECIPIENT
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
void ContextDeathRecipientManager::AddDeathRecipient(std::shared_ptr<ContextCallback> &callback, uint64_t contextId)
{
    IAM_LOGD("start");
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);

    const sptr<IIamCallback> iamCallback = callback->GetIamCallback();
    if (iamCallback == nullptr) {
        IAM_LOGE("callback_ is nullptr");
        return;
    }
    auto obj = iamCallback->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return;
    }

    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) ContextDeathRecipient(contextId));
    if ((dr == nullptr) || (!obj->AddDeathRecipient(dr))) {
        IAM_LOGE("AddDeathRecipient failed");
        return;
    }

    deathRecipient_ = dr;
    IAM_LOGD("AddDeathRecipient success, contextId:****%{public}hx", static_cast<uint16_t>(contextId));
    return;
}

void ContextDeathRecipientManager::RemoveDeathRecipient(std::shared_ptr<ContextCallback> &callback)
{
    IAM_LOGD("start");
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);

    if (deathRecipient_ == nullptr) {
        IAM_LOGE("deathRecipient_ is nullptr");
        return;
    }

    const sptr<IIamCallback> iamCallback = callback->GetIamCallback();
    if (iamCallback == nullptr) {
        IAM_LOGE("callback_ is nullptr");
        return;
    }

    auto obj = iamCallback->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return;
    }

    obj->RemoveDeathRecipient(deathRecipient_);
    deathRecipient_ = nullptr;
    IAM_LOGD("RemoveDeathRecipient success");
    return;
}

ContextDeathRecipient::ContextDeathRecipient(uint64_t contextId)
    : contextId_(contextId)
{
    IAM_LOGD("start");
}

void ContextDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start, contextId: ****%{public}hx", static_cast<uint16_t>(contextId_));
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }

    auto context = ContextPool::Instance().Select(contextId_).lock();
    if (context == nullptr) {
        IAM_LOGE("context is nullptr");
        return;
    }

    if (!context->Stop()) {
        IAM_LOGE("failed to cancel enroll or auth");
        return;
    }
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
