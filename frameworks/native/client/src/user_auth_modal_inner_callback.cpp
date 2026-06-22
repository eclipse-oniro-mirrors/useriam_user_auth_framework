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

#include "user_auth_modal_inner_callback.h"

#include "iam_logger.h"

#include "user_auth_napi_client_impl.h"

#define LOG_TAG "USER_AUTH_SDK"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_MODAL_INNER_CALLBACK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
UserAuthModalInnerCallback::UserAuthModalInnerCallback()
{}

UserAuthModalInnerCallback::~UserAuthModalInnerCallback()
{}

void UserAuthModalInnerCallback::SendCommand(uint64_t contextId, const std::string &cmdData)
{
    IAM_LOGI("SendCommand start");
    CancelAuthentication(contextId, CancelReason::MODAL_CREATE_ERROR);
    IAM_LOGI("invalid request");
}

bool UserAuthModalInnerCallback::IsModalInit()
{
    IAM_LOGD("get is modal init");
    return false;
}

bool UserAuthModalInnerCallback::IsModalDestroy()
{
    IAM_LOGD("get is modal on destroy");
    return false;
}

void UserAuthModalInnerCallback::CancelAuthentication(uint64_t contextId, int32_t cancelReason)
{
    // cancel for failed
    int32_t code = UserAuthNapiClientImpl::Instance().CancelAuthentication(contextId, cancelReason);
    IAM_LOGI("CancelAuthentication, code: %{public}d, contextId: ****%{public}hx", code,
        static_cast<uint16_t>(contextId));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS