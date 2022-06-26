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

#include "user_auth.h"

#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>

#include "iam_logger.h"
#include "system_ability_definition.h"
#include "user_auth_native.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
void UserAuth::GetProperty(const int32_t userId, const GetPropertyRequest &request,
    std::shared_ptr<GetPropCallback> callback)
{
    IAM_LOGD("GetProperty start");
    if (callback == nullptr) {
        IAM_LOGE("GetProperty callback is nullptr");
        return;
    }
    IAM_LOGI("GetProperty start with userid: %{public}d", userId);
    UserAuthNative::GetInstance().GetProperty(userId, request, callback);
}

void UserAuth::SetProperty(const int32_t userId, const SetPropertyRequest &request,
    std::shared_ptr<SetPropCallback> callback)
{
    static_cast<void>(userId);
    IAM_LOGD("SetProperty start");
    if (callback == nullptr) {
        IAM_LOGE("SetProperty callback is nullptr");
        return;
    }
    IAM_LOGI("SetProperty start with userid: %{public}d", userId);
    UserAuthNative::GetInstance().SetProperty(request, callback);
}

uint64_t UserAuth::AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
    const AuthTrustLevel authTrustLevel, std::shared_ptr<UserAuthCallback> callback)
{
    IAM_LOGD("AuthUser start with userid: %{public}d", userId);
    if (callback == nullptr) {
        IAM_LOGE("AuthUser callback is nullptr");
        return INVALID_PARAMETERS;
    }
    return UserAuthNative::GetInstance().AuthUser(userId, challenge, authType, authTrustLevel, callback);
}

int32_t UserAuth::CancelAuth(const uint64_t contextId)
{
    IAM_LOGD("CancelAuth start");
    return UserAuthNative::GetInstance().CancelAuth(contextId);
}

uint64_t UserAuth::Identify(const uint64_t challenge, const AuthType authType,
    std::shared_ptr<UserIdentifyCallback> callback)
{
    IAM_LOGD("Identify start");
    if (callback == nullptr) {
        IAM_LOGE("Identify callback is nullptr");
        return INVALID_PARAMETERS;
    }
    return UserAuthNative::GetInstance().Identify(challenge, authType, callback);
}

int32_t UserAuth::CancelIdentify(const uint64_t contextId)
{
    IAM_LOGD("CancelIdentify start");
    return UserAuthNative::GetInstance().CancelIdentify(contextId);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
