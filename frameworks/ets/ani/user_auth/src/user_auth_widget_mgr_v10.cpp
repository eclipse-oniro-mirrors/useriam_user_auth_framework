/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "user_auth_widget_mgr_v10.h"

#include <string>
#include <cstring>

#include "iam_logger.h"
#include "iam_ptr.h"
#include "user_auth_client_impl.h"
#include "user_auth_helper.h"

#define LOG_FILE_ID LOG_FILE_USER_AUTH_WIDGET_MGR_V10_ANI
#define LOG_TAG "USER_AUTH_ANI"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const std::string TYPE_COMMAND = "command";

UserAuthWidgetMgr::UserAuthWidgetMgr()
    : callback_(Common::MakeShared<UserAuthWidgetCallback>())
{
}

UserAuthResultCode UserAuthWidgetMgr::Init(int32_t version)
{
    IAM_LOGI("UserAuthWidgetMgr init");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    IAM_LOGI("UserAuthWidgetMgr version: %{public}d", version);

    if (version != WIDGET_NOTICE) {
        IAM_LOGE("version error: %{public}d", version);
        return UserAuthResultCode::TYPE_NOT_SUPPORT;
    }
    version_ = version;
    int32_t result = UserAuthClientImpl::Instance().SetWidgetCallback(version_, callback_);
    IAM_LOGI("version SetWidgetCallback result: %{public}d", result);
    return static_cast<UserAuthResultCode>(UserAuthHelper::GetResultCodeV10(result));
}

UserAuthResultCode UserAuthWidgetMgr::OnCommand(userAuth::IAuthWidgetCallback const &callback)
{
    IAM_LOGI("UserAuthWidgetMgr on");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    IAM_LOGI("SetCommandCallback");
    if (callback_->HasCommandCallback()) {
        IAM_LOGE("command callback has been registerred");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    callback_->SetCommandCallback(callback);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthWidgetMgr::OffCommand(taihe::optional_view<userAuth::IAuthWidgetCallback> callback)
{
    IAM_LOGI("UserAuthWidgetMgr off");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (!callback_->HasCommandCallback()) {
        IAM_LOGE("no command callback register yet");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    IAM_LOGI("ClearCommandCallback");
    callback_->ClearCommandCallback();
    return UserAuthResultCode::SUCCESS;
}
}  // namespace UserAuth
}  // namespace UserIam
}  // namespace OHOS
 
