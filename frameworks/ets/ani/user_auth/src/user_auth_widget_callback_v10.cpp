/*
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

#include "user_auth_widget_callback_v10.h"
#include "iam_ptr.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_ANI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_WIDGET_CALLBACK_V10_ANI

namespace OHOS {
namespace UserIam {
namespace UserAuth {

UserAuthWidgetCallback::UserAuthWidgetCallback()
{}

UserAuthWidgetCallback::~UserAuthWidgetCallback()
{}

void UserAuthWidgetCallback::SetCommandCallback(userAuth::IAuthWidgetCallback const &callback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    commandCallback_ = Common::MakeShared<userAuth::IAuthWidgetCallback>(callback);
}

void UserAuthWidgetCallback::ClearCommandCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    commandCallback_ = nullptr;
}

bool UserAuthWidgetCallback::HasCommandCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return commandCallback_ != nullptr;
}

void UserAuthWidgetCallback::SendCommand(const std::string &cmdData)
{
    IAM_LOGI("start");
    std::shared_ptr<userAuth::IAuthWidgetCallback> callback;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (commandCallback_ == nullptr) {
            IAM_LOGE("commandCallback_ is null");
            return;
        }
        callback = commandCallback_;
    }
    callback->sendCommand(cmdData);
}

}  // namespace UserAuth
}  // namespace UserIam
}  // namespace OHOS
 
