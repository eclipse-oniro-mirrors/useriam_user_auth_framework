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

#ifndef USER_AUTH_REMOTE_AUTH_CALLBACK_H
#define USER_AUTH_REMOTE_AUTH_CALLBACK_H

#include <mutex>

#include "nocopyable.h"

#include "auth_common.h"
#include "user_auth_napi_helper.h"
#include "iam_common_defines.h"
#include "user_auth_common_defines.h"
#include "set_widget_param_callback.h"
#include "user_auth_modal_callback.h"
#include "user_auth_napi_client_impl.h"
#include "attributes.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteAuthCallback : public RemoteAuthClientCallback,
                           public std::enable_shared_from_this<RemoteAuthCallback>,
                           public NoCopyable {
public:
    RemoteAuthCallback(napi_env env, const std::shared_ptr<JsRefHolder> &widgetParamCallback,
        const std::shared_ptr<JsRefHolder> &resultCallback);
    ~RemoteAuthCallback() override;

    void OnGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge,
        const std::shared_ptr<SetWidgetParamClientCallback> &callback) override;
    void OnRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t result,
        const Attributes &extraInfo) override;

private:
    napi_status DoGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge, napi_value *result);
    napi_status DoRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t result,
        const std::vector<uint8_t> &token,
        int32_t authType, EnrolledState enrolledState);
    napi_status ConvertRemoteAuthWidgetParam(napi_env env, napi_value value,
        WidgetParamNapi &widgetParam, std::shared_ptr<UserAuthModalCallback> &modalCallback);

    std::shared_ptr<JsRefHolder> GetWidgetParamCallback();
    std::shared_ptr<JsRefHolder> GetResultCallback();
    void ClearWidgetParamCallback();
    void ClearResultCallback();

    napi_env env_ = nullptr;
    std::mutex mutex_;
    std::shared_ptr<JsRefHolder> widgetParamCallback_ = nullptr;
    std::shared_ptr<JsRefHolder> resultCallback_ = nullptr;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_REMOTE_AUTH_CALLBACK_H
