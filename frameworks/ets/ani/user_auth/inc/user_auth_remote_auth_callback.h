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

#include "ability.h"
#include "nocopyable.h"
#include "ohos.userIAM.userAuth.userAuth.proj.hpp"

#include "auth_common.h"
#include "user_auth_napi_client_impl.h"
#include "set_widget_param_callback.h"
#include "user_auth_modal_inner_callback.h"
#include "user_auth_common_defines.h"

namespace userAuth = ohos::userIAM::userAuth::userAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteAuthCallback : public RemoteAuthClientCallback,
    public std::enable_shared_from_this<RemoteAuthCallback>, public NoCopyable {
public:
    RemoteAuthCallback(const userAuth::IRemoteAuthCallback &callback);
    ~RemoteAuthCallback();

    void OnGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge,
        const std::shared_ptr<SetWidgetParamClientCallback> &callback) override;
    void OnRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t resultCode,
        const Attributes &extraInfo) override;

private:
    bool DoGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge, userAuth::WidgetParam &widgetParam);
    bool DoRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t resultCode,
        const Attributes &extraInfo);

    std::shared_ptr<userAuth::IRemoteAuthCallback> callback_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_REMOTE_AUTH_CALLBACK_H