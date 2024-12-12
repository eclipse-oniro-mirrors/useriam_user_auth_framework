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

#ifndef USER_ACCESS_CTRL_CALLBACK_V16_H
#define USER_ACCESS_CTRL_CALLBACK_V16_H

#include "nocopyable.h"

#include "user_access_ctrl_client.h"
#include "user_access_ctrl_napi_helper.h"
#include "user_auth_napi_helper.h"

namespace OHOS {
namespace UserIam {
namespace UserAccessCtrl {
class UserAccessCtrlCallbackV16 : public UserAuth::VerifyTokenCallback,
                                  public std::enable_shared_from_this<UserAccessCtrlCallbackV16>,
                                  public NoCopyable {
public:
    UserAccessCtrlCallbackV16(napi_env env, napi_deferred promise);
    ~UserAccessCtrlCallbackV16() override;
    void OnResult(int32_t result, const UserAuth::Attributes &extraInfo) override;

    napi_status DoResultPromise(int32_t result, AuthToken authToken);
    napi_status ProcessAuthTokenResult(napi_env env, napi_value value, AuthToken authToken);

private:
    napi_env env_ = nullptr;
    napi_deferred promise_ = nullptr;
};
} // namespace UserAccessCtrl
} // namespace UserIam
} // namespace OHOS
#endif // USER_ACCESS_CTRL_CALLBACK_V16_H