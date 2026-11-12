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

#ifndef USER_ACCESS_CTRL_INSTANCE_V16_H
#define USER_ACCESS_CTRL_INSTANCE_V16_H

#include "nocopyable.h"

#include "iam_ptr.h"

#include "user_access_ctrl_common.h"
#include "user_access_ctrl_callback_v16.h"

namespace OHOS {
namespace UserIam {
namespace UserAccessCtrl {
class UserAccessCtrlInstanceV16 : public NoCopyable {
public:
    explicit  UserAccessCtrlInstanceV16(napi_env env);
    ~UserAccessCtrlInstanceV16() override = default;

    static napi_value VerifyAuthToken(napi_env env, napi_callback_info info);
    static napi_value RedeemScheduledAuthToken(napi_env env, napi_callback_info info);
};
} // namespace UserAccessCtrl
} // namespace UserIam
} // namespace OHOS
#endif // USER_ACCESS_CTRL_INSTANCE_V16_H