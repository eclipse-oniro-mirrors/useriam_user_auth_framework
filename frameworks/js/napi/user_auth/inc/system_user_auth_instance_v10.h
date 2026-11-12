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

#ifndef SYSTEM_USER_AUTH_INSTANCE_V10_H
#define SYSTEM_USER_AUTH_INSTANCE_V10_H

#include <mutex>

#include "nocopyable.h"

#include "auth_common.h"
#include "user_auth_callback_v10.h"
#include "user_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class SystemUserAuthInstanceNapi : public NoCopyable {
public:
    explicit SystemUserAuthInstanceNapi(napi_env env);
    ~SystemUserAuthInstanceNapi() override = default;
    UserAuthResultCode Init(napi_env env, napi_callback_info info);
    UserAuthResultCode OnResult(napi_env env, napi_callback_info info);
    UserAuthResultCode OffResult(napi_env env, napi_callback_info info);
    UserAuthResultCode OnAcquireInfo(napi_env env, napi_callback_info info);
    UserAuthResultCode OffAcquireInfo(napi_env env, napi_callback_info info);
    UserAuthResultCode Start(napi_env env, napi_callback_info info);
    UserAuthResultCode Cancel(napi_env env, napi_callback_info info);

private:
    UserAuthResultCode SetResultCallback(napi_env env, napi_value value);
    UserAuthResultCode SetAcquireInfoCallback(napi_env env, napi_value value);

    AuthParamInner authParam_ {};
    std::shared_ptr<UserAuthCallbackV10> callback_ {nullptr};
    std::mutex mutex_;
    uint64_t contextId_ {BAD_CONTEXT_ID};
    bool isStarted_ {false};
    bool isFinished_ {false};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // SYSTEM_USER_AUTH_INSTANCE_V10_H
