/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_INSTANCE_V10_H
#define USER_AUTH_INSTANCE_V10_H

#include <mutex>

#include "window.h"
#include "nocopyable.h"

#include "ability.h"

#include "napi/native_api.h"
#include "auth_common.h"
#include "auth_instance_v9.h"
#include "user_auth_callback_v10.h"
#include "user_auth_modal_callback.h"
#include "user_auth_napi_client_impl.h"
#include "user_auth_api_event_reporter.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthInstanceV10 : public NoCopyable {
public:
    explicit UserAuthInstanceV10(napi_env env);
    ~UserAuthInstanceV10() override = default;

    UserAuthResultCode Init(napi_env env, napi_callback_info info);
    UserAuthResultCode On(napi_env env, napi_callback_info info);
    UserAuthResultCode Off(napi_env env, napi_callback_info info);
    UserAuthResultCode Start(napi_env env, napi_callback_info info);
    UserAuthResultCode Cancel(napi_env env, napi_callback_info info);

private:
    std::shared_ptr<JsRefHolder> GetCallback(napi_env env, napi_value value, const char *propertyName);
    UserAuthResultCode SetResultCallback(napi_env env, napi_value value);
    UserAuthResultCode SetTipCallback(napi_env env, napi_value value);
    UserAuthResultCode ClearResultCallback(napi_env env, size_t argc, napi_value *value);
    UserAuthResultCode ClearTipCallback(napi_env env, size_t argc, napi_value *value);

    AuthParamInner authParam_ = {};
    WidgetParamNapi widgetParam_ = {};

    uint64_t contextId_ = 0;
    bool isAuthStarted_ = false;
    std::mutex mutex_;
    std::shared_ptr<UserAuthCallbackV10> callback_ = nullptr;
    std::shared_ptr<UserAuthModalCallback> modalCallback_ = nullptr;
    std::shared_ptr<AbilityRuntime::Context> context_ = nullptr;
    sptr<OHOS::Rosen::Window> window_ = nullptr;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_INSTANCE_V10_H
