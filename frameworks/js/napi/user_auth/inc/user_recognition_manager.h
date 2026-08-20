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

#ifndef USER_RECOGNITION_MANAGER_NAPI_H
#define USER_RECOGNITION_MANAGER_NAPI_H

#include <memory>
#include <mutex>
#include <vector>

#include "napi/native_api.h"
#include "auth_common.h"
#include "user_auth_client.h"
#include "user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserRecognitionManagerNapi {
public:
    UserRecognitionManagerNapi() = default;
    ~UserRecognitionManagerNapi();

    static napi_value Constructor(napi_env env, napi_callback_info info);
    static napi_value JsClass(napi_env env);
    static napi_value GetInstance(napi_env env, napi_callback_info info);
    static napi_value GetUserRecognitionResult(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);

    class CallbackImpl;

private:
    using CallbackList = std::vector<std::shared_ptr<CallbackImpl>>;
    static UserAuthResultCode OnInternal(napi_env env, napi_callback_info info);
    static UserAuthResultCode OffInternal(napi_env env, napi_callback_info info);
    CallbackList::iterator FindCallback(napi_env env, napi_value fn);
    UserAuthResultCode RegisterCallback(napi_env env, napi_value fn);
    CallbackList callbacks_;
    std::mutex mutex_;
};

napi_value UserRecognitionStatusConstructor(napi_env env);
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_RECOGNITION_MANAGER_NAPI_H
