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

#include "iam_logger.h"

#include "nlohmann/json.hpp"

#include "user_access_ctrl_instance_v16.h"

#define LOG_FILE_ID LOG_FILE_USER_ACCESS_CTRL_ENTRY
#define LOG_TAG "USER_ACCESS_CTRL_NAPI"

namespace OHOS {
namespace UserIam {
namespace UserAccessCtrl {
namespace {

napi_value VerifyAuthToken(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    return UserAccessCtrlInstanceV16::VerifyAuthToken(env, info);
}

napi_value AuthTokenTypeConstructor(napi_env env)
{
    napi_value authTokenType = nullptr;
    napi_value tokenTypeLocalAuth = nullptr;
    napi_value tokenTypeLocalResign = nullptr;
    napi_value tokenTypeLocalCoauth = nullptr;
    NAPI_CALL(env, napi_create_object(env, &authTokenType));
    NAPI_CALL(env, napi_create_int32(env, AuthTokenType::TOKEN_TYPE_LOCAL_AUTH, &tokenTypeLocalAuth));
    NAPI_CALL(env, napi_create_int32(env, AuthTokenType::TOKEN_TYPE_LOCAL_RESIGN, &tokenTypeLocalResign));
    NAPI_CALL(env, napi_create_int32(env, AuthTokenType::TOKEN_TYPE_LOCAL_COAUTH, &tokenTypeLocalCoauth));
    NAPI_CALL(env, napi_set_named_property(env, authTokenType, "TOKEN_TYPE_LOCAL_AUTH", tokenTypeLocalAuth));
    NAPI_CALL(env, napi_set_named_property(env, authTokenType, "TOKEN_TYPE_LOCAL_RESIGN", tokenTypeLocalResign));
    NAPI_CALL(env, napi_set_named_property(env, authTokenType, "TOKEN_TYPE_LOCAL_COAUTH", tokenTypeLocalCoauth));
    return authTokenType;
}

napi_value UserAccessCtrlInit(napi_env env, napi_value exports)
{
    IAM_LOGI("start");
    napi_status status;
    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_FUNCTION("verifyAuthToken", UserAccessCtrl::VerifyAuthToken),
    };
    status = napi_define_properties(env, exports,
        sizeof(exportFuncs) / sizeof(napi_property_descriptor), exportFuncs);
    if (status != napi_ok) {
        IAM_LOGE("napi_define_properties failed");
        NAPI_CALL(env, status);
    }
    return exports;
}

napi_value EnumExport(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("AuthTokenType", AuthTokenTypeConstructor(env)),
    };
    NAPI_CALL(env, napi_define_properties(env, exports,
        sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors));
    return exports;
}

napi_value ModuleInit(napi_env env, napi_value exports)
{
    napi_value val = UserAccessCtrlInit(env, exports);
    return EnumExport(env, val);
}
} // namespace

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module module = {
        .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = ModuleInit,
        .nm_modname = "userIAM.userAccessCtrl",
        .nm_priv = nullptr,
        .reserved = {}
    };
    napi_module_register(&module);
}
} // namespace UserAccessCtrl
} // namespace UserIam
} // namespace OHOS
