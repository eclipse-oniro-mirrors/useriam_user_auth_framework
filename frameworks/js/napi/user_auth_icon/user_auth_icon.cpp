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

#include "native_engine/native_engine.h"
 
#include "napi/native_api.h"
#include "napi/native_node_api.h"
 
extern const char _binary_user_auth_icon_abc_start[];
extern const char _binary_user_auth_icon_abc_end[];
 
// Napi get abc code function
extern "C" __attribute__((visibility("default"))) void NAPI_userIAM_userAuthIcon_GetABCCode(
    const char **buf, int *buflen)
    {
        if (buf != nullptr) {
            *buf = _binary_user_auth_icon_abc_start;
        }
        if (buflen != nullptr) {
            *buflen = _binary_user_auth_icon_abc_end - _binary_user_auth_icon_abc_start;
        }
    }
 
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_modname = "userIAM.userAuthIcon",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};
 
extern "C" __attribute__((constructor)) void UserAuthIconRegisterModule(void)
{
    napi_module_register(&g_module);
}