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

#include "user_access_ctrl_napi_helper.h"
#include "user_auth_napi_helper.h"

#include "napi/native_api.h"

#include <cinttypes>

#include "iam_logger.h"

#define LOG_TAG "USER_ACCESS_CTRL_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_ACCESS_CTRL_NAPI_HELPER

namespace OHOS {
namespace UserIam {
namespace UserAccessCtrl {

napi_status UserAccessCtrlNapiHelper::SetUint64Property(napi_env env, napi_value obj, const char *name, uint64_t value)
{
    napi_value napiValue = nullptr;
    napi_status ret = napi_create_bigint_uint64(env, value, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_bigint_uint64 failed %{public}d", ret);
        return ret;
    }
    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

bool UserAccessCtrlNapiHelper::CheckAllowableDuration(uint64_t allowableDuration)
{
    if (allowableDuration <= 0 || allowableDuration > MAX_ALLOWABLE_VERIFY_AUTH_TOKEN_DURATION) {
        IAM_LOGE("allowableDuration check fail:%{public}" PRIu64, allowableDuration);
        return false;
    }
    return true;
}
} // namespace UserAccessCtrl
} // namespace UserIam
} // namespace OHOS
