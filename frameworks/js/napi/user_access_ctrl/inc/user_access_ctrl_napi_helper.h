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

#ifndef USER_ACCESS_CTRL_NAPI_HELPER_H
#define USER_ACCESS_CTRL_NAPI_HELPER_H

#include "user_access_ctrl_common.h"

namespace OHOS {
namespace UserIam {
namespace UserAccessCtrl {
class UserAccessCtrlNapiHelper {
public:
    static bool CheckAllowableDuration(uint64_t allowableDuration);
    static int32_t GetResultCodeV16(int32_t result);
    static napi_status SetUint64Property(napi_env env, napi_value obj, const char *name, uint64_t value);

private:
    UserAccessCtrlNapiHelper() = default;
    ~UserAccessCtrlNapiHelper() = default;
};
} // namespace UserAccessCtrl
} // namespace UserIam
} // namespace OHOS
#endif // USER_ACCESS_CTRL_NAPI_HELPER_H