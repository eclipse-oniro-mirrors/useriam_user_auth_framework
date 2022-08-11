/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FACERECOGNITION_AUTH_BUILD_H
#define FACERECOGNITION_AUTH_BUILD_H

#include <vector>
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "nocopyable.h"
#include "auth_common.h"
#include "result_convert.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthBuild {
public:
    DISALLOW_COPY_AND_MOVE(AuthBuild);
    AuthBuild();
    virtual ~AuthBuild();
    bool NapiTypeObject(napi_env env, napi_value value);
    bool NapiTypeNumber(napi_env env, napi_value value);

    std::vector<uint8_t> GetUint8Array(napi_env env, napi_value value);
    uint64_t GetUint8ArrayTo64(napi_env env, napi_value value);
    int32_t NapiGetValueInt32(napi_env env, napi_value value);
    napi_value Uint64ToUint8Array(napi_env env, uint64_t value);

private:
    ResultConvert convert_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // FACERECOGNITION_AUTH_BUILD_H
