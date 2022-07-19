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

#ifndef IEXECUTE_CALLBACK_H
#define IEXECUTE_CALLBACK_H

#include <cstdint>
#include <vector>

#include "iam_common_defines.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class IExecuteCallback {
public:
    using ResultCode = UserIam::UserAuth::ResultCode;
    IExecuteCallback() = default;
    virtual ~IExecuteCallback() = default;

    virtual void OnResult(ResultCode result, const std::vector<uint8_t> &extraInfo) = 0;
    virtual void OnResult(ResultCode result) = 0;
    virtual void OnAcquireInfo(int32_t acquire, const std::vector<uint8_t> &extraInfo) = 0;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS

#endif // EXECUTE_CALLBACK_H