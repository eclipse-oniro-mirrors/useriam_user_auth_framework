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

#ifndef USER_AUTH_FRAMEWORK_AUTH_STAGES_H
#define USER_AUTH_FRAMEWORK_AUTH_STAGES_H

#include <cstdint>

namespace OHOS {
namespace UserIam {
namespace UserAuth {

enum class StageId: uint32_t {
    S_CONTEXT_START = 1,
    S_BEGIN_SCHEDULE_START = 2,
    S_BEGIN_SCHEDULE_END = 3,
    S_UPDATE_SCHEDULE_RESULT_START = 4,
    S_UPDATE_SCHEDULE_RESULT_END = 5,
    S_CANCEL = 6,
    S_ON_RESULT = 7,

    // auth
    S_ON_TIP_AUTH_SUCC = 101,
};

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_AUTH_FRAMEWORK_AUTH_STAGES_H
