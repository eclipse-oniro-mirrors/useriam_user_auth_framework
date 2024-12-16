/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_USER_ACCESS_CTRL_CLIENT_CALLBACK_H
#define MOCK_USER_ACCESS_CTRL_CLIENT_CALLBACK_H

#include <gmock/gmock.h>

#include "user_access_ctrl_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockVerifyTokenCallback final : public VerifyTokenCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const Attributes &extraInfo));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_USER_ACCESS_CTRL_CLIENT_CALLBACK_H