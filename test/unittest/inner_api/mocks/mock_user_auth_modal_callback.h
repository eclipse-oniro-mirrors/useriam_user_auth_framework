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

#ifndef MOCK_USER_AUTH_MODAL_CALLBACK_H
#define MOCK_USER_AUTH_MODAL_CALLBACK_H

#include <gmock/gmock.h>

#include "user_auth_modal_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserAuthModalCallback final : public UserAuthModalClientCallback {
public:
    MockUserAuthModalCallback() = default;
    virtual ~MockUserAuthModalCallback() = default;
    MOCK_METHOD2(SendCommand, void(uint64_t contextId, const std::string &cmdData));
    MOCK_METHOD0(IsModalInit, bool());
    MOCK_METHOD0(IsModalDestroy, bool());

private:
    MOCK_METHOD2(CancelAuthentication, void(uint64_t contextId, int32_t cancelReason));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_USER_AUTH_MODAL_CALLBACK_H