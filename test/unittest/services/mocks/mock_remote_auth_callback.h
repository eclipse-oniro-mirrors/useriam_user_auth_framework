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

#ifndef MOCK_REMOTE_AUTH_CALLBACK_H
#define MOCK_REMOTE_AUTH_CALLBACK_H

#include <gmock/gmock.h>

#include "remote_auth_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockRemoteAuthCallback : public RemoteAuthCallbackStub {
public:
    MOCK_METHOD2(OnGetRemoteAuthWidgetParam, ErrCode(const std::vector<uint8_t> &challenge,
        const sptr<ISetWidgetParamCallback> &setWidgetParamCallback));
    MOCK_METHOD3(OnRemoteAuthResult, ErrCode(const std::vector<uint8_t> &challenge,
        int32_t resultCode, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_REMOTE_AUTH_CALLBACK_H