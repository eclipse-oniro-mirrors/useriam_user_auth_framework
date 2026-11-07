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

#ifndef MOCK_USER_AUTH_CLIENT_CALLBACK_H
#define MOCK_USER_AUTH_CLIENT_CALLBACK_H

#include <gmock/gmock.h>

#include "user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockAuthenticationCallback final : public AuthenticationCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const Attributes &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, void(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo));
};

class MockIdentificationCallback final : public IdentificationCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const Attributes &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, void(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo));
};

class MockGetPropCallback final : public GetPropCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const Attributes &extraInfo));
};

class MockSetPropCallback final : public SetPropCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const Attributes &extraInfo));
};

class MockAuthSuccessEventListener final : public AuthSuccessEventListener {
public:
    MOCK_METHOD3(OnNotifyAuthSuccessEvent, void(int32_t userId, AuthType authType,
        const AuthSuccessEventInfo &eventInfo));
};

class MockPrepareRemoteAuthCallback final : public PrepareRemoteAuthCallback {
public:
    MOCK_METHOD1(OnResult, void(int32_t result));
};

class MockUserRecognitionEventListener final : public UserRecognitionEventListener {
public:
    MOCK_METHOD1(OnUserRecognitionEvent, void(const UserRecognitionResult &result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_USER_AUTH_CLIENT_CALLBACK_H