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
#ifndef IAM_MOCK_USER_AUTH_CALLBACK_H
#define IAM_MOCK_USER_AUTH_CALLBACK_H

#include <gmock/gmock.h>
#include <iremote_stub.h>

#include "iiam_callback.h"
#include "iget_executor_property_callback.h"
#include "iset_executor_property_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserAuthCallback final : public IRemoteStub<IIamCallback> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD2(OnResult, int32_t(int32_t resultCode, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, int32_t(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};

class MockGetExecutorPropertyCallback final : public IRemoteStub<IGetExecutorPropertyCallback> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD2(OnGetExecutorPropertyResult, int32_t(int32_t resultCode, const std::vector<uint8_t> &attributes));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};

class MockSetExecutorPropertyCallback final : public IRemoteStub<ISetExecutorPropertyCallback> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD1(OnSetExecutorPropertyResult, int32_t(int32_t result));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_USER_AUTH_CALLBACK_H