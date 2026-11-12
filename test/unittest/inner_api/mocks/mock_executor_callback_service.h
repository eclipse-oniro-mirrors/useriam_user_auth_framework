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

#ifndef MOCK_EXECUTOR_CALLBACK_SERVICE_H
#define MOCK_EXECUTOR_CALLBACK_SERVICE_H

#include <gmock/gmock.h>

#include "executor_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockExecutorCallbackService final : public ExecutorCallbackStub {
public:
    MOCK_METHOD3(OnMessengerReady, int32_t(const sptr<IExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList));
    MOCK_METHOD3(OnBeginExecute, int32_t(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command));
    MOCK_METHOD2(OnEndExecute, int32_t(uint64_t scheduleId, const std::vector<uint8_t> &command));
    MOCK_METHOD2(OnSetProperty, int32_t(const std::vector<uint8_t> &properties, std::vector<uint8_t> &values));
    MOCK_METHOD2(OnGetProperty, int32_t(const std::vector<uint8_t> &condition, std::vector<uint8_t> &values));
    MOCK_METHOD2(OnSendData, int32_t(uint64_t scheduleId, const std::vector<uint8_t> &data));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_EXECUTOR_CALLBACK_SERVICE_H
