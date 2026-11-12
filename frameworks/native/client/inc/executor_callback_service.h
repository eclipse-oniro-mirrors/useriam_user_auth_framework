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

#ifndef EXECUTOR_CALLBACK_SERVICE_H
#define EXECUTOR_CALLBACK_SERVICE_H

#include "executor_callback_stub.h"

#include "co_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorCallbackService : public ExecutorCallbackStub {
public:
    explicit ExecutorCallbackService(const std::shared_ptr<ExecutorRegisterCallback> &impl);
    ~ExecutorCallbackService() override = default;
    int32_t OnMessengerReady(const sptr<IExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList) override;
    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const std::vector<uint8_t> &command) override;
    int32_t OnEndExecute(uint64_t scheduleId, const std::vector<uint8_t> &command) override;
    int32_t OnSetProperty(const std::vector<uint8_t> &properties, std::vector<uint8_t> &values) override;
    int32_t OnGetProperty(const std::vector<uint8_t> &condition, std::vector<uint8_t> &values) override;
    int32_t OnSendData(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
private:
    std::shared_ptr<ExecutorRegisterCallback> callback_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // EXECUTOR_CALLBACK_SERVICE_H