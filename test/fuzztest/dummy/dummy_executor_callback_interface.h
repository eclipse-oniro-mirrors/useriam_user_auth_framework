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

#ifndef DUMMY_EXECUTOR_CALLBACK_INTERFACE_H
#define DUMMY_EXECUTOR_CALLBACK_INTERFACE_H

#include "executor_callback_interface.h"

#undef private

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyExecutorCallbackInterface : public ExecutorCallbackInterface {
public:
    void OnMessengerReady(uint64_t executorIndex, sptr<ExecutorMessengerInterface> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList){};
    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command)
        {
            return 0;
        };
    int32_t OnEndExecute(uint64_t scheduleId, const Attributes &command)
    {
        return 0;
    };
    int32_t OnSetProperty(const Attributes &properties)
    {
        return 0;
    };
    int32_t OnGetProperty(const Attributes &condition, Attributes &values)
    {
        return 0;
    };
    int32_t OnSendData(uint64_t scheduleId, const Attributes &data)
    {
        return 0;
    };
    sptr<IRemoteObject> AsObject()
    {
        return nullptr;
    };
};
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // DUMMY_EXECUTOR_CALLBACK_INTERFACE_H