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

#include "iexecutor_callback.h"

#undef private

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyExecutorCallbackInterface : public IExecutorCallback {
public:
    int32_t OnMessengerReady(const sptr<IExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList)
        {
            return 0;
        };
    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const std::vector<uint8_t> &command)
        {
            return 0;
        };
    int32_t OnEndExecute(uint64_t scheduleId, const std::vector<uint8_t> &command)
    {
        return 0;
    };
    int32_t OnSetProperty(const std::vector<uint8_t> &properties, std::vector<uint8_t> &values)
    {
        return 0;
    };
    int32_t OnGetProperty(const std::vector<uint8_t> &condition, std::vector<uint8_t> &values)
    {
        return 0;
    };
    int32_t OnSendData(uint64_t scheduleId, const std::vector<uint8_t> &data)
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