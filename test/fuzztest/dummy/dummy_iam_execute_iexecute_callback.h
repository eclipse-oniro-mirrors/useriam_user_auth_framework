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

#ifndef DUMMY_IAM_EXECUTE_IEXECUTE_CALLBACK_H
#define DUMMY_IAM_EXECUTE_IEXECUTE_CALLBACK_H

#include "iam_executor_iexecute_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyExecuteCallback : public IExecuteCallback {
public:
    virtual ~DummyExecuteCallback() = default;

    void OnResult(ResultCode result, const std::vector<uint8_t> &extraInfo) override
    {};

    void OnResult(ResultCode result) override
    {};

    void OnAcquireInfo(int32_t acquire, const std::vector<uint8_t> &extraInfo) override
    {};

    void OnMessage(int destRole, const std::vector<uint8_t> &msg) override
    {};
};
}
} // UserAuth
} // UserIam
} // OHOS

#endif // DUMMY_IAM_EXECUTE_IEXECUTE_CALLBACK_H