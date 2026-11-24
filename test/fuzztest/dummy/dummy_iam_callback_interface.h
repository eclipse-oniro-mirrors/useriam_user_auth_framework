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

#ifndef DUMMY_IAM_CALLBACK_INTERFACE_H
#define DUMMY_IAM_CALLBACK_INTERFACE_H

#include "iiam_callback.h"


namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyIamCallbackInterface : public IIamCallback {
    int32_t OnResult(int32_t result, const std::vector<uint8_t> &extraInfo) override
    {
        return 0;
    };
    int32_t OnAcquireInfo(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo) override
    {
        return 0;
    };
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};
}
} // UserAuth
} // UserIam
} // OHOS

#endif // DUMMY_IAM_CALLBACK_INTERFACE_H