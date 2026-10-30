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
#include "mock_ipc_client_utils.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
sptr<IRemoteObject> IpcClientUtils::obj_ {nullptr};

sptr<IRemoteObject> IpcClientUtils::GetRemoteObject(int32_t saId)
{
    return obj_;
}

void IpcClientUtils::SetObj(const sptr<IRemoteObject> &obj)
{
    obj_ = obj;
}

void IpcClientUtils::ResetObj()
{
    obj_ = nullptr;
}

int32_t IpcClientUtils::RunOnResidentSync(std::function<int32_t()> func, uint32_t timeoutSec)
{
    static_cast<void>(timeoutSec);
    if (func) {
        return func();
    }
    return 0;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS