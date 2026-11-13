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

#ifndef MOCK_IPC_CLIENT_UTILS_H
#define MOCK_IPC_CLIENT_UTILS_H
#define IPC_CLIENT_UTILS_H  // Prevent real ipc_client_utils.h from redefining IpcClientUtils

#include "iremote_object.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IpcClientUtils {
public:
    static sptr<IRemoteObject> GetRemoteObject(int32_t saId);
    static void SetObj(const sptr<IRemoteObject> &obj);
    static void ResetObj();
    static int32_t RunOnResidentSync(std::function<int32_t()> func, uint32_t timeoutSec);

private:
    static sptr<IRemoteObject> obj_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_IPC_CLIENT_UTILS_H