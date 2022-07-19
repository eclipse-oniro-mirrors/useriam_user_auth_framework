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

#include "executor_mgr_wrapper.h"

#include "co_auth_client.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using namespace OHOS::UserIam::UserAuth;
void ExecutorMgrWrapper::Register(const ExecutorInfo &info, std::shared_ptr<ExecutorRegisterCallback> callback)
{
    UserAuth::CoAuthClient::GetInstance().Register(info, callback);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
