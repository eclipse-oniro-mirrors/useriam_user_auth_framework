/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef USER_LAUNCH_SERVICE_CALLBACK_SERVICE_H
#define USER_LAUNCH_SERVICE_CALLBACK_SERVICE_H

#include "launch_service_callback_stub.h"
#include "launch_service_list_callback_stub.h"
#include "user_launch_service_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class LaunchServiceCallbackService : public LaunchServiceCallbackStub {
public:
    explicit LaunchServiceCallbackService(const std::shared_ptr<LaunchServiceCallback> &impl);
    ~LaunchServiceCallbackService() override;
    int32_t OnLaunchServiceResult(int32_t resultCode) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::shared_ptr<LaunchServiceCallback> operateCallback_ {nullptr};
};

class LaunchServiceListCallbackService : public LaunchServiceListCallbackStub {
public:
    explicit LaunchServiceListCallbackService(const std::shared_ptr<LaunchServiceListCallback> &impl);
    ~LaunchServiceListCallbackService() override;
    int32_t OnLaunchServiceListResult(int32_t resultCode,
        const std::vector<IpcLaunchServiceFlatInfo> &serviceList) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::shared_ptr<LaunchServiceListCallback> listCallback_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_LAUNCH_SERVICE_CALLBACK_SERVICE_H
