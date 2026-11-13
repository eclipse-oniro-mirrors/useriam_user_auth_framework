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

#ifndef MOCK_LAUNCH_SERVICE_CLIENT_CALLBACK_H
#define MOCK_LAUNCH_SERVICE_CLIENT_CALLBACK_H

#include <gmock/gmock.h>

#include "user_launch_service_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockLaunchServiceCallback final : public LaunchServiceCallback {
public:
    MOCK_METHOD1(OnResult, void(int32_t result));
};

class MockLaunchServiceListCallback final : public LaunchServiceListCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const std::vector<LaunchServiceFlatInfo> &serviceList));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_LAUNCH_SERVICE_CLIENT_CALLBACK_H
