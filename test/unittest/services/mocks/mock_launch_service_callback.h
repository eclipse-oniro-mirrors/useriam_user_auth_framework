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
#ifndef IAM_MOCK_LAUNCH_SERVICE_CALLBACK_H
#define IAM_MOCK_LAUNCH_SERVICE_CALLBACK_H

#include <gmock/gmock.h>
#include <iremote_stub.h>

#include "ilaunch_service_callback.h"
#include "ilaunch_service_list_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockLaunchServiceCallback final : public IRemoteStub<ILaunchServiceCallback> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD1(OnLaunchServiceResult, int32_t(int32_t resultCode));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};

class MockLaunchServiceListCallback final : public IRemoteStub<ILaunchServiceListCallback> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD2(OnLaunchServiceListResult, int32_t(int32_t resultCode,
        const std::vector<IpcLaunchServiceFlatInfo> &serviceList));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_LAUNCH_SERVICE_CALLBACK_H
