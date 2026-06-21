/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef IAM_MOCK_WIDGET_SCHEDULE_NODE_H
#define IAM_MOCK_WIDGET_SCHEDULE_NODE_H

#include <gmock/gmock.h>

#include "widget_schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockWidgetScheduleNode final : public WidgetScheduleNode {
public:
    MOCK_METHOD0(StartSchedule, bool());
    MOCK_METHOD0(StartDirectAuth, bool());
    MOCK_METHOD0(StopSchedule, bool());
    MOCK_METHOD3(StartAuthList, bool(const std::vector<AuthType> &authTypeList, bool endAfterFirstFail,
        AuthIntent authIntent));
    MOCK_METHOD1(StopAuthList, bool(const std::vector<AuthType> &));
    MOCK_METHOD1(SuccessAuth, bool(AuthType));
    MOCK_METHOD1(FailAuth, bool(AuthType));
    MOCK_METHOD0(NaviPinAuth, bool());
    MOCK_METHOD0(WidgetParaInvalid, bool());
    MOCK_METHOD1(SetCallback, void(std::shared_ptr<WidgetScheduleNodeCallback>));
    MOCK_METHOD4(WidgetReload, bool(uint32_t orientation, uint32_t needRotate, uint32_t alreadyLoad,
        AuthType &rotateAuthType));
    MOCK_METHOD2(SendAuthTipInfo, void(const std::vector<AuthType> &authTypeList, int32_t tipCode));
    MOCK_METHOD0(ClearSchedule, bool());
    MOCK_METHOD0(GetRemoteAuthParam, bool());
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_WIDGET_SCHEDULE_NODE_H