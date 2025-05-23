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

#ifndef MOCK_IUSER_AUTH_WIDGET_CALLBACK_H
#define MOCK_IUSER_AUTH_WIDGET_CALLBACK_H

#include <gmock/gmock.h>

#include "iuser_auth_widget_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockIUserAuthWidgetCallback final : public IUserAuthWidgetCallback {
public:
    MOCK_METHOD1(SendCommand, void(const std::string &cmdData));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_USER_AUTH_CLIENT_CALLBACK_H