/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_CLIENT_TEST_H
#define USER_AUTH_CLIENT_TEST_H

#include <gtest/gtest.h>
#include "mock_ipc_client_utils.h"
#include "mock_remote_object.h"
#include "mock_user_auth_callback_service.h"
#include "mock_user_auth_service.h"
#include "mock_user_auth_client_callback.h"
#include "mock_iuser_auth_widget_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthClientTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;

    void CallRemoteObject(const std::shared_ptr<MockUserAuthService> service, const sptr<MockRemoteObject> &obj,
        sptr<IRemoteObject::DeathRecipient> &dr, uint32_t sendRequestTimes = 1);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CLIENT_TEST_H