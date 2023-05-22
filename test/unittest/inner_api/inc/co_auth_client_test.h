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

#ifndef CO_AUTH_CLIENT_TEST_H
#define CO_AUTH_CLIENT_TEST_H

#include <gtest/gtest.h>
#include "mock_co_auth_service.h"
#include "mock_executor_register_callback.h"
#include "mock_remote_object.h"
#include "mock_ipc_client_utils.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CoAuthClientTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;

    void CallRemoteObject(const std::shared_ptr<MockCoAuthService> service, const sptr<MockRemoteObject> &obj,
        sptr<IRemoteObject::DeathRecipient> &dr, uint64_t testExecutorIndex);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_CLIENT_TEST_H