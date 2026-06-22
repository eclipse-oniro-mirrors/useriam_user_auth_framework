/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "user_auth_event_listener_callback_stub.h"

#include <cinttypes>

#include "mock_user_auth_callback_service.h"
#include "iuser_auth.h"
#include "user_auth_interface_ipc_interface_code.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {

class AuthEventListenerStubTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void AuthEventListenerStubTest::SetUpTestCase()
{
}

void AuthEventListenerStubTest::TearDownTestCase()
{
}

void AuthEventListenerStubTest::SetUp()
{
}

void AuthEventListenerStubTest::TearDown()
{
}

HWTEST_F(AuthEventListenerStubTest, AuthEventListenerStubTest001, TestSize.Level0)
{
    int32_t testUserId = 3467;
    AuthType testAuthType = FACE;
    std::string callerName = "settings";
    int32_t callerType = 0;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_EVENT_LISTENER_NOTIFY;
    EXPECT_TRUE(data.WriteInterfaceToken(AuthEventListenerInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteString(callerName));
    EXPECT_TRUE(data.WriteInt32(callerType));

    MockAuthEventListenerService service;
    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS