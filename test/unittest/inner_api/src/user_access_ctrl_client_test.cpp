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

#include "user_access_ctrl_client_test.h"

#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "user_access_ctrl_client.h"
#include "user_access_ctrl_client_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAccessCtrlClientTest::SetUpTestCase()
{
}

void UserAccessCtrlClientTest::TearDownTestCase()
{
}

void UserAccessCtrlClientTest::SetUp()
{
}

void UserAccessCtrlClientTest::TearDown()
{
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAccessCtrlClientTest, UserAccessCtrlClientVerifyAuthToken001, TestSize.Level0)
{
    std::vector<uint8_t> tokenIn;
    uint64_t allowableDuration = 0;
    std::shared_ptr<MockVerifyTokenCallback> testCallback = Common::MakeShared<MockVerifyTokenCallback>();
    EXPECT_NE(testCallback, nullptr);
    UserAccessCtrlClientImpl::Instance().VerifyAuthToken(tokenIn, allowableDuration, testCallback);
}

HWTEST_F(UserAccessCtrlClientTest, UserAccessCtrlClientVerifyAuthToken002, TestSize.Level0)
{
    std::vector<uint8_t> testTokenIn;
    uint64_t testAllowableDuration = 0;
    auto testCallback = Common::MakeShared<MockVerifyTokenCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, VerifyAuthToken(_, _, _)).Times(Exactly(1));
    ON_CALL(*service, VerifyAuthToken)
        .WillByDefault(
            [&testTokenIn, &testAllowableDuration, &testCallback]
            (const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
                const sptr<IVerifyTokenCallback> &callback) {
                EXPECT_EQ(testTokenIn, tokenIn);
                EXPECT_EQ(testAllowableDuration, allowableDuration);
                return SUCCESS;
            }
        );

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserAccessCtrlClientImpl::Instance().VerifyAuthToken(testTokenIn, testAllowableDuration, testCallback);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAccessCtrlClientTest, UserAccessCtrlClientVerifyAuthToken003, TestSize.Level0)
{
    std::vector<uint8_t> tokenIn;
    uint64_t allowableDuration = 0;
    auto testCallback = Common::MakeShared<MockVerifyTokenCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcClientUtils::ResetObj();
    UserAccessCtrlClientImpl::Instance().VerifyAuthToken(tokenIn, allowableDuration, testCallback);
}

void UserAccessCtrlClientTest::CallRemoteObject(const std::shared_ptr<MockUserAuthService> service,
    const sptr<MockRemoteObject> &obj, sptr<IRemoteObject::DeathRecipient> &dr)
{
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillRepeatedly([&dr](const sptr<IRemoteObject::DeathRecipient> &recipient) {
            dr = recipient;
            return true;
        });

    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS