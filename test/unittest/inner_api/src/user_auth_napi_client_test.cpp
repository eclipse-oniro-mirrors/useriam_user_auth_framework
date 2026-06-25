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

#include "user_auth_napi_client_test.h"

#include "iam_ptr.h"
#include "modal_callback_service.h"
#include "user_auth_modal_inner_callback.h"
#include "user_auth_napi_client_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthNapiClientTest::SetUpTestCase()
{
}

void UserAuthNapiClientTest::TearDownTestCase()
{
}

void UserAuthNapiClientTest::SetUp()
{
}

void UserAuthNapiClientTest::TearDown()
{
}

HWTEST_F(UserAuthNapiClientTest, UserAuthNapiClientBeginWidgetAuth001, TestSize.Level0)
{
    static const int32_t apiVersion = 0;
    AuthParamInner authParam;
    WidgetParamNapi widgetParam;
    std::shared_ptr<MockAuthenticationCallback> testCallback = nullptr;
    testCallback = Common::MakeShared<MockAuthenticationCallback>();
    std::shared_ptr<UserAuthModalInnerCallback> testModalCallback = Common::MakeShared<UserAuthModalInnerCallback>();
    uint64_t widgetAuth = UserAuthNapiClientImpl::Instance().BeginWidgetAuth(apiVersion, authParam,
        widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(widgetAuth, 0);
}

HWTEST_F(UserAuthNapiClientTest, UserAuthNapiClientBeginWidgetAuth002, TestSize.Level0)
{
    int32_t testVersion = 0;
    AuthParamInner testParam = {};
    testParam.challenge = {0};
    testParam.authTypes = {ALL};
    WidgetParamInner testWidgetParamInner = {};
    testWidgetParamInner.title = "title";
    auto testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);

    uint64_t testContextId = 1;
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AuthWidget(_, _, _, _, _, _)).Times(1);
    ON_CALL(*service, AuthWidget)
        .WillByDefault(
            [&testVersion, &testParam, &testWidgetParamInner, &testContextId](int32_t apiVersion,
            const IpcAuthParamInner &authParam, const IpcWidgetParamInner &widgetParam,
            const sptr<IIamCallback> &callback, const sptr<IModalCallback> &modalCallback,
            uint64_t &contextId) {
                EXPECT_EQ(apiVersion, testVersion);
                EXPECT_EQ(authParam.authTypes[0], static_cast<int32_t>(testParam.authTypes[0]));
                EXPECT_EQ(widgetParam.title, testWidgetParamInner.title);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo.Serialize());
                }
                contextId = testContextId;
                return SUCCESS;
            }
        );

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    AuthParamInner testAuthParam = {};
    testAuthParam.challenge = {0};
    testAuthParam.authTypes = {ALL};
    WidgetParamNapi testWidgetParam = {};
    testWidgetParam.title = "title";
    std::shared_ptr<UserAuthModalInnerCallback> testModalCallback = Common::MakeShared<UserAuthModalInnerCallback>();
    uint64_t widgetAuth = UserAuthNapiClientImpl::Instance().BeginWidgetAuth(testVersion, testAuthParam,
        testWidgetParam, testCallback, testModalCallback);
    EXPECT_EQ(widgetAuth, testContextId);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthNapiClientTest, UserAuthNapiClientBeginWidgetAuth003, TestSize.Level0)
{
    static const int32_t apiVersion = 0;
    AuthParamInner authParam;
    authParam.userId = 101;
    WidgetParamNapi widgetParam;
    std::shared_ptr<MockAuthenticationCallback> testCallback = nullptr;
    testCallback = Common::MakeShared<MockAuthenticationCallback>();
    std::shared_ptr<UserAuthModalInnerCallback> testModalCallback = Common::MakeShared<UserAuthModalInnerCallback>();
    uint64_t widgetAuth = UserAuthNapiClientImpl::Instance().BeginWidgetAuth(apiVersion, authParam,
        widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(widgetAuth, 0);
}

HWTEST_F(UserAuthNapiClientTest, UserAuthNapiClientBeginWidgetAuth004, TestSize.Level0)
{
    int32_t testVersion = 0;
    AuthParamInner testParam = {};
    testParam.userId = 101;
    testParam.challenge = {0};
    testParam.authTypes = {ALL};
    WidgetParamInner testWidgetParamInner = {};
    testWidgetParamInner.title = "title";
    auto testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);

    uint64_t testContextId = 1;
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AuthWidget(_, _, _, _, _, _)).Times(1);
    ON_CALL(*service, AuthWidget)
        .WillByDefault(
            [&testVersion, &testParam, &testWidgetParamInner, &testContextId](int32_t apiVersion,
            const IpcAuthParamInner &authParam, const IpcWidgetParamInner &widgetParam,
            const sptr<IIamCallback> &callback, const sptr<IModalCallback> &modalCallback,
            uint64_t &contextId) {
                EXPECT_EQ(apiVersion, testVersion);
                EXPECT_EQ(authParam.authTypes[0], static_cast<int32_t>(testParam.authTypes[0]));
                EXPECT_EQ(widgetParam.title, testWidgetParamInner.title);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo.Serialize());
                }
                contextId = testContextId;
                return SUCCESS;
            }
        );

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    AuthParamInner testAuthParam = {};
    testAuthParam.challenge = {0};
    testAuthParam.authTypes = {ALL};
    WidgetParamNapi testWidgetParam = {};
    testWidgetParam.title = "title";
    std::shared_ptr<UserAuthModalInnerCallback> testModalCallback = Common::MakeShared<UserAuthModalInnerCallback>();
    uint64_t widgetAuth = UserAuthNapiClientImpl::Instance().BeginWidgetAuth(testVersion, testAuthParam,
        testWidgetParam, testCallback, testModalCallback);
    EXPECT_EQ(widgetAuth, testContextId);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

void UserAuthNapiClientTest::CallRemoteObject(const std::shared_ptr<MockUserAuthService> service,
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
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS