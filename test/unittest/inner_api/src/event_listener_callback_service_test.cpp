/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "event_listener_callback_service_test.h"

#include "event_listener_callback_service.h"

#include "callback_manager.h"
#include "iam_check.h"
#include "iam_ptr.h"
#include "user_auth_client_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void EventListenerCallbackServiceTest::SetUpTestCase()
{
}

void EventListenerCallbackServiceTest::TearDownTestCase()
{
}

void EventListenerCallbackServiceTest::SetUp()
{
}

void EventListenerCallbackServiceTest::TearDown()
{
}

HWTEST_F(EventListenerCallbackServiceTest, RegisterListenerTest, TestSize.Level0)
{
    std::vector<AuthType> authTypes = {AuthType::PIN};
    auto ret = EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().RegisterListener(
        authTypes, nullptr);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    ret = EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().UnRegisterListener(nullptr);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    auto tmpListener = Common::MakeShared<MockAuthSuccessEventListener>();
    ret = EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().RegisterListener(
        authTypes, tmpListener);
    EXPECT_EQ(ret, GENERAL_ERROR);
    ret = EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().UnRegisterListener(tmpListener);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().GetEventListenerSet(AuthType::PIN);
}

HWTEST_F(EventListenerCallbackServiceTest, OnNotifyAuthSuccessEventSuccess, TestSize.Level0)
{
    auto service = EventListenerCallbackService::GetInstance();
    ASSERT_NE(service, nullptr);

    IpcAuthSuccessEventInfo eventInfo = {
        .callerName = "testCaller",
        .callerType = 1,
        .isWidgetAuth = false
    };

    auto ret = service->OnNotifyAuthSuccessEvent(1001, AuthType::PIN, eventInfo);
    EXPECT_EQ(ret, SUCCESS);

    ret = service->OnNotifyAuthSuccessEvent(1002, AuthType::FACE, eventInfo);
    EXPECT_EQ(ret, SUCCESS);

    ret = service->OnNotifyAuthSuccessEvent(1003, AuthType::FINGERPRINT, eventInfo);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(EventListenerCallbackServiceTest, OnNotifyAuthSuccessEventWithListenerSuccess, TestSize.Level0)
{
    auto mockService = Common::MakeShared<MockUserAuthService>();
    ASSERT_NE(mockService, nullptr);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    ASSERT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);

    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&mockService](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            mockService->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });

    ON_CALL(*mockService, RegistUserAuthSuccessEventListener)
        .WillByDefault([](const sptr<IEventListenerCallback> &listener) {
            return SUCCESS;
        });

    auto listener = Common::MakeShared<MockAuthSuccessEventListener>();
    ASSERT_NE(listener, nullptr);
    EXPECT_CALL(*listener, OnNotifyAuthSuccessEvent(_, _, _)).Times(1);

    std::vector<AuthType> authTypes = {AuthType::PIN};
    auto regRet = UserAuthClientImpl::Instance().RegistUserAuthSuccessEventListener(authTypes, listener);
    EXPECT_EQ(regRet, SUCCESS);

    auto service = EventListenerCallbackService::GetInstance();
    ASSERT_NE(service, nullptr);
    IpcAuthSuccessEventInfo eventInfo = {
        .callerName = "testCaller",
        .callerType = 1,
        .isWidgetAuth = false
    };
    auto ret = service->OnNotifyAuthSuccessEvent(1001, AuthType::PIN, eventInfo);
    EXPECT_EQ(ret, SUCCESS);
    auto unregRet = UserAuthClientImpl::Instance().UnRegistUserAuthSuccessEventListener(listener);
    EXPECT_EQ(unregRet, SUCCESS);
    IpcClientUtils::ResetObj();
}

HWTEST_F(EventListenerCallbackServiceTest, OnNotifyAuthSuccessEventMultiListenersSuccess, TestSize.Level0)
{
    auto mockService = Common::MakeShared<MockUserAuthService>();
    ASSERT_NE(mockService, nullptr);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    ASSERT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);

    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&mockService](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            mockService->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });

    ON_CALL(*mockService, RegistUserAuthSuccessEventListener)
        .WillByDefault([](const sptr<IEventListenerCallback> &listener) {
            return SUCCESS;
        });

    auto listener1 = Common::MakeShared<MockAuthSuccessEventListener>();
    auto listener2 = Common::MakeShared<MockAuthSuccessEventListener>();
    ASSERT_NE(listener1, nullptr);
    ASSERT_NE(listener2, nullptr);

    EXPECT_CALL(*listener1, OnNotifyAuthSuccessEvent(_, _, _)).Times(1);
    EXPECT_CALL(*listener2, OnNotifyAuthSuccessEvent(_, _, _)).Times(1);

    std::vector<AuthType> authTypes = {AuthType::FACE};
    auto regRet1 = UserAuthClientImpl::Instance().RegistUserAuthSuccessEventListener(authTypes, listener1);
    EXPECT_EQ(regRet1, SUCCESS);

    auto regRet2 = UserAuthClientImpl::Instance().RegistUserAuthSuccessEventListener(authTypes, listener2);
    EXPECT_EQ(regRet2, SUCCESS);
    auto service = EventListenerCallbackService::GetInstance();
    ASSERT_NE(service, nullptr);
    IpcAuthSuccessEventInfo eventInfo = {
        .callerName = "multiTestCaller",
        .callerType = 2,
        .isWidgetAuth = true
    };
    auto ret = service->OnNotifyAuthSuccessEvent(1002, AuthType::FACE, eventInfo);
    EXPECT_EQ(ret, SUCCESS);
    auto unregRet1 = UserAuthClientImpl::Instance().UnRegistUserAuthSuccessEventListener(listener1);
    EXPECT_EQ(unregRet1, SUCCESS);
    auto unregRet2 = UserAuthClientImpl::Instance().UnRegistUserAuthSuccessEventListener(listener2);
    EXPECT_EQ(unregRet2, SUCCESS);
    IpcClientUtils::ResetObj();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS