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

#include "user_recognition_callback_service_test.h"

#include "iam_ptr.h"
#include "user_auth_client_callback.h"
#include "user_recognition_callback_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

// Local mock for the client-side UserRecognitionEventListener callback. The sibling
// event_listener_callback_service_test uses MockAuthSuccessEventListener from
// mocks/mock_user_auth_client_callback.h, but that header does not yet ship a recognition
// variant; rather than editing shared mock headers (out of scope for this change) we
// define the mock inline, matching the pattern of MockAuthSuccessEventListener.
class MockUserRecognitionEventListener final : public UserRecognitionEventListener {
public:
    MOCK_METHOD(void, OnUserRecognitionEvent, (const UserRecognitionResult &result));
};

static constexpr int32_t TEST_USER_ID = 1234;

void UserRecognitionCallbackServiceTest::SetUpTestCase()
{
}

void UserRecognitionCallbackServiceTest::TearDownTestCase()
{
}

void UserRecognitionCallbackServiceTest::SetUp()
{
}

void UserRecognitionCallbackServiceTest::TearDown()
{
}

// AddListener rejects a null listener; OnUserRecognitionEvent on a service with no
// listeners is a harmless no-op returning SUCCESS (defensive guards).
HWTEST_F(UserRecognitionCallbackServiceTest, AddListenerRejectsNullAndEmptyServiceNoOps, TestSize.Level0)
{
    auto service = Common::MakeShared<UserRecognitionCallbackService>();
    ASSERT_NE(service, nullptr);
    std::shared_ptr<UserRecognitionEventListener> nullListener = nullptr;
    service->AddListener(nullListener);
    EXPECT_TRUE(service->Empty());
    IpcUserRecognitionResult ipc {};
    ipc.status = static_cast<int32_t>(UserRecognitionStatus::MATCH);
    EXPECT_EQ(service->OnUserRecognitionEvent(ipc), SUCCESS);
}

// OnUserRecognitionEvent deserializes (reads) an IpcUserRecognitionResult and forwards all
// fields to the user listener: status / userId / userInfo / hasAuthTrustLevel / authTrustLevel.
HWTEST_F(UserRecognitionCallbackServiceTest, OnUserRecognitionEventForwardsAllFields, TestSize.Level0)
{
    auto listener = Common::MakeShared<MockUserRecognitionEventListener>();
    ASSERT_NE(listener, nullptr);
    auto service = Common::MakeShared<UserRecognitionCallbackService>();
    ASSERT_NE(service, nullptr);
    service->AddListener(listener);

    IpcUserRecognitionResult ipc {};
    ipc.status = static_cast<int32_t>(UserRecognitionStatus::MATCH);
    ipc.userId = TEST_USER_ID;
    ipc.userInfo = "matched-user-info";
    ipc.hasAuthTrustLevel = true;
    ipc.authTrustLevel = static_cast<uint32_t>(AuthTrustLevel::ATL3);

    EXPECT_CALL(*listener, OnUserRecognitionEvent(_))
        .WillOnce([](const UserRecognitionResult &r) {
            EXPECT_EQ(UserRecognitionStatus::MATCH, r.status);
            EXPECT_EQ(TEST_USER_ID, r.userId);
            EXPECT_EQ("matched-user-info", r.userInfo);
            ASSERT_TRUE(r.authTrustLevel.has_value());
            EXPECT_EQ(static_cast<uint32_t>(AuthTrustLevel::ATL3), *r.authTrustLevel);
        });
    EXPECT_EQ(service->OnUserRecognitionEvent(ipc), SUCCESS);
}

// Status range validation (the clamp fix): a status below UNCERTAIN is clamped to UNCERTAIN
// before forwarding so the JS layer never sees an undefined enumerator.
HWTEST_F(UserRecognitionCallbackServiceTest, OnUserRecognitionEventClampStatusBelowRange, TestSize.Level0)
{
    auto listener = Common::MakeShared<MockUserRecognitionEventListener>();
    ASSERT_NE(listener, nullptr);
    auto service = Common::MakeShared<UserRecognitionCallbackService>();
    ASSERT_NE(service, nullptr);
    service->AddListener(listener);

    IpcUserRecognitionResult ipc {};
    ipc.status = static_cast<int32_t>(UserRecognitionStatus::UNCERTAIN) - 1; // below range
    ipc.userId = 1;
    EXPECT_CALL(*listener, OnUserRecognitionEvent(_))
        .WillOnce([](const UserRecognitionResult &r) {
            EXPECT_EQ(UserRecognitionStatus::UNCERTAIN, r.status);
        });
    EXPECT_EQ(service->OnUserRecognitionEvent(ipc), SUCCESS);
}

// Status range validation (the clamp fix): a status above MATCH is clamped to UNCERTAIN.
HWTEST_F(UserRecognitionCallbackServiceTest, OnUserRecognitionEventClampStatusAboveRange, TestSize.Level0)
{
    auto listener = Common::MakeShared<MockUserRecognitionEventListener>();
    ASSERT_NE(listener, nullptr);
    auto service = Common::MakeShared<UserRecognitionCallbackService>();
    ASSERT_NE(service, nullptr);
    service->AddListener(listener);

    IpcUserRecognitionResult ipc {};
    ipc.status = static_cast<int32_t>(UserRecognitionStatus::MATCH) + 1; // above range
    ipc.userId = 2;
    EXPECT_CALL(*listener, OnUserRecognitionEvent(_))
        .WillOnce([](const UserRecognitionResult &r) {
            EXPECT_EQ(UserRecognitionStatus::UNCERTAIN, r.status);
        });
    EXPECT_EQ(service->OnUserRecognitionEvent(ipc), SUCCESS);
}

// MarkInactive: events that race with Unregister are dropped (not forwarded) and surface SUCCESS.
HWTEST_F(UserRecognitionCallbackServiceTest, OnUserRecognitionEventInactiveDropsEvent, TestSize.Level0)
{
    auto listener = Common::MakeShared<MockUserRecognitionEventListener>();
    ASSERT_NE(listener, nullptr);
    auto service = Common::MakeShared<UserRecognitionCallbackService>();
    ASSERT_NE(service, nullptr);
    service->AddListener(listener);

    service->MarkInactive();
    IpcUserRecognitionResult ipc {};
    ipc.status = static_cast<int32_t>(UserRecognitionStatus::MATCH);
    EXPECT_CALL(*listener, OnUserRecognitionEvent(_)).Times(0);
    EXPECT_EQ(service->OnUserRecognitionEvent(ipc), SUCCESS);
}

// 1-to-N fan-out: every registered listener receives the event, and RemoveListener drops
// only the targeted one while the rest keep receiving.
HWTEST_F(UserRecognitionCallbackServiceTest, OnUserRecognitionEventFansOutToAllListeners, TestSize.Level0)
{
    auto listenerA = Common::MakeShared<MockUserRecognitionEventListener>();
    auto listenerB = Common::MakeShared<MockUserRecognitionEventListener>();
    ASSERT_NE(listenerA, nullptr);
    ASSERT_NE(listenerB, nullptr);
    auto service = Common::MakeShared<UserRecognitionCallbackService>();
    ASSERT_NE(service, nullptr);
    service->AddListener(listenerA);
    service->AddListener(listenerB);
    EXPECT_FALSE(service->Empty());

    IpcUserRecognitionResult ipc {};
    ipc.status = static_cast<int32_t>(UserRecognitionStatus::MATCH);
    EXPECT_CALL(*listenerA, OnUserRecognitionEvent(_)).Times(1);
    EXPECT_CALL(*listenerB, OnUserRecognitionEvent(_)).Times(1);
    EXPECT_EQ(service->OnUserRecognitionEvent(ipc), SUCCESS);

    service->RemoveListener(listenerA);
    EXPECT_FALSE(service->Empty());
    EXPECT_CALL(*listenerA, OnUserRecognitionEvent(_)).Times(0);
    EXPECT_CALL(*listenerB, OnUserRecognitionEvent(_)).Times(1);
    EXPECT_EQ(service->OnUserRecognitionEvent(ipc), SUCCESS);
}

// CallbackEnter / CallbackExit stub hooks always succeed (no behaviour beyond logging).
HWTEST_F(UserRecognitionCallbackServiceTest, CallbackEnterExitSuccess, TestSize.Level0)
{
    auto listener = Common::MakeShared<MockUserRecognitionEventListener>();
    ASSERT_NE(listener, nullptr);
    auto service = Common::MakeShared<UserRecognitionCallbackService>();
    ASSERT_NE(service, nullptr);
    service->AddListener(listener);
    EXPECT_EQ(service->CallbackEnter(0), SUCCESS);
    EXPECT_EQ(service->CallbackExit(0, SUCCESS), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
