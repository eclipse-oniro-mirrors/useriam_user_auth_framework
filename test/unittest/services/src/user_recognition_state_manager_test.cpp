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

#include "user_recognition_state_manager_test.h"
#include "callback_death_recipient.h"
#include "user_recognition_state_manager.h"
#include "user_recognition_state_manager_impl.h"

#include <atomic>
#include <chrono>
#include <thread>

#include "accesstoken_kit.h"
#include "gtest/gtest.h"
#include "iam_common_defines.h"
#include "mock_remote_object.h"
#include "user_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

// Local mock of the IUserRecognitionCallback IPC interface. The sibling
// event_listener_manager_test pulls MockEventListener from mocks/mock_event_listener.h,
// but no mock exists yet for IUserRecognitionCallback; rather than editing shared mock
// headers (out of scope for this change) we define the mock inline here, matching the
// pattern in mocks/mock_event_listener.h.
class MockUserRecognitionCallback final : public IUserRecognitionCallback {
public:
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, ());
    MOCK_METHOD(int32_t, OnUserRecognitionEvent, (const IpcUserRecognitionResult &result));
};

static constexpr int32_t TEST_USER_ID_ALICE = 1001;
static constexpr int32_t TEST_USER_ID_BOB = 1002;
static constexpr int32_t TEST_USER_ID_CAROL = 1003;
static constexpr int32_t DISPATCH_POLL_MAX_ATTEMPTS = 200;
static constexpr int32_t DISPATCH_POLL_INTERVAL_MS = 10;
static constexpr int32_t ON_REMOTE_DIED_POLL_MAX_ATTEMPTS = 50;

void UserRecognitionStateManagerTest::SetUpTestCase()
{
}

void UserRecognitionStateManagerTest::TearDownTestCase()
{
}

void UserRecognitionStateManagerTest::SetUp()
{
    // Hand each test a pristine manager so listeners/cache from earlier tests cannot leak in.
    // The manager is a process-lifetime singleton: RegisterListenerSuccess and
    // TwoListenersKeyedIndependently register a listener and never unregister it, so their mocks
    // stay in listenerMap_. A later SetUserRecognitionResult then fans out to those leftover
    // mocks on the resident thread, where gmock has no live expectation for the call and aborts
    // (SIGABRT in UntypedFunctionMockerBase::FailureCleanupHandler). A fresh instance per test
    // removes the leftover listeners entirely; each case then behaves like the isolated run.
    SetUserRecognitionStateManager(CreateUserRecognitionStateManager());
}

void UserRecognitionStateManagerTest::TearDown()
{
    // Restore the auto singleton so other suites in this binary see default behaviour.
    SetUserRecognitionStateManager(nullptr);
}

static void WaitUntilDispatched(std::atomic<int> &fired, int expected)
{
    for (int i = 0; i < DISPATCH_POLL_MAX_ATTEMPTS && fired.load() < expected; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(DISPATCH_POLL_INTERVAL_MS));
    }
}

// Registers a listener backed by a proxy-style MockRemoteObject (IsProxyObject = true,
// AddDeathRecipient = true). Leaves the listener registered so follow-up tests can observe fan-out
// behaviour; the singleton survives for the test binary lifetime.
static sptr<MockUserRecognitionCallback> RegisterProxyListener(sptr<MockRemoteObject> obj,
    int32_t callerType = Security::AccessToken::TOKEN_NATIVE)
{
    auto cb = new (std::nothrow) MockUserRecognitionCallback();
    EXPECT_NE(cb, nullptr);
    EXPECT_CALL(*cb, AsObject()).WillRepeatedly(Return(obj));
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_)).WillRepeatedly(Return(true));
    std::atomic<int> syncFired {0};
    EXPECT_CALL(*cb, OnUserRecognitionEvent(_))
        .WillOnce([&syncFired](const IpcUserRecognitionResult &) {
            syncFired.fetch_add(1);
            return SUCCESS;
        })
        .RetiresOnSaturation();
    EXPECT_EQ(GetUserRecognitionStateManager().RegisterListener(callerType, cb), SUCCESS);
    WaitUntilDispatched(syncFired, 1);
    EXPECT_EQ(syncFired.load(), 1);
    return cb;
}

// Builds a MATCH result with ATL and an optional auth token.
static IpcUserRecognitionResult MakeMatchResult(int32_t userId, std::vector<uint8_t> token)
{
    IpcUserRecognitionResult result {};
    result.status = static_cast<int32_t>(UserRecognitionStatus::MATCH);
    result.userId = userId;
    result.userInfo = "token-info";
    result.hasAuthTrustLevel = true;
    result.authTrustLevel = AuthTrustLevel::ATL3;
    result.authToken = std::move(token);
    return result;
}

// RegisterListener: nullptr listener is rejected with GENERAL_ERROR (mirrors the sibling test).
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerRegisterListenerNullptr, TestSize.Level0)
{
    EXPECT_EQ(GetUserRecognitionStateManager().RegisterListener(Security::AccessToken::TOKEN_NATIVE,
        nullptr), GENERAL_ERROR);
}

// RegisterListener: a proxy object is accepted and wired with a death recipient. A duplicate
// RegisterListener of the same AsObject() short-circuits to SUCCESS (the manager's
// "already registered" early-return path) — verified by the first RegisterListener succeeding
// and the second one returning SUCCESS without disturbing the existing entry.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerRegisterListenerSuccess, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj, nullptr);
    auto cb = RegisterProxyListener(obj);
    EXPECT_EQ(GetUserRecognitionStateManager().RegisterListener(Security::AccessToken::TOKEN_NATIVE, cb),
        SUCCESS);
}

// RegisterListener: a same-process stub (IsProxyObject = false) is accepted WITHOUT wiring
// a death recipient — mirrors the same-process branch of the sibling EventListenerManager.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerRegisterListenerSameProcess, TestSize.Level0)
{
    auto cb = new (std::nothrow) MockUserRecognitionCallback();
    ASSERT_NE(cb, nullptr);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*cb, AsObject()).WillRepeatedly(Return(obj));
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(false));
    EXPECT_CALL(*obj, AddDeathRecipient(_)).Times(0);
    std::atomic<int> syncFired {0};
    EXPECT_CALL(*cb, OnUserRecognitionEvent(_))
        .WillOnce([&syncFired](const IpcUserRecognitionResult &) {
            syncFired.fetch_add(1);
            return SUCCESS;
        })
        .RetiresOnSaturation();
    EXPECT_EQ(GetUserRecognitionStateManager().RegisterListener(Security::AccessToken::TOKEN_NATIVE, cb),
        SUCCESS);
    WaitUntilDispatched(syncFired, 1);
    EXPECT_EQ(syncFired.load(), 1);
}

// UnregisterListener: nullptr is rejected, removing an unknown listener is a no-op SUCCESS.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerUnregisterListener, TestSize.Level0)
{
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(nullptr), GENERAL_ERROR);

    auto cb = new (std::nothrow) MockUserRecognitionCallback();
    ASSERT_NE(cb, nullptr);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*cb, AsObject()).WillRepeatedly(Return(obj));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(cb), SUCCESS);
}

// Two distinct listener stubs (distinct AsObject()) are keyed independently; removing one
// leaves the other in the map.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerTwoListenersKeyedIndependently, TestSize.Level0)
{
    sptr<MockRemoteObject> obj1(new (std::nothrow) MockRemoteObject);
    sptr<MockRemoteObject> obj2(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj1, nullptr);
    ASSERT_NE(obj2, nullptr);
    auto cb1 = RegisterProxyListener(obj1);
    auto cb2 = RegisterProxyListener(obj2);

    // Remove cb1; cb2 must remain (verify via RemoveDeathRecipient — should fire for obj1
    // exactly once and not at all for obj2).
    EXPECT_CALL(*obj1, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_CALL(*obj2, RemoveDeathRecipient(_)).Times(0);
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(cb1), SUCCESS);
}

HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerCacheInitiallyEmpty, TestSize.Level0)
{
    EXPECT_NO_THROW([] {
        IpcUserRecognitionResult out = GetUserRecognitionStateManager().GetCachedUserRecognitionResult();
        (void)out;
    }());
}

// SetUserRecognitionResult: a MATCH carrying authTrustLevel is cached with hasAuthTrustLevel=true
// and fanned out to registered listeners with the ATL preserved. A subsequent identical push
// is a no-op (fire-on-change dedup via IsSameRecognitionResult) — the listener fires ONCE.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerMatchResultDedup, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj, nullptr);
    auto cb = RegisterProxyListener(obj);

    IpcUserRecognitionResult eng {};
    eng.status = static_cast<int32_t>(UserRecognitionStatus::MATCH);
    eng.userId = TEST_USER_ID_ALICE;
    eng.userInfo = "match-info";
    eng.hasAuthTrustLevel = true;
    eng.authTrustLevel = AuthTrustLevel::ATL3;

    // Dedup contract: an identical second push must NOT fire the listener again. Express this
    // as a single Times(1) expectation across both pushes — if dedup breaks and the listener
    // fires twice, gmock's cardinality check fails at teardown.
    std::atomic<int> fired {0};
    EXPECT_CALL(*cb, OnUserRecognitionEvent(_))
        .Times(1)
        .WillOnce([&fired](const IpcUserRecognitionResult &r) {
            EXPECT_EQ(static_cast<int32_t>(UserRecognitionStatus::MATCH), r.status);
            EXPECT_EQ(TEST_USER_ID_ALICE, r.userId);
            EXPECT_EQ("match-info", r.userInfo);
            EXPECT_TRUE(r.hasAuthTrustLevel);
            EXPECT_EQ(static_cast<uint32_t>(AuthTrustLevel::ATL3), r.authTrustLevel);
            fired.fetch_add(1);
            return SUCCESS;
        });
    GetUserRecognitionStateManager().SetUserRecognitionResult(eng);
    GetUserRecognitionStateManager().SetUserRecognitionResult(eng);
    // Fan-out is posted to the resident thread; wait for the single dispatch (dedup drops the 2nd)
    // before the mock is torn down.
    WaitUntilDispatched(fired, 1);
    EXPECT_EQ(fired.load(), 1);

    // Cache reflects the latest MATCH result with ATL.
    IpcUserRecognitionResult cached = GetUserRecognitionStateManager().GetCachedUserRecognitionResult();
    EXPECT_EQ(static_cast<int32_t>(UserRecognitionStatus::MATCH), cached.status);
    EXPECT_TRUE(cached.hasAuthTrustLevel);
    EXPECT_EQ(static_cast<uint32_t>(AuthTrustLevel::ATL3), cached.authTrustLevel);

    // Cleanup.
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(cb), SUCCESS);
}

// Producer gate: a status change MATCH -> MISMATCH fires the listener for the new status,
// and the MISMATCH result drops authTrustLevel (hasAuthTrustLevel=false) even if the engine
// had populated it — the MATCH-gate fix in SetUserRecognitionResult.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerMatchToMismatchDropsAtl, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj, nullptr);
    auto cb = RegisterProxyListener(obj);

    IpcUserRecognitionResult match {};
    match.status = static_cast<int32_t>(UserRecognitionStatus::MATCH);
    match.userId = TEST_USER_ID_BOB;
    match.userInfo = "match-info-2";
    match.hasAuthTrustLevel = true;
    match.authTrustLevel = AuthTrustLevel::ATL2;

    IpcUserRecognitionResult mismatch {};
    mismatch.status = static_cast<int32_t>(UserRecognitionStatus::MISMATCH);
    mismatch.userId = TEST_USER_ID_BOB;
    mismatch.userInfo = "mismatch-info";
    // Engine erroneously attaches an ATL on a non-MATCH status — the manager must drop it.
    mismatch.hasAuthTrustLevel = true;
    mismatch.authTrustLevel = AuthTrustLevel::ATL4;

    std::atomic<int> fired {0};
    EXPECT_CALL(*cb, OnUserRecognitionEvent(_))
        .WillOnce([&fired](const IpcUserRecognitionResult &r) {
            EXPECT_EQ(static_cast<int32_t>(UserRecognitionStatus::MATCH), r.status);
            EXPECT_TRUE(r.hasAuthTrustLevel);
            fired.fetch_add(1);
            return SUCCESS;
        })
        .WillOnce([&fired](const IpcUserRecognitionResult &r) {
            EXPECT_EQ(static_cast<int32_t>(UserRecognitionStatus::MISMATCH), r.status);
            // Producer gate: ATL must be dropped on a non-MATCH status.
            EXPECT_FALSE(r.hasAuthTrustLevel);
            EXPECT_EQ(0u, r.authTrustLevel);
            fired.fetch_add(1);
            return SUCCESS;
        });
    GetUserRecognitionStateManager().SetUserRecognitionResult(match);
    GetUserRecognitionStateManager().SetUserRecognitionResult(mismatch);
    // Fan-out is posted to the resident thread; wait for both dispatches before teardown.
    WaitUntilDispatched(fired, 2);
    EXPECT_EQ(fired.load(), 2);

    IpcUserRecognitionResult cached = GetUserRecognitionStateManager().GetCachedUserRecognitionResult();
    EXPECT_EQ(static_cast<int32_t>(UserRecognitionStatus::MISMATCH), cached.status);
    EXPECT_FALSE(cached.hasAuthTrustLevel);

    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(cb), SUCCESS);
}

// Producer gate: an out-of-the-box UNCERTAIN push that erroneously carries an authTrustLevel
// must be forwarded with hasAuthTrustLevel=false (the manager's belt-and-suspenders gate).
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerUncertainDropsAtl, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj, nullptr);
    auto cb = RegisterProxyListener(obj);

    IpcUserRecognitionResult eng {};
    eng.status = static_cast<int32_t>(UserRecognitionStatus::UNCERTAIN);
    eng.userId = TEST_USER_ID_CAROL;
    eng.userInfo = "uncertain-info";
    eng.hasAuthTrustLevel = true;
    eng.authTrustLevel = AuthTrustLevel::ATL1; // should be dropped

    std::atomic<int> fired {0};
    EXPECT_CALL(*cb, OnUserRecognitionEvent(_))
        .WillOnce([&fired](const IpcUserRecognitionResult &r) {
            EXPECT_EQ(static_cast<int32_t>(UserRecognitionStatus::UNCERTAIN), r.status);
            EXPECT_FALSE(r.hasAuthTrustLevel);
            EXPECT_EQ(0u, r.authTrustLevel);
            fired.fetch_add(1);
            return SUCCESS;
        });
    GetUserRecognitionStateManager().SetUserRecognitionResult(eng);
    // Fan-out is posted to the resident thread; wait for the dispatch before teardown.
    WaitUntilDispatched(fired, 1);
    EXPECT_EQ(fired.load(), 1);

    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(cb), SUCCESS);
}

// CallbackDeathRecipient::Register factory: returns nullptr when AddDeathRecipient fails,
// and a valid recipient when it succeeds. Mirrors the sibling's AddDeathRecipient tests.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerDeathRecipientFactory, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj, nullptr);

    // AddDeathRecipient fails -> Register returns nullptr.
    EXPECT_CALL(*obj, AddDeathRecipient(_)).WillOnce(Return(false));
    auto dr = CallbackDeathRecipient::Register(obj, []() {});
    EXPECT_EQ(dr, nullptr);

    // AddDeathRecipient succeeds -> Register returns a valid recipient.
    EXPECT_CALL(*obj, AddDeathRecipient(_)).WillOnce(Return(true));
    auto dr2 = CallbackDeathRecipient::Register(obj, []() {});
    EXPECT_NE(dr2, nullptr);
}

// OnRemoteDied: posting the cleanup closure to the resident thread must not throw. The
// resident ThreadHandler singleton executes the posted task asynchronously; we additionally
// verify the closure actually runs by waiting on an atomic flag (bounded retry so the test
// fails rather than hangs if the post is dropped).
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerOnRemoteDied, TestSize.Level0)
{
    using DeathCallback = CallbackDeathRecipient::DeathCallback;
    std::atomic<int> fired {0};
    DeathCallback cleanup = [&fired]() { fired.fetch_add(1); };
    // private default ctor becomes reachable via the test's -Dprivate=public cflag.
    sptr<CallbackDeathRecipient> dr(
        new (std::nothrow) CallbackDeathRecipient(std::move(cleanup)));
    ASSERT_NE(dr, nullptr);

    wptr<IRemoteObject> nullRemote = nullptr;
    EXPECT_NO_THROW(dr->OnRemoteDied(nullRemote));

    auto mro = sptr<MockRemoteObject>(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(mro, nullptr);
    EXPECT_NO_THROW(dr->OnRemoteDied(mro));

    // OnRemoteDied ignores its remote arg and posts one cleanup task per call, so both calls
    // above post; drain both before teardown so neither posted task outlives this stack counter.
    for (int i = 0; i < ON_REMOTE_DIED_POLL_MAX_ATTEMPTS && fired.load() < 2; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(DISPATCH_POLL_INTERVAL_MS));
    }
    EXPECT_EQ(fired.load(), 2);
}

// A TOKEN_NATIVE (SA) subscriber receives the auth token carried by a MATCH result, and the
// cache retains it for later queries.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerNativeListenerReceivesAuthToken,
    TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj, nullptr);
    auto cb = RegisterProxyListener(obj);

    const std::vector<uint8_t> token = {0xA1, 0xB2, 0xC3};
    std::atomic<int> fired {0};
    EXPECT_CALL(*cb, OnUserRecognitionEvent(_))
        .WillOnce([&fired, &token](const IpcUserRecognitionResult &r) {
            EXPECT_EQ(token, r.authToken);
            fired.fetch_add(1);
            return SUCCESS;
        });
    GetUserRecognitionStateManager().SetUserRecognitionResult(MakeMatchResult(TEST_USER_ID_ALICE, token));
    WaitUntilDispatched(fired, 1);
    EXPECT_EQ(fired.load(), 1);

    IpcUserRecognitionResult cached = GetUserRecognitionStateManager().GetCachedUserRecognitionResult();
    EXPECT_EQ(token, cached.authToken);

    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(cb), SUCCESS);
}

// A TOKEN_HAP subscriber gets the auth token stripped from the same event a TOKEN_NATIVE
// subscriber receives in full — the SA-only delivery contract.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerHapListenerGetsStrippedToken,
    TestSize.Level0)
{
    sptr<MockRemoteObject> nativeObj(new (std::nothrow) MockRemoteObject);
    sptr<MockRemoteObject> hapObj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(nativeObj, nullptr);
    ASSERT_NE(hapObj, nullptr);
    auto nativeCb = RegisterProxyListener(nativeObj);
    auto hapCb = RegisterProxyListener(hapObj, Security::AccessToken::TOKEN_HAP);

    const std::vector<uint8_t> token = {0x11, 0x22, 0x33};
    std::atomic<int> nativeFired {0};
    std::atomic<int> hapFired {0};
    EXPECT_CALL(*nativeCb, OnUserRecognitionEvent(_))
        .WillOnce([&nativeFired, &token](const IpcUserRecognitionResult &r) {
            EXPECT_EQ(token, r.authToken);
            nativeFired.fetch_add(1);
            return SUCCESS;
        });
    EXPECT_CALL(*hapCb, OnUserRecognitionEvent(_))
        .WillOnce([&hapFired](const IpcUserRecognitionResult &r) {
            EXPECT_TRUE(r.authToken.empty());
            // The non-token fields are still delivered intact.
            EXPECT_EQ(static_cast<int32_t>(UserRecognitionStatus::MATCH), r.status);
            EXPECT_EQ(TEST_USER_ID_ALICE, r.userId);
            EXPECT_TRUE(r.hasAuthTrustLevel);
            hapFired.fetch_add(1);
            return SUCCESS;
        });
    GetUserRecognitionStateManager().SetUserRecognitionResult(MakeMatchResult(TEST_USER_ID_ALICE, token));
    WaitUntilDispatched(nativeFired, 1);
    WaitUntilDispatched(hapFired, 1);
    EXPECT_EQ(nativeFired.load(), 1);
    EXPECT_EQ(hapFired.load(), 1);

    EXPECT_CALL(*nativeObj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_CALL(*hapObj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(nativeCb), SUCCESS);
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(hapCb), SUCCESS);
}

// Catch-up on register replays the cached result with the token stripped for a TOKEN_HAP
// subscriber. SetUserRecognitionResult updates the cache with no listener registered.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerCatchUpStripsTokenForHapSubscriber,
    TestSize.Level0)
{
    const std::vector<uint8_t> token = {0x9A, 0xBC};
    GetUserRecognitionStateManager().SetUserRecognitionResult(MakeMatchResult(TEST_USER_ID_BOB, token));

    sptr<MockRemoteObject> hapObj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(hapObj, nullptr);
    auto hapCb = new (std::nothrow) MockUserRecognitionCallback();
    ASSERT_NE(hapCb, nullptr);
    EXPECT_CALL(*hapCb, AsObject()).WillRepeatedly(Return(hapObj));
    EXPECT_CALL(*hapObj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*hapObj, AddDeathRecipient(_)).WillRepeatedly(Return(true));
    std::atomic<int> hapSyncFired {0};
    EXPECT_CALL(*hapCb, OnUserRecognitionEvent(_))
        .WillOnce([&hapSyncFired](const IpcUserRecognitionResult &r) {
            EXPECT_EQ(static_cast<int32_t>(UserRecognitionStatus::MATCH), r.status);
            EXPECT_EQ(TEST_USER_ID_BOB, r.userId);
            EXPECT_TRUE(r.authToken.empty());
            hapSyncFired.fetch_add(1);
            return SUCCESS;
        })
        .RetiresOnSaturation();
    EXPECT_EQ(GetUserRecognitionStateManager().RegisterListener(Security::AccessToken::TOKEN_HAP,
        hapCb), SUCCESS);
    WaitUntilDispatched(hapSyncFired, 1);
    EXPECT_EQ(hapSyncFired.load(), 1);

    EXPECT_CALL(*hapObj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(hapCb), SUCCESS);
}

// Catch-up on register replays the cached result with the token intact for a TOKEN_NATIVE
// subscriber.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerCatchUpKeepsTokenForNativeSubscriber,
    TestSize.Level0)
{
    const std::vector<uint8_t> token = {0x9A, 0xBC};
    GetUserRecognitionStateManager().SetUserRecognitionResult(MakeMatchResult(TEST_USER_ID_BOB, token));

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj, nullptr);
    auto nativeCb = new (std::nothrow) MockUserRecognitionCallback();
    ASSERT_NE(nativeCb, nullptr);
    EXPECT_CALL(*nativeCb, AsObject()).WillRepeatedly(Return(obj));
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_)).WillRepeatedly(Return(true));
    std::atomic<int> nativeSyncFired {0};
    EXPECT_CALL(*nativeCb, OnUserRecognitionEvent(_))
        .WillOnce([&nativeSyncFired, &token](const IpcUserRecognitionResult &r) {
            EXPECT_EQ(token, r.authToken);
            nativeSyncFired.fetch_add(1);
            return SUCCESS;
        })
        .RetiresOnSaturation();
    EXPECT_EQ(GetUserRecognitionStateManager().RegisterListener(Security::AccessToken::TOKEN_NATIVE,
        nativeCb), SUCCESS);
    WaitUntilDispatched(nativeSyncFired, 1);
    EXPECT_EQ(nativeSyncFired.load(), 1);

    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(nativeCb), SUCCESS);
}

// A duplicate RegisterListener short-circuits and keeps the ORIGINAL caller type: first
// registered as HAP, a second register claiming TOKEN_NATIVE must not upgrade the entry.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerDuplicateRegisterKeepsOriginalType,
    TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj, nullptr);
    auto cb = RegisterProxyListener(obj, Security::AccessToken::TOKEN_HAP);
    EXPECT_EQ(GetUserRecognitionStateManager().RegisterListener(Security::AccessToken::TOKEN_NATIVE, cb),
        SUCCESS);

    const std::vector<uint8_t> token = {0x55};
    std::atomic<int> fired {0};
    EXPECT_CALL(*cb, OnUserRecognitionEvent(_))
        .WillOnce([&fired](const IpcUserRecognitionResult &r) {
            EXPECT_TRUE(r.authToken.empty());
            fired.fetch_add(1);
            return SUCCESS;
        });
    GetUserRecognitionStateManager().SetUserRecognitionResult(MakeMatchResult(TEST_USER_ID_ALICE, token));
    WaitUntilDispatched(fired, 1);
    EXPECT_EQ(fired.load(), 1);

    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(cb), SUCCESS);
}

// Dedup includes the token: two MATCH pushes identical in every semantic field but with
// different tokens must BOTH dispatch, so SA subscribers always observe the freshest token.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerTokenChangeForcesDispatch,
    TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj, nullptr);
    auto cb = RegisterProxyListener(obj);

    const std::vector<uint8_t> tokenA = {0x01};
    const std::vector<uint8_t> tokenB = {0x02};
    std::atomic<int> fired {0};
    EXPECT_CALL(*cb, OnUserRecognitionEvent(_))
        .WillOnce([&fired, &tokenA](const IpcUserRecognitionResult &r) {
            EXPECT_EQ(tokenA, r.authToken);
            fired.fetch_add(1);
            return SUCCESS;
        })
        .WillOnce([&fired, &tokenB](const IpcUserRecognitionResult &r) {
            EXPECT_EQ(tokenB, r.authToken);
            fired.fetch_add(1);
            return SUCCESS;
        });
    GetUserRecognitionStateManager().SetUserRecognitionResult(MakeMatchResult(TEST_USER_ID_ALICE, tokenA));
    GetUserRecognitionStateManager().SetUserRecognitionResult(MakeMatchResult(TEST_USER_ID_ALICE, tokenB));
    WaitUntilDispatched(fired, 2);
    EXPECT_EQ(fired.load(), 2);

    IpcUserRecognitionResult cached = GetUserRecognitionStateManager().GetCachedUserRecognitionResult();
    EXPECT_EQ(tokenB, cached.authToken);

    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(cb), SUCCESS);
}

// Producer gate: a non-MATCH push that erroneously carries a token must be sanitized — the
// token is a secret and meaningless on non-MATCH results, so neither listeners nor the cache
// may retain it.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerNonMatchSanitizesToken, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    ASSERT_NE(obj, nullptr);
    auto cb = RegisterProxyListener(obj);

    IpcUserRecognitionResult mismatch {};
    mismatch.status = static_cast<int32_t>(UserRecognitionStatus::MISMATCH);
    mismatch.userId = TEST_USER_ID_BOB;
    mismatch.userInfo = "mismatch-with-token";
    mismatch.authToken = {0xDE, 0xAD};

    std::atomic<int> fired {0};
    EXPECT_CALL(*cb, OnUserRecognitionEvent(_))
        .WillOnce([&fired](const IpcUserRecognitionResult &r) {
            EXPECT_TRUE(r.authToken.empty());
            fired.fetch_add(1);
            return SUCCESS;
        });
    GetUserRecognitionStateManager().SetUserRecognitionResult(mismatch);
    WaitUntilDispatched(fired, 1);
    EXPECT_EQ(fired.load(), 1);

    IpcUserRecognitionResult cached = GetUserRecognitionStateManager().GetCachedUserRecognitionResult();
    EXPECT_TRUE(cached.authToken.empty());

    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillOnce(Return(true));
    EXPECT_EQ(GetUserRecognitionStateManager().UnregisterListener(cb), SUCCESS);
}

// BuildUserRecognitionResultForCaller (private static, reached via -Dprivate=public): a
// TOKEN_NATIVE caller gets the result untouched; a TOKEN_HAP caller gets the token stripped
// with every other field intact; the input result is not modified.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerBuildResultForCaller, TestSize.Level0)
{
    IpcUserRecognitionResult result {};
    result.status = static_cast<int32_t>(UserRecognitionStatus::MATCH);
    result.userId = TEST_USER_ID_ALICE;
    result.userInfo = "build-info";
    result.hasAuthTrustLevel = true;
    result.authTrustLevel = AuthTrustLevel::ATL3;
    result.authToken = {0x01, 0x02, 0x03};

    auto manager = std::static_pointer_cast<UserRecognitionStateManager>(CreateUserRecognitionStateManager());
    ASSERT_NE(manager, nullptr);

    IpcUserRecognitionResult nativeResult = manager->BuildUserRecognitionResultForCaller(
        Security::AccessToken::TOKEN_NATIVE, result);
    EXPECT_EQ(result.status, nativeResult.status);
    EXPECT_EQ(result.userId, nativeResult.userId);
    EXPECT_EQ(result.userInfo, nativeResult.userInfo);
    EXPECT_EQ(result.hasAuthTrustLevel, nativeResult.hasAuthTrustLevel);
    EXPECT_EQ(result.authTrustLevel, nativeResult.authTrustLevel);
    EXPECT_EQ(result.authToken, nativeResult.authToken);

    IpcUserRecognitionResult hapResult = manager->BuildUserRecognitionResultForCaller(
        Security::AccessToken::TOKEN_HAP, result);
    EXPECT_TRUE(hapResult.authToken.empty());
    EXPECT_EQ(result.status, hapResult.status);
    EXPECT_EQ(result.userId, hapResult.userId);
    EXPECT_EQ(result.userInfo, hapResult.userInfo);
    EXPECT_EQ(result.hasAuthTrustLevel, hapResult.hasAuthTrustLevel);
    EXPECT_EQ(result.authTrustLevel, hapResult.authTrustLevel);

    // The input is taken by value and must stay untouched.
    EXPECT_EQ(std::vector<uint8_t>({0x01, 0x02, 0x03}), result.authToken);
}

// GetCachedUserRecognitionResultForCaller: the cached result is returned intact for a
// TOKEN_NATIVE caller and with the token stripped for everyone else.
HWTEST_F(UserRecognitionStateManagerTest, UserRecognitionManagerCachedResultForCaller, TestSize.Level0)
{
    const std::vector<uint8_t> token = {0xAA, 0xBB};
    GetUserRecognitionStateManager().SetUserRecognitionResult(MakeMatchResult(TEST_USER_ID_BOB, token));

    IpcUserRecognitionResult nativeResult = GetUserRecognitionStateManager()
        .GetCachedUserRecognitionResultForCaller(Security::AccessToken::TOKEN_NATIVE);
    EXPECT_EQ(static_cast<int32_t>(UserRecognitionStatus::MATCH), nativeResult.status);
    EXPECT_EQ(TEST_USER_ID_BOB, nativeResult.userId);
    EXPECT_EQ(token, nativeResult.authToken);

    IpcUserRecognitionResult hapResult = GetUserRecognitionStateManager()
        .GetCachedUserRecognitionResultForCaller(Security::AccessToken::TOKEN_HAP);
    EXPECT_EQ(static_cast<int32_t>(UserRecognitionStatus::MATCH), hapResult.status);
    EXPECT_EQ(TEST_USER_ID_BOB, hapResult.userId);
    EXPECT_TRUE(hapResult.authToken.empty());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
