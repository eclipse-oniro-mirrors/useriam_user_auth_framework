/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "iam_event_dispatcher_test.h"

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include "attributes.h"
#include "iam_event_dispatcher.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

namespace {
constexpr EventId EVT_A = EVENT_AUTH_INITIATED;
constexpr EventId EVT_B = EVENT_AUTH_RESULT;
constexpr int POLL_INTERVAL_MS = 5;
constexpr int NO_DELIVERY_WAIT_MS = 200;
constexpr int POST_FUTURE_WAIT_SEC = 2;
constexpr int DISPATCH_TIMEOUT_MS = 2000;
constexpr int CONCURRENT_DISPATCH_TIMEOUT_MS = 3000;

IamEventData MakeData(int32_t value)
{
    auto data = std::make_shared<Attributes>();
    (void)data->SetInt32Value(Attributes::ATTR_RESULT_CODE, value);
    return data;
}

// Spin until `hits` reaches `expected` or `timeoutMs` elapses. Real dispatch is asynchronous on
// the RelativeTimer worker thread (see relative_timer_test.cpp for the same await pattern).
bool WaitForHits(std::atomic<int> &hits, int expected, int timeoutMs)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (hits.load() < expected && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(POLL_INTERVAL_MS));
    }
    return hits.load() >= expected;
}
} // namespace

void IamEventDispatcherTest::SetUpTestCase()
{
}

void IamEventDispatcherTest::TearDownTestCase()
{
}

void IamEventDispatcherTest::SetUp()
{
    SetIamEventDispatcher(CreateIamEventDispatcher());
}

void IamEventDispatcherTest::TearDown()
{
    SetIamEventDispatcher(nullptr);
}

// Post routes by event id; the same Attributes instance is shared with the handler.
HWTEST_F(IamEventDispatcherTest, PostRoutesByEventId, TestSize.Level3)
{
    auto &dispatcher = GetIamEventDispatcher();
    std::promise<void> done;
    auto future = done.get_future();
    auto data = MakeData(7);
    auto sub = dispatcher.Subscribe(EVT_A, [&done, &data](const IamEventData &event) {
        EXPECT_EQ(event.get(), data.get()); // shared, not copied
        done.set_value();
    });
    ASSERT_NE(sub, nullptr);
    dispatcher.Post(EVT_A, data);
    EXPECT_EQ(future.wait_for(std::chrono::seconds(POST_FUTURE_WAIT_SEC)), std::future_status::ready);
}

// An event id nobody subscribed to is not delivered.
HWTEST_F(IamEventDispatcherTest, UnsubscribedEventIdNotDelivered, TestSize.Level3)
{
    auto &dispatcher = GetIamEventDispatcher();
    std::atomic<int> hits(0);
    auto sub = dispatcher.Subscribe(EVT_A, [&hits](const IamEventData &) { hits++; });
    ASSERT_NE(sub, nullptr);
    dispatcher.Post(EVT_B, MakeData(1)); // different id
    std::this_thread::sleep_for(std::chrono::milliseconds(NO_DELIVERY_WAIT_MS));
    EXPECT_EQ(hits.load(), 0);
}

// Dropping the last reference to the handle unregisters the handler.
HWTEST_F(IamEventDispatcherTest, DropHandleUnsubscribes, TestSize.Level3)
{
    auto &dispatcher = GetIamEventDispatcher();
    std::atomic<int> hits(0);
    {
        auto sub = dispatcher.Subscribe(EVT_A, [&hits](const IamEventData &) { hits++; });
        ASSERT_NE(sub, nullptr);
    } // handle dropped -> unsubscribed
    dispatcher.Post(EVT_A, MakeData(1));
    std::this_thread::sleep_for(std::chrono::milliseconds(NO_DELIVERY_WAIT_MS));
    EXPECT_EQ(hits.load(), 0);
}

// Explicit Unsubscribe is idempotent and stops further delivery.
HWTEST_F(IamEventDispatcherTest, UnsubscribeIsIdempotent, TestSize.Level3)
{
    auto &dispatcher = GetIamEventDispatcher();
    std::atomic<int> hits(0);
    auto sub = dispatcher.Subscribe(EVT_A, [&hits](const IamEventData &) { hits++; });
    ASSERT_NE(sub, nullptr);
    sub->Unsubscribe();
    sub->Unsubscribe(); // idempotent
    dispatcher.Post(EVT_A, MakeData(1));
    std::this_thread::sleep_for(std::chrono::milliseconds(NO_DELIVERY_WAIT_MS));
    EXPECT_EQ(hits.load(), 0);
}

// Multiple subscribers to the same id all receive the event.
HWTEST_F(IamEventDispatcherTest, MultipleSubscribersReceive, TestSize.Level3)
{
    auto &dispatcher = GetIamEventDispatcher();
    std::atomic<int> hits(0);
    auto sub1 = dispatcher.Subscribe(EVT_A, [&hits](const IamEventData &) { hits++; });
    auto sub2 = dispatcher.Subscribe(EVT_A, [&hits](const IamEventData &) { hits++; });
    ASSERT_NE(sub1, nullptr);
    ASSERT_NE(sub2, nullptr);
    dispatcher.Post(EVT_A, MakeData(1));
    EXPECT_TRUE(WaitForHits(hits, 2, DISPATCH_TIMEOUT_MS));
    EXPECT_EQ(hits.load(), 2);
}

// Mutating the live subscriber map from within a handler does not crash and does not drop the
// other handler that was captured in the Post-time snapshot.
HWTEST_F(IamEventDispatcherTest, MutateSubscribersDuringDispatch, TestSize.Level3)
{
    auto &dispatcher = GetIamEventDispatcher();
    std::atomic<int> hits(0);
    auto sub2 = dispatcher.Subscribe(EVT_A, [&hits](const IamEventData &) { hits++; });
    ASSERT_NE(sub2, nullptr);
    // sub2 outlives dispatch; capture a raw pointer so the unique_ptr keeps sole ownership.
    Subscription *raw2 = sub2.get();
    auto sub1 = dispatcher.Subscribe(EVT_A, [raw2, &hits](const IamEventData &) {
        raw2->Unsubscribe(); // mutate live map during dispatch
        hits++;
    });
    ASSERT_NE(sub1, nullptr);
    EXPECT_NO_THROW(dispatcher.Post(EVT_A, MakeData(1)));
    EXPECT_TRUE(WaitForHits(hits, 2, DISPATCH_TIMEOUT_MS)); // both handlers were in the snapshot
    EXPECT_EQ(hits.load(), 2);
}

// A null handler is rejected with a null handle.
HWTEST_F(IamEventDispatcherTest, NullHandlerRejected, TestSize.Level3)
{
    auto &dispatcher = GetIamEventDispatcher();
    auto sub = dispatcher.Subscribe(EVT_A, nullptr);
    EXPECT_EQ(sub, nullptr);
}

// Concurrent Post calls from many threads are safe and every event is delivered.
HWTEST_F(IamEventDispatcherTest, ConcurrentPostIsSafe, TestSize.Level3)
{
    auto &dispatcher = GetIamEventDispatcher();
    std::atomic<int> hits(0);
    auto sub = dispatcher.Subscribe(EVT_A, [&hits](const IamEventData &) { hits++; });
    ASSERT_NE(sub, nullptr);
    constexpr int N = 50;
    std::vector<std::thread> threads;
    threads.reserve(N);
    for (int i = 0; i < N; ++i) {
        threads.emplace_back([&dispatcher]() { dispatcher.Post(EVT_A, MakeData(1)); });
    }
    for (auto &t : threads) {
        t.join();
    }
    EXPECT_TRUE(WaitForHits(hits, N, CONCURRENT_DISPATCH_TIMEOUT_MS));
    EXPECT_EQ(hits.load(), N);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
