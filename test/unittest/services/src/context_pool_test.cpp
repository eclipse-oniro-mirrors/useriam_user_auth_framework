/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "context_pool_test.h"

#include <chrono>
#include <future>
#include <thread>

#include "context_pool.h"
#include "iam_scope_guard.h"
#include "thread_handler.h"

#include "mock_context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ContextPoolTest::SetUpTestCase()
{
}

void ContextPoolTest::TearDownTestCase()
{
}

void ContextPoolTest::SetUp()
{
}

void ContextPoolTest::TearDown()
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    if (handler == nullptr) {
        return;
    }
    handler->EnsureTask([]() {});
    for (auto &context : ContextPool::Instance().SelectAll()) {
        auto ctx = context.lock();
        if (ctx != nullptr) {
            ContextPool::Instance().Delete(ctx->GetContextId());
        }
    }
    handler->EnsureTask([]() {});
}

HWTEST_F(ContextPoolTest, ContextPoolGetInstance, TestSize.Level0)
{
    auto &pool = ContextPool::Instance();
    EXPECT_NE(&pool, nullptr);
}

HWTEST_F(ContextPoolTest, ContextPoolGetUniqueInstance, TestSize.Level0)
{
    auto &pool1 = ContextPool::Instance();
    auto &pool2 = ContextPool::Instance();
    ASSERT_NE(&pool1, nullptr);
    ASSERT_NE(&pool2, nullptr);
    EXPECT_EQ(&pool1, &pool2);
}

HWTEST_F(ContextPoolTest, ContextPoolScheduleNull, TestSize.Level0)
{
    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(nullptr), false);
}

HWTEST_F(ContextPoolTest, ContextPoolDelete, TestSize.Level0)
{
    const uint64_t CONTEXT_ID = 200;
    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Delete(CONTEXT_ID), false);
    auto context = MockContext::CreateWithContextId(CONTEXT_ID);
    EXPECT_EQ(pool.Schedule(context), true);
    EXPECT_EQ(pool.Delete(CONTEXT_ID), true);
    EXPECT_EQ(pool.Select(CONTEXT_ID).lock(), nullptr);
}

HWTEST_F(ContextPoolTest, ContextPoolScheduleAndDelete, TestSize.Level0)
{
    auto &pool = ContextPool::Instance();
    const uint64_t CONTEXT_ID1 = 300;
    const uint64_t CONTEXT_ID2 = 400;
    const uint64_t CONTEXT_ID3 = 500;
    auto context1 = MockContext::CreateWithContextId(CONTEXT_ID1);
    auto context2 = MockContext::CreateWithContextId(CONTEXT_ID2);
    auto context3 = MockContext::CreateWithContextId(CONTEXT_ID3);
    EXPECT_EQ(pool.Select(CONTEXT_ID3).lock(), nullptr);
    EXPECT_EQ(pool.Schedule(context1), true);
    EXPECT_EQ(pool.Schedule(context2), true);
    EXPECT_EQ(pool.Schedule(context3), true);
    EXPECT_EQ(pool.Select(CONTEXT_ID3).lock(), context3);
    EXPECT_EQ(pool.Select(CONTEXT_ID2).lock(), context2);
    EXPECT_EQ(pool.Select(CONTEXT_ID1).lock(), context1);

    EXPECT_EQ(pool.Delete(CONTEXT_ID1), true);
    EXPECT_EQ(pool.Delete(CONTEXT_ID2), true);
    EXPECT_EQ(pool.Delete(CONTEXT_ID3), true);

    EXPECT_FALSE(pool.Delete(CONTEXT_ID1));
    EXPECT_FALSE(pool.Delete(CONTEXT_ID2));
    EXPECT_FALSE(pool.Delete(CONTEXT_ID3));
}

HWTEST_F(ContextPoolTest, ContextSelectScheduleNodeByScheduleId, TestSize.Level0)
{
    const uint64_t CONTEXT_ID1 = 100;
    const uint64_t SCHEDULE_ID1 = 102;
    const uint64_t CONTEXT_ID2 = 200;
    const uint64_t SCHEDULE_ID2 = 202;
    auto &pool = ContextPool::Instance();
    auto context1 = MockContext::CreateContextWithScheduleNode(CONTEXT_ID1, {SCHEDULE_ID1});
    EXPECT_EQ(pool.Schedule(context1), true);
    auto context2 = MockContext::CreateContextWithScheduleNode(CONTEXT_ID2, {SCHEDULE_ID2});
    EXPECT_EQ(pool.Schedule(context2), true);

    EXPECT_EQ(pool.SelectScheduleNodeByScheduleId(302), nullptr);
    EXPECT_NE(pool.SelectScheduleNodeByScheduleId(SCHEDULE_ID1), nullptr);
    EXPECT_EQ(pool.Delete(CONTEXT_ID1), true);
    EXPECT_EQ(pool.SelectScheduleNodeByScheduleId(SCHEDULE_ID1), nullptr);

    EXPECT_NE(pool.SelectScheduleNodeByScheduleId(SCHEDULE_ID2), nullptr);
    EXPECT_EQ(pool.Delete(CONTEXT_ID2), true);
    EXPECT_EQ(pool.SelectScheduleNodeByScheduleId(SCHEDULE_ID2), nullptr);
}

HWTEST_F(ContextPoolTest, ContextPoolCleaner, TestSize.Level0)
{
    const uint64_t CONTEXT_ID1 = 100;
    const uint64_t SCHEDULE_ID1 = 102;
    auto &pool = ContextPool::Instance();

    auto context = MockContext::CreateContextWithScheduleNode(CONTEXT_ID1, {SCHEDULE_ID1});
    EXPECT_EQ(pool.Schedule(context), true);
    EXPECT_NE(pool.Select(CONTEXT_ID1).lock(), nullptr);

    ContextPool::Cleaner clear(context);
    clear();
    EXPECT_EQ(pool.Select(CONTEXT_ID1).lock(), nullptr);
}

HWTEST_F(ContextPoolTest, ContextPoolRandomId, TestSize.Level0)
{
    std::set<uint64_t> generated;

    for (int i = 0; i < 1000; i++) {
        auto contextId = ContextPool::GetNewContextId();
        EXPECT_NE(contextId, 0U);
        EXPECT_TRUE(generated.find(contextId) == generated.end());
        generated.emplace(contextId);
    }
}

HWTEST_F(ContextPoolTest, ContextPoolTestSelect, TestSize.Level0)
{
    auto context1 = Common::MakeShared<MockContext>();
    EXPECT_NE(context1, nullptr);
    EXPECT_CALL(*context1, GetContextId()).WillRepeatedly(Return(10));
    EXPECT_CALL(*context1, GetContextType()).WillRepeatedly(Return(CONTEXT_SIMPLE_AUTH));

    auto context2 = Common::MakeShared<MockContext>();
    EXPECT_NE(context2, nullptr);
    EXPECT_CALL(*context2, GetContextId()).WillRepeatedly(Return(20));
    EXPECT_CALL(*context2, GetContextType()).WillRepeatedly(Return(CONTEXT_IDENTIFY));

    auto &pool = ContextPool::Instance();
    auto contextVector = pool.Select(CONTEXT_SIMPLE_AUTH);
    EXPECT_EQ(contextVector.size(), 0);
    EXPECT_TRUE(pool.Schedule(context1));
    EXPECT_TRUE(pool.Schedule(context2));

    contextVector = pool.Select(WIDGET_AUTH_CONTEXT);
    EXPECT_EQ(contextVector.size(), 0);
    contextVector = pool.Select(CONTEXT_SIMPLE_AUTH);
    EXPECT_EQ(contextVector.size(), 1);
    auto tempContext = contextVector[0].lock();
    EXPECT_NE(tempContext, nullptr);
    EXPECT_EQ(tempContext->GetContextId(), 10);
    EXPECT_TRUE(pool.Delete(10));
    EXPECT_TRUE(pool.Delete(20));
}

HWTEST_F(ContextPoolTest, ContextPoolTestGetNewContextId, TestSize.Level0)
{
    const int32_t COUNT = 10;
    std::vector<uint64_t> contextIdVector(COUNT);

    for (int32_t i = 0; i < COUNT; ++i) {
        uint64_t contextId = ContextPool::GetNewContextId();
        contextIdVector[i] = contextId;
        auto context = MockContext::CreateWithContextId(contextId);
        ContextPool::Instance().Schedule(context);
    }

    for (int32_t i = 0; i < COUNT; ++i) {
        uint64_t contextId = contextIdVector[i];
        EXPECT_TRUE(ContextPool::Instance().Delete(contextId));
    }
}

HWTEST_F(ContextPoolTest, StartSubscribeOsAccountSaStatusTest, TestSize.Level0)
{
    EXPECT_NO_THROW(ContextPool::Instance().StartSubscribeOsAccountSaStatus());
    EXPECT_NO_THROW(ContextPool::Instance().StartSubscribeOsAccountSaStatus());
}

HWTEST_F(ContextPoolTest, CancelAllTest, TestSize.Level0)
{
    auto context = Common::MakeShared<MockContext>();
    EXPECT_NE(context, nullptr);
    uint64_t contextId = 100;

    EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(contextId));
    EXPECT_TRUE(ContextPool::Instance().Schedule(context));
    {
        EXPECT_CALL(*context, Stop()).WillRepeatedly(Return(true));
        EXPECT_NO_THROW(ContextPool::Instance().CancelAll());
    }

    {
        EXPECT_CALL(*context, Stop()).WillRepeatedly(Return(false));
        EXPECT_NO_THROW(ContextPool::Instance().CancelAll());
    }
    EXPECT_TRUE(ContextPool::Instance().Delete(contextId));
}

namespace {
// drain passes: EnsureTask only waits out tasks posted before it, not their nested posts
constexpr int32_t DRAIN_PASSES = 3;

void DrainSerialThread()
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    for (int pass = 0; pass < DRAIN_PASSES; ++pass) {
        handler->EnsureTask([]() {});
    }
}

void SetupPrimaryPinAuthMock(const std::shared_ptr<MockContext> &mock, const std::string &callerName,
    int32_t userId, bool canStart)
{
    ON_CALL(*mock, GetContextType()).WillByDefault(Return(ContextType::CONTEXT_SIMPLE_AUTH));
    ON_CALL(*mock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*mock, GetCallerName()).WillByDefault(Return(callerName));
    ON_CALL(*mock, GetAuthType()).WillByDefault(Return(static_cast<int32_t>(PIN)));
    ON_CALL(*mock, GetUserId()).WillByDefault(Return(userId));
    ON_CALL(*mock, CanStart(_)).WillByDefault(Return(canStart));
}
} // namespace

HWTEST_F(ContextPoolTest, ContextPoolScheduleDuplicateId, TestSize.Level0)
{
    const uint64_t CONTEXT_ID = 600;
    auto context1 = MockContext::CreateWithContextId(CONTEXT_ID);
    auto context2 = MockContext::CreateWithContextId(CONTEXT_ID);
    ASSERT_NE(context1, nullptr);
    ASSERT_NE(context2, nullptr);
    auto mock1 = std::static_pointer_cast<MockContext>(context1);
    EXPECT_CALL(*mock1, Start()).Times(1).WillOnce(Return(true));
    auto &pool = ContextPool::Instance();

    EXPECT_EQ(pool.Schedule(context1), true);
    // A duplicate id must be rejected without posting a start or evicting the holder.
    EXPECT_EQ(pool.Schedule(context2), false);
    EXPECT_EQ(pool.Select(CONTEXT_ID).lock(), context1);

    DrainSerialThread();
    EXPECT_EQ(pool.Delete(CONTEXT_ID), true);
}

HWTEST_F(ContextPoolTest, ContextPoolScheduleStartFailInvokesOnStartFailed, TestSize.Level0)
{
    const uint64_t CONTEXT_ID = 610;
    auto context = MockContext::CreateWithContextId(CONTEXT_ID);
    ASSERT_NE(context, nullptr);
    auto mock = std::static_pointer_cast<MockContext>(context);
    EXPECT_CALL(*mock, Start()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*mock, GetLatestError()).WillRepeatedly(Return(GENERAL_ERROR));
    EXPECT_CALL(*mock, OnStartFailed(GENERAL_ERROR)).Times(1);
    auto &pool = ContextPool::Instance();

    EXPECT_EQ(pool.Schedule(context), true);

    DrainSerialThread();
    EXPECT_EQ(pool.Delete(CONTEXT_ID), true);
}

HWTEST_F(ContextPoolTest, ContextPoolScheduleDeletedBeforeStart, TestSize.Level0)
{
    const uint64_t CONTEXT_ID = 620;
    auto context = MockContext::CreateWithContextId(CONTEXT_ID);
    ASSERT_NE(context, nullptr);
    auto mock = std::static_pointer_cast<MockContext>(context);
    EXPECT_CALL(*mock, Start()).Times(0);
    EXPECT_CALL(*mock, OnStartFailed(_)).Times(0);
    auto &pool = ContextPool::Instance();

    // hold the serial thread so the posted start stays queued behind the blocker,
    // or it may win the race and violate Times(0)
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    std::promise<void> release;
    Common::IamScopeGuard releaseGuard([&release]() { release.set_value(); });
    handler->PostTask([&release]() { release.get_future().get(); });

    EXPECT_EQ(pool.Schedule(context), true);
    // the cancel (pool entry dropped) wins the race with the posted start, which must stay silent
    EXPECT_EQ(pool.Delete(CONTEXT_ID), true);

    releaseGuard.Cancel();
    release.set_value();
    DrainSerialThread();
}

// waiters hold no seat yet: even one whose decision would yield is not a
// victim of an unrelated newcomer; only same-caller/widget rules or
// Cancel evict it from the queue
HWTEST_F(ContextPoolTest, ContextPoolWaiterNotYieldVictim, TestSize.Level0)
{
    const uint64_t WAITING_ID = 630;
    const uint64_t INCOMING_ID = 631;
    auto waiter = MockContext::CreateWithContextId(WAITING_ID);
    auto incoming = MockContext::CreateWithContextId(INCOMING_ID);
    ASSERT_NE(waiter, nullptr);
    ASSERT_NE(incoming, nullptr);
    auto waiterMock = std::static_pointer_cast<MockContext>(waiter);
    auto incomingMock = std::static_pointer_cast<MockContext>(incoming);
    ON_CALL(*incomingMock, GetCallerName()).WillByDefault(Return("incoming_caller"));
    ON_CALL(*waiterMock, IsPrimaryContext()).WillByDefault(Return(true));
    EXPECT_CALL(*waiterMock, CanStart(_)).WillRepeatedly(Return(false));
    // same rule as WidgetContext: a member only ever yields its place to a
    // newer widget session; an unrelated newcomer must not evict a waiter
    ON_CALL(*waiterMock, GetPreemptDecision(_)).WillByDefault(
        [](const Context &newRequest) {
            if (newRequest.GetContextType() == ContextType::WIDGET_AUTH_CONTEXT) {
                return PreemptDecision::STOP_NOW;
            }
            return PreemptDecision::KEEP_RUNNING;
        });
    EXPECT_CALL(*waiterMock, Start()).Times(0);
    EXPECT_CALL(*waiterMock, OnStartFailed(_)).Times(0);
    EXPECT_CALL(*waiterMock, Stop()).Times(0);
    EXPECT_CALL(*incomingMock, Start()).Times(1).WillOnce(Return(true));
    auto &pool = ContextPool::Instance();

    EXPECT_EQ(pool.Schedule(waiter), true);
    EXPECT_EQ(pool.Schedule(incoming), true);

    DrainSerialThread();
    EXPECT_NE(pool.Select(WAITING_ID).lock(), nullptr);
    EXPECT_EQ(pool.Delete(INCOMING_ID), true);
    EXPECT_EQ(pool.Delete(WAITING_ID), true);
}

HWTEST_F(ContextPoolTest, ContextPoolSameCallerPreemptSkipsNonPrimaryChild, TestSize.Level0)
{
    const uint64_t CHILD_ID = 640;
    const uint64_t INCOMING_ID = 641;
    auto child = MockContext::CreateWithContextId(CHILD_ID);
    auto incoming = MockContext::CreateWithContextId(INCOMING_ID);
    ASSERT_NE(child, nullptr);
    ASSERT_NE(incoming, nullptr);
    auto childMock = std::static_pointer_cast<MockContext>(child);
    auto incomingMock = std::static_pointer_cast<MockContext>(incoming);

    ON_CALL(*childMock, GetContextType()).WillByDefault(Return(ContextType::CONTEXT_SIMPLE_AUTH));
    ON_CALL(*childMock, IsPrimaryContext()).WillByDefault(Return(false));
    ON_CALL(*childMock, GetCallerName()).WillByDefault(Return("same_caller"));
    ON_CALL(*childMock, GetAuthType()).WillByDefault(Return(static_cast<int32_t>(PIN)));
    ON_CALL(*childMock, GetUserId()).WillByDefault(Return(100));
    ON_CALL(*childMock, Start()).WillByDefault(Return(true));
    // internal children (widget/sudo sub-auth) are never same-caller victims
    EXPECT_CALL(*childMock, Stop()).Times(0);

    ON_CALL(*incomingMock, GetContextType()).WillByDefault(Return(ContextType::CONTEXT_SIMPLE_AUTH));
    ON_CALL(*incomingMock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*incomingMock, GetCallerName()).WillByDefault(Return("same_caller"));
    ON_CALL(*incomingMock, GetAuthType()).WillByDefault(Return(static_cast<int32_t>(PIN)));
    ON_CALL(*incomingMock, GetUserId()).WillByDefault(Return(100));
    ON_CALL(*incomingMock, Start()).WillByDefault(Return(true));

    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(child), true);
    DrainSerialThread();
    EXPECT_EQ(pool.Schedule(incoming), true);
    DrainSerialThread();

    EXPECT_NE(pool.Select(INCOMING_ID).lock(), nullptr);
    EXPECT_EQ(pool.Delete(INCOMING_ID), true);
    EXPECT_EQ(pool.Delete(CHILD_ID), true);
    DrainSerialThread();
}

HWTEST_F(ContextPoolTest, ContextPoolWaiterWaitsWithoutTimeoutUntilCancel, TestSize.Level0)
{
    const uint64_t HOLDER_ID = 650;
    const uint64_t WAITER_ID = 651;
    const int32_t WAIT_OBSERVATION_WINDOW_MS = 100;
    auto holder = MockContext::CreateWithContextId(HOLDER_ID);
    auto waiter = MockContext::CreateWithContextId(WAITER_ID);
    ASSERT_NE(holder, nullptr);
    ASSERT_NE(waiter, nullptr);
    auto holderMock = std::static_pointer_cast<MockContext>(holder);
    auto waiterMock = std::static_pointer_cast<MockContext>(waiter);

    ON_CALL(*holderMock, GetContextType()).WillByDefault(Return(ContextType::CONTEXT_SIMPLE_AUTH));
    ON_CALL(*holderMock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*holderMock, GetCallerName()).WillByDefault(Return("holder_caller"));
    ON_CALL(*holderMock, GetAuthType()).WillByDefault(Return(static_cast<int32_t>(PIN)));
    ON_CALL(*holderMock, GetUserId()).WillByDefault(Return(100));
    ON_CALL(*holderMock, CanStart(_)).WillByDefault(Return(true));
    ON_CALL(*holderMock, Start()).WillByDefault(Return(true));

    ON_CALL(*waiterMock, GetContextType()).WillByDefault(Return(ContextType::CONTEXT_SIMPLE_AUTH));
    ON_CALL(*waiterMock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*waiterMock, GetCallerName()).WillByDefault(Return("waiter_caller"));
    ON_CALL(*waiterMock, GetAuthType()).WillByDefault(Return(static_cast<int32_t>(PIN)));
    ON_CALL(*waiterMock, GetUserId()).WillByDefault(Return(100));
    // the factory defaults CanStart to true; keep the waiter waiting in the FIFO
    ON_CALL(*waiterMock, CanStart(_)).WillByDefault(Return(false));
    // mirror BaseContext::Stop: a never-started context deletes itself from the
    // pool (queue included) and reports CANCELED, executor untouched
    // capture weakly: a shared_ptr capture would cycle (mock owns its default
    // action) and leak the mock past the gtest exit leak check
    ON_CALL(*waiterMock, Stop()).WillByDefault([weakWaiter = std::weak_ptr<MockContext>(waiterMock)]() {
        ContextPool::Instance().Delete(WAITER_ID);
        if (auto waiter = weakWaiter.lock()) {
            waiter->OnStartFailed(ResultCode::CANCELED);
        }
        return true;
    });

    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(holder), true);
    EXPECT_EQ(pool.Schedule(waiter), true);
    DrainSerialThread();
    EXPECT_NE(pool.Select(WAITER_ID).lock(), nullptr);

    // no waiting timeout exists: the waiter stays in the FIFO until the caller cancels
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_OBSERVATION_WINDOW_MS));
    EXPECT_NE(pool.Select(WAITER_ID).lock(), nullptr);

    EXPECT_CALL(*waiterMock, OnStartFailed(ResultCode::CANCELED)).Times(1);
    pool.Cancel(WAITER_ID);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(WAITER_ID).lock(), nullptr);

    EXPECT_EQ(pool.Delete(HOLDER_ID), true);
    DrainSerialThread();
}

HWTEST_F(ContextPoolTest, ContextPoolSameCallerPreemptsOwnOldestWaiting, TestSize.Level0)
{
    const uint64_t HOLDER_ID = 660;
    const uint64_t FIRST_WAITER_ID = 661;
    const uint64_t SECOND_WAITER_ID = 662;
    auto holder = MockContext::CreateWithContextId(HOLDER_ID);
    auto firstWaiter = MockContext::CreateWithContextId(FIRST_WAITER_ID);
    auto secondWaiter = MockContext::CreateWithContextId(SECOND_WAITER_ID);
    ASSERT_NE(holder, nullptr);
    ASSERT_NE(firstWaiter, nullptr);
    ASSERT_NE(secondWaiter, nullptr);
    auto holderMock = std::static_pointer_cast<MockContext>(holder);
    auto firstWaiterMock = std::static_pointer_cast<MockContext>(firstWaiter);
    auto secondWaiterMock = std::static_pointer_cast<MockContext>(secondWaiter);

    SetupPrimaryPinAuthMock(holderMock, "holder_caller", 100, true);
    ON_CALL(*holderMock, Start()).WillByDefault(Return(true));

    // a flooding caller queues several waiters behind the running holder
    for (auto &waiterMock : {firstWaiterMock, secondWaiterMock}) {
        SetupPrimaryPinAuthMock(waiterMock, "flood_caller", 100, false);
    }
    // weak captures: shared_ptr captures would cycle with the mock's own action storage
    ON_CALL(*firstWaiterMock, Stop()).WillByDefault(
        [weakFirst = std::weak_ptr<MockContext>(firstWaiterMock)]() {
            ContextPool::Instance().Delete(FIRST_WAITER_ID);
            if (auto firstWaiter = weakFirst.lock()) {
                firstWaiter->OnStartFailed(ResultCode::CANCELED);
            }
            return true;
        });
    ON_CALL(*secondWaiterMock, Stop()).WillByDefault(
        [weakSecond = std::weak_ptr<MockContext>(secondWaiterMock)]() {
            ContextPool::Instance().Delete(SECOND_WAITER_ID);
            if (auto secondWaiter = weakSecond.lock()) {
                secondWaiter->OnStartFailed(ResultCode::CANCELED);
            }
            return true;
        });

    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(holder), true);
    EXPECT_EQ(pool.Schedule(firstWaiter), true);
    DrainSerialThread();
    EXPECT_NE(pool.Select(FIRST_WAITER_ID).lock(), nullptr);

    // a newer same-caller request supersedes the OLDEST waiting one: the victim leaves
    // with CANCELED, never touched an executor; the newcomer waits
    EXPECT_CALL(*firstWaiterMock, OnStartFailed(ResultCode::CANCELED)).Times(1);
    EXPECT_CALL(*firstWaiterMock, Start()).Times(0);
    EXPECT_EQ(pool.Schedule(secondWaiter), true);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(FIRST_WAITER_ID).lock(), nullptr);
    EXPECT_NE(pool.Select(SECOND_WAITER_ID).lock(), nullptr);
    Mock::VerifyAndClearExpectations(firstWaiterMock.get());

    EXPECT_EQ(pool.Delete(HOLDER_ID), true);
    EXPECT_EQ(pool.Delete(SECOND_WAITER_ID), true);
    DrainSerialThread();
}

HWTEST_F(ContextPoolTest, ContextPoolSameCallerSupersedesRunningPrimary, TestSize.Level0)
{
    const uint64_t VICTIM_ID = 650;
    const uint64_t INCOMING_ID = 651;
    auto victim = MockContext::CreateWithContextId(VICTIM_ID);
    auto incoming = MockContext::CreateWithContextId(INCOMING_ID);
    ASSERT_NE(victim, nullptr);
    ASSERT_NE(incoming, nullptr);
    auto victimMock = std::static_pointer_cast<MockContext>(victim);
    auto incomingMock = std::static_pointer_cast<MockContext>(incoming);

    ON_CALL(*victimMock, GetContextType()).WillByDefault(Return(ContextType::CONTEXT_SIMPLE_AUTH));
    ON_CALL(*victimMock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*victimMock, GetCallerName()).WillByDefault(Return("same_caller"));
    ON_CALL(*victimMock, GetAuthType()).WillByDefault(Return(static_cast<int32_t>(PIN)));
    ON_CALL(*victimMock, GetUserId()).WillByDefault(Return(100));
    ON_CALL(*victimMock, Start()).WillByDefault(Return(true));
    EXPECT_CALL(*victimMock, Stop()).Times(1);

    ON_CALL(*incomingMock, GetContextType()).WillByDefault(Return(ContextType::CONTEXT_SIMPLE_AUTH));
    ON_CALL(*incomingMock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*incomingMock, GetCallerName()).WillByDefault(Return("same_caller"));
    ON_CALL(*incomingMock, GetAuthType()).WillByDefault(Return(static_cast<int32_t>(PIN)));
    ON_CALL(*incomingMock, GetUserId()).WillByDefault(Return(100));
    ON_CALL(*incomingMock, Start()).WillByDefault(Return(true));

    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(victim), true);
    DrainSerialThread();
    EXPECT_EQ(pool.Schedule(incoming), true);
    DrainSerialThread();

    EXPECT_EQ(pool.Delete(INCOMING_ID), true);
    EXPECT_EQ(pool.Delete(VICTIM_ID), true);
    DrainSerialThread();
}

HWTEST_F(ContextPoolTest, ContextPoolSameCallerNeedsPrimaryIncoming, TestSize.Level0)
{
    const uint64_t VICTIM_ID = 655;
    const uint64_t INCOMING_ID = 656;
    auto victim = MockContext::CreateWithContextId(VICTIM_ID);
    auto incoming = MockContext::CreateWithContextId(INCOMING_ID);
    ASSERT_NE(victim, nullptr);
    ASSERT_NE(incoming, nullptr);
    auto victimMock = std::static_pointer_cast<MockContext>(victim);
    auto incomingMock = std::static_pointer_cast<MockContext>(incoming);

    ON_CALL(*victimMock, GetContextType()).WillByDefault(Return(ContextType::CONTEXT_SIMPLE_AUTH));
    ON_CALL(*victimMock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*victimMock, GetCallerName()).WillByDefault(Return("same_caller"));
    ON_CALL(*victimMock, GetAuthType()).WillByDefault(Return(static_cast<int32_t>(PIN)));
    ON_CALL(*victimMock, GetUserId()).WillByDefault(Return(100));
    ON_CALL(*victimMock, Start()).WillByDefault(Return(true));
    EXPECT_CALL(*victimMock, Stop()).Times(0);

    ON_CALL(*incomingMock, GetContextType()).WillByDefault(Return(ContextType::CONTEXT_SIMPLE_AUTH));
    ON_CALL(*incomingMock, IsPrimaryContext()).WillByDefault(Return(false));
    ON_CALL(*incomingMock, GetCallerName()).WillByDefault(Return("same_caller"));
    ON_CALL(*incomingMock, GetAuthType()).WillByDefault(Return(static_cast<int32_t>(PIN)));
    ON_CALL(*incomingMock, GetUserId()).WillByDefault(Return(100));
    ON_CALL(*incomingMock, Start()).WillByDefault(Return(true));

    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(victim), true);
    DrainSerialThread();
    EXPECT_EQ(pool.Schedule(incoming), true);
    DrainSerialThread();

    EXPECT_EQ(pool.Delete(INCOMING_ID), true);
    EXPECT_EQ(pool.Delete(VICTIM_ID), true);
    DrainSerialThread();
}

HWTEST_F(ContextPoolTest, ContextPoolCancelByContextIdStopsRunningContext, TestSize.Level0)
{
    const uint64_t CONTEXT_ID = 660;
    auto context = MockContext::CreateWithContextId(CONTEXT_ID);
    ASSERT_NE(context, nullptr);
    auto mock = std::static_pointer_cast<MockContext>(context);
    EXPECT_CALL(*mock, Start()).WillOnce(Return(true));
    // Emulate a real context: the pool entry is dropped once the stop lands.
    EXPECT_CALL(*mock, Stop()).WillOnce([]() {
        return ContextPool::Instance().Delete(CONTEXT_ID);
    });
    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(context), true);
    DrainSerialThread();

    ContextPool::Instance().Cancel(CONTEXT_ID);
    // Stop is queued on the serial thread, never executed synchronously here.
    DrainSerialThread();
    EXPECT_EQ(pool.Select(CONTEXT_ID).lock(), nullptr);
}

HWTEST_F(ContextPoolTest, ContextPoolCancelByContextIdIsNoOpAfterEnd, TestSize.Level0)
{
    const uint64_t CONTEXT_ID = 661;
    auto context = MockContext::CreateWithContextId(CONTEXT_ID);
    ASSERT_NE(context, nullptr);
    auto mock = std::static_pointer_cast<MockContext>(context);
    EXPECT_CALL(*mock, Start()).WillOnce(Return(true));
    EXPECT_CALL(*mock, Stop()).WillOnce([]() {
        return ContextPool::Instance().Delete(CONTEXT_ID);
    });
    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(context), true);
    DrainSerialThread();

    ContextPool::Instance().Cancel(CONTEXT_ID);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(CONTEXT_ID).lock(), nullptr);
    // A late duplicate cancel must not re-enter an ended context: Stop stays at one.
    ContextPool::Instance().Cancel(CONTEXT_ID);
    DrainSerialThread();
}

HWTEST_F(ContextPoolTest, ContextPoolCancelWaitingContextReportsCanceledWithoutStart, TestSize.Level0)
{
    const uint64_t WAITING_ID = 662;
    auto context = MockContext::CreateWithContextId(WAITING_ID);
    ASSERT_NE(context, nullptr);
    auto mock = std::static_pointer_cast<MockContext>(context);
    // Keep the context in the waiting FIFO.
    EXPECT_CALL(*mock, CanStart(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mock, Start()).Times(0);
    // mirror BaseContext::Stop's never-started path: report CANCELED and leave
    // the pool via the result delivery's cleaner, which the mock callback lacks
    EXPECT_CALL(*mock, Stop()).WillOnce([weakMock = std::weak_ptr<MockContext>(mock)]() {
        if (auto ctx = weakMock.lock()) {
            ctx->OnStartFailed(ResultCode::CANCELED);
        }
        ContextPool::Instance().Delete(WAITING_ID);
        return true;
    });
    EXPECT_CALL(*mock, OnStartFailed(ResultCode::CANCELED)).Times(1);
    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(context), true);
    DrainSerialThread();

    ContextPool::Instance().Cancel(WAITING_ID);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(WAITING_ID).lock(), nullptr);
}

// a cleaner built from a null context must not delete anything: the old form
// collapsed it to id 0 and still called Delete, evicting an unrelated pooled
// context holding that id
HWTEST_F(ContextPoolTest, ContextPoolCleanerNullContextDeletesNothing, TestSize.Level0)
{
    const uint64_t CONTEXT_ID = 0;
    auto context = MockContext::CreateWithContextId(CONTEXT_ID);
    ASSERT_NE(context, nullptr);
    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(context), true);
    DrainSerialThread();
    EXPECT_NE(pool.Select(CONTEXT_ID).lock(), nullptr);

    ContextPool::Cleaner cleaner(nullptr);
    cleaner();
    // the pooled context is untouched: null context carries no valid id to delete
    EXPECT_NE(pool.Select(CONTEXT_ID).lock(), nullptr);

    EXPECT_EQ(pool.Delete(CONTEXT_ID), true);
    DrainSerialThread();
}

// a context whose id was never allocated (still INVALID_CONTEXT_ID) must not
// be deleted by id either: the delete would land on any pooled context
// holding that id
HWTEST_F(ContextPoolTest, ContextPoolCleanerInvalidContextIdDeletesNothing, TestSize.Level0)
{
    const uint64_t CONTEXT_ID = INVALID_CONTEXT_ID;
    auto pooled = MockContext::CreateWithContextId(CONTEXT_ID);
    ASSERT_NE(pooled, nullptr);
    auto &pool = ContextPool::Instance();
    EXPECT_EQ(pool.Schedule(pooled), true);
    DrainSerialThread();
    EXPECT_NE(pool.Select(CONTEXT_ID).lock(), nullptr);

    // model an id-less context: GetContextId still reports the invalid id
    auto idless = MockContext::CreateWithContextId(INVALID_CONTEXT_ID);
    ASSERT_NE(idless, nullptr);
    ContextPool::Cleaner cleaner(idless);
    cleaner();
    // the pooled context is untouched: an invalid id deletes nothing
    EXPECT_NE(pool.Select(CONTEXT_ID).lock(), nullptr);

    EXPECT_EQ(pool.Delete(CONTEXT_ID), true);
    DrainSerialThread();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
