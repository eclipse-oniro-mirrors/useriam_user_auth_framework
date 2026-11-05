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

#include <future>
#include <optional>
#include <vector>

#include "attributes.h"
#include "context_pool.h"
#include "context_arbitration_policy.h"
#include "iam_common_defines.h"
#include "delete_context.h"
#include "enroll_context.h"
#include "iam_ptr.h"
#include "mock_authentication.h"
#include "mock_context.h"
#include "mock_deletion.h"
#include "mock_enrollment.h"
#include "mock_user_auth_engine.h"
#include "mock_resource_node.h"
#include "mock_schedule_node.h"
#include "resource_node_pool.h"
#include "simple_auth_context.h"
#include "sudo_auth_context.h"
#include "thread_handler.h"
#include "widget_context.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t PIN_EXECUTOR_INDEX = 601;
// drain passes: EnsureTask only waits out tasks posted before it, not their nested posts
constexpr int32_t DRAIN_PASSES = 3;
constexpr int32_t REMAIN_SUFFICIENT = 4;
constexpr uint64_t DIALOG_CHILD_ID_OFFSET = 100;

void DrainSerialThread()
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    for (int pass = 0; pass < DRAIN_PASSES; ++pass) {
        handler->EnsureTask([]() {});
    }
}

void PrimePinCredentialAndExecutor(int32_t remainTimes, int32_t freezingTime)
{
    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential(_, _, _))
        .WillByDefault([](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            infos.push_back({.credentialId = 1, .executorIndex = PIN_EXECUTOR_INDEX, .templateId = 9,
                .authType = static_cast<HdiAuthType>(AuthType::PIN), .executorMatcher = 1,
                .executorSensorHint = 1, .authSubType = static_cast<uint64_t>(PinSubType::PIN_SIX)});
            return SUCCESS;
        });
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(PIN_EXECUTOR_INDEX, PIN, ALL_IN_ONE);
    ASSERT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _))
        .WillByDefault([remainTimes, freezingTime](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainTimes);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime);
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, static_cast<int32_t>(PinSubType::PIN_SIX));
            return SUCCESS;
        });
}

std::shared_ptr<SimpleAuthContext> MakeSimpleAuth(uint64_t contextId, int32_t userId, AuthType authType,
    bool isPrimary, std::shared_ptr<MockAuthentication> &authOut, std::shared_ptr<MockContextCallback> &cbOut)
{
    auto auth = Common::MakeShared<MockAuthentication>();
    auto node = Common::MakeShared<MockScheduleNode>();
    EXPECT_NE(auth, nullptr);
    EXPECT_NE(node, nullptr);
    ON_CALL(*node, GetScheduleId()).WillByDefault(Return(contextId));
    ON_CALL(*node, StartSchedule()).WillByDefault(Return(true));
    ON_CALL(*node, StopSchedule()).WillByDefault(Return(true));
    ON_CALL(*auth, Start(_, _, _))
        .WillByDefault([node](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                            AcquireInfoCallback &acquireInfoCallback,
                            std::shared_ptr<ScheduleNodeCallback> callback) {
            scheduleList.push_back(node);
            return true;
        });
    ON_CALL(*auth, Cancel()).WillByDefault(Return(true));
    ON_CALL(*auth, GetUserId()).WillByDefault(Return(userId));
    ON_CALL(*auth, GetAuthType()).WillByDefault(Return(authType));
    ON_CALL(*auth, GetAccessTokenId()).WillByDefault(Return(1U));
    ON_CALL(*auth, GetLatestError()).WillByDefault(Return(GENERAL_ERROR));
    auto callback = Common::MakeShared<MockContextCallback>();
    auto context = Common::MakeShared<SimpleAuthContext>(contextId, auth, false, isPrimary, callback);
    authOut = auth;
    cbOut = callback;
    return context;
}

std::shared_ptr<EnrollContext> MakeEnrollContext(uint64_t contextId, std::shared_ptr<MockEnrollment> &enrollOut)
{
    auto enroll = Common::MakeShared<MockEnrollment>();
    EXPECT_NE(enroll, nullptr);
    // OnStart requires exactly one node from Start; capture it by value or the
    // reference dangles after this helper returns
    auto node = Common::MakeShared<MockScheduleNode>();
    ON_CALL(*node, GetScheduleId()).WillByDefault(Return(contextId));
    ON_CALL(*node, StartSchedule()).WillByDefault(Return(true));
    ON_CALL(*node, StopSchedule()).WillByDefault(Return(true));
    ON_CALL(*enroll, GetAccessTokenId()).WillByDefault(Return(1U));
    ON_CALL(*enroll, GetUserId()).WillByDefault(Return(1));
    ON_CALL(*enroll, Start(_, _))
        .WillByDefault([node](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
            std::shared_ptr<ScheduleNodeCallback> callback) {
            scheduleList.push_back(node);
            return true;
        });
    auto callback = Common::MakeShared<MockContextCallback>();
    auto context = Common::MakeShared<EnrollContext>(contextId, enroll, false, callback);
    enrollOut = enroll;
    return context;
}

std::shared_ptr<DeleteContext> MakeDeleteContext(uint64_t contextId)
{
    auto deletion = Common::MakeShared<MockDeletion>();
    EXPECT_NE(deletion, nullptr);
    ON_CALL(*deletion, GetAccessTokenId()).WillByDefault(Return(1U));
    ON_CALL(*deletion, GetUserId()).WillByDefault(Return(1));
    // mark the deletion credential-delete so OnStart takes the direct-success branch
    ON_CALL(*deletion, Start(_, _, _, _))
        .WillByDefault([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
            std::shared_ptr<ScheduleNodeCallback> callback, bool &isCredentialDelete,
            std::vector<EngCredentialInfo> &credentialInfos) {
            isCredentialDelete = true;
            return true;
        });
    auto callback = Common::MakeShared<MockContextCallback>();
    return Common::MakeShared<DeleteContext>(contextId, deletion, callback);
}

// SUDO orchestrator with both children substituted: records the branch and stays
// in RUN until the test drives OnChildResult
class StubChildSudoContext : public SudoAuthContext {
public:
    StubChildSudoContext(uint64_t contextId, const ContextFactory::SudoAuthContextPara &para,
        std::shared_ptr<ContextCallback> callback)
        : SudoAuthContext(contextId, para, callback)
    {
    }
    ~StubChildSudoContext() override = default;

    bool StartSilentChild(const ContextFactory::AuthProfile &profile) override
    {
        silentBranchCount++;
        childIsWidget_ = false;
        return InstallStubChild();
    }

    bool StartWidgetChild(const ContextFactory::AuthProfile &profile) override
    {
        if (dialogGate_.has_value()) {
            dialogGate_->wait();
            dialogGate_.reset();
        }
        widgetBranchCount++;
        childIsWidget_ = true;
        dialogActive_.store(true);
        ContextPool::Instance().NotifyPreemptStateChanged();
        return InstallStubChild();
    }

    void HoldDialogStart(std::future<void> gate)
    {
        dialogGate_ = std::move(gate);
    }

    bool InstallStubChild()
    {
        auto stub = MockContext::CreateWithContextId(GetContextId() + 1);
        EXPECT_NE(stub, nullptr);
        ON_CALL(*static_cast<MockContext *>(stub.get()), Start()).WillByDefault(Return(true));
        ON_CALL(*static_cast<MockContext *>(stub.get()), Stop()).WillByDefault(Return(true));
        childContextId_ = stub->GetContextId();
        phase_ = PHASE_RUN;
        return true;
    }

    int silentBranchCount = 0;
    int widgetBranchCount = 0;

private:
    std::optional<std::future<void>> dialogGate_;
};

std::shared_ptr<StubChildSudoContext> MakeSudo(uint64_t contextId, int32_t userId,
    std::shared_ptr<MockContextCallback> &cbOut, const std::string &callerName = "sudo_test")
{
    ContextFactory::SudoAuthContextPara para;
    para.userId = userId;
    para.tokenId = 1;
    para.sdkVersion = INNER_API_VERSION_10000;
    para.callerName = callerName;
    para.atl = ATL2;
    para.additionalInfo = "sudo test title";
    auto callback = Common::MakeShared<MockContextCallback>();
    auto context = Common::MakeShared<StubChildSudoContext>(contextId, para, callback);
    cbOut = callback;
    return context;
}

// dialog child goes through the REAL Schedule against its pooled dialog parent:
// mirrors SudoAuthContext::StartWidgetChild's flag/id-before-Schedule ordering,
// with a mock child whose yield rule matches WidgetContext (yields to widgets)
class RealScheduleSudoContext : public StubChildSudoContext {
public:
    RealScheduleSudoContext(uint64_t contextId, const ContextFactory::SudoAuthContextPara &para,
        std::shared_ptr<ContextCallback> callback)
        : StubChildSudoContext(contextId, para, callback)
    {
    }
    ~RealScheduleSudoContext() override = default;

    bool StartWidgetChild(const ContextFactory::AuthProfile &profile) override
    {
        widgetBranchCount++;
        childIsWidget_ = true;
        dialogActive_.store(true);
        ContextPool::Instance().NotifyPreemptStateChanged();
        auto stub = MockContext::CreateWithContextId(GetContextId() + DIALOG_CHILD_ID_OFFSET);
        EXPECT_NE(stub, nullptr);
        auto raw = static_cast<MockContext *>(stub.get());
        ON_CALL(*raw, GetContextType()).WillByDefault(Return(ContextType::WIDGET_AUTH_CONTEXT));
        ON_CALL(*raw, GetAuthType()).WillByDefault(Return(AuthType::PIN));
        ON_CALL(*raw, Start()).WillByDefault(Return(true));
        ON_CALL(*raw, Stop()).WillByDefault(Return(true));
        // same rule as WidgetContext::GetPreemptDecision
        ON_CALL(*raw, GetPreemptDecision(_)).WillByDefault([](const Context &newRequest) {
            if (newRequest.GetContextType() != ContextType::WIDGET_AUTH_CONTEXT) {
                return PreemptDecision::KEEP_RUNNING;
            }
            return PreemptDecision::STOP_NOW;
        });
        childContextId_ = stub->GetContextId();
        phase_ = PHASE_RUN;
        return ContextPool::Instance().Schedule(stub) && phase_ != PHASE_END;
    }
};
// helper: a primary PIN-bearing widget mock that waits by the real policy
std::shared_ptr<MockContext> MakeWaitingWidgetMock(uint64_t contextId, int32_t userId, int &startCount)
{
    auto context = MockContext::CreateWithContextId(contextId);
    EXPECT_NE(context, nullptr);
    auto mock = std::static_pointer_cast<MockContext>(context);
    ON_CALL(*mock, GetContextType()).WillByDefault(Return(ContextType::WIDGET_AUTH_CONTEXT));
    ON_CALL(*mock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*mock, GetUserId()).WillByDefault(Return(userId));
    ON_CALL(*mock, GetAuthType()).WillByDefault(Return(AuthType::PIN));
    ON_CALL(*mock, CanStart(_)).WillByDefault(
        [raw = mock.get()](const std::vector<std::weak_ptr<Context>> &predecessors) {
            return ContextAdmissionPolicy::CanStart(*raw, predecessors);
        });
    // same rule as WidgetContext: the session only ever yields to a newer
    // widget session (replace-only, no user check), never to other newcomers
    ON_CALL(*mock, GetPreemptDecision(_)).WillByDefault([](const Context &newRequest) {
        if (newRequest.GetContextType() != ContextType::WIDGET_AUTH_CONTEXT) {
            return PreemptDecision::KEEP_RUNNING;
        }
        return PreemptDecision::STOP_NOW;
    });
    ON_CALL(*mock, Start()).WillByDefault([&startCount]() {
        startCount++;
        return true;
    });
    return mock;
}

} // namespace

class ContextArbitrationTest : public testing::Test {
public:
    void TearDown() override
    {
        DrainSerialThread();
        auto &pool = ContextPool::Instance();
        for (auto &id : insertedIds_) {
            pool.Delete(id);
        }
        insertedIds_.clear();
        DrainSerialThread();
        for (auto &weak : pool.SelectAll()) {
            if (auto ctx = weak.lock()) {
                pool.Delete(ctx->GetContextId());
            }
        }
        DrainSerialThread();
        ResourceNodePool::Instance().Delete(PIN_EXECUTOR_INDEX);
        MockUserAuthEngine::Holder::GetInstance().Reset();
    }

    void Track(uint64_t contextId)
    {
        insertedIds_.push_back(contextId);
    }

private:
    std::vector<uint64_t> insertedIds_;
};

HWTEST_F(ContextArbitrationTest, PinSlotCrossUserNormalAuthsNoMutex, TestSize.Level0)
{
    constexpr uint64_t authAId = 101;
    constexpr uint64_t authBId = 102;
    constexpr int32_t userA = 1;
    constexpr int32_t userB = 2;
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(authAId, userA, PIN, true, authA, cbA);
    EXPECT_CALL(*authA, Start(_, _, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(authAId);

    std::shared_ptr<MockAuthentication> authB;
    std::shared_ptr<MockContextCallback> cbB;
    auto ctxB = MakeSimpleAuth(authBId, userB, PIN, true, authB, cbB);
    EXPECT_CALL(*authB, Start(_, _, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(ctxB));
    Track(authBId);
    DrainSerialThread();
}

HWTEST_F(ContextArbitrationTest, PinSlotSameUserNormalAuthsNoMutex, TestSize.Level0)
{
    constexpr uint64_t authAId = 111;
    constexpr uint64_t authBId = 112;
    constexpr int32_t user = 2;
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(authAId, user, PIN, true, authA, cbA);
    ON_CALL(*cbA, GetCallerName()).WillByDefault(Return("normal_auth_first"));
    EXPECT_CALL(*authA, Start(_, _, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(authAId);
    DrainSerialThread();

    std::shared_ptr<MockAuthentication> authB;
    std::shared_ptr<MockContextCallback> cbB;
    auto ctxB = MakeSimpleAuth(authBId, user, PIN, true, authB, cbB);
    ON_CALL(*cbB, GetCallerName()).WillByDefault(Return("normal_auth_second"));
    EXPECT_CALL(*authB, Start(_, _, _)).Times(1);
    EXPECT_CALL(*authA, Cancel()).Times(0);
    ASSERT_TRUE(pool.Schedule(ctxB));
    Track(authBId);
    DrainSerialThread();
    EXPECT_NE(pool.Select(authAId).lock(), nullptr);
    EXPECT_NE(pool.Select(authBId).lock(), nullptr);
}

HWTEST_F(ContextArbitrationTest, PinSlotSudoWaitsBehindNormalAuth, TestSize.Level0)
{
    constexpr uint64_t authId = 201;
    constexpr uint64_t sudoId = 202;
    constexpr int32_t user = 100;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(authId, user, PIN, true, authA, cbA);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(authId);
    DrainSerialThread();

    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    // WAITING: QUERY has not run at all.
    EXPECT_EQ(sudo->silentBranchCount, 0);
    EXPECT_EQ(sudo->widgetBranchCount, 0);

    // terminal of the front auth frees the slot; drain admits the SUDO (remain=4 -> silent)
    EXPECT_TRUE(pool.Delete(authId));
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);
    EXPECT_EQ(sudo->widgetBranchCount, 0);
}

HWTEST_F(ContextArbitrationTest, PinSlotSudoVsSudoFifo, TestSize.Level0)
{
    constexpr uint64_t authId = 301;
    constexpr uint64_t sudoFirstId = 302;
    constexpr uint64_t sudoSecondId = 303;
    constexpr int32_t user = 5;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(authId, user, PIN, true, authA, cbA);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(authId);
    DrainSerialThread();

    std::shared_ptr<MockContextCallback> cbFirst;
    // distinct callers: a same-caller re-request would supersede its own oldest waiter
    // (ContextPoolSameCallerPreemptsOwnOldestWaiting), not what this FIFO case asserts
    auto sudoFirst = MakeSudo(sudoFirstId, user, cbFirst, "sudo_fifo_first");
    ASSERT_TRUE(pool.Schedule(sudoFirst));
    Track(sudoFirstId);
    std::shared_ptr<MockContextCallback> cbSecond;
    auto sudoSecond = MakeSudo(sudoSecondId, user, cbSecond, "sudo_fifo_second");
    ASSERT_TRUE(pool.Schedule(sudoSecond));
    Track(sudoSecondId);
    EXPECT_EQ(sudoFirst->silentBranchCount + sudoFirst->widgetBranchCount, 0);
    EXPECT_EQ(sudoSecond->silentBranchCount + sudoSecond->widgetBranchCount, 0);

    // Front auth leaves; only the first-in SUDO is admitted (it stays RUN).
    EXPECT_TRUE(pool.Delete(authId));
    DrainSerialThread();
    EXPECT_EQ(sudoFirst->silentBranchCount, 1);
    EXPECT_EQ(sudoSecond->silentBranchCount + sudoSecond->widgetBranchCount, 0);

    // First SUDO terminal (driven) frees the slot for the second.
    sudoFirst->OnChildResult(ResultCode::CANCELED, {});
    EXPECT_TRUE(pool.Delete(sudoFirstId));
    DrainSerialThread();
    EXPECT_EQ(sudoSecond->silentBranchCount, 1);
}

HWTEST_F(ContextArbitrationTest, PinSlotCancelWaitingZeroConsumption, TestSize.Level0)
{
    constexpr uint64_t authId = 401;
    constexpr uint64_t sudoId = 402;
    constexpr int32_t user = 8;
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(authId, user, PIN, true, authA, cbA);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(authId);
    DrainSerialThread();

    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    EXPECT_EQ(sudo->silentBranchCount + sudo->widgetBranchCount, 0);

    EXPECT_CALL(*sudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    // capture the id only (as the production Cleaner does): a shared_ptr capture
    // would cycle context -> callback -> action -> context and leak the mock
    ON_CALL(*sudoCb, OnResult(_, _)).WillByDefault([sudoId](int32_t, const Attributes &) {
        ContextPool::Instance().Delete(sudoId);
    });
    EXPECT_TRUE(sudo->Stop());
    DrainSerialThread();
    // Out of pool and FIFO; the slot holder keeps running undisturbed.
    EXPECT_EQ(pool.Select(sudoId).lock(), nullptr);
    EXPECT_TRUE(pool.Select(authId).lock() != nullptr);
}

HWTEST_F(ContextArbitrationTest, StopBeforePostedStartDeliversCanceledImmediately, TestSize.Level0)
{
    constexpr uint64_t authId = 451;
    constexpr int32_t user = 21;
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> auth;
    std::shared_ptr<MockContextCallback> cb;
    auto ctx = MakeSimpleAuth(authId, user, PIN, true, auth, cb);
    Track(authId);
    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    // capture the id only (as the production Cleaner does): a shared_ptr capture
    // would cycle context -> callback -> action -> context and leak the mock
    ON_CALL(*cb, OnResult(_, _)).WillByDefault([authId](int32_t, const Attributes &) {
        ContextPool::Instance().Delete(authId);
    });

    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    auto release = std::make_shared<std::promise<void>>();
    handler->PostTask([release]() { release->get_future().get(); });

    EXPECT_TRUE(pool.Schedule(ctx));
    EXPECT_TRUE(ctx->Stop());
    EXPECT_EQ(pool.Select(authId).lock(), nullptr);

    release->set_value();
    DrainSerialThread();
}

HWTEST_F(ContextArbitrationTest, StopWaitingContextTwiceDeliversCanceledOnce, TestSize.Level0)
{
    constexpr uint64_t authId = 461;
    constexpr uint64_t sudoId = 462;
    constexpr int32_t user = 31;
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(authId, user, PIN, true, authA, cbA);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(authId);

    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    Track(sudoId);
    EXPECT_CALL(*sudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    // capture the id only (as the production Cleaner does): a shared_ptr capture
    // would cycle context -> callback -> action -> context and leak the mock
    ON_CALL(*sudoCb, OnResult(_, _)).WillByDefault([sudoId](int32_t, const Attributes &) {
        ContextPool::Instance().Delete(sudoId);
    });

    EXPECT_TRUE(pool.Schedule(sudo));
    EXPECT_EQ(sudo->silentBranchCount, 0);
    EXPECT_TRUE(sudo->Stop());
    EXPECT_EQ(pool.Select(sudoId).lock(), nullptr);
    EXPECT_TRUE(sudo->Stop());
    EXPECT_EQ(pool.Select(sudoId).lock(), nullptr);

    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 0);
    EXPECT_TRUE(pool.Select(authId).lock() != nullptr);
}

HWTEST_F(ContextArbitrationTest, PinEnrollDoesNotContendWithAuth, TestSize.Level0)
{
    constexpr uint64_t authId = 501;
    constexpr uint64_t sudoId = 502;
    constexpr uint64_t enrollId = 510;
    constexpr int32_t user = 10;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(authId, user, PIN, true, authA, cbA);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(authId);
    DrainSerialThread();

    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    EXPECT_EQ(sudo->silentBranchCount + sudo->widgetBranchCount, 0);

    // enroll/delete take no part in arbitration: no preempt, no mutex, no queue
    std::shared_ptr<MockEnrollment> enroll;
    auto enrollCtx = MakeEnrollContext(enrollId, enroll);
    EXPECT_CALL(*enroll, Start(_, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(enrollCtx));
    Track(enrollId);
    DrainSerialThread();

    EXPECT_CALL(*authA, Cancel()).Times(0);
    EXPECT_CALL(*sudoCb, OnResult(_, _)).Times(0);
    EXPECT_NE(pool.Select(authId).lock(), nullptr);
    EXPECT_NE(pool.Select(sudoId).lock(), nullptr);
    EXPECT_EQ(sudo->silentBranchCount + sudo->widgetBranchCount, 0);
    EXPECT_TRUE(ContextAdmissionPolicy::CanStart(*enrollCtx, std::vector<std::weak_ptr<Context>>{ctxA}));
}

HWTEST_F(ContextArbitrationTest, PinSlotFaceEnrollNoPreempt, TestSize.Level0)
{
    constexpr uint64_t authId = 601;
    constexpr uint64_t enrollId = 602;
    constexpr int32_t user = 12;
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(authId, user, PIN, true, authA, cbA);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(authId);
    DrainSerialThread();

    EXPECT_CALL(*authA, Cancel()).Times(0);
    std::shared_ptr<MockEnrollment> enroll;
    // primary like all credential-change requests, yet it must not contend:
    // pin-slot membership comes from the auth types alone
    auto enrollCtx = MakeEnrollContext(enrollId, enroll);
    EXPECT_CALL(*enroll, Start(_, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(enrollCtx));
    Track(enrollId);
    DrainSerialThread();
    EXPECT_TRUE(ContextAdmissionPolicy::CanStart(*enrollCtx, std::vector<std::weak_ptr<Context>>{ctxA}));
}

HWTEST_F(ContextArbitrationTest, PinSlotFaceDeleteNoPreempt, TestSize.Level0)
{
    constexpr uint64_t authId = 651;
    constexpr uint64_t deleteId = 652;
    constexpr int32_t user = 17;
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(authId, user, PIN, true, authA, cbA);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(authId);
    DrainSerialThread();

    EXPECT_CALL(*authA, Cancel()).Times(0);
    auto deleteCtx = MakeDeleteContext(deleteId);
    ASSERT_TRUE(pool.Schedule(deleteCtx));
    Track(deleteId);
    DrainSerialThread();
    EXPECT_NE(pool.Select(deleteId).lock(), nullptr);
    EXPECT_TRUE(ContextAdmissionPolicy::CanStart(*deleteCtx, std::vector<std::weak_ptr<Context>>{ctxA}));
}

HWTEST_F(ContextArbitrationTest, PinAuthDoesNotWaitBehindPinEnroll, TestSize.Level0)
{
    constexpr uint64_t enrollId = 661;
    constexpr uint64_t authId = 662;
    constexpr int32_t user = 10;
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockEnrollment> enroll;
    auto enrollCtx = MakeEnrollContext(enrollId, enroll);
    EXPECT_CALL(*enroll, Start(_, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(enrollCtx));
    Track(enrollId);
    DrainSerialThread();

    // the running enroll does not gate auth: the pin auth starts immediately
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(authId, user, PIN, true, authA, cbA);
    EXPECT_CALL(*authA, Start(_, _, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(authId);
    DrainSerialThread();
    EXPECT_NE(pool.Select(authId).lock(), nullptr);
    EXPECT_NE(pool.Select(enrollId).lock(), nullptr);
}

HWTEST_F(ContextArbitrationTest, PinDeleteDoesNotContendWithSudo, TestSize.Level0)
{
    constexpr uint64_t sudoId = 701;
    constexpr uint64_t deleteId = 710;
    constexpr int32_t user = 13;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);

    // the delete neither preempts nor queues: it starts immediately
    auto deleteCtx = MakeDeleteContext(deleteId);
    ASSERT_TRUE(pool.Schedule(deleteCtx));
    Track(deleteId);
    DrainSerialThread();
    EXPECT_CALL(*sudoCb, OnResult(_, _)).Times(0);
    EXPECT_NE(pool.Select(sudoId).lock(), nullptr);
    EXPECT_TRUE(ContextAdmissionPolicy::CanStart(*deleteCtx, std::vector<std::weak_ptr<Context>>{sudo}));
}

HWTEST_F(ContextArbitrationTest, PinSlotWidgetWithPinHoldsSlot, TestSize.Level0)
{
    constexpr uint64_t widgetId = 801;
    constexpr uint64_t sudoId = 802;
    constexpr int32_t user = 14;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    ContextFactory::AuthWidgetContextPara para;
    para.userId = user;
    para.authTypeList = {AuthType::PIN};
    auto callback = Common::MakeShared<MockContextCallback>();
    auto widget = Common::MakeShared<WidgetContext>(widgetId, para, true, callback, nullptr, nullptr);
    ASSERT_NE(widget, nullptr);
    ASSERT_TRUE(pool.Schedule(widget));
    Track(widgetId);
    // the slot is held by pool membership; the posted start lands during the drain below
    DrainSerialThread();

    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    EXPECT_EQ(sudo->silentBranchCount + sudo->widgetBranchCount, 0);

    EXPECT_TRUE(pool.Delete(widgetId));
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);

    sudo->OnChildResult(ResultCode::CANCELED, {});
}

HWTEST_F(ContextArbitrationTest, PinSlotInternalChildNotHolder, TestSize.Level0)
{
    constexpr uint64_t sudoId = 901;
    constexpr uint64_t childId = sudoId + DIALOG_CHILD_ID_OFFSET;
    constexpr uint64_t authId = 902;
    constexpr int32_t user = 16;
    PrimePinCredentialAndExecutor(1, 0);
    auto &pool = ContextPool::Instance();
    ContextFactory::SudoAuthContextPara para;
    para.userId = user;
    para.tokenId = 1;
    para.sdkVersion = INNER_API_VERSION_10000;
    para.callerName = "sudo_child_not_holder";
    para.atl = ATL2;
    para.additionalInfo = "sudo test title";
    auto sudoCb = Common::MakeShared<MockContextCallback>();
    auto sudo = Common::MakeShared<RealScheduleSudoContext>(sudoId, para, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    Track(childId);
    DrainSerialThread();
    EXPECT_EQ(sudo->widgetBranchCount, 1);
    auto child = pool.Select(childId).lock();
    ASSERT_NE(child, nullptr);
    EXPECT_THAT(child->GetAuthTypeList(), testing::Contains(AuthType::PIN));

    EXPECT_CALL(*sudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    sudo->OnChildResult(ResultCode::CANCELED, {});
    pool.Delete(sudoId);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(sudoId).lock(), nullptr);
    EXPECT_NE(pool.Select(childId).lock(), nullptr);

    std::shared_ptr<MockAuthentication> auth;
    std::shared_ptr<MockContextCallback> cb;
    auto ctx = MakeSimpleAuth(authId, user, PIN, true, auth, cb);
    EXPECT_CALL(*auth, Start(_, _, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(ctx));
    Track(authId);
    DrainSerialThread();
    EXPECT_NE(pool.Select(authId).lock(), nullptr);
    EXPECT_NE(pool.Select(childId).lock(), nullptr);
}
HWTEST_F(ContextArbitrationTest, EarlierSudoBlocksLaterPinButNotFaceOrChildren, TestSize.Level0)
{
    constexpr uint64_t pinAId = 1001;
    constexpr uint64_t sudoId = 1002;
    constexpr uint64_t pinBId = 1003;
    constexpr uint64_t faceId = 1004;
    constexpr uint64_t childId = 1005;
    constexpr int32_t pinUser = 1;
    constexpr int32_t faceUser = 4;
    constexpr int32_t childUser = 5;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA, authB, authFace, authChild;
    std::shared_ptr<MockContextCallback> cbA, cbB, cbFace, cbChild, sudoCb;
    auto a = MakeSimpleAuth(pinAId, pinUser, PIN, true, authA, cbA);
    auto sudo = MakeSudo(sudoId, pinUser, sudoCb);
    auto b = MakeSimpleAuth(pinBId, pinUser, PIN, true, authB, cbB);
    auto face = MakeSimpleAuth(faceId, faceUser, FACE, true, authFace, cbFace);
    auto child = MakeSimpleAuth(childId, childUser, PIN, false, authChild, cbChild);
    for (auto id : {pinAId, sudoId, pinBId, faceId, childId}) {
        Track(id);
    }
    ASSERT_TRUE(pool.Schedule(a));
    DrainSerialThread();
    ASSERT_TRUE(pool.Schedule(sudo));
    EXPECT_CALL(*authB, Start(_, _, _)).Times(0);
    EXPECT_CALL(*authFace, Start(_, _, _)).Times(1);
    EXPECT_CALL(*authChild, Start(_, _, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(b));
    ASSERT_TRUE(pool.Schedule(face));
    ASSERT_TRUE(pool.Schedule(child));
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 0);

    ASSERT_TRUE(pool.Delete(pinAId));
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(authB.get()));
    EXPECT_CALL(*authB, Start(_, _, _)).Times(1);
    ASSERT_TRUE(pool.Delete(sudoId));
    DrainSerialThread();
}

HWTEST_F(ContextArbitrationTest, CancelEarlierSudoAdmitsLaterPinWhileHolderRuns, TestSize.Level0)
{
    constexpr uint64_t authId = 1101;
    constexpr uint64_t sudoId = 1102;
    constexpr uint64_t pinId = 1103;
    constexpr int32_t user = 1;
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA, authB;
    std::shared_ptr<MockContextCallback> cbA, cbB, sudoCb;
    auto a = MakeSimpleAuth(authId, user, PIN, true, authA, cbA);
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    auto b = MakeSimpleAuth(pinId, user, PIN, true, authB, cbB);
    for (auto id : {authId, sudoId, pinId}) {
        Track(id);
    }
    ASSERT_TRUE(pool.Schedule(a));
    DrainSerialThread();
    ASSERT_TRUE(pool.Schedule(sudo));
    EXPECT_CALL(*authB, Start(_, _, _)).Times(0);
    ASSERT_TRUE(pool.Schedule(b));
    DrainSerialThread();
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(authB.get()));
    EXPECT_CALL(*authB, Start(_, _, _)).Times(1);
    EXPECT_CALL(*sudoCb, OnResult(CANCELED, _)).Times(1);
    // capture the id only (as the production Cleaner does): a shared_ptr capture
    // would cycle context -> callback -> action -> context and leak the mock
    ON_CALL(*sudoCb, OnResult(_, _)).WillByDefault([sudoId](int32_t, const Attributes &) {
        ContextPool::Instance().Delete(sudoId);
    });
    ThreadHandler::GetSingleThreadInstance()->EnsureTask([sudo]() { sudo->Stop(); });
    DrainSerialThread();
    EXPECT_NE(pool.Select(authId).lock(), nullptr);
}

HWTEST_F(ContextArbitrationTest, SudoDialogPreemptedByNewSudo, TestSize.Level0)
{
    constexpr uint64_t oldSudoId = 1201;
    constexpr uint64_t newSudoId = 1210;
    constexpr int32_t oldUser = 18;
    constexpr int32_t newUser = 19;
    // remain=1 routes the SUDO to the last-attempt warning dialog
    PrimePinCredentialAndExecutor(1, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> oldSudoCb;
    auto oldSudo = MakeSudo(oldSudoId, oldUser, oldSudoCb);
    ASSERT_TRUE(pool.Schedule(oldSudo));
    Track(oldSudoId);
    DrainSerialThread();
    EXPECT_EQ(oldSudo->widgetBranchCount, 1);

    // a newer SUDO takes over the dialog directly: the old one is stopped as the
    // victim and the new SUDO claims the window in the same round
    std::shared_ptr<MockContextCallback> newSudoCb;
    auto newSudo = MakeSudo(newSudoId, newUser, newSudoCb);
    ASSERT_TRUE(pool.Schedule(newSudo));
    Track(newSudoId);
    DrainSerialThread();
    EXPECT_EQ(newSudo->widgetBranchCount, 1);

    // the stop cascaded to the old child: drive the stub terminal and release
    EXPECT_CALL(*oldSudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    oldSudo->OnChildResult(ResultCode::CANCELED, {});
    pool.Delete(oldSudoId);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(oldSudoId).lock(), nullptr);
    EXPECT_EQ(newSudo->widgetBranchCount, 1);

    newSudo->OnChildResult(ResultCode::CANCELED, {});
    pool.Delete(newSudoId);
}

// same-user takeover is same-round too: the dialog SUDO victim is sentenced in
// this pass, so the per-user pin predicate must not hold the new SUDO back until
// the old tree tears down (victims never gate their takers)
HWTEST_F(ContextArbitrationTest, SudoDialogPreemptedByNewSudoSameUser, TestSize.Level0)
{
    // remain=1 routes both SUDOs to the last-attempt warning dialog
    PrimePinCredentialAndExecutor(1, 0);
    constexpr uint64_t oldSudoId = 1220;
    constexpr uint64_t newSudoId = 1230;
    constexpr int32_t user = 21;
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> oldSudoCb;
    auto oldSudo = MakeSudo(oldSudoId, user, oldSudoCb);
    ASSERT_TRUE(pool.Schedule(oldSudo));
    Track(oldSudoId);
    DrainSerialThread();
    EXPECT_EQ(oldSudo->widgetBranchCount, 1);

    std::shared_ptr<MockContextCallback> newSudoCb;
    auto newSudo = MakeSudo(newSudoId, user, newSudoCb);
    ASSERT_TRUE(pool.Schedule(newSudo));
    Track(newSudoId);
    DrainSerialThread();
    EXPECT_EQ(newSudo->widgetBranchCount, 1);

    EXPECT_CALL(*oldSudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    oldSudo->OnChildResult(ResultCode::CANCELED, {});
    pool.Delete(oldSudoId);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(oldSudoId).lock(), nullptr);
    EXPECT_EQ(newSudo->widgetBranchCount, 1);

    newSudo->OnChildResult(ResultCode::CANCELED, {});
    pool.Delete(newSudoId);
}

// the dialog child really goes through Schedule while its dialog parent is
// pooled: the window admission clause must not block a non-primary child on its
// own parent, and a later same-user primary widget replaces the whole dialog
// (parent + live child) in one round
HWTEST_F(ContextArbitrationTest, DialogChildRealScheduleAgainstPooledParent, TestSize.Level0)
{
    constexpr uint64_t sudoId = 1700;
    constexpr uint64_t childId = sudoId + DIALOG_CHILD_ID_OFFSET;
    constexpr uint64_t widgetId = 1701;
    constexpr int32_t user = 40;
    PrimePinCredentialAndExecutor(1, 0);
    auto &pool = ContextPool::Instance();
    ContextFactory::SudoAuthContextPara para;
    para.userId = user;
    para.tokenId = 1;
    para.sdkVersion = INNER_API_VERSION_10000;
    para.callerName = "sudo_real_child";
    para.atl = ATL2;
    para.additionalInfo = "sudo test title";
    auto sudoCb = Common::MakeShared<MockContextCallback>();
    auto sudo = Common::MakeShared<RealScheduleSudoContext>(sudoId, para, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    Track(childId); // the dialog child created inside StartWidgetChild
    DrainSerialThread();
    EXPECT_EQ(sudo->widgetBranchCount, 1);
    // the non-primary child was admitted against its pooled dialog parent
    EXPECT_NE(pool.Select(childId).lock(), nullptr);
    // the parent is spared: its own dialog child's spawn sentences nobody
    EXPECT_NE(pool.Select(sudoId).lock(), nullptr);
    EXPECT_CALL(*sudoCb, OnResult(_, _)).Times(0);
    Mock::VerifyAndClearExpectations(sudoCb.get());

    // a same-user primary widget takes over the whole dialog in one round
    int wStart = 0;
    auto w = MakeWaitingWidgetMock(widgetId, user, wStart);
    ASSERT_TRUE(pool.Schedule(w));
    Track(widgetId);
    DrainSerialThread();
    EXPECT_EQ(wStart, 1);

    // parent was sentenced as victim: drive its stub terminal to finish teardown
    EXPECT_CALL(*sudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    sudo->OnChildResult(ResultCode::CANCELED, {});
    pool.Delete(sudoId);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(sudoId).lock(), nullptr);
    EXPECT_EQ(wStart, 1);

    EXPECT_TRUE(pool.Delete(widgetId));
    EXPECT_TRUE(pool.Delete(childId));
    DrainSerialThread();
}

HWTEST_F(ContextArbitrationTest, WidgetSessionReplacesDialog, TestSize.Level0)
{
    constexpr uint64_t sudoId = 1240;
    constexpr uint64_t widgetId = 1250;
    constexpr int32_t user = 18;
    // remain=1 routes the SUDO to the last-attempt warning dialog
    PrimePinCredentialAndExecutor(1, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> oldSudoCb;
    auto oldSudo = MakeSudo(sudoId, user, oldSudoCb);
    ASSERT_TRUE(pool.Schedule(oldSudo));
    Track(sudoId);
    DrainSerialThread();
    EXPECT_EQ(oldSudo->widgetBranchCount, 1);

    // a new widget session takes the window directly: the dialog SUDO is stopped
    // as the victim; a same-user plain pin auth takes it over the same way
    // (SudoDialogYieldsToSameUserPin)
    auto widget = MockContext::CreateWithContextId(widgetId);
    ASSERT_NE(widget, nullptr);
    auto widgetMock = std::static_pointer_cast<MockContext>(widget);
    int widgetStartCount = 0;
    ON_CALL(*widgetMock, GetContextType()).WillByDefault(Return(ContextType::WIDGET_AUTH_CONTEXT));
    ON_CALL(*widgetMock, IsPrimaryContext()).WillByDefault(Return(true));
    // delegate to the REAL policy, or the takeover flow is not exercised
    ON_CALL(*widgetMock, CanStart(_)).WillByDefault(
        [widgetRaw = widgetMock.get()](const std::vector<std::weak_ptr<Context>> &predecessors) {
            return ContextAdmissionPolicy::CanStart(*widgetRaw, predecessors);
        });
    ON_CALL(*widgetMock, Start()).WillByDefault([&widgetStartCount]() {
        widgetStartCount++;
        return true;
    });

    ASSERT_TRUE(pool.Schedule(widget));
    Track(widgetId);
    DrainSerialThread();
    EXPECT_EQ(widgetStartCount, 1);

    // the victim teardown still reports CANCELED once the stub child is driven;
    // the real cleaner then deletes the parent, the mock callback elides it
    EXPECT_CALL(*oldSudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    oldSudo->OnChildResult(ResultCode::CANCELED, {});
    pool.Delete(sudoId);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(sudoId).lock(), nullptr);
    EXPECT_EQ(widgetStartCount, 1);

    EXPECT_EQ(pool.Delete(widgetId), true);
    DrainSerialThread();
}

// once the dialog is up, a same-user plain PIN auth takes the PIN slot over by
// cancellation — the dialog SUDO is stopped as a victim and the pin starts in
// the same round (no coexistence)
HWTEST_F(ContextArbitrationTest, SudoDialogYieldsToSameUserPin, TestSize.Level0)
{
    constexpr uint64_t sudoId = 1301;
    constexpr uint64_t pinId = 1310;
    constexpr int32_t user = 20;
    PrimePinCredentialAndExecutor(1, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    DrainSerialThread();
    EXPECT_EQ(sudo->widgetBranchCount, 1);

    // the pin auth takes the dialog over: holder sentenced, pin starts same round
    std::shared_ptr<MockAuthentication> authB;
    std::shared_ptr<MockContextCallback> cbB;
    auto ctxB = MakeSimpleAuth(pinId, user, PIN, true, authB, cbB);
    EXPECT_CALL(*authB, Start(_, _, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(ctxB));
    Track(pinId);
    DrainSerialThread();
    EXPECT_TRUE(sudo->stopping_);
    EXPECT_NE(pool.Select(sudoId).lock(), nullptr);

    // teardown: drive the sudo terminal (victim stop already cascaded), then delete
    EXPECT_CALL(*sudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    sudo->OnChildResult(ResultCode::CANCELED, {});
    pool.Delete(sudoId);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(sudoId).lock(), nullptr);
}

// the pin queues while the SUDO is admitted but still pre-dialog; when the
// dialog rises, the drain round (NotifyPreemptStateChanged) lets the waiting
// pin collect the holder's yield — the SUDO is cancelled and the pin takes the
// slot over in the same round
HWTEST_F(ContextArbitrationTest, QueuedPinTakesDialogOverOnDrain, TestSize.Level0)
{
    constexpr uint64_t sudoId = 1401;
    constexpr uint64_t pinId = 1410;
    constexpr int32_t user = 23;
    PrimePinCredentialAndExecutor(1, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    std::promise<void> dialogMayStart;
    sudo->HoldDialogStart(dialogMayStart.get_future());
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);

    // pre-dialog the SUDO gates the PIN slot, so the pin waits
    std::shared_ptr<MockAuthentication> authB;
    std::shared_ptr<MockContextCallback> cbB;
    auto ctxB = MakeSimpleAuth(pinId, user, PIN, true, authB, cbB);
    EXPECT_CALL(*authB, Start(_, _, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(ctxB));
    Track(pinId);
    dialogMayStart.set_value();

    DrainSerialThread();
    EXPECT_EQ(sudo->widgetBranchCount, 1);
    EXPECT_TRUE(sudo->stopping_);
    EXPECT_NE(pool.Select(sudoId).lock(), nullptr);

    // teardown: drive the sudo terminal, the pin context is tracked/cleaned
    EXPECT_CALL(*sudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    sudo->OnChildResult(ResultCode::CANCELED, {});
    pool.Delete(sudoId);
    DrainSerialThread();
    EXPECT_EQ(pool.Select(sudoId).lock(), nullptr);
}

// a queued member collects yields on a drain round too — no new arrival is
// needed. The waiting widget asks the dialog SUDO for the window as soon as the
// dialog rises (NotifyPreemptStateChanged) and takes it over
HWTEST_F(ContextArbitrationTest, QueuedWidgetPreemptsDialogOnDrain, TestSize.Level0)
{
    constexpr uint64_t sudoId = 1421;
    constexpr uint64_t widgetId = 1430;
    constexpr int32_t user = 24;
    PrimePinCredentialAndExecutor(1, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    std::promise<void> dialogMayStart;
    sudo->HoldDialogStart(dialogMayStart.get_future());
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);

    // pre-dialog the SUDO gates the PIN slot, so the widget waits. No drain here:
    // the serial thread is parked inside the gated dialog start
    int wStart = 0;
    auto widget = MakeWaitingWidgetMock(widgetId, user, wStart);
    ASSERT_TRUE(pool.Schedule(widget));
    Track(widgetId);
    EXPECT_EQ(sudo->widgetBranchCount, 0);
    EXPECT_EQ(wStart, 0);
    EXPECT_NE(pool.Select(widgetId).lock(), nullptr);

    // the dialog rises: the drain round lets the waiting widget collect the
    // holder's yield and take the window over in the same round
    dialogMayStart.set_value();
    DrainSerialThread();
    EXPECT_EQ(sudo->widgetBranchCount, 1);
    EXPECT_TRUE(sudo->stopping_);
    EXPECT_EQ(wStart, 1);
    EXPECT_NE(pool.Select(widgetId).lock(), nullptr);

    // teardown: the preempted sudo reports CANCELED once its child terminal lands
    EXPECT_CALL(*sudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    sudo->OnChildResult(ResultCode::CANCELED, {});
    EXPECT_TRUE(pool.Delete(sudoId));
    EXPECT_TRUE(pool.Delete(widgetId));
    DrainSerialThread();
}

HWTEST_F(ContextArbitrationTest, PinAuthQueuesBehindSilentSudo, TestSize.Level0)
{
    constexpr uint64_t sudoId = 1501;
    constexpr uint64_t pinId = 1510;
    constexpr int32_t user = 26;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);

    // pre-dialog the SUDO mutually excludes with all pin-related requests
    std::shared_ptr<MockAuthentication> authB;
    std::shared_ptr<MockContextCallback> cbB;
    auto ctxB = MakeSimpleAuth(pinId, user, PIN, true, authB, cbB);
    EXPECT_CALL(*authB, Start(_, _, _)).Times(0);
    ASSERT_TRUE(pool.Schedule(ctxB));
    Track(pinId);
    DrainSerialThread();

    Mock::VerifyAndClearExpectations(authB.get());
    EXPECT_CALL(*authB, Start(_, _, _)).Times(1);
    EXPECT_CALL(*sudoCb, OnResult(ResultCode::CANCELED, _)).Times(1);
    sudo->OnChildResult(ResultCode::CANCELED, {});
    EXPECT_TRUE(pool.Delete(sudoId));
    DrainSerialThread();
    EXPECT_EQ(pool.Select(sudoId).lock(), nullptr);
}

HWTEST_F(ContextArbitrationTest, PinSlotCrossUserRunsParallel, TestSize.Level0)
{
    constexpr uint64_t pinId = 1520;
    constexpr uint64_t sudoId = 1521;
    constexpr int32_t pinUser = 100;
    constexpr int32_t sudoUser = 101;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockAuthentication> authA;
    std::shared_ptr<MockContextCallback> cbA;
    auto ctxA = MakeSimpleAuth(pinId, pinUser, PIN, true, authA, cbA);
    ASSERT_TRUE(pool.Schedule(ctxA));
    Track(pinId);
    DrainSerialThread();

    // per-user slot (UT-C02): a SUDO for another user never queues behind user 100
    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, sudoUser, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);

    sudo->OnChildResult(ResultCode::CANCELED, {});
}

// the pin seat is per-user: SUDO x SUDO across users run in parallel,
// mirroring the XTS cross-user case
HWTEST_F(ContextArbitrationTest, SudoCrossUserSilentRunsParallel, TestSize.Level0)
{
    constexpr uint64_t sudoAId = 1540;
    constexpr uint64_t sudoBId = 1541;
    constexpr int32_t userA = 100;
    constexpr int32_t userB = 101;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> cbA;
    auto sudoA = MakeSudo(sudoAId, userA, cbA);
    ASSERT_TRUE(pool.Schedule(sudoA));
    Track(sudoAId);
    DrainSerialThread();
    EXPECT_EQ(sudoA->silentBranchCount, 1);

    std::shared_ptr<MockContextCallback> cbB;
    auto sudoB = MakeSudo(sudoBId, userB, cbB);
    ASSERT_TRUE(pool.Schedule(sudoB));
    Track(sudoBId);
    DrainSerialThread();
    EXPECT_EQ(sudoB->silentBranchCount, 1);

    sudoB->OnChildResult(ResultCode::CANCELED, {});
    sudoA->OnChildResult(ResultCode::CANCELED, {});
}

HWTEST_F(ContextArbitrationTest, PinSlotInvalidUserIdNeverLocks, TestSize.Level0)
{
    constexpr uint64_t sudoId = 1530;
    constexpr uint64_t pinId = 1531;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, INVALID_USER_ID, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);

    // un-normalized ids never contend (UT-C16): both sides INVALID_USER_ID run in parallel
    std::shared_ptr<MockAuthentication> authB;
    std::shared_ptr<MockContextCallback> cbB;
    auto ctxB = MakeSimpleAuth(pinId, INVALID_USER_ID, PIN, true, authB, cbB);
    EXPECT_CALL(*authB, Start(_, _, _)).Times(1);
    ASSERT_TRUE(pool.Schedule(ctxB));
    Track(pinId);
    DrainSerialThread();
    Mock::VerifyAndClearExpectations(authB.get());
}

// the SystemUI window is replace-only: a new widget session stops the live one
// as a preemption victim and starts in the same round (the yield itself is
// WidgetContext::GetPreemptDecision, mocked here for the pool flow)
HWTEST_F(ContextArbitrationTest, WidgetSessionTakesOverLiveWidget, TestSize.Level0)
{
    constexpr uint64_t liveId = 1610;
    constexpr uint64_t nextId = 1611;
    constexpr int32_t user = 30;
    auto &pool = ContextPool::Instance();
    auto live = MockContext::CreateWithContextId(liveId);
    ASSERT_NE(live, nullptr);
    auto liveMock = std::static_pointer_cast<MockContext>(live);
    ON_CALL(*liveMock, GetContextType()).WillByDefault(Return(ContextType::WIDGET_AUTH_CONTEXT));
    ON_CALL(*liveMock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*liveMock, GetUserId()).WillByDefault(Return(user));
    ON_CALL(*liveMock, Stop()).WillByDefault(Return(true));
    ON_CALL(*liveMock, GetPreemptDecision(_)).WillByDefault([](const Context &newRequest) {
        if (newRequest.GetContextType() != ContextType::WIDGET_AUTH_CONTEXT) {
            return PreemptDecision::KEEP_RUNNING;
        }
        return PreemptDecision::STOP_NOW;
    });
    ASSERT_TRUE(pool.Schedule(live));
    Track(liveId);
    DrainSerialThread();

    auto next = MockContext::CreateWithContextId(nextId);
    ASSERT_NE(next, nullptr);
    auto nextMock = std::static_pointer_cast<MockContext>(next);
    int nextStartCount = 0;
    ON_CALL(*nextMock, GetContextType()).WillByDefault(Return(ContextType::WIDGET_AUTH_CONTEXT));
    ON_CALL(*nextMock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*nextMock, GetUserId()).WillByDefault(Return(user));
    ON_CALL(*nextMock, CanStart(_)).WillByDefault(
        [nextRaw = nextMock.get()](const std::vector<std::weak_ptr<Context>> &predecessors) {
            return ContextAdmissionPolicy::CanStart(*nextRaw, predecessors);
        });
    ON_CALL(*nextMock, Start()).WillByDefault([&nextStartCount]() {
        nextStartCount++;
        return true;
    });

    EXPECT_CALL(*liveMock, Stop()).Times(1);
    ASSERT_TRUE(pool.Schedule(next));
    Track(nextId);
    DrainSerialThread();
    EXPECT_EQ(nextStartCount, 1);
    Mock::VerifyAndClearExpectations(liveMock.get());

    EXPECT_TRUE(pool.Delete(liveId));
    EXPECT_TRUE(pool.Delete(nextId));
    DrainSerialThread();
}

// a SUDO does not queue behind a cross-user widget: it runs alongside the
// live session instead
HWTEST_F(ContextArbitrationTest, SilentSudoRunsAlongsideLiveWidget, TestSize.Level0)
{
    constexpr uint64_t widgetId = 1620;
    constexpr uint64_t sudoId = 1621;
    constexpr int32_t widgetUser = 31;
    constexpr int32_t sudoUser = 32;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    auto widget = MockContext::CreateWithContextId(widgetId);
    ASSERT_NE(widget, nullptr);
    auto widgetMock = std::static_pointer_cast<MockContext>(widget);
    ON_CALL(*widgetMock, GetContextType()).WillByDefault(Return(ContextType::WIDGET_AUTH_CONTEXT));
    ON_CALL(*widgetMock, IsPrimaryContext()).WillByDefault(Return(true));
    ON_CALL(*widgetMock, GetUserId()).WillByDefault(Return(widgetUser));
    ASSERT_TRUE(pool.Schedule(widget));
    Track(widgetId);
    DrainSerialThread();

    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, sudoUser, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);

    sudo->OnChildResult(ResultCode::CANCELED, {});
    EXPECT_TRUE(pool.Delete(sudoId));
    EXPECT_TRUE(pool.Delete(widgetId));
    DrainSerialThread();
}

// a waiting widget collects yields on any pass, but it is not spared either: a
// newer widget request retires it outright. The newer widget is cross-user: no
// window queue exists (the window axis is replace-only), so it runs beside the
// silent SUDO, which nobody sentences
HWTEST_F(ContextArbitrationTest, WaitingWidgetSparesCompanions, TestSize.Level0)
{
    constexpr uint64_t sudoId = 1630;
    constexpr uint64_t w1Id = 1631;
    constexpr uint64_t w2Id = 1632;
    constexpr int32_t user = 33;
    constexpr int32_t w2User = 34;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);

    // same-user PIN widget waits behind the silent SUDO (PIN slot)
    int w1Start = 0;
    auto w1 = MakeWaitingWidgetMock(w1Id, user, w1Start);
    int w1Stop = 0;
    ON_CALL(*w1, Stop()).WillByDefault([&w1Stop]() {
        w1Stop++;
        return true;
    });
    ASSERT_TRUE(pool.Schedule(w1));
    Track(w1Id);
    DrainSerialThread();
    EXPECT_EQ(w1Start, 0);

    // a cross-user widget retires the waiting one (replace-only, no user check)
    // and runs immediately beside the silent SUDO — the window axis never queues
    int w2Start = 0;
    auto w2 = MakeWaitingWidgetMock(w2Id, w2User, w2Start);
    ASSERT_TRUE(pool.Schedule(w2));
    Track(w2Id);
    DrainSerialThread();
    EXPECT_EQ(w2Start, 1);
    EXPECT_EQ(w1Stop, 1);
    EXPECT_TRUE(pool.Delete(w1Id));
    EXPECT_EQ(pool.Select(w1Id).lock(), nullptr);
    EXPECT_CALL(*sudoCb, OnResult(_, _)).Times(0);
    Mock::VerifyAndClearExpectations(sudoCb.get());

    // teardown: holder and the running cross-user widget leave
    sudo->OnChildResult(ResultCode::CANCELED, {});
    EXPECT_TRUE(pool.Delete(sudoId));
    EXPECT_TRUE(pool.Delete(w2Id));
    DrainSerialThread();
}

// widget sessions are replace-only down to the waiting queue: a newer widget
// request retires the waiting one outright (CANCELED) and takes its place in
// line, instead of queueing behind it for the single seat
HWTEST_F(ContextArbitrationTest, NewWidgetSupersedesWaitingWidget, TestSize.Level0)
{
    constexpr uint64_t sudoId = 1640;
    constexpr uint64_t w1Id = 1641;
    constexpr uint64_t w2Id = 1642;
    constexpr int32_t user = 35;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, user, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);

    int w1Start = 0;
    auto w1 = MakeWaitingWidgetMock(w1Id, user, w1Start);
    int w1Stop = 0;
    ON_CALL(*w1, Stop()).WillByDefault([&w1Stop]() {
        w1Stop++;
        return true;
    });
    ASSERT_TRUE(pool.Schedule(w1));
    Track(w1Id);
    int w2Start = 0;
    auto w2 = MakeWaitingWidgetMock(w2Id, user, w2Start);
    ASSERT_TRUE(pool.Schedule(w2));
    Track(w2Id);
    DrainSerialThread();
    // the waiting W1 is retired by the newer widget session; W2 waits on
    EXPECT_EQ(w1Start, 0);
    EXPECT_EQ(w1Stop, 1);
    EXPECT_TRUE(pool.Delete(w1Id));
    EXPECT_EQ(w2Start, 0);
    EXPECT_NE(pool.Select(w2Id).lock(), nullptr);

    // the holder leaves: the surviving newer widget takes the seat
    sudo->OnChildResult(ResultCode::CANCELED, {});
    EXPECT_TRUE(pool.Delete(sudoId));
    DrainSerialThread();
    EXPECT_EQ(w2Start, 1);

    EXPECT_TRUE(pool.Delete(w2Id));
    DrainSerialThread();
}

// widget supersede is unconditional: the live widget a new request replaces is
// stopped at the newcomer's arrival. Cross-user, the newcomer also starts
// immediately — the window axis is replace-only and never queues a widget
// behind an unrelated SUDO
HWTEST_F(ContextArbitrationTest, NewWidgetRetiresLiveWidgetAndRunsCrossUser, TestSize.Level0)
{
    constexpr uint64_t w1Id = 1650;
    constexpr uint64_t sudoId = 1660;
    constexpr uint64_t w2Id = 1651;
    constexpr int32_t widgetUser = 36;
    constexpr int32_t sudoUser = 37;
    PrimePinCredentialAndExecutor(REMAIN_SUFFICIENT, 0);
    auto &pool = ContextPool::Instance();
    int w1Start = 0;
    auto w1 = MakeWaitingWidgetMock(w1Id, widgetUser, w1Start);
    int w1Stop = 0;
    ON_CALL(*w1, Stop()).WillByDefault([&w1Stop]() {
        w1Stop++;
        return true;
    });
    ASSERT_TRUE(pool.Schedule(w1));
    Track(w1Id);
    DrainSerialThread();
    EXPECT_EQ(w1Start, 1);

    std::shared_ptr<MockContextCallback> sudoCb;
    auto sudo = MakeSudo(sudoId, sudoUser, sudoCb);
    ASSERT_TRUE(pool.Schedule(sudo));
    Track(sudoId);
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);

    int w2Start = 0;
    auto w2 = MakeWaitingWidgetMock(w2Id, widgetUser, w2Start);
    ASSERT_TRUE(pool.Schedule(w2));
    Track(w2Id);
    DrainSerialThread();
    // arrival: the live widget is superseded; cross-user SUDO never queues the
    // newcomer, so w2 runs at once and the SUDO is spared
    EXPECT_EQ(w1Stop, 1);
    EXPECT_EQ(w2Start, 1);
    EXPECT_CALL(*sudoCb, OnResult(_, _)).Times(0);
    Mock::VerifyAndClearExpectations(sudoCb.get());

    EXPECT_TRUE(pool.Delete(w1Id));
    sudo->OnChildResult(ResultCode::CANCELED, {});
    EXPECT_TRUE(pool.Delete(sudoId));
    EXPECT_TRUE(pool.Delete(w2Id));
    DrainSerialThread();
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
