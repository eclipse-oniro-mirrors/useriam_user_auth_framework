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

#include <atomic>
#include <chrono>
#include <future>
#include <vector>

#include "attributes.h"
#include "mock_user_auth_callback.h"
#include "widget_context.h"
#include "context_pool.h"
#include "iam_defines.h"
#include "iam_ptr.h"
#include "mock_context.h"
#include "mock_iuser_auth_interface.h"
#include "mock_resource_node.h"
#include "resource_node_pool.h"
#include "simple_auth_context.h"
#include "sudo_auth_context.h"
#include "thread_handler.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t PIN_EXECUTOR_INDEX = 611;
constexpr uint64_t SUDO_TEST_CONTEXT_ID = 2001;
constexpr int32_t SUDO_TEST_USER_ID = 100;
// drain passes: EnsureTask only waits out tasks posted before it, not their nested posts
constexpr int32_t DRAIN_PASSES = 3;
constexpr int32_t REMAIN_SUFFICIENT = 4;
constexpr int32_t REMAIN_AFTER_CHILD_SUCCESS = 3;
constexpr int32_t NEXT_FAIL_LOCKOUT_DURATION = 300000;

void DrainSerialThread()
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    for (int pass = 0; pass < DRAIN_PASSES; ++pass) {
        handler->EnsureTask([]() {});
    }
}

// newcomer role used when probing a dialog-active SUDO holder
struct DialogProbeSet {
    std::shared_ptr<MockContext> plain;
    std::shared_ptr<MockContext> sudo;
    std::shared_ptr<MockContext> widget;
    std::shared_ptr<MockContext> childLike;
    std::shared_ptr<MockContext> crossUserPin;
    std::shared_ptr<MockContext> sameUserFace;
};

std::shared_ptr<MockContext> CreateRoleContext(uint64_t contextId, ContextType type, int32_t userId,
    int32_t authType, bool primary)
{
    auto context = MockContext::CreateWithContextId(contextId);
    if (context == nullptr) {
        return nullptr;
    }
    auto mock = std::static_pointer_cast<MockContext>(context);
    ON_CALL(*mock, GetContextType()).WillByDefault(Return(type));
    ON_CALL(*mock, GetUserId()).WillByDefault(Return(userId));
    ON_CALL(*mock, GetAuthType()).WillByDefault(Return(authType));
    ON_CALL(*mock, IsPrimaryContext()).WillByDefault(Return(primary));
    return mock;
}

void CreateDialogProbes(int32_t sudoUser, DialogProbeSet &probes)
{
    constexpr uint64_t newcomerId = 0x5EED01;
    constexpr uint64_t sudoId = newcomerId + 1;
    constexpr uint64_t widgetId = sudoId + 1;
    constexpr uint64_t childLikeId = widgetId + 1;
    constexpr uint64_t crossUserPinId = childLikeId + 1;
    constexpr uint64_t sameUserFaceId = crossUserPinId + 1;
    probes.plain = CreateRoleContext(newcomerId, ContextType::CONTEXT_SIMPLE_AUTH, sudoUser, AuthType::PIN, true);
    ASSERT_NE(probes.plain, nullptr);
    probes.sudo = CreateRoleContext(sudoId, ContextType::SUDO_AUTH_CONTEXT, sudoUser, AuthType::PIN, true);
    ASSERT_NE(probes.sudo, nullptr);
    probes.widget = CreateRoleContext(widgetId, ContextType::WIDGET_AUTH_CONTEXT, sudoUser, AuthType::PIN, true);
    ASSERT_NE(probes.widget, nullptr);
    probes.childLike = CreateRoleContext(childLikeId, ContextType::CONTEXT_SIMPLE_AUTH, sudoUser, AuthType::PIN, false);
    ASSERT_NE(probes.childLike, nullptr);
    probes.crossUserPin =
        CreateRoleContext(crossUserPinId, ContextType::CONTEXT_SIMPLE_AUTH, sudoUser + 1, AuthType::PIN, true);
    ASSERT_NE(probes.crossUserPin, nullptr);
    probes.sameUserFace =
        CreateRoleContext(sameUserFaceId, ContextType::CONTEXT_SIMPLE_AUTH, sudoUser, AuthType::FACE, true);
    ASSERT_NE(probes.sameUserFace, nullptr);
}

// remain/freeze/next-phase served by the mock pin executor; changeable between calls.
struct ProfileStub {
    int32_t remainTimes {5};
    int32_t freezingTime {0};
    int32_t nextFreezingTime {0};
    int getPropertyCallCount {0};
};

void PrimePinCredential(ProfileStub &stub)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential(_, _, _))
        .WillByDefault([](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            infos.push_back({.credentialId = 1, .executorIndex = PIN_EXECUTOR_INDEX, .templateId = 9,
                .authType = static_cast<HdiAuthType>(AuthType::PIN), .executorMatcher = 1,
                .executorSensorHint = 1, .authSubType = static_cast<uint64_t>(PinSubType::PIN_SIX)});
            return HDF_SUCCESS;
        });
    ON_CALL(*mockHdi, GetCredentialById(_, _)).WillByDefault(Return(HDF_FAILURE));
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(PIN_EXECUTOR_INDEX, PIN, ALL_IN_ONE);
    ASSERT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _))
        .WillByDefault([&stub](const Attributes &condition, Attributes &values) {
            stub.getPropertyCallCount++;
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, stub.remainTimes);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, stub.freezingTime);
            values.SetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, stub.nextFreezingTime);
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, static_cast<int32_t>(PinSubType::PIN_SIX));
            return SUCCESS;
        });
}

// SUDO orchestrator with children substituted, recording branch selection.
class BranchRecordingSudoContext : public SudoAuthContext {
public:
    BranchRecordingSudoContext(uint64_t contextId, const ContextFactory::SudoAuthContextPara &para,
        std::shared_ptr<ContextCallback> callback)
        : SudoAuthContext(contextId, para, callback)
    {
    }
    ~BranchRecordingSudoContext() override = default;

    bool StartSilentChild(const ContextFactory::AuthProfile &profile) override
    {
        silentBranchCount++;
        lastProfile = profile;
        childIsWidget_ = false;
        return InstallStubChild();
    }

    bool StartWidgetChild(const ContextFactory::AuthProfile &profile) override
    {
        widgetBranchCount++;
        lastProfile = profile;
        childIsWidget_ = true;
        return InstallStubChild();
    }

    bool InstallStubChild()
    {
        auto stub = MockContext::CreateWithContextId(GetContextId() + 1);
        EXPECT_NE(stub, nullptr);
        ON_CALL(*static_cast<MockContext *>(stub.get()), Start()).WillByDefault(Return(true));
        ON_CALL(*static_cast<MockContext *>(stub.get()), Stop()).WillByDefault(Return(true));
        childContextId_ = stub->GetContextId();
        stubChild = stub;
        phase_ = PHASE_RUN;
        return true;
    }

    int silentBranchCount = 0;
    int widgetBranchCount = 0;
    ContextFactory::AuthProfile lastProfile {};
    std::shared_ptr<Context> stubChild {nullptr};
};

std::shared_ptr<BranchRecordingSudoContext> MakeSudo(std::shared_ptr<MockContextCallback> &cbOut,
    const std::string &additionalInfo = "sudo test title")
{
    ContextFactory::SudoAuthContextPara para;
    para.userId = SUDO_TEST_USER_ID;
    para.tokenId = 1;
    para.sdkVersion = INNER_API_VERSION_10000;
    para.callerName = "sudo_test";
    para.atl = ATL2;
    para.additionalInfo = additionalInfo;
    auto callback = Common::MakeShared<MockContextCallback>();
    auto context = Common::MakeShared<BranchRecordingSudoContext>(SUDO_TEST_CONTEXT_ID, para, callback);
    cbOut = callback;
    return context;
}
} // namespace

class SudoAuthContextTest : public testing::Test {
public:
    void TearDown() override
    {
        DrainSerialThread();
        ContextPool::Instance().Delete(SUDO_TEST_CONTEXT_ID);
        ContextPool::Instance().Delete(SUDO_TEST_CONTEXT_ID + 1);
        // Deletes can post arbitration tasks; flush them before fixture state dies.
        DrainSerialThread();
        ResourceNodePool::Instance().Delete(PIN_EXECUTOR_INDEX);
        MockIUserAuthInterface::Holder::GetInstance().Reset();
    }
};

HWTEST_F(SudoAuthContextTest, SudoAuthContextBasics, TestSize.Level0)
{
    std::shared_ptr<MockContextCallback> cb;
    auto sudo = MakeSudo(cb);
    EXPECT_EQ(sudo->GetContextType(), SUDO_AUTH_CONTEXT);
    EXPECT_EQ(sudo->GetAuthIntent(), AuthIntent::SUDO_PIN_AUTH);
    EXPECT_EQ(sudo->GetAuthType(), AuthType::PIN);
    EXPECT_EQ(sudo->GetUserId(), SUDO_TEST_USER_ID);
}

HWTEST_F(SudoAuthContextTest, SudoAuthSilentBranchOnSufficientRemain, TestSize.Level0)
{
    ProfileStub stub;
    stub.remainTimes = REMAIN_SUFFICIENT;
    stub.freezingTime = 0;
    PrimePinCredential(stub);
    std::shared_ptr<MockContextCallback> cb;
    auto sudo = MakeSudo(cb);
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);
    EXPECT_EQ(sudo->widgetBranchCount, 0);
    EXPECT_EQ(sudo->lastProfile.remainTimes, REMAIN_SUFFICIENT);
    // One zero-consumption profile read in total.
    EXPECT_EQ(stub.getPropertyCallCount, 1);

    Attributes childResult;
    childResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, REMAIN_AFTER_CHILD_SUCCESS);
    EXPECT_CALL(*cb, OnResult(ResultCode::SUCCESS, _)).Times(1);
    sudo->OnChildResult(ResultCode::SUCCESS, childResult);
}

HWTEST_F(SudoAuthContextTest, SudoAuthLockedFastFail, TestSize.Level0)
{
    ProfileStub stub;
    stub.remainTimes = 0;
    stub.freezingTime = FIRST_LOCKOUT_DURATION_OF_PIN;
    PrimePinCredential(stub);
    std::shared_ptr<MockContextCallback> cb;
    auto sudo = MakeSudo(cb);
    int32_t reportedResult = 0;
    int32_t reportedRemain = -1;
    int32_t reportedFreeze = -1;
    EXPECT_CALL(*cb, OnResult(_, _))
        .WillOnce([&reportedResult, &reportedRemain, &reportedFreeze](int32_t resultCode,
            const Attributes &finalResult) {
            reportedResult = resultCode;
            finalResult.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, reportedRemain);
            finalResult.GetInt32Value(Attributes::ATTR_FREEZING_TIME, reportedFreeze);
        });
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    EXPECT_EQ(reportedResult, ResultCode::LOCKED);
    EXPECT_EQ(reportedRemain, 0);
    EXPECT_EQ(reportedFreeze, FIRST_LOCKOUT_DURATION_OF_PIN);
    EXPECT_EQ(sudo->silentBranchCount + sudo->widgetBranchCount, 0);
    EXPECT_EQ(stub.getPropertyCallCount, 1);
}

HWTEST_F(SudoAuthContextTest, SudoAuthDialogBranchLockedSynthesis, TestSize.Level0)
{
    ProfileStub stub;
    stub.remainTimes = 1;
    stub.freezingTime = 0;
    PrimePinCredential(stub);
    std::shared_ptr<MockContextCallback> cb;
    auto sudo = MakeSudo(cb);
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    EXPECT_EQ(sudo->widgetBranchCount, 1);
    EXPECT_EQ(sudo->silentBranchCount, 0);
    EXPECT_EQ(stub.getPropertyCallCount, 1);

    // The last attempt is lost in the dialog: re-query reports frozen, and the
    // reported next-fail phase comes from that authoritative re-query (the
    // child's own claim in failResult is superseded by it).
    stub.remainTimes = 0;
    stub.freezingTime = FIRST_LOCKOUT_DURATION_OF_PIN;
    stub.nextFreezingTime = NEXT_FAIL_LOCKOUT_DURATION;
    int32_t reportedResult = 0;
    int32_t reportedRemain = -1;
    int32_t reportedFreeze = -1;
    int32_t reportedNextPhase = -1;
    EXPECT_CALL(*cb, OnResult(_, _))
        .WillOnce([&reportedResult, &reportedRemain, &reportedFreeze, &reportedNextPhase](int32_t resultCode,
            const Attributes &finalResult) {
            reportedResult = resultCode;
            finalResult.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, reportedRemain);
            finalResult.GetInt32Value(Attributes::ATTR_FREEZING_TIME, reportedFreeze);
            finalResult.GetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, reportedNextPhase);
        });
    Attributes failResult;
    failResult.SetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, NEXT_FAIL_LOCKOUT_DURATION);
    sudo->OnChildResult(ResultCode::FAIL, failResult);
    EXPECT_EQ(reportedResult, ResultCode::LOCKED);
    EXPECT_EQ(reportedRemain, 0);
    EXPECT_EQ(reportedFreeze, FIRST_LOCKOUT_DURATION_OF_PIN);
    EXPECT_EQ(reportedNextPhase, NEXT_FAIL_LOCKOUT_DURATION);
    EXPECT_EQ(stub.getPropertyCallCount, 2);
}

HWTEST_F(SudoAuthContextTest, SudoAuthDialogCancelTransparent, TestSize.Level0)
{
    ProfileStub stub;
    stub.remainTimes = 1;
    stub.freezingTime = 0;
    PrimePinCredential(stub);
    std::shared_ptr<MockContextCallback> cb;
    auto sudo = MakeSudo(cb);
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    EXPECT_EQ(sudo->widgetBranchCount, 1);

    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    Attributes cancelResult;
    sudo->OnChildResult(ResultCode::CANCELED, cancelResult);
    EXPECT_EQ(stub.getPropertyCallCount, 1);
}

HWTEST_F(SudoAuthContextTest, SudoAuthNotEnrolled, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential(_, _, _))
        .WillByDefault([](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            return HDF_SUCCESS;
        });
    std::shared_ptr<MockContextCallback> cb;
    auto sudo = MakeSudo(cb);
    EXPECT_CALL(*cb, OnResult(ResultCode::NOT_ENROLLED, _)).Times(1);
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount + sudo->widgetBranchCount, 0);
}

HWTEST_F(SudoAuthContextTest, SudoAuthQueryFailClosed, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential(_, _, _))
        .WillByDefault([](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            infos.push_back({.credentialId = 1, .executorIndex = PIN_EXECUTOR_INDEX, .templateId = 9,
                .authType = static_cast<HdiAuthType>(AuthType::PIN), .executorMatcher = 1,
                .executorSensorHint = 1, .authSubType = 0});
            return HDF_SUCCESS;
        });
    // No resource node registered for the credential's executor.
    std::shared_ptr<MockContextCallback> cb;
    auto sudo = MakeSudo(cb);
    EXPECT_CALL(*cb, OnResult(ResultCode::GENERAL_ERROR, _)).Times(1);
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount + sudo->widgetBranchCount, 0);
}

HWTEST_F(SudoAuthContextTest, SudoAuthCancelCascades, TestSize.Level0)
{
    ProfileStub stub;
    stub.remainTimes = REMAIN_SUFFICIENT;
    stub.freezingTime = 0;
    PrimePinCredential(stub);
    std::shared_ptr<MockContextCallback> cb;
    auto sudo = MakeSudo(cb);
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    EXPECT_EQ(sudo->silentBranchCount, 1);
    auto child = std::static_pointer_cast<MockContext>(sudo->stubChild);
    ASSERT_NE(child, nullptr);
    ASSERT_TRUE(ContextPool::Instance().Schedule(child));
    DrainSerialThread();

    EXPECT_CALL(*child, Stop()).WillOnce(Return(true));
    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    ContextPool::Instance().Cancel(SUDO_TEST_CONTEXT_ID);
    DrainSerialThread();
    DrainSerialThread();
    sudo->OnChildResult(ResultCode::CANCELED, {});
    // A late duplicate child report must not produce a second terminal.
    sudo->OnChildResult(ResultCode::SUCCESS, {});
}

HWTEST_F(SudoAuthContextTest, SudoAuthCancelWaitsForChildStartup, TestSize.Level0)
{
    ProfileStub stub;
    PrimePinCredential(stub);
    std::shared_ptr<MockContextCallback> cb;
    auto sudo = MakeSudo(cb);
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    auto child = std::static_pointer_cast<MockContext>(sudo->stubChild);
    ASSERT_NE(child, nullptr);

    std::promise<void> startEntered;
    std::promise<void> releaseStart;
    auto entered = startEntered.get_future();
    auto release = releaseStart.get_future();
    std::atomic<bool> startFinished {false};
    EXPECT_CALL(*child, Start()).WillOnce([&]() {
        startEntered.set_value();
        release.wait();
        startFinished = true;
        return true;
    });
    EXPECT_CALL(*child, Stop()).WillOnce([&]() {
        EXPECT_TRUE(startFinished.load());
        return true;
    });
    EXPECT_CALL(*cb, OnResult(_, _)).Times(0);
    ASSERT_TRUE(ContextPool::Instance().Schedule(child));
    constexpr auto CHILD_STARTUP_WAIT = std::chrono::seconds(5);
    auto status = entered.wait_for(CHILD_STARTUP_WAIT);
    if (status != std::future_status::ready) {
        releaseStart.set_value();
        DrainSerialThread();
        FAIL() << "child startup did not run";
        return;
    }

    ContextPool::Instance().Cancel(SUDO_TEST_CONTEXT_ID);
    EXPECT_NE(ContextPool::Instance().Select(sudo->GetContextId()).lock(), nullptr);
    releaseStart.set_value();
    DrainSerialThread();
    DrainSerialThread();
    EXPECT_EQ(sudo->phase_, SudoAuthContext::PHASE_RUN);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(cb.get()));
    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).Times(1);
    sudo->OnChildResult(ResultCode::CANCELED, {});
}

HWTEST_F(SudoAuthContextTest, SudoAuthFailedStopKeepsParentUntilChildResult, TestSize.Level0)
{
    ProfileStub stub;
    PrimePinCredential(stub);
    std::shared_ptr<MockContextCallback> cb;
    auto sudo = MakeSudo(cb);
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    auto child = std::static_pointer_cast<MockContext>(sudo->stubChild);
    ASSERT_NE(child, nullptr);
    ASSERT_TRUE(ContextPool::Instance().Schedule(child));
    EXPECT_CALL(*child, Stop()).WillOnce(Return(false));
    EXPECT_CALL(*cb, OnResult(_, _)).Times(0);

    ContextPool::Instance().Cancel(SUDO_TEST_CONTEXT_ID);
    DrainSerialThread();
    DrainSerialThread();
    EXPECT_EQ(sudo->phase_, SudoAuthContext::PHASE_RUN);
    ASSERT_TRUE(sudo->childContextId_.has_value());
    EXPECT_EQ(*sudo->childContextId_, child->GetContextId());
    EXPECT_NE(ContextPool::Instance().Select(sudo->GetContextId()).lock(), nullptr);

    ASSERT_TRUE(Mock::VerifyAndClearExpectations(cb.get()));
    EXPECT_CALL(*cb, OnResult(ResultCode::CANCELED, _)).WillOnce([](int32_t, const Attributes &) {
        ContextPool::Instance().Delete(SUDO_TEST_CONTEXT_ID);
    });
    sudo->OnChildResult(ResultCode::SUCCESS, {});
    EXPECT_EQ(ContextPool::Instance().Select(sudo->GetContextId()).lock(), nullptr);
    sudo->OnChildResult(ResultCode::CANCELED, {});
}
namespace {
class LifecycleSudoContext : public SudoAuthContext {
public:
    LifecycleSudoContext(uint64_t id, const std::shared_ptr<ContextCallback> &callback)
        : SudoAuthContext(id, ContextFactory::SudoAuthContextPara {}, callback) {}
    LifecycleSudoContext(uint64_t id, const ContextFactory::SudoAuthContextPara &para,
        const std::shared_ptr<ContextCallback> &callback)
        : SudoAuthContext(id, para, callback) {}
    bool OnStart() override
    {
        onStartCount++;
        return true;
    }
    int onStartCount = 0;
};
}

// The widget child delivers the sudo result through the real child callback
// wiring: the parent session is released by its cleaner as soon as the result
// reaches the caller, while the widget child itself stays pooled until its UI
// release (ClearSchedule), where its own release is idempotent.
HWTEST_F(SudoAuthContextTest, RealWidgetChildReleaseAfterParentResult, TestSize.Level0)
{
    sptr<MockUserAuthCallback> ipcCallback = new MockUserAuthCallback();
    auto callback = ContextCallback::NewInstance(ipcCallback, TRACE_AUTH_USER_SECURITY);
    auto sudo = Common::MakeShared<LifecycleSudoContext>(SUDO_TEST_CONTEXT_ID, callback);
    callback->SetCleaner(ContextPool::Cleaner(sudo));
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    EXPECT_CALL(*ipcCallback, OnResult(SUCCESS, _)).Times(1);
    ThreadHandler::GetSingleThreadInstance()->EnsureTask([sudo]() {
        ContextFactory::AuthProfile profile {};
        profile.remainTimes = 1;
        sudo->DispatchByProfile(profile);
        ASSERT_TRUE(sudo->childContextId_.has_value());
        auto childId = sudo->childContextId_.value();
        auto child = std::static_pointer_cast<WidgetContext>(ContextPool::Instance().Select(childId).lock());
        ASSERT_NE(child, nullptr);
        // Complete before the posted child start; this exercises the real child callback wiring.
        child->End(SUCCESS);
        EXPECT_EQ(ContextPool::Instance().Select(SUDO_TEST_CONTEXT_ID).lock(), nullptr);
        EXPECT_NE(ContextPool::Instance().Select(childId).lock(), nullptr);
        child->ClearSchedule();
        EXPECT_EQ(ContextPool::Instance().Select(childId).lock(), nullptr);
        EXPECT_EQ(ContextPool::Instance().Select(SUDO_TEST_CONTEXT_ID).lock(), nullptr);
        child->ClearSchedule();
    });
    DrainSerialThread();
}

HWTEST_F(SudoAuthContextTest, RealWidgetStartFailureReleasesParent, TestSize.Level0)
{
    sptr<MockUserAuthCallback> ipcCallback = new MockUserAuthCallback();
    auto callback = ContextCallback::NewInstance(ipcCallback, TRACE_AUTH_USER_SECURITY);
    auto sudo = Common::MakeShared<LifecycleSudoContext>(SUDO_TEST_CONTEXT_ID, callback);
    callback->SetCleaner(ContextPool::Cleaner(sudo));
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();
    EXPECT_CALL(*ipcCallback, OnResult(GENERAL_ERROR, _)).Times(1);
    ThreadHandler::GetSingleThreadInstance()->EnsureTask([sudo]() {
        ContextFactory::AuthProfile profile {};
        profile.remainTimes = 1;
        sudo->DispatchByProfile(profile);
        ASSERT_TRUE(sudo->childContextId_.has_value());
        auto childId = sudo->childContextId_.value();
        auto child = ContextPool::Instance().Select(childId).lock();
        ASSERT_NE(child, nullptr);
        child->OnStartFailed(GENERAL_ERROR);
        EXPECT_EQ(ContextPool::Instance().Select(childId).lock(), nullptr);
        EXPECT_EQ(ContextPool::Instance().Select(SUDO_TEST_CONTEXT_ID).lock(), nullptr);
    });
    DrainSerialThread();
}

HWTEST_F(SudoAuthContextTest, RealSilentChildRunsAndReleasesParent, TestSize.Level0)
{
    ProfileStub stub;
    PrimePinCredential(stub);
    sptr<MockUserAuthCallback> ipcCallback = new MockUserAuthCallback();
    auto callback = ContextCallback::NewInstance(ipcCallback, TRACE_AUTH_USER_SECURITY);
    auto sudo = Common::MakeShared<LifecycleSudoContext>(SUDO_TEST_CONTEXT_ID, callback);
    callback->SetCleaner(ContextPool::Cleaner(sudo));
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();

    uint64_t childId = 0;
    EXPECT_CALL(*ipcCallback, OnResult(_, _)).Times(1);
    ThreadHandler::GetSingleThreadInstance()->EnsureTask([sudo, &childId]() {
        ContextFactory::AuthProfile profile {};
        profile.remainTimes = 5;
        sudo->DispatchByProfile(profile);
        ASSERT_TRUE(sudo->childContextId_.has_value());
        childId = sudo->childContextId_.value();
        auto child = ContextPool::Instance().Select(childId).lock();
        ASSERT_NE(child, nullptr);
        EXPECT_EQ(child->GetContextType(), CONTEXT_SIMPLE_AUTH);
        EXPECT_FALSE(child->IsPrimaryContext());
        // silent branch must never raise a dialog: no widget child exists
        EXPECT_TRUE(ContextPool::Instance().Select(WIDGET_AUTH_CONTEXT).empty());
    });
    DrainSerialThread();
    DrainSerialThread();
    EXPECT_EQ(ContextPool::Instance().Select(childId).lock(), nullptr);
    EXPECT_EQ(ContextPool::Instance().Select(SUDO_TEST_CONTEXT_ID).lock(), nullptr);
}

// once the dialog is up, the SUDO yields by cancellation: to a newer SUDO
// request, a main widget session, or a same-user plain PIN auth; cross-user/
// non-PIN auth and internal children never take over
HWTEST_F(SudoAuthContextTest, DialogActiveSudoYieldsByCancellation, TestSize.Level0)
{
    sptr<MockUserAuthCallback> ipcCallback = new MockUserAuthCallback();
    auto callback = ContextCallback::NewInstance(ipcCallback, TRACE_AUTH_USER_SECURITY);
    ContextFactory::SudoAuthContextPara para {};
    para.userId = SUDO_TEST_USER_ID;
    auto sudo = Common::MakeShared<LifecycleSudoContext>(SUDO_TEST_CONTEXT_ID, para, callback);
    callback->SetCleaner(ContextPool::Cleaner(sudo));
    ASSERT_TRUE(ContextPool::Instance().Schedule(sudo));
    DrainSerialThread();

    // plain same-user pin auth / primary sudo / primary widget / scoped probes.
    // LifecycleSudoContext runs the REAL StartWidgetChild, so dialogActive_ does
    // rise; the tenant user id must be a real one because the PIN-slot conflict
    // check deliberately ignores INVALID_USER_ID.
    const int32_t sudoUser = sudo->GetUserId();
    DialogProbeSet probes;
    CreateDialogProbes(sudoUser, probes);

    // pre-dialog nothing takes the seat: silent/query phases never yield
    EXPECT_EQ(sudo->GetPreemptDecision(*probes.plain), PreemptDecision::KEEP_RUNNING);
    EXPECT_EQ(sudo->GetPreemptDecision(*probes.sudo), PreemptDecision::KEEP_RUNNING);
    EXPECT_EQ(sudo->GetPreemptDecision(*probes.widget), PreemptDecision::KEEP_RUNNING);

    ThreadHandler::GetSingleThreadInstance()->EnsureTask([sudo, &probes]() {
        ContextFactory::AuthProfile profile {};
        profile.remainTimes = 1;
        sudo->DispatchByProfile(profile);
        ASSERT_TRUE(sudo->childContextId_.has_value());
        // dialog raised: newer SUDO / main widget / same-user plain PIN cancel
        // the holder; cross-user PIN, same-user non-PIN and children never do
        EXPECT_EQ(sudo->GetPreemptDecision(*probes.plain), PreemptDecision::STOP_NOW);
        EXPECT_EQ(sudo->GetPreemptDecision(*probes.sudo), PreemptDecision::STOP_NOW);
        EXPECT_EQ(sudo->GetPreemptDecision(*probes.widget), PreemptDecision::STOP_NOW);
        EXPECT_EQ(sudo->GetPreemptDecision(*probes.childLike), PreemptDecision::KEEP_RUNNING);
        EXPECT_EQ(sudo->GetPreemptDecision(*probes.crossUserPin), PreemptDecision::KEEP_RUNNING);
        EXPECT_EQ(sudo->GetPreemptDecision(*probes.sameUserFace), PreemptDecision::KEEP_RUNNING);
    });
    DrainSerialThread();

    ContextPool::Instance().Delete(sudo->childContextId_.value_or(0));
    DrainSerialThread();
}

HWTEST_F(SudoAuthContextTest, ResolveWidgetTitleFromJson, TestSize.Level0)
{
    EXPECT_EQ(SudoAuthContext::ResolveWidgetTitle("{\"title\":\"json title\"}"), "json title");
    EXPECT_EQ(SudoAuthContext::ResolveWidgetTitle("{\"title\":\"含特殊字符\\\"引号\"}"), "含特殊字符\"引号");
    EXPECT_EQ(SudoAuthContext::ResolveWidgetTitle("{\"title\":\"最后一次机会：请谨慎输入锁屏密码\"}"),
        "最后一次机会：请谨慎输入锁屏密码");
}

HWTEST_F(SudoAuthContextTest, ResolveWidgetTitleInvalidFillEmpty, TestSize.Level0)
{
    // invalid JSON: fill empty
    EXPECT_EQ(SudoAuthContext::ResolveWidgetTitle("{\"title\":"), "");
    EXPECT_EQ(SudoAuthContext::ResolveWidgetTitle(""), "");
    // JSON object without a title field
    EXPECT_EQ(SudoAuthContext::ResolveWidgetTitle("{\"other\":\"x\"}"), "");
    // title is not a string
    EXPECT_EQ(SudoAuthContext::ResolveWidgetTitle("{\"title\":123}"), "");
    // empty title: fill empty
    EXPECT_EQ(SudoAuthContext::ResolveWidgetTitle("{\"title\":\"\"}"), "");
    // JSON array/scalar is not an object
    EXPECT_EQ(SudoAuthContext::ResolveWidgetTitle("[\"title\"]"), "");
    EXPECT_EQ(SudoAuthContext::ResolveWidgetTitle("\"pure string\""), "");
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
