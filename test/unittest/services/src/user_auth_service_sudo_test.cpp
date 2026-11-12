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

#include <chrono>
#include <thread>

#include "attributes.h"
#include "context_pool.h"
#include "iam_defines.h"
#include "mock_iuser_auth_interface.h"
#include "mock_ipc_common.h"
#include "mock_resource_node.h"
#include "mock_user_auth_callback.h"
#include "resource_node_pool.h"
#include "sudo_auth_context.h"
#include "thread_handler.h"
#include "widget_context.h"
#include "user_auth_service.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t PIN_EXECUTOR_INDEX = 621;
constexpr int32_t SUDO_TEST_USER = 123;
// drain passes: EnsureTask only waits out tasks posted before it, not their nested posts
constexpr int32_t DRAIN_PASSES = 3;
constexpr uint64_t SEEDED_CONTEXT_ID = 100;
constexpr int32_t REUSE_DURATION_MS = 1000;
constexpr uint64_t FACE_SCHEDULE_ID = 21;
constexpr uint64_t FACE_TEMPLATE_ID = 31;

void DrainSerialThread()
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    for (int pass = 0; pass < DRAIN_PASSES; ++pass) {
        handler->EnsureTask([]() {});
    }
}

IpcAuthParamInner MakeSudoIpcParam(const std::string &additionalInfo)
{
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = SUDO_TEST_USER;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = {1, 2, 3};
    ipcAuthParamInner.authType = static_cast<int32_t>(AuthType::PIN);
    ipcAuthParamInner.authTrustLevel = static_cast<int32_t>(ATL2);
    ipcAuthParamInner.authIntent = static_cast<int32_t>(AuthIntent::SUDO_PIN_AUTH);
    ipcAuthParamInner.additionalInfo = additionalInfo;
    ipcAuthParamInner.hasAdditionalInfo = true;
    return ipcAuthParamInner;
}
} // namespace

class UserAuthServiceSudoTest : public testing::Test {
public:
    void SetUp() override
    {
        // earlier suites may leave armed HDI expectations on the shared mock that
        // would shadow this suite's ON_CALL defaults
        MockIUserAuthInterface::Holder::GetInstance().Reset();
        IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
        IpcCommon::AddPermission(IS_SYSTEM_APP);
    }

    void TearDown() override
    {
        DrainSerialThread();
        for (auto &context : ContextPool::Instance().SelectAll()) {
            auto ctx = context.lock();
            if (ctx != nullptr) {
                ContextPool::Instance().Delete(ctx->GetContextId());
            }
        }
        // Deletes can post arbitration starts/stops; flush them before the mocks die
        DrainSerialThread();
        ResourceNodePool::Instance().Delete(PIN_EXECUTOR_INDEX);
        MockIUserAuthInterface::Holder::GetInstance().Reset();
        IpcCommon::DeleteAllPermission();
    }
};

HWTEST_F(UserAuthServiceSudoTest, UserAuthServiceSudoAuthAccepted, TestSize.Level0)
{
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    // No credential -> NOT_ENROLLED terminal keeps the case self-contained.
    ON_CALL(*mockHdi, GetCredential(_, _, _))
        .WillByDefault([](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            return HDF_SUCCESS;
        });

    UserAuthService service;
    auto testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(ResultCode::NOT_ENROLLED, _)).Times(1);

    IpcRemoteAuthParam ipcRemoteAuthParam = {};
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.AuthUser(MakeSudoIpcParam("sudo title"), ipcRemoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, 0);
    DrainSerialThread();
    EXPECT_EQ(ContextPool::Instance().Select(contextId).lock(), nullptr);
}

HWTEST_F(UserAuthServiceSudoTest, UserAuthServiceSudoAuthNonSystemCallerRejected, TestSize.Level0)
{
    // an internal-perm hap that is neither a native SA nor a system app is caught by
    // the system-only param gate (sudo intent >= QUESTION_AUTH) before the sudo caller gate
    IpcCommon::DeleteAllPermission();
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);

    UserAuthService service;
    auto testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(CHECK_SYSTEM_APP_FAILED, _)).Times(1);

    IpcRemoteAuthParam ipcRemoteAuthParam = {};
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.AuthUser(MakeSudoIpcParam("sudo title"), ipcRemoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, CHECK_SYSTEM_APP_FAILED);
    EXPECT_EQ(contextId, 0);
    DrainSerialThread();
}

HWTEST_F(UserAuthServiceSudoTest, UserAuthServiceSudoAuthParamRejected, TestSize.Level0)
{
    UserAuthService service;
    IpcRemoteAuthParam ipcRemoteAuthParam = {};

    auto expectRejected = [&service](IpcAuthParamInner &ipcAuthParamInner, IpcRemoteAuthParam &remoteParam) {
        auto testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
        ASSERT_NE(testCallback, nullptr);
        EXPECT_CALL(*testCallback, OnResult(ResultCode::INVALID_PARAMETERS, _)).Times(1);
        sptr<IIamCallback> callbackInterface = testCallback;
        uint64_t contextId = SEEDED_CONTEXT_ID;
        int32_t ret = service.AuthUser(ipcAuthParamInner, remoteParam, callbackInterface, contextId);
        EXPECT_EQ(ret, INVALID_PARAMETERS);
        EXPECT_EQ(contextId, 0);
        auto contexts = ContextPool::Instance().Select(SUDO_AUTH_CONTEXT);
        EXPECT_TRUE(contexts.empty());
    };

    // authType not PIN
    auto param = MakeSudoIpcParam("sudo title");
    param.authType = static_cast<int32_t>(AuthType::FACE);
    expectRejected(param, ipcRemoteAuthParam);

    // empty additionalInfo
    param = MakeSudoIpcParam("");
    expectRejected(param, ipcRemoteAuthParam);

    // over ADDITIONAL_INFO_MAX characters
    param = MakeSudoIpcParam(std::string(ADDITIONAL_INFO_MAX + 1, 'x'));
    expectRejected(param, ipcRemoteAuthParam);

    // reuse unlock result not allowed
    param = MakeSudoIpcParam("sudo title");
    param.reuseUnlockResult.isReuse = true;
    param.reuseUnlockResult.reuseDuration = REUSE_DURATION_MS;
    expectRejected(param, ipcRemoteAuthParam);

    // remote auth not allowed
    param = MakeSudoIpcParam("sudo title");
    IpcRemoteAuthParam remoteParam = {};
    remoteParam.isHasRemoteAuthParam = true;
    expectRejected(param, remoteParam);

    // token schedule with remote param is rejected: sudo does not accept remote param,
    // and schedule+remote is rejected at the AuthUser param gate
    param = MakeSudoIpcParam("sudo title");
    param.hasTokenSchedule = true;
    expectRejected(param, remoteParam);
}

HWTEST_F(UserAuthServiceSudoTest, UserAuthServiceSudoAuthAcceptsTokenSchedule, TestSize.Level0)
{
    // sudo supports scheduled auth token: a valid schedule passes the sudo param gate and
    // the sudo context is created (param plumbing only; no credential pinned so the child
    // ends with NOT_ENROLLED, engine schedule binding is out of scope here)
    // sudo auth and tokenSchedule are both system-api-only, so the caller must be a system caller
    IpcCommon::DeleteAllPermission();
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);

    UserAuthService service;
    auto testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    IpcAuthParamInner param = MakeSudoIpcParam("sudo title");
    param.hasTokenSchedule = true;
    param.hasTokenScheduleValidStartTime = true;
    param.hasTokenScheduleValidEndTime = true;
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    param.tokenScheduleValidStartTime = now;
    param.tokenScheduleValidEndTime = now + 3600 * 1000; // 1h span, within MAX_TOKEN_SCHEDULE_SPAN_MS

    IpcRemoteAuthParam ipcRemoteAuthParam = {};
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.AuthUser(param, ipcRemoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, 0);
    DrainSerialThread();
}

// pins a last-attempt pin credential behind the mock executor so the SUDO routes
// to the dialog branch
void PrimeDialogBranchExecutor()
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
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(PIN_EXECUTOR_INDEX, PIN, ALL_IN_ONE);
    ASSERT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto *node = static_cast<MockResourceNode *>(resourceNode.get());
    ON_CALL(*node, GetProperty(_, _))
        .WillByDefault([](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 1);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, static_cast<int32_t>(PinSubType::PIN_SIX));
            return SUCCESS;
        });
}

HWTEST_F(UserAuthServiceSudoTest, UserAuthServiceSudoAuthDialogBranch, TestSize.Level0)
{
    PrimeDialogBranchExecutor();

    UserAuthService service;
    auto testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    ASSERT_NE(testCallback, nullptr);
    // no UI extension here: the dialog child waits in the widget FSM forever, so drive
    // the terminal by cancelling -- the cascade delivers exactly one CANCELED
    EXPECT_CALL(*testCallback, OnResult(ResultCode::CANCELED, _)).Times(1);

    IpcRemoteAuthParam ipcRemoteAuthParam = {};
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    int32_t ret = service.AuthUser(MakeSudoIpcParam("last chance"), ipcRemoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, 0);
    DrainSerialThread();

    // SUDO orchestrator entered the pool and routed to the dialog branch.
    auto sudoContext = ContextPool::Instance().Select(contextId).lock();
    ASSERT_NE(sudoContext, nullptr);
    EXPECT_EQ(sudoContext->GetContextType(), SUDO_AUTH_CONTEXT);
    EXPECT_EQ(sudoContext->GetAuthIntent(), AuthIntent::SUDO_PIN_AUTH);

    // the caller's additionalInfo is the user-visible title of the warning dialog
    auto widgetChildren = ContextPool::Instance().Select(WIDGET_AUTH_CONTEXT);
    ASSERT_EQ(widgetChildren.size(), 1UL);
    auto dialogChild = std::static_pointer_cast<WidgetContext>(widgetChildren.front().lock());
    ASSERT_NE(dialogChild, nullptr);
    EXPECT_EQ(dialogChild->para_.widgetParam.title, "last chance");

    auto cancelHandler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(cancelHandler, nullptr);
    cancelHandler->PostTask([sudoContext]() { sudoContext->Stop(); });
    // the stop cascade is a chain of posted tasks: poll-drain instead of betting
    // on a fixed count
    constexpr int32_t pollRounds = 100;
    constexpr int32_t pollIntervalMs = 10;
    bool parentReleased = false;
    for (int32_t i = 0; i < pollRounds; ++i) {
        DrainSerialThread();
        if (ContextPool::Instance().Select(contextId).lock() == nullptr) {
            parentReleased = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs));
    }
    EXPECT_TRUE(parentReleased);
}

HWTEST_F(UserAuthServiceSudoTest, UserAuthServiceSudoAuthPermissionDenied, TestSize.Level0)
{
    IpcCommon::DeleteAllPermission();
    UserAuthService service;
    auto testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(ResultCode::CHECK_SYSTEM_APP_FAILED, _)).Times(1);

    IpcRemoteAuthParam ipcRemoteAuthParam = {};
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = SEEDED_CONTEXT_ID;
    int32_t ret = service.AuthUser(MakeSudoIpcParam("sudo title"), ipcRemoteAuthParam, callbackInterface, contextId);
    EXPECT_EQ(ret, CHECK_SYSTEM_APP_FAILED);
    EXPECT_EQ(contextId, 0);
    DrainSerialThread();
    auto contexts = ContextPool::Instance().Select(SUDO_AUTH_CONTEXT);
    EXPECT_TRUE(contexts.empty());
}

HWTEST_F(UserAuthServiceSudoTest, UserAuthServicePublicAuthNotRoutedToSudo, TestSize.Level0)
{
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    // the plain auth context must stay pooled and running, so the face credential
    // and its executor have to exist
    ON_CALL(*mockHdi, GetCredential(_, _, _))
        .WillByDefault([](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            infos.push_back({.credentialId = 1, .executorIndex = PIN_EXECUTOR_INDEX, .templateId = 9,
                .authType = static_cast<HdiAuthType>(AuthType::FACE), .executorMatcher = 1,
                .executorSensorHint = 1, .authSubType = 0});
            return HDF_SUCCESS;
        });
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(PIN_EXECUTOR_INDEX, FACE, ALL_IN_ONE);
    ASSERT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    ON_CALL(*mockHdi, BeginAuthenticationExt(_, _, _))
        .WillByDefault([](uint64_t contextId, const HdiAuthParamExt &param,
            std::vector<HdiScheduleInfo> &scheduleInfos) {
            HdiScheduleInfo scheduleInfo = {};
            scheduleInfo.authType = HdiAuthType::FACE;
            scheduleInfo.executorMatcher = 0;
            scheduleInfo.executorIndexes.push_back(PIN_EXECUTOR_INDEX);
            scheduleInfo.scheduleId = FACE_SCHEDULE_ID;
            scheduleInfo.scheduleMode = ScheduleMode::AUTH;
            scheduleInfo.templateIds.push_back(FACE_TEMPLATE_ID);
            std::vector<uint8_t> executorMessages;
            executorMessages.resize(1);
            scheduleInfo.executorMessages.push_back(executorMessages);
            scheduleInfos.push_back(scheduleInfo);
            return HDF_SUCCESS;
        });

    UserAuthService service;
    auto testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto ipcAuthParamInner = MakeSudoIpcParam("sudo title");
    ipcAuthParamInner.authType = static_cast<int32_t>(AuthType::FACE);
    IpcRemoteAuthParam ipcRemoteAuthParam = {};
    sptr<IIamCallback> callbackInterface = testCallback;
    uint64_t contextId = 0;
    constexpr int32_t legacyApiVersion = 9;
    int32_t ret = service.Auth(legacyApiVersion, ipcAuthParamInner, callbackInterface, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(contextId, 0);
    DrainSerialThread();

    auto sudoContexts = ContextPool::Instance().Select(SUDO_AUTH_CONTEXT);
    EXPECT_TRUE(sudoContexts.empty());
    auto authContext = ContextPool::Instance().Select(contextId).lock();
    ASSERT_NE(authContext, nullptr);
    EXPECT_EQ(authContext->GetContextType(), CONTEXT_SIMPLE_AUTH);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
