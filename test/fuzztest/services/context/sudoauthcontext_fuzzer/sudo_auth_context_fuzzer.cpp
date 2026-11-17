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

#include "sudo_auth_context_fuzzer.h"

#include "parcel.h"

#include "attributes.h"
#include "context_callback_impl.h"
#include "context_factory.h"
#include "context_pool.h"
#include "extension_manager_client.h"
#include "iam_check.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "relative_timer.h"
#include "sudo_auth_context.h"
#include "thread_handler.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SUDO_AUTH_CONTEXT

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyUserAuthCallback : public IIamCallback {
public:
    ~DummyUserAuthCallback() override = default;

    int32_t OnAcquireInfo(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo) override
    {
        IAM_LOGI("start");
        static_cast<void>(module);
        static_cast<void>(acquireInfo);
        static_cast<void>(extraInfo);
        return SUCCESS;
    }

    int32_t OnResult(int32_t result, const std::vector<uint8_t> &extraInfo) override
    {
        IAM_LOGI("start");
        static_cast<void>(result);
        static_cast<void>(extraInfo);
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

std::shared_ptr<SudoAuthContext> CreateSudoContext(Parcel &parcel)
{
    uint64_t contextId = ContextPool::Instance().GetNewContextId();
    ContextFactory::SudoAuthContextPara para;
    para.userId = parcel.ReadInt32();
    para.sdkVersion = parcel.ReadInt32();
    para.tokenId = parcel.ReadUint32();
    para.callerType = parcel.ReadInt32();
    para.callerName = "sudo_fuzz_caller";
    para.atl = static_cast<AuthTrustLevel>(parcel.ReadUint32());
    FillFuzzString(parcel, para.additionalInfo);
    para.isOsAccountVerified = parcel.ReadBool();
    auto contextCallback = MakeShared<ContextCallbackImpl>(new (std::nothrow) DummyUserAuthCallback(),
        static_cast<OperationType>(TRACE_AUTH_USER_BEHAVIOR));
    IF_FALSE_LOGE_AND_RETURN_VAL(contextCallback != nullptr, nullptr);
    auto context = Common::MakeShared<SudoAuthContext>(contextId, para, contextCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(context != nullptr, nullptr);
    // mirror the service wiring: a terminal result must take the context out of the
    // pool, otherwise the pool saturates and later Schedules silently fail
    contextCallback->SetCleaner(ContextPool::Cleaner(context));
    return context;
}

ContextFactory::AuthProfile CreateProfile(Parcel &parcel)
{
    ContextFactory::AuthProfile profile;
    profile.pinSubType = parcel.ReadInt32();
    profile.remainTimes = parcel.ReadInt32();
    profile.freezingTime = parcel.ReadInt32();
    profile.cameraStatus = parcel.ReadUint32();
    return profile;
}

void SyncSerialThread()
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
    handler->EnsureTask([]() {});
}

// Widget teardown (FSM stop event -> EndAuthAsCancel -> End -> StopAllRunTask ->
// DisconnectExtension) runs on the singleton timer-backed thread, and the last posts
// come from the destructors of the harness-local contexts, i.e. after the final
// SyncSerialThread() inside each fuzz func. Without a drain after those destructors,
// libFuzzer's exit() races the in-flight DisconnectExtension into aafwk singletons
// being torn down (exit-time SEGV, non-deterministic).
void DrainSingletonThread()
{
    SyncSerialThread();
    // one extra beat for teardown tasks that re-post a follow-up event
    SyncSerialThread();
}

// Drain alone cannot close the exit race: the widget teardown chain (FSM stop
// event -> EndAuthAsCancel -> ... -> DisconnectExtension) may still be in
// flight on the timer thread while exit() is running. ExtensionManagerClient
// is a Meyers singleton whose __cxa_atexit destructor registers at FIRST USE
// (mid-run), i.e. AFTER our guard below -- and reverse destruction order then
// runs its destructor BEFORE our guard, destroying mutex_/proxy_ under the
// in-flight chain (SEGV in GetExtensionManager, 2026-11-16 rerun faultlog;
// first run SEGV'd in RefBase::IncStrongRef on the already-released proxy).
// So: force construction of every racing lazy singleton BEFORE constructing
// our guard, so their destructors register EARLIER and run AFTER us; our
// guard then drains the timer thread and stops it entirely, and no teardown
// code can touch half-destroyed singletons. G.FUU.04 forbids atexit(), so the
// hook is a function-local static guard whose destructor runs at exit instead.
struct SingletonThreadStopGuard {
    ~SingletonThreadStopGuard()
    {
        DrainSingletonThread();
        RelativeTimer::GetInstance().Stop();
    }
};

void InstallSingletonThreadStopHook()
{
    RelativeTimer::GetInstance(); // leaky DelayedRefSingleton; constructed here for clarity
    AAFwk::ExtensionManagerClient::GetInstance(); // Meyers static; construct early, see above
    static const SingletonThreadStopGuard guard;
    (void)guard;
}

// schedule/start through the real profile query (no HDI mock, so it fail-closes),
// a direct fuzz-profile Route and a child terminal, then a pool cancel; the
// FAIL-to-LOCKED synthesis in OnChildResult is unreachable without a profile mock
void FuzzRouteAndTerminal(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto sudo = CreateSudoContext(parcel);
    IF_FALSE_LOGE_AND_RETURN(sudo != nullptr);
    ContextPool::Instance().Schedule(sudo);
    SyncSerialThread();

    sudo->DispatchByProfile(CreateProfile(parcel));

    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION,
        static_cast<int32_t>(parcel.ReadUint32()));
    sudo->OnChildResult(parcel.ReadInt32(), finalResult);

    ContextPool::Instance().Cancel(sudo->GetContextId());
    SyncSerialThread();
    // drop any still-pooled parent so the pool cannot saturate across iterations
    ContextPool::Instance().Delete(sudo->GetContextId());
    SyncSerialThread();
    IAM_LOGI("end");
}

// a second SUDO while the first holds the dialog exercises the takeover path
void FuzzSudoPreemptedByNewSudo(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto first = CreateSudoContext(parcel);
    IF_FALSE_LOGE_AND_RETURN(first != nullptr);
    ContextPool::Instance().Schedule(first);
    SyncSerialThread();

    ContextFactory::AuthProfile dialogProfile;
    dialogProfile.remainTimes = 1;
    first->DispatchByProfile(dialogProfile);
    first->GetPreemptDecision(*first);

    auto second = CreateSudoContext(parcel);
    if (second != nullptr) {
        ContextPool::Instance().Schedule(second);
    }
    SyncSerialThread();

    ContextPool::Instance().CancelAll();
    SyncSerialThread();
    // CancelAll stops what it can, but wedged holders survive it; clear the rest
    ContextPool::Instance().Delete(first->GetContextId());
    if (second != nullptr) {
        ContextPool::Instance().Delete(second->GetContextId());
    }
    SyncSerialThread();
    IAM_LOGI("end");
}

// schedule then stop from the pool door before any routing happens
void FuzzCancelBeforeRoute(Parcel &parcel)
{
    IAM_LOGI("begin");
    auto sudo = CreateSudoContext(parcel);
    IF_FALSE_LOGE_AND_RETURN(sudo != nullptr);
    ContextPool::Instance().Schedule(sudo);
    ContextPool::Instance().Cancel(sudo->GetContextId());
    SyncSerialThread();
    sudo->DispatchByProfile(CreateProfile(parcel));
    SyncSerialThread();
    ContextPool::Instance().Delete(sudo->GetContextId());
    SyncSerialThread();
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzRouteAndTerminal);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzRouteAndTerminal,
    FuzzSudoPreemptedByNewSudo,
    FuzzCancelBeforeRoute,
};

} // namespace

void SudoAuthContextFuzzTest(const uint8_t *data, size_t size)
{
    InstallSingletonThreadStopHook();
    {
        Parcel parcel;
        parcel.WriteBuffer(data, size);
        parcel.RewindRead(0);
        uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
        auto fuzzFunc = g_fuzzFuncs[index];
        fuzzFunc(parcel);
    } // harness-local contexts are destroyed here; their destructors post the final stop events
    DrainSingletonThread();
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::SudoAuthContextFuzzTest(data, size);
    return 0;
}
