/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "context_pool_impl_fuzzer.h"

#include "parcel.h"

#include "dummy_authentication.h"
#include "dummy_context_pool.h"
#include "dummy_iam_callback_interface.h"
#include "dummy_executor_callback_interface.h"
#include "dummy_resource_node.h"
#include "dummy_schedule_node_callback.h"

#include "attributes.h"
#include "context.h"
#include "context_pool.h"
#include "context_callback_impl.h"
#include "context_arbitration_policy.h"
#include "iam_check.h"
#include "iam_event_dispatcher.h"
#include "simple_auth_context.h"
#include "thread_handler.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_CONTEXT_POOL_IMPL

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t OPERATION_TYPE = 1;

void FillTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    SetIamEventDispatcher(CreateIamEventDispatcher());
    ContextPool::Instance().GetNewContextId();
    
    auto dummyAuth = MakeShared<DummyAuthentication>();
    auto contextCallback = MakeShared<ContextCallbackImpl>(new (std::nothrow) DummyIamCallbackInterface(),
        static_cast<OperationType>(OPERATION_TYPE));
    auto context = MakeShared<SimpleAuthContext>(parcel.ReadUint64(), dummyAuth, true, false, contextCallback);
    if (context != nullptr && contextCallback != nullptr) {
        // a terminal result must take the context out of the pool like the service does
        contextCallback->SetCleaner(ContextPool::Cleaner(context));
    }

    ContextPool::Instance().Schedule(context);

    ContextPool::Instance().Delete(parcel.ReadUint64());

    ContextPool::Instance().CancelAll();

    ContextPool::Instance().Select(parcel.ReadUint64());

    ContextPool::Instance().Select(static_cast<ContextType>(parcel.ReadUint32()));

    ContextPool::Instance().SelectScheduleNodeByScheduleId(parcel.ReadUint64());

    IAM_LOGI("end");
}

// a plain controllable context with fields straight from the fuzz input, so real
// arbitration sees varied types/users/callers and the FIFO, waiting and
// same-caller-supersede branches become reachable
class FuzzArbitrationContext : public Context {
public:
    FuzzArbitrationContext(uint64_t contextId, ContextType type, bool isPrimary, int32_t userId,
        const std::string &callerName, AuthType authType, bool forceWait)
        : contextId_(contextId), type_(type), isPrimary_(isPrimary), userId_(userId),
          callerName_(callerName), authType_(authType), forceWait_(forceWait)
    {
    }
    ~FuzzArbitrationContext() override = default;

    bool Start() override
    {
        return true;
    }
    void OnStartFailed(int32_t errorCode) override
    {
        static_cast<void>(errorCode);
    }
    uint64_t GetContextId() const override
    {
        return contextId_;
    }
    ContextType GetContextType() const override
    {
        return type_;
    }
    std::shared_ptr<ScheduleNode> GetScheduleNode(uint64_t scheduleId) const override
    {
        static_cast<void>(scheduleId);
        return nullptr;
    }
    uint32_t GetTokenId() const override
    {
        return 0;
    }
    int32_t GetLatestError() const override
    {
        return GENERAL_ERROR;
    }
    int32_t GetUserId() const override
    {
        return userId_;
    }
    std::string GetCallerName() const override
    {
        return callerName_;
    }
    int32_t GetAuthType() const override
    {
        return static_cast<int32_t>(authType_);
    }
    std::vector<int32_t> GetAuthTypeList() const override
    {
        return {static_cast<int32_t>(authType_)};
    }
    void SetRemoteAuthParam(const WidgetParamInner &widgetParam, const sptr<IModalCallback> &modalCallback) override
    {
        static_cast<void>(widgetParam);
        static_cast<void>(modalCallback);
    }
    bool IsPrimaryContext() const override
    {
        return isPrimary_;
    }
    bool CanStart(const std::vector<std::weak_ptr<Context>> &predecessors) const override
    {
        if (forceWait_) {
            return false;
        }
        return ContextAdmissionPolicy::CanStart(*this, predecessors);
    }
    bool Stop() override
    {
        // model the real terminal contract: stopping a context leaves the pool
        // (Delete also removes a waiting context), otherwise contexts accumulate
        // and Schedule fails for good
        ContextPool::Instance().Delete(contextId_);
        return true;
    }
    void SetLatestError(int32_t error) override
    {
        static_cast<void>(error);
    }

private:
    uint64_t contextId_;
    ContextType type_;
    bool isPrimary_;
    int32_t userId_;
    std::string callerName_;
    AuthType authType_;
    bool forceWait_;
};

void FillArbitration(Parcel &parcel)
{
    IAM_LOGI("begin");
    SetIamEventDispatcher(CreateIamEventDispatcher());
    static constexpr uint32_t MAX_FUZZ_CONTEXTS = 8;
    static const char *callerNames[] = {"fuzz_caller_a", "fuzz_caller_b", "fuzz_caller_c"};
    static constexpr uint32_t CALLER_KINDS = sizeof(callerNames) / sizeof(callerNames[0]);
    static constexpr uint32_t USER_KINDS = 4;
    uint32_t count = parcel.ReadUint32() % MAX_FUZZ_CONTEXTS;
    std::vector<uint64_t> contextIds;
    for (uint32_t i = 0; i < count; i++) {
        static constexpr uint32_t TYPE_KINDS = 4;
        static constexpr ContextType TYPE_TABLE[TYPE_KINDS] = {
            ContextType::CONTEXT_SIMPLE_AUTH, ContextType::WIDGET_AUTH_CONTEXT,
            ContextType::CONTEXT_IDENTIFY, ContextType::CONTEXT_ENROLL,
        };
        ContextType type = TYPE_TABLE[parcel.ReadUint32() % TYPE_KINDS];
        bool isPrimary = parcel.ReadBool();
        int32_t userId = static_cast<int32_t>(parcel.ReadUint32() % USER_KINDS); // 0..3, mix of users
        std::string callerName = callerNames[parcel.ReadUint32() % CALLER_KINDS]; // mix of same/diff callers
        AuthType authType = (parcel.ReadBool() ? AuthType::PIN : AuthType::FACE);
        bool forceWait = parcel.ReadBool();
        auto context = Common::MakeShared<FuzzArbitrationContext>(ContextPool::Instance().GetNewContextId(),
            type, isPrimary, userId, callerName, authType, forceWait);
        if (context == nullptr) {
            continue;
        }
        contextIds.push_back(context->GetContextId());
        ContextPool::Instance().Schedule(context);
    }
    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
    handler->EnsureTask([]() {});
    if (!contextIds.empty() && parcel.ReadBool()) {
        ContextPool::Instance().Cancel(contextIds[parcel.ReadUint32() % contextIds.size()]);
    }
    ContextPool::Instance().Delete(parcel.ReadUint64());
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
    handler->EnsureTask([]() {});
    // churn between inputs but keep the pool bounded for the next input
    ContextPool::Instance().CancelAll();
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
    handler->EnsureTask([]() {});
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FillTest);
FuzzFunc *g_fuzzFuncs[] = {
    FillTest,
    FillArbitration,
};

void ContextPoolImplFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::ContextPoolImplFuzzTest(data, size);
    return 0;
}
