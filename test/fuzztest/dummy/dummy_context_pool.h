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

#ifndef DUMMY_CONTEXT_POOL_H
#define DUMMY_CONTEXT_POOL_H

#include "context_pool.h"
#include "context_callback_impl.h"
#include "simple_auth_context.h"
#include "dummy_authentication.h"
#include "dummy_iam_callback_interface.h"
#include "iam_ptr.h"


#undef private

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyContextPool : public ContextPool {
public:
    static uint64_t GetNewContextId()
    {
        return 0;
    };
    static ContextPool &Instance();
    bool Schedule(const std::shared_ptr<Context> &context)
    {
        return true;
    };
    bool Delete(uint64_t contextId)
    {
        return true;
    };
    void Cancel(uint64_t contextId) {};
    void CancelAll() {};
    void NotifyPreemptStateChanged() {};
    std::weak_ptr<Context> Select(uint64_t contextId) const
    {
        constexpr uint32_t OPERATIONTYPE = 1;
        constexpr uint64_t CONTEXT_ID = 1;
        auto dummyAuthentication = Common::MakeShared<DummyAuthentication>();
        auto contextCallback = Common::MakeShared<ContextCallbackImpl>(new (std::nothrow) DummyIamCallbackInterface(),
        static_cast<UserAuth::OperationType>(OPERATIONTYPE));
        auto context = Common::MakeShared<SimpleAuthContext>(CONTEXT_ID, dummyAuthentication, true, false,
        contextCallback);
        return context;
    };
    std::vector<std::weak_ptr<Context>> Select(ContextType contextType) const
    {
        return {};
    };
    std::shared_ptr<ScheduleNode> SelectScheduleNodeByScheduleId(uint64_t scheduleId)
    {
        return nullptr;
    };
    void StartSubscribeOsAccountSaStatus() {};
#ifdef IAM_TEST_ENABLE
    std::vector<std::weak_ptr<Context>> SelectAll() const
    {
        return {};
    };
#endif
};
}
} // UserAuth
} // UserIam
} // OHOS

#endif // DUMMY_CONTEXT_POOL_H