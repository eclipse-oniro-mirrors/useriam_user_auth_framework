/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef IAM_CONTEXT_POOL_H
#define IAM_CONTEXT_POOL_H

#include <cstdint>

#include "context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ContextPool {
public:
    class Cleaner final {
    public:
        explicit Cleaner(const std::shared_ptr<Context> &context);
        ~Cleaner() = default;
        void operator()();

    private:
        uint64_t contextId_ = INVALID_CONTEXT_ID;
    };

    static uint64_t GetNewContextId();
    static ContextPool &Instance();
    virtual bool Schedule(const std::shared_ptr<Context> &context) = 0;
    virtual void Cancel(uint64_t contextId) = 0;
    virtual bool Delete(uint64_t contextId) = 0;
    virtual void CancelAll() = 0;
    virtual void NotifyPreemptStateChanged() = 0;
    virtual std::weak_ptr<Context> Select(uint64_t contextId) const = 0;
    virtual std::vector<std::weak_ptr<Context>> Select(ContextType contextType) const = 0;
    virtual std::shared_ptr<ScheduleNode> SelectScheduleNodeByScheduleId(uint64_t scheduleId) = 0;
    virtual void StartSubscribeOsAccountSaStatus() = 0;
#ifdef IAM_TEST_ENABLE
    virtual std::vector<std::weak_ptr<Context>> SelectAll() const = 0;
#endif
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CONTEXT_POOL_H
