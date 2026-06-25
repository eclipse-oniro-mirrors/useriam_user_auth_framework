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

#ifndef IAM_BASE_CONTEXT_H
#define IAM_BASE_CONTEXT_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "nocopyable.h"
#include "context.h"
#include "context_appstate_observer.h"
#include "context_callback.h"
#include "context_death_recipient.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::AppExecFwk;
class BaseContext : public ScheduleNodeCallback,
                    public Context,
                    public std::enable_shared_from_this<BaseContext>,
                    public ContextDeathRecipientManager,
                    public ContextAppStateObserverManager,
                    public NoCopyable {
public:
    BaseContext(const std::string &type, uint64_t contextId, std::shared_ptr<ContextCallback> callback,
        bool needSubscribeAppState);
    ~BaseContext() override;

    uint64_t GetContextId() const override;
    std::shared_ptr<ScheduleNode> GetScheduleNode(uint64_t scheduleId) const override;
    int32_t GetUserId() const override;
    int32_t GetAuthType() const override;
    std::string GetCallerName() const override;

    void OnScheduleStarted() override;
    void OnScheduleProcessed(ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg) override;
    void OnScheduleStoped(int32_t resultCode, const std::shared_ptr<Attributes> &finalResult) override;
    void SetRemoteAuthParam(const WidgetParamInner &widgetParam, const sptr<IModalCallback> &modalCallback) override;
    int32_t GetLatestError() const override;

protected:
    void SetLatestError(int32_t error) override;
    const char *GetDescription() const;
    virtual bool OnStart() = 0;
    virtual void OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr) = 0;
    virtual bool OnStop() = 0;
    std::vector<std::shared_ptr<ScheduleNode>> GetScheduleList() const;
    void SetScheduleList(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList);
    std::shared_ptr<ContextCallback> callback_ = nullptr;

private:
    bool Start() final;
    bool Stop() final;
    uint64_t contextId_ = INVALID_CONTEXT_ID;
    std::string description_;
    bool hasStarted_ = false;
    mutable std::recursive_mutex mutex_;
    int32_t latestError_ = ResultCode::GENERAL_ERROR;
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_BASE_CONTEXT_H