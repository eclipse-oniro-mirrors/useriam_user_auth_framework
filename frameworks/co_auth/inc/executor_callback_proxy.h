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

#ifndef EXECUTOR_CALLBACK_PROXY_H
#define EXECUTOR_CALLBACK_PROXY_H

#include <iremote_proxy.h>
#include "nocopyable.h"
#include "iexecutor_callback.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class ExecutorCallbackProxy : public IRemoteProxy<IExecutorCallback> {
public:
    explicit ExecutorCallbackProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IExecutorCallback>(impl) {}
    ~ExecutorCallbackProxy() override = default;

    void OnMessengerReady(const sptr<IExecutorMessenger> &messenger,
        std::vector<uint8_t> &frameworkPublicKey, std::vector<uint64_t> &templateIds) override;
    int32_t OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
        std::shared_ptr<UserIam::UserAuth::Attributes> commandAttrs) override;
    int32_t OnEndExecute(uint64_t scheduleId, std::shared_ptr<UserIam::UserAuth::Attributes> consumerAttr) override;
    int32_t OnSetProperty(std::shared_ptr<UserIam::UserAuth::Attributes> properties)  override;
    int32_t OnGetProperty(std::shared_ptr<UserIam::UserAuth::Attributes> conditions,
        std::shared_ptr<UserIam::UserAuth::Attributes> values) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<ExecutorCallbackProxy> delegator_;
};
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS

#endif  // EXECUTOR_CALLBACK_PROXY_H