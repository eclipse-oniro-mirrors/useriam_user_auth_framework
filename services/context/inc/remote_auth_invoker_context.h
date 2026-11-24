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

#ifndef REMOTE_AUTH_INVOKER_CONTEXT_H
#define REMOTE_AUTH_INVOKER_CONTEXT_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

#include "attributes.h"
#include "authentication_impl.h"
#include "base_context.h"
#include "remote_auth_context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
struct RemoteAuthInvokerContextParam {
    std::string connectionName;
    std::string verifierNetworkId;
    std::string collectorNetworkId;
    uint32_t tokenId;
    uint32_t collectorTokenId;
    std::string callerName;
    int32_t callerType;
};

class RemoteAuthInvokerContext : public BaseContext {
public:
    RemoteAuthInvokerContext(uint64_t contextId, AuthParamInner authParam, RemoteAuthInvokerContextParam param,
        std::shared_ptr<ContextCallback> callback);
    ~RemoteAuthInvokerContext() override;
    ContextType GetContextType() const override;
    uint32_t GetTokenId() const override;

    void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply);
    void OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus);

    void SetVerifierContextId(uint64_t contextId);
    void OnTimeOut();

protected:
    bool OnStart() override;
    void OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr) override;
    bool OnStop() override;

private:
    int32_t ProcAuthTipMsg(Attributes &message);
    int32_t ProcAuthResultMsg(Attributes &message);
    int32_t ProcAuthResultMsgInner(Attributes &message, int32_t &resultCode, Attributes &attr);

    bool SendRequest();

    AuthParamInner authParam_;
    std::string connectionName_;
    std::string verifierNetworkId_;
    std::string collectorNetworkId_;
    std::string verifierUdid_;
    uint32_t tokenId_ = 0;
    uint32_t collectorTokenId_ = 0;
    std::string callerName_;
    int32_t callerType_ = -1;
    std::shared_ptr<ContextCallback> callback_ {nullptr};

    std::recursive_mutex mutex_;
    std::shared_ptr<Attributes> request_ = nullptr;
    std::string endPointName_;
    std::optional<uint64_t> verifierContextId_;
    std::optional<uint32_t> cancelTimerId_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // REMOTE_AUTH_INVOKER_CONTEXT_H