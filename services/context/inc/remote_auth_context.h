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

#ifndef REMOTE_AUTH_CONTEXT_H
#define REMOTE_AUTH_CONTEXT_H

#include <cstdint>
#include <memory>
#include <mutex>

#include "authentication_impl.h"
#include "remote_executor_proxy.h"
#include "simple_auth_context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
struct RemoteAuthContextParam {
    AuthType authType;
    std::string connectionName;
    std::string collectorNetworkId;
    std::vector<uint8_t> executorInfoMsg;
};

class RemoteAuthContext : public SimpleAuthContext {
public:
    RemoteAuthContext(uint64_t contextId, std::shared_ptr<Authentication> auth, RemoteAuthContextParam &param,
        bool isPrimaryContext, std::shared_ptr<ContextCallback> callback);
    ~RemoteAuthContext() override;
    ContextType GetContextType() const override;

    void SetExecutorInfoMsg(std::vector<uint8_t> msg);

    void OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus);

    void OnTimeOut();

protected:
    bool OnStart() override;

#ifndef IAM_TEST_ENABLE
private:
#endif
    bool StartAuth();
    void StartAuthDelayed();
    bool SetupConnection();
    bool SendQueryExecutorInfoMsg();

    std::recursive_mutex mutex_;
    int32_t authType_ = INVALID_AUTH_TYPE;
    std::string connectionName_;
    std::string collectorNetworkId_;
    std::vector<uint8_t> executorInfoMsg_;

    bool needSetupConnection_ = false;
    std::string endPointName_;
    std::shared_ptr<RemoteExecutorProxy> remoteExecutorProxy_ = nullptr;
    std::optional<uint32_t> cancelTimerId_ = std::nullopt;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // REMOTE_AUTH_CONTEXT_H