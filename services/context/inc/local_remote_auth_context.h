/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef LOCAL_REMOTE_AUTH_CONTEXT_H
#define LOCAL_REMOTE_AUTH_CONTEXT_H

#include <cstdint>
#include <memory>
#include <mutex>

#include "authentication_impl.h"
#include "simple_auth_context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
struct LocalRemoteAuthContextParam {
    std::string collectorNetworkId;
};

class LocalRemoteAuthContext : public SimpleAuthContext {
public:
    LocalRemoteAuthContext(uint64_t contextId, std::shared_ptr<Authentication> auth, LocalRemoteAuthContextParam &param,
        bool isPrimaryContext, std::shared_ptr<ContextCallback> callback);
    ~LocalRemoteAuthContext() override;
    ContextType GetContextType() const override;

    void OnTimeOut();

protected:
    bool OnStart() override;

#ifndef IAM_TEST_ENABLE
private:
#endif
    std::recursive_mutex mutex_;
    std::string collectorNetworkId_;
    std::optional<uint32_t> cancelTimerId_ = std::nullopt;
};

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // LOCAL_REMOTE_AUTH_CONTEXT_H
