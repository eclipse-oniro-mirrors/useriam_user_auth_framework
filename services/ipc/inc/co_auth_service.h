/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef CO_AUTH_SERVICE_H
#define CO_AUTH_SERVICE_H

#include "co_auth_stub.h"
#include "co_auth_interface.h"

#include <optional>

#include "resource_node_pool.h"
#include <system_ability.h>
#include <system_ability_definition.h>
#include "system_ability_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using ExecutorRegisterInfo = CoAuthInterface::ExecutorRegisterInfo;
class CoAuthService : public SystemAbility, public CoAuthStub {
public:
    static constexpr uint32_t DEFER_TIME = 100;
    DECLARE_SYSTEM_ABILITY(CoAuthService);
    static std::shared_ptr<CoAuthService> GetInstance();

    CoAuthService();
    ~CoAuthService() override = default;
    int Dump(int fd, const std::vector<std::u16string> &args) override;
    int32_t ExecutorRegister(const IpcExecutorRegisterInfo &ipcExecutorRegisterInfo,
        const sptr<IExecutorCallback> &executorCallback, uint64_t &executorIndex) override;
    int32_t ExecutorUnregister(uint64_t executorIndex) override;
    void SetIsReady(bool isReady);
    void SetAccessTokenReady(bool isReady);
    void OnEngineReady();
    void OnEngineUnavailable();
    ResultCode RegisterAccessTokenListener();
    ResultCode UnRegisterAccessTokenListener();
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

protected:
    void OnStart() override;
    void OnStop() override;

private:
    static void AddExecutorDeathRecipient(uint64_t executorIndex, AuthType authType, ExecutorRole role,
        std::shared_ptr<IExecutorCallback> callback);
    void NotifyFwkReady();
    bool IsFwkReady();
    int32_t ProcExecutorRegisterSuccess(std::shared_ptr<ResourceNode> &resourceNode,
        const std::shared_ptr<IExecutorCallback> &callback, std::vector<uint64_t> &templateIdList,
        std::vector<uint8_t> &fwkPublicKey);
    void InitExecutorRegisterInfo(const IpcExecutorRegisterInfo &ipcExecutorRegisterInfo,
        ExecutorRegisterInfo &executorRegisterInfo);

    static std::shared_ptr<CoAuthService> instance_;
    std::recursive_mutex mutex_;
    bool isReady_{false};
    bool accessTokenReady_{false};
    sptr<SystemAbilityListener> accessTokenListener_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_SERVICE_H
