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

#ifndef SERVICE_INIT_MANAGER_H
#define SERVICE_INIT_MANAGER_H

#include <memory>

#include "iam_common_defines.h"
#include "system_ability_listener.h"
#include "thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ServiceInitManager {
public:
    static ServiceInitManager &GetInstance();

    void OnCoAuthServiceStart();
    void OnCoAuthServiceStop();
    void OnUserAuthServiceStart();
    void OnUserAuthServiceStop();
    void OnIdmServiceStart();
    void OnIdmServiceStop();

    void OnEngineReady();
    void OnEngineUnavailable();
    void OnAccessTokenReady();

private:
    ServiceInitManager();
    ~ServiceInitManager() = default;

    void StartCoAuthServiceImpl();
    void StopCoAuthServiceImpl();
    void StartUserAuthServiceImpl();
    void StopUserAuthServiceImpl();
    void StartIdmServiceImpl();
    void StopIdmServiceImpl();

    void HandleServiceStart();
    void HandleServiceStop();

    void InitGlobalInstance();
    void DeinitGlobalInstance();
    void CheckAllFlags();
    void PublishAllServices();

    void OnEngineReadyImpl();
    void OnEngineUnavailableImpl();
    void OnAccessTokenReadyImpl();

    ResultCode RegisterAccessTokenListenerImpl();
    ResultCode UnRegisterAccessTokenListenerImpl();

    std::shared_ptr<ThreadHandler> threadHandler_;

    bool isCoAuthServiceStart_ = false;
    bool isUserAuthServiceStart_ = false;
    bool isIdmServiceStart_ = false;
    bool accessTokenReady_ = false;
    bool fwkReady_ = false;
    bool engineReady_ = false;

    sptr<SystemAbilityListener> accessTokenListener_{nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // SERVICE_INIT_MANAGER_H
