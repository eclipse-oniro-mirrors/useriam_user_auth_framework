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

#include <mutex>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ServiceInitManager {
public:
    static ServiceInitManager &GetInstance();

    void OnIdmServiceStart();
    void OnIdmServiceStop();

    void OnCoAuthServiceStart();
    void OnCoAuthServiceStop();

    void OnUserAuthServiceStart();
    void OnUserAuthServiceStop();

private:
    ServiceInitManager() = default;
    ~ServiceInitManager() = default;

    void CheckAllServiceStart();
    void CheckAllServiceStop();

    std::recursive_mutex mutex_;

    bool isUserAuthServiceStart_ = false;
    bool isCoAuthServiceStart_ = false;
    bool isIdmServiceStart_ = false;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // SERVICE_INIT_MANAGER_H
