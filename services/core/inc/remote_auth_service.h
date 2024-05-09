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

#ifndef REMOTE_AUTH_SERVICE_H
#define REMOTE_AUTH_SERVICE_H

#include <map>
#include <mutex>
#include <string>

#include "attributes.h"
#include "remote_connect_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteAuthService {
public:
    static RemoteAuthService &GetInstance();
    RemoteAuthService() = default;
    virtual ~RemoteAuthService() = default;

    virtual bool Start() = 0;
    virtual void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply) = 0;

    virtual int32_t ProcStartRemoteAuthRequest(std::string connectionName, const std::shared_ptr<Attributes> &request,
        std::shared_ptr<Attributes> &reply) = 0;
    virtual int32_t ProcQueryExecutorInfoRequest(const std::shared_ptr<Attributes> &request,
        std::shared_ptr<Attributes> &reply) = 0;
    virtual int32_t ProcBeginExecuteRequest(const std::shared_ptr<Attributes> &request,
        std::shared_ptr<Attributes> &reply) = 0;
    virtual int32_t ProcEndExecuteRequest(const std::shared_ptr<Attributes> &request,
        std::shared_ptr<Attributes> &reply) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // REMOTE_AUTH_SERVICE_H