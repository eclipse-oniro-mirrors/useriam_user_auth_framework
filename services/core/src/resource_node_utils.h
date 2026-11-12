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

#ifndef IAM_RESOURCE_NODE_UTILS_H
#define IAM_RESOURCE_NODE_UTILS_H

#include <cstdint>
#include <map>
#include <memory>

#include "credential_info_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ResourceNodeUtils {
public:
    static int32_t NotifyExecutorToDeleteTemplates(const std::vector<std::shared_ptr<CredentialInfoInterface>> &infos,
        std::string changeReasonTrace);
    static void SendMsgToExecutor(uint64_t executorIndex, int32_t commandId, const std::vector<uint8_t> &msg);
    static void SetCachedTemplates(uint64_t executorIndex,
        const std::vector<std::shared_ptr<CredentialInfoInterface>> &infos);
    static ResultCode ClassifyCredInfoByExecutor(const std::vector<std::shared_ptr<CredentialInfoInterface>> &in,
        std::map<uint64_t, std::vector<std::shared_ptr<CredentialInfoInterface>>> &out);
    static int32_t SendCommandToExecutor(AuthType authType, ExecutorRole role, uint32_t propertyMode,
        const std::vector<uint8_t> &extraInfo, std::vector<uint8_t> &extraOut);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_RESOURCE_NODE_UTILS_H