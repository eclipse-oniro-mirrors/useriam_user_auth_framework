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

#ifndef IAM_SOFT_BUS_MESSAGE_H
#define IAM_SOFT_BUS_MESSAGE_H

#include <cstdint>
#include <vector>
#include <string>

#include "device_manager_util.h"
#include "nocopyable.h"
#include "attributes.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class SoftBusMessage : public std::enable_shared_from_this<SoftBusMessage>,
                       public NoCopyable {
public:
    SoftBusMessage(int32_t messageSeq, const std::string &connectionName,
        const std::string &srcEndPoint, const std::string &destEndPoint,
        const std::shared_ptr<Attributes> &attributes);
    ~SoftBusMessage() override = default;

    uint32_t GetMessageSeq();
    uint32_t GetMessageVersion();
    uint32_t GetAckFlag();
    std::shared_ptr<Attributes> GetAttributes();
    std::string GetSrcEndPoint();
    std::string GetDestEndPoint();
    std::string GetConnectionName();
    std::shared_ptr<Attributes> CreateMessage(bool response);
    std::shared_ptr<Attributes> ParseMessage(const void *message, uint32_t messageLen);

private:
    uint32_t messageSeq_ = 0;
    uint32_t messageVersion_ = 0;
    std::string connectionName_ = "";
    std::string srcEndPoint_ = "";
    std::string destEndPoint_ = "";
    std::shared_ptr<Attributes> attributes_ = nullptr;
    bool isAck_ = false;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SOFT_BUS_CHANNEL_H
