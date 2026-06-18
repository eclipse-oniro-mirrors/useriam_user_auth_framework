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

#include "hdi_message_callback_service.h"

#include <mutex>

#include "context_pool.h"
#include "attributes.h"
#include "iam_logger.h"
#include "iam_check.h"
#include "hdi_wrapper.h"

#define LOG_FILE_ID LOG_FILE_HDI_MESSAGE_CALLBACK_SERVICE
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
sptr<HdiMessageCallbackService> HdiMessageCallbackService::GetInstance()
{
    static sptr<HdiMessageCallbackService> instance = new HdiMessageCallbackService();
    IF_FALSE_LOGE_AND_RETURN_VAL(instance != nullptr, nullptr);
    return instance;
}

void HdiMessageCallbackService::OnHdiConnect()
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN(hdi != nullptr);

    int32_t ret = hdi->RegisterMessageCallback(GetInstance());
    IF_FALSE_LOGE_AND_RETURN(ret == HDF_SUCCESS);
    IAM_LOGI("success");
}

int32_t HdiMessageCallbackService::OnMessage(uint64_t scheduleId, int32_t destRole, const std::vector<uint8_t>& msg)
{
    std::shared_ptr<ScheduleNode> scheduleNode = ContextPool::Instance().SelectScheduleNodeByScheduleId(scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleNode != nullptr, HDF_FAILURE);

    Attributes attr;
    bool roleRet = attr.SetInt32Value(Attributes::ATTR_SRC_ROLE, SCHEDULER);
    IF_FALSE_LOGE_AND_RETURN_VAL(roleRet, HDF_FAILURE);
    bool setExtraInfoRet = attr.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, msg);
    IF_FALSE_LOGE_AND_RETURN_VAL(setExtraInfoRet, HDF_FAILURE);

    bool ret = scheduleNode->SendMessage(static_cast<ExecutorRole>(destRole), attr.Serialize());
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == true, HDF_FAILURE);

    return HDF_SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
