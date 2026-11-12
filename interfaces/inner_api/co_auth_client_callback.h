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

/**
 * @file co_auth_client_callback.h
 *
 * @brief Callback definitions returned by coAuth client.
 * @since 3.1
 * @version 3.2
 */

#ifndef CO_AUTH_CLIENT_CALLBACK_H
#define CO_AUTH_CLIENT_CALLBACK_H

#include "attributes.h"
#include "co_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorRegisterCallback {
public:
    /**
     * @brief Called by the coAuth resource pool to tell the executor messenger ready.
     *
     * @param messenger Messenger used for execute process.
     * @param publicKey Public key of the framework.
     * @param templateIds Matched templateIds based on authType and executor info.
     */
    virtual void OnMessengerReady(const std::shared_ptr<ExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList) = 0;

    /**
     * @brief Called by coAuth resource pool to tell the executor to begin.
     *
     * @param scheduleId Specify the current schedule.
     * @param publicKey Public key of the framework.
     * @param commandAttrs Properties of this operation.
     * @return Return begin execute success or not(0:success; other:failed).
     */
    virtual int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &commandAttrs) = 0;

    /**
     * @brief Notify the executor to end the operation.
     *
     * @param scheduleId Specify the current schedule.
     * @param commandAttrs Properties of this operation.
     * @return Return end execute success or not(0:success; other:failed).
     */
    virtual int32_t OnEndExecute(uint64_t scheduleId, const Attributes &commandAttrs) = 0;

    /**
     * @brief Called by coAuth resource pool to set executor's property.
     *
     * @param properties The properties need to set.
     * @return Return set property success or not(0:success; other:failed).
     */
    virtual int32_t OnSetProperty(const Attributes &properties, Attributes &results) = 0;

    /**
     * @brief Called by coAuth resource pool to get executor's property.
     *
     * @param conditions The condition to get property.
     * @param results The result of get property.
     * @return Return get property success or not(0:success; other:failed).
     */
    virtual int32_t OnGetProperty(const Attributes &conditions, Attributes &results) = 0;

    /**
     * @brief Called by coAuth resource pool to send data.
     *
     * @param scheduleId Specify the current schedule.
     * @param results The result of get property.
     * @return data Data.
     */
    virtual int32_t OnSendData(uint64_t scheduleId, const Attributes &data) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // CO_AUTH_CLIENT_CALLBACK_H