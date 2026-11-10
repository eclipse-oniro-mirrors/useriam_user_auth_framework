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
 * @file iam_executor_iauth_executor_hdi.h
 *
 * @brief Hardware device interface for authenticate executor.
 * @since 3.1
 * @version 3.2
 */

#ifndef IAM_EXECUTOR_IAUTH_EXECUTOR_HDI_H
#define IAM_EXECUTOR_IAUTH_EXECUTOR_HDI_H

#include <cstdint>
#include <vector>

#include "co_auth_client.h"
#include "iam_common_defines.h"
#include "iam_executor_framework_types.h"
#include "iam_executor_iexecute_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IAuthExecutorHdi {
public:
    /**
     * @brief Default constructor.
     */
    IAuthExecutorHdi() = default;

    /**
     * @brief Deconstructor.
     */
    virtual ~IAuthExecutorHdi() = default;

    /**
     * @brief Get executor infomation.
     *
     * @param info The executor infomation.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode GetExecutorInfo(ExecutorInfo &info) = 0;

    /**
     * @brief Register is finish.
     *
     * @param templateIdList Template ID list.
     * @param frameworkPublicKey Framework publickey
     * @param extraInfo Extra infomation.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) = 0;

    /**
     * @brief Cancel the action of executor.
     *
     * @param scheduleId Current working schedule ID.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode Cancel(uint64_t scheduleId) = 0;

    /**
     * @brief Cancel the action of executor.
     *
     * @param scheduleId Current working schedule ID.
     * @param srcRole Source role.
     * @param msg Message.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg) = 0;

    /**
     * @brief Begin enroll.
     *
     * @param scheduleId Current enroll schedule ID.
     * @param param Enroll param.
     * @param callbackObj Callback of enroll result.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode Enroll(uint64_t scheduleId, const EnrollParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);

    /**
     * @brief Begin authenticate.
     *
     * @param scheduleId Current authenticate schedule ID.
     * @param param Authenticate param.
     * @param callbackObj Callback of authenticate result.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode Authenticate(uint64_t scheduleId, const AuthenticateParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);

    /**
     * @brief Begin collect.
     *
     * @param scheduleId Current collect schedule ID.
     * @param param Collect param.
     * @param callbackObj Callback of authenticate result.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode Collect(uint64_t scheduleId, const CollectParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);

    /**
     * @brief Begin identify.
     *
     * @param scheduleId Current identify schedule ID.
     * @param param Identify param.
     * @param callbackObj Callback of identify result.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode Identify(uint64_t scheduleId, const IdentifyParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);

    /**
     * @brief Delete.
     *
     * @param templateIdList Template ID list.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode Delete(const std::vector<uint64_t> &templateIdList);

    /**
     * @brief Delete with extra information.
     *
     * @param templateId Template ID to delete.
     * @param extraInfo Extra information for delete, e.g. abandon flag.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode DeleteExt(
        const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &extraInfo);

    /**
     * @brief Send command.
     *
     * @param commandId Command ID.
     * @param extraInfo Extra information of send command.
     * @param callbackObj Callback of send command result.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode SendCommand(PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);

    /**
     * @brief Get property.
     *
     * @param templateIdList Template id list.
     * @param keys Keys of property to get.
     * @param property Return property .
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode GetProperty(const std::vector<uint64_t> &templateIdList,
        const std::vector<Attributes::AttributeKey> &keys, Property &property);

    /**
     * @brief Set cached templates.
     *
     * @param templateIdList Template id list.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode SetCachedTemplates(const std::vector<uint64_t> &templateIdList);

    /**
     * @brief Notify collector ready.
     *
     * @param scheduleId Current collect schedule ID.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode NotifyCollectorReady(uint64_t scheduleId);

    /**
     * @brief Begin abandon.
     *
     * @param scheduleId Current abandon schedule ID.
     * @param param Abandon param.
     * @param callbackObj Callback of abandon result.
     * @return Return the result success or error code{@link ResultCode}.
     */
    virtual ResultCode Abandon(uint64_t scheduleId, const DeleteParam &param,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_EXECUTOR_IAUTH_EXECUTOR_HDI_H