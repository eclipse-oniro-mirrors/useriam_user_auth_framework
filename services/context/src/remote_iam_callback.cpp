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

#include "remote_iam_callback.h"

#include "iam_check.h"
#include "iam_ptr.h"
#include "remote_connect_manager.h"
#include "remote_msg_util.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
RemoteIamCallback::RemoteIamCallback(std::string &connectionName) : connectionName_(connectionName)
{
    endPointName_ = REMOTE_CALLBACK_ENDPOINT_NAME;
}

RemoteIamCallback::~RemoteIamCallback()
{
}

int32_t RemoteIamCallback::OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("result: %{public}d", resultCode);

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>(extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(request != nullptr, GENERAL_ERROR);

    bool setMsgTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, SEND_REMOTE_AUTH_RESULT);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMsgTypeRet, GENERAL_ERROR);

    bool setResultRet = request->SetInt32Value(Attributes::ATTR_RESULT, resultCode);
    IF_FALSE_LOGE_AND_RETURN_VAL(setResultRet, GENERAL_ERROR);

    MsgCallback msgCallback = [](const std::shared_ptr<Attributes> &) { IAM_LOGI("message sent"); };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        REMOTE_AUTH_INVOKER_CONTEXT_ENDPOINT_NAME, request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == ResultCode::SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

int32_t RemoteIamCallback::OnAcquireInfo(int32_t module, int32_t acquireInfo,
    const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("module: %{public}d, acquireInfo: %{public}d", module, acquireInfo);

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>(extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(request != nullptr, GENERAL_ERROR);

    bool setMsgTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, SEND_REMOTE_AUTH_TIP);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMsgTypeRet, GENERAL_ERROR);

    bool setModuleRet = request->SetInt32Value(Attributes::ATTR_DEST_ROLE, module);
    IF_FALSE_LOGE_AND_RETURN_VAL(setModuleRet, GENERAL_ERROR);

    bool setAcquireInfoRet = request->SetInt32Value(Attributes::ATTR_TIP_INFO, acquireInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAcquireInfoRet, GENERAL_ERROR);

    MsgCallback msgCallback = [](const std::shared_ptr<Attributes> &) { IAM_LOGI("message sent"); };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        REMOTE_AUTH_INVOKER_CONTEXT_ENDPOINT_NAME, request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == ResultCode::SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

sptr<IRemoteObject> RemoteIamCallback::AsObject()
{
    return nullptr;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS