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

#include "auth_command.h"

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_executor_framework_types.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_AUTH_COMMAND

namespace OHOS {
namespace UserIam {
namespace UserAuth {
AuthCommand::AuthCommand(std::weak_ptr<Executor> executor, uint64_t scheduleId,
    const Attributes &attributes, std::shared_ptr<ExecutorMessenger> executorMessenger)
    : AsyncCommandBase("AUTH", scheduleId, executor, executorMessenger),
      attributes_(Common::MakeShared<Attributes>(attributes.Serialize())),
      iamHitraceHelper_(Common::MakeShared<IamHitraceHelper>("AuthCommand"))
{
}

ResultCode AuthCommand::SendRequest()
{
    IAM_LOGD("%{public}s send request start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes_ != nullptr, ResultCode::GENERAL_ERROR);

    auto hdi = GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    std::vector<uint64_t> templateIdList;
    bool getTemplateIdListRet = attributes_->GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTemplateIdListRet == true, ResultCode::GENERAL_ERROR);
    uint32_t tokenId = 0;
    bool getTokenIdRet = attributes_->GetUint32Value(Attributes::ATTR_ACCESS_TOKEN_ID, tokenId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTokenIdRet == true, ResultCode::GENERAL_ERROR);
    bool endAfterFirstFail;
    bool getEndAfterFirstFailRet = attributes_->GetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, endAfterFirstFail);
    IF_FALSE_LOGE_AND_RETURN_VAL(getEndAfterFirstFailRet == true, ResultCode::GENERAL_ERROR);
    std::vector<uint8_t> extraInfo;
    bool getExtraInfoRet = attributes_->GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExtraInfoRet == true, ResultCode::GENERAL_ERROR);
    IAM_LOGD("%{public}s auth message len %{public}zu", GetDescription(), extraInfo.size());

    int32_t authIntent;
    bool getAuthIntent = attributes_->GetInt32Value(Attributes::ATTR_AUTH_INTENTION, authIntent);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthIntent == true, ResultCode::GENERAL_ERROR);

    int32_t userId;
    bool getUserId = attributes_->GetInt32Value(Attributes::ATTR_USER_ID, userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getUserId == true, ResultCode::GENERAL_ERROR);

    int32_t authSceneValue = static_cast<int32_t>(AUTH_SCENE_DEFAULT);
    bool getAuthScene = attributes_->GetInt32Value(Attributes::ATTR_AUTH_SCENE, authSceneValue);
    if (!getAuthScene) {
        IAM_LOGI("%{public}s ATTR_AUTH_SCENE not found, use default scene", GetDescription());
    }

    std::string title;
    bool getTitle = attributes_->GetStringValue(Attributes::ATTR_WIDGET_TITLE, title);
    if (!getTitle) {
        IAM_LOGI("%{public}s ATTR_WIDGET_TITLE not found, use empty title", GetDescription());
    }

    IamHitraceHelper traceHelper("hdi Authenticate");
    ResultCode ret = hdi->Authenticate(scheduleId_,
        (AuthenticateParam) {
            tokenId, templateIdList, extraInfo, endAfterFirstFail, authIntent, userId,
            static_cast<AuthScene>(authSceneValue), title
        },
        shared_from_this());
    IAM_LOGD("%{public}s authenticate result %{public}d", GetDescription(), ret);
    return ret;
}

void AuthCommand::OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGD("%{public}s on result start", GetDescription());

    std::vector<uint8_t> nonConstExtraInfo(extraInfo.begin(), extraInfo.end());
    auto authAttributes = Common::MakeShared<Attributes>();
    IF_FALSE_LOGE_AND_RETURN(authAttributes != nullptr);
    bool setResultCodeRet = authAttributes->SetUint32Value(Attributes::ATTR_RESULT_CODE, result);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet == true);
    bool setAuthResultRet =
        authAttributes->SetUint8ArrayValue(Attributes::ATTR_RESULT, nonConstExtraInfo);
    IF_FALSE_LOGE_AND_RETURN(setAuthResultRet == true);
    iamHitraceHelper_ = nullptr;
    int32_t ret = MessengerFinish(scheduleId_, result, authAttributes);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("%{public}s call finish fail", GetDescription());
        return;
    }
    IAM_LOGD("%{public}s call finish success result %{public}d", GetDescription(), result);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
