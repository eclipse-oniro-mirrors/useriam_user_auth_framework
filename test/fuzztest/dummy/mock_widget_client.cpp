/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mock_widget_client.h"

#include "system_ability_definition.h"

#include "auth_common.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_time.h"
#include "nlohmann/json.hpp"
#include "iwidget_callback.h"
#include "hisysevent_adapter.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_WIDGET_CLIENT

namespace OHOS {
namespace UserIam {
namespace UserAuth {
WidgetClient &WidgetClient::Instance()
{
    static WidgetClient widgetClient;
    return widgetClient;
}

WidgetClient::~WidgetClient()
{
    IAM_LOGD("start.");
}

void WidgetClient::SetWidgetSchedule(uint64_t contextId, const std::shared_ptr<WidgetScheduleNode> &schedule)
{
    IAM_LOGD("start.");
}

ResultCode WidgetClient::OnNotice(NoticeType type, const std::string &eventData)
{
    IAM_LOGD("start.");
    return ResultCode::SUCCESS;
}

void WidgetClient::ReportWidgetResult(int32_t result, AuthType authType,
    int32_t lockoutDuration, int32_t remainAttempts, bool skipLockedBiometricAuth)
{
    IAM_LOGD("start.");
}

void WidgetClient::ReportWidgetTip(int32_t tipType, AuthType authType, std::vector<uint8_t> tipInfo,
    bool skipLockedBiometricAuth)
{
    IAM_LOGD("start.");
}

void WidgetClient::SetWidgetParam(const WidgetParamInner &param)
{
    IAM_LOGD("start.");
}

void WidgetClient::SetAuthTypeList(const std::vector<AuthType> &authTypeList)
{
    IAM_LOGD("start.");
}

void WidgetClient::SetWidgetCallback(const sptr<IWidgetCallback> &callback)
{
    IAM_LOGD("start.");
}

void WidgetClient::SetAuthTokenId(uint32_t tokenId)
{
    IAM_LOGD("start.");
}

uint32_t WidgetClient::GetAuthTokenId()
{
    IAM_LOGD("start.");
    return 0;
}

void WidgetClient::Reset()
{
    IAM_LOGD("start.");
}

void WidgetClient::ForceStopAuth()
{
    IAM_LOGD("start.");
}

void WidgetClient::SetPinSubType(const PinSubType &subType)
{
    IAM_LOGD("start.");
}

void WidgetClient::SetSensorInfo(const std::string &info)
{
    IAM_LOGD("start.");
}

void WidgetClient::SetChallenge(const std::vector<uint8_t> &challenge)
{
    IAM_LOGD("start.");
}

void WidgetClient::SetCallingBundleName(const std::string &callingBundleName)
{
    IAM_LOGD("start.");
}

void WidgetClient::ClearSchedule(uint64_t contextId)
{
    IAM_LOGD("start.");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS