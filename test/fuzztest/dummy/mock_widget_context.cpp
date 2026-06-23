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
#include "mock_widget_context.h"

#include <algorithm>
#include "bool_wrapper.h"
#include "double_wrapper.h"
#include "int_wrapper.h"
#include "refbase.h"

#include "ability_connection.h"
#include "ability_connect_callback.h"
#include "accesstoken_kit.h"
#include "auth_widget_helper.h"
#include "context_helper.h"
#include "context_pool.h"
#include "context_death_recipient.h"
#include "hisysevent_adapter.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "iam_time.h"
#include "parameters.h"
#include "relative_timer.h"
#include "schedule_node.h"
#include "schedule_node_callback.h"
#include "string_wrapper.h"
#include "system_ability_definition.h"
#include "want_params_wrapper.h"
#include "widget_schedule_node_impl.h"
#include "widget_client.h"
#include <sys/stat.h>
#ifdef SCENE_BOARD_ENABLE
#include "display_manager_lite.h"
#else
#include "display_manager.h"
#endif

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_WIDGET_CONTEXT

namespace OHOS {
namespace UserIam {
namespace UserAuth {
WidgetContext::WidgetContext(uint64_t contextId, const ContextFactory::AuthWidgetContextPara &para,
    std::shared_ptr<ContextCallback> callback, const sptr<IModalCallback> &modalCallback,
    const sptr<IRemoteAuthCallback> &remoteAuthCallback)
{
    IAM_LOGD("start.");
}

WidgetContext::~WidgetContext()
{
    IAM_LOGD("start.");
}

bool WidgetContext::Start()
{
    IAM_LOGD("start.");
    return true;
}

bool WidgetContext::Stop()
{
    IAM_LOGD("start.");
    return true;
}

uint64_t WidgetContext::GetContextId() const
{
    IAM_LOGD("start.");
    return 0;
}

ContextType WidgetContext::GetContextType() const
{
    IAM_LOGD("start.");
    return WIDGET_AUTH_CONTEXT;
}

std::shared_ptr<ScheduleNode> WidgetContext::GetScheduleNode(uint64_t scheduleId) const
{
    IAM_LOGD("start.");
    return nullptr;
}

uint32_t WidgetContext::GetTokenId() const
{
    IAM_LOGD("start.");
    return 0;
}

int32_t WidgetContext::GetUserId() const
{
    IAM_LOGD("start.");
    return 0;
}

int32_t WidgetContext::GetAuthType() const
{
    IAM_LOGD("start.");
    return 0;
}

std::string WidgetContext::GetCallerName() const
{
    IAM_LOGD("start.");
    return std::string();
}

void WidgetContext::SetRemoteAuthParam(const WidgetParamInner &widgetParam, const sptr<IModalCallback> &modalCallback)
{
    IAM_LOGD("start.");
}

int32_t WidgetContext::GetLatestError() const
{
    IAM_LOGD("start.");
    return 0;
}

void WidgetContext::SetLatestError(int32_t error)
{
    IAM_LOGD("start.");
}

void WidgetContext::AuthResult(int32_t resultCode, int32_t authType, const Attributes &finalResult)
{
    IAM_LOGD("start.");
}

void WidgetContext::AuthTipInfo(int32_t tipType, int32_t authType, const Attributes &extraInfo)
{
    IAM_LOGD("start.");
}

bool WidgetContext::LaunchWidget()
{
    IAM_LOGD("start.");
    return true;
}

void WidgetContext::ExecuteAuthList(const std::set<AuthType> &authTypeList, bool endAfterFirstFail,
    AuthIntent authIntent)
{
    IAM_LOGD("start.");
}

void WidgetContext::EndAuthAsCancel()
{
    IAM_LOGD("start.");
}

void WidgetContext::EndAuthAsNaviPin()
{
    IAM_LOGD("start.");
}

void WidgetContext::EndAuthAsWidgetParaInvalid()
{
    IAM_LOGD("start.");
}

void WidgetContext::AuthWidgetReloadInit()
{
    IAM_LOGD("start.");
}

bool WidgetContext::AuthWidgetReload(uint32_t orientation, uint32_t needRotate, uint32_t alreadyLoad,
    AuthType &rotateAuthType)
{
    IAM_LOGD("start.");
    return true;
}

void WidgetContext::StopAuthList(const std::vector<AuthType> &authTypeList)
{
    IAM_LOGD("start.");
}

void WidgetContext::SuccessAuth(AuthType authType)
{
    IAM_LOGD("start.");
}

void WidgetContext::FailAuth(AuthType authType)
{
    IAM_LOGD("start.");
}

void WidgetContext::SendAuthTipInfo(int32_t authType, int32_t tipCode)
{
    IAM_LOGD("start.");
}

void WidgetContext::ClearSchedule()
{
    IAM_LOGD("start.");
}

bool WidgetContext::GetRemoteAuthParam()
{
    IAM_LOGD("start.");
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS