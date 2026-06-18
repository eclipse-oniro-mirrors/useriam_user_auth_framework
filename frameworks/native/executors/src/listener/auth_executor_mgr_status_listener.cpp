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

#include "auth_executor_mgr_status_listener.h"

#include "driver_manager.h"
#include "iam_logger.h"
#include "iam_time.h"
#include "hisysevent_adapter.h"
#include "system_ability_definition.h"

#define LOG_FILE_ID LOG_FILE_AUTH_EXECUTOR_MGR_STATUS_LISTENER
#define LOG_TAG "USER_AUTH_EXECUTOR"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
sptr<AuthExecutorMgrStatusListener> AuthExecutorMgrStatusListener::GetInstance()
{
    static sptr<AuthExecutorMgrStatusListener> instance(new (std::nothrow) AuthExecutorMgrStatusListener());
    if (instance == nullptr) {
        IAM_LOGE("instance is nullptr");
    }
    return instance;
}

void AuthExecutorMgrStatusListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR) {
        return;
    }

    IAM_LOGD("auth executor mgr SA added");
}

void AuthExecutorMgrStatusListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR) {
        return;
    }

    UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "user_auth_framework");
    IAM_LOGE("auth executor mgr SA removed");
    DriverManager::GetInstance().OnFrameworkDown();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
