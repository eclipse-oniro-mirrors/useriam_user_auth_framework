/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef IAM_WIDGET_SCHEDULE_CALLBACK_H
#define IAM_WIDGET_SCHEDULE_CALLBACK_H

#include <cstdint>
#include <memory>
#include <set>
#include <vector>

#include "attributes.h"
#include "iam_common_defines.h"
#include "user_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class WidgetScheduleNodeCallback {
public:
    virtual ~WidgetScheduleNodeCallback() = default;
    virtual bool LaunchWidget() = 0;
    virtual void ExecuteAuthList(const std::set<AuthType> &authTypeList, bool endAfterFirstFail,
        AuthIntent authIntent) = 0;
    virtual void EndAuthAsCancel() = 0;
    virtual void EndAuthAsNaviPin() = 0;
    virtual void EndAuthAsWidgetParaInvalid() = 0;
    virtual void StopAuthList(const std::vector<AuthType> &authTypeList) = 0;
    virtual void SuccessAuth(AuthType authType) = 0;
    virtual void FailAuth(AuthType authType) = 0;
    virtual bool AuthWidgetReload(uint32_t orientation, uint32_t needRotate, uint32_t alreadyLoad,
        AuthType &rotateAuthType) = 0;
    virtual void AuthWidgetReloadInit() = 0;
    virtual void SendAuthTipInfo(int32_t authType, int32_t tipInfo) = 0;
    virtual void ClearSchedule() = 0;
    virtual bool GetRemoteAuthParam() = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_WIDGET_SCHEDULE_CALLBACK_H