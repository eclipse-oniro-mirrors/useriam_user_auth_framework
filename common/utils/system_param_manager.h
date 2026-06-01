/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SYSTEM_PARAM_MANAGER_H
#define SYSTEM_PARAM_MANAGER_H

#include <mutex>
#include <vector>

#include "parameter.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
inline const char *TRUE_STR = "true";
inline const char *FALSE_STR = "false";

inline const char *FWK_READY_KEY = "bootevent.useriam.fwkready";
inline const char *IS_PIN_ENROLLED_KEY = "persist.useriam.isPinEnrolled";
inline const char *IS_CREDENTIAL_CHECKED_KEY = "useriam.isCredentialChecked";
inline const char *IS_PIN_FUNCTION_READY_KEY = "useriam.isPinFunctionReady";
inline const char *STOP_SA_KEY = "useriam.stopSa";
inline const char *START_SA_KEY = "useriam.startSa";
inline const char *START_SA_INNER_KEY = "useriam.startSaInner";
inline const char *IDM_SESSION_INFO = "useriam.idmSessionInfo";
inline const char *CREDENTIAL_UPDATED_KEY = "useriam.credUpdated";
inline const char *CDA_START_SA_KEY = "companiondeviceauth.startSa";
inline const char *CDA_IS_FUNCTION_READY_KEY = "companiondeviceauth.isFunctionReady";

class SystemParamManager {
public:
    static SystemParamManager &GetInstance();

    std::string GetParam(const std::string &key, const std::string &defaultValue);
    void SetParam(const std::string &key, const std::string &value);
    void SetParamTwice(const std::string &key, const std::string &value1, const std::string &value2);
    typedef void (*SystemParamCallback)(const std::string &value);
    void WatchParam(const std::string &key, SystemParamCallback callback);
    void OnParamChange(const std::string &key, const std::string &value);

private:
    SystemParamManager() = default;
    ~SystemParamManager() = default;

    std::recursive_mutex mutex_;
    std::vector<std::pair<std::string, SystemParamCallback>> keyCallbackVec_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // SYSTEM_PARAM_MANAGER_H
