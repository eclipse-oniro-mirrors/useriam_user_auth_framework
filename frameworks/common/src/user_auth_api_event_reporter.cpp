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

#include "user_auth_api_event_reporter.h"

#include <chrono>
#include <cinttypes>
#include <thread>

#include "app_event.h"
#include "app_event_processor_mgr.h"

#include "config_parser.h"
#include "iam_logger.h"

#define LOG_FILE_ID LOG_FILE_USER_AUTH_API_EVENT_REPORTER
#define LOG_TAG "USER_AUTH_COMMON"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace HiviewDFX::HiAppEvent;
using namespace std::chrono;
namespace {
constexpr int32_t REPORT_SUCCESS = 0;
constexpr int32_t REPORT_FAILED = 1;
constexpr int64_t INVALID_PROCESSOR_ID = -1;
void AddEventConfigs(ReportConfig &config)
{
    config.eventConfigs.clear();
    EventConfig event1;
    event1.domain = "api_diagnostic";
    event1.name = "api_exec_end";
    event1.isRealTime = false;
    config.eventConfigs.push_back(event1);

    EventConfig event2;
    event2.domain = "api_diagnostic";
    event2.name = "api_called_stat";
    event2.isRealTime = true;
    config.eventConfigs.push_back(event2);

    EventConfig event3;
    event3.domain = "api_diagnostic";
    event3.name = "api_called_stat_cnt";
    event3.isRealTime = true;
    config.eventConfigs.push_back(event3);
}
} // namespace
int64_t UserAuthApiEventReporter::processorId_ = INVALID_PROCESSOR_ID;

UserAuthApiEventReporter::UserAuthApiEventReporter(std::string apiName) : apiName_(apiName)
{
    transId_ = std::string("transId_") + std::to_string(std::rand());
    beginTime_ = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void UserAuthApiEventReporter::ReportSuccess()
{
    Report(REPORT_SUCCESS, 0);
}

void UserAuthApiEventReporter::ReportFailed(UserAuthResultCode resultCode)
{
    Report(REPORT_FAILED, static_cast<int32_t>(resultCode));
}

void UserAuthApiEventReporter::ReportFailed(int32_t resultCode)
{
    Report(REPORT_FAILED, resultCode);
}

void UserAuthApiEventReporter::Report(int32_t result, int32_t errCode)
{
    if (isReported_) {
        IAM_LOGI("already reported");
        return;
    }
    isReported_ = true;

    std::thread([transId = transId_, apiName = apiName_, beginTime = beginTime_, result, errCode] () {
        const char *kitName = "UserAuthenticationKit";
        int64_t processorId = GetProcessorId();
        if (processorId <= 0) {
            IAM_LOGE("GetProcessorId failed");
            return;
        }

        int64_t endTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        HiviewDFX::HiAppEvent::Event event("api_diagnostic", "api_exec_end", HiviewDFX::HiAppEvent::BEHAVIOR);
        event.AddParam("trans_id", transId);
        event.AddParam("api_name", apiName);
        event.AddParam("sdk_name", kitName);
        event.AddParam("begin_time", beginTime);
        event.AddParam("end_time", endTime);
        event.AddParam("result", result);
        event.AddParam("error_code", errCode);
        int ret = Write(event);
        IAM_LOGI(
            "WriteEndEvent transId:%{public}s, apiName:%{public}s, result:%{public}d, errCode:%{public}d, "
            "ret:%{public}d", transId.c_str(), apiName.c_str(), result, errCode, ret);
    }).detach();
}

int64_t UserAuthApiEventReporter::GetProcessorId()
{
    constexpr int TRIGGER_COND_TIMEOUT = 90;
    constexpr int TRIGGER_COND_ROW = 30;
    const char *API_REPORT_CONFIG_PATH = "/system/etc/useriam/useriam_api_event_report.cfg";
    const char *DEFAULT_API_CONFIG_APP_ID = "useriam_verify_ohos_sdk_ocg";
    const char *DEFAULT_API_PROCESSOR_NAME = "useriam_verify_processor";

    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    if (processorId_ > 0) {
        return processorId_;
    }

    ReportConfig config;
    config.appId = DEFAULT_API_CONFIG_APP_ID;
    config.name = DEFAULT_API_PROCESSOR_NAME;
    config.routeInfo = "AUTO";

    ConfigParser parser;
    if (parser.Load(API_REPORT_CONFIG_PATH)) {
        config.appId = parser.Get("appId", DEFAULT_API_CONFIG_APP_ID);
        config.name = parser.Get("name", DEFAULT_API_PROCESSOR_NAME);
        IAM_LOGI("Loaded config from file: appId=%{public}s, name=%{public}s", config.appId.c_str(),
            config.name.c_str());
    } else {
        IAM_LOGI("Failed to load config file, using default values");
    }

    config.triggerCond.timeout = TRIGGER_COND_TIMEOUT;
    config.triggerCond.row = TRIGGER_COND_ROW;

    AddEventConfigs(config);

    int64_t processorId = AppEventProcessorMgr::AddProcessor(config);
    if (processorId < 0) {
        IAM_LOGE("AddProcessor failed, ret = %{public}" PRIi64, processorId);
        return INVALID_PROCESSOR_ID;
    }

    IAM_LOGI("AddProcessor success");
    processorId_ = processorId;
    return processorId_;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS