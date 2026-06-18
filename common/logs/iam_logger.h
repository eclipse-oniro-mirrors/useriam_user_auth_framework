/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef IAM_LOGGER_H
#define IAM_LOGGER_H

#include "hilog/log.h"
#include "iam_log_tracer.h"

namespace OHOS {
namespace UserIam {
namespace Common {

#ifndef LOG_FILE_ID
#define LOG_FILE_ID LOG_FILE_UNKNOWN
#endif

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD002401

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#ifdef ENABLE_LOG_TRACE
#define IAM_LOG_HOOK() OHOS::UserIam::Common::LogTracer::GetInstance().Record(LOG_FILE_ID, __LINE__)
#else
#define IAM_LOG_HOOK() ((void)0)
#endif

#define IAM_LOGD(fmt, ...) ((void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, LOG_DOMAIN, LOG_TAG, \
    "[%{public}s@%{public}04x:%{public}d] " fmt, __FUNCTION__, LOG_FILE_ID, __LINE__, ##__VA_ARGS__))
#define IAM_LOGE(fmt, ...)                \
    do {                                  \
        IAM_LOG_HOOK();                   \
        ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, LOG_DOMAIN, LOG_TAG, \
            "[%{public}s@%{public}04x:%{public}d] " fmt, __FUNCTION__, LOG_FILE_ID, __LINE__, ##__VA_ARGS__)); \
    } while (0)
#define IAM_LOGW(fmt, ...) ((void)HILOG_IMPL(LOG_CORE, LOG_WARN, LOG_DOMAIN, LOG_TAG, \
    "[%{public}s@%{public}04x:%{public}d] " fmt, __FUNCTION__, LOG_FILE_ID, __LINE__, ##__VA_ARGS__))
#define IAM_LOGI(fmt, ...) ((void)HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_DOMAIN, LOG_TAG, \
    "[%{public}s@%{public}04x:%{public}d] " fmt, __FUNCTION__, LOG_FILE_ID, __LINE__, ##__VA_ARGS__))
#define IAM_LOGF(fmt, ...) ((void)HILOG_IMPL(LOG_CORE, LOG_FATAL, LOG_DOMAIN, LOG_TAG, \
    "[%{public}s@%{public}04x:%{public}d] " fmt, __FUNCTION__, LOG_FILE_ID, __LINE__, ##__VA_ARGS__))

} // namespace Common
} // namespace UserIam
} // namespace OHOS

#endif // IAM_LOGGER_H
