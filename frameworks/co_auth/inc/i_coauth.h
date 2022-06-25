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

#ifndef I_COAUTH_H
#define I_COAUTH_H

#include <iremote_broker.h>
#include <singleton.h>
#include "icoauth_callback.h"
#include "attributes.h"
#include "iexecutor_callback.h"
#include "iquery_callback.h"
#include "auth_executor.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
class ICoAuth : public IRemoteBroker {
public:

    /* Message ID */
    enum {
        COAUTH_EXECUTOR_REGIST = 0,
        COAUTH_QUERY_STATUS,
    };

    /* Business function */
    virtual uint64_t Register(std::shared_ptr<AuthResPool::AuthExecutor> executorInfo,
        const sptr<AuthResPool::IExecutorCallback> &callback) = 0;
    virtual void QueryStatus(AuthResPool::AuthExecutor &executorInfo,
        const sptr<AuthResPool::IQueryCallback> &callback) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.CoAuth.ICoAuth");
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // I_COAUTH_H