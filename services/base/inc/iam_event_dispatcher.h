/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef IAM_EVENT_DISPATCHER_H
#define IAM_EVENT_DISPATCHER_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>

#include "attributes.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

enum EventId : int32_t {
    EVENT_AUTH_INITIATED = 1,
    EVENT_AUTH_RESULT = 2,
};

using IamEventData = std::shared_ptr<Attributes>;
using IamEventCallback = std::function<void(const IamEventData &)>;

class IamEventDispatcher {
public:
    virtual ~IamEventDispatcher() = default;
    virtual void Post(EventId eventId, const IamEventData &data) = 0;
    virtual std::unique_ptr<Subscription> Subscribe(EventId eventId, IamEventCallback callback) = 0;
};

IamEventDispatcher &GetIamEventDispatcher();
void SetIamEventDispatcher(std::shared_ptr<IamEventDispatcher> dispatcher);
std::shared_ptr<IamEventDispatcher> CreateIamEventDispatcher();
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_EVENT_DISPATCHER_H
