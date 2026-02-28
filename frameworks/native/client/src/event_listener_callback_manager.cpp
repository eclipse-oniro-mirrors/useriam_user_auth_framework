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

#include "event_listener_callback_service.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iservice_registry.h"
#include "ipc_client_utils.h"
#include "system_ability_status_change_stub.h"
#include "system_ability_definition.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
template<typename T> struct SystemAbilityId { static constexpr int32_t id = 0; };
template<> struct SystemAbilityId<CredChangeEventListener> {
    static constexpr int32_t id = SUBSYS_USERIAM_SYS_ABILITY_USERIDM;
};
template<> struct SystemAbilityId<AuthSuccessEventListener> {
    static constexpr int32_t id = SUBSYS_USERIAM_SYS_ABILITY_USERAUTH;
};
template<typename T> class IamServiceListener;

template<typename T>
EventListenerCallbackManager<T>::EventListenerCallbackManager()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    IF_FALSE_LOGE_AND_RETURN(sam != nullptr);
    auto listener = new (std::nothrow) IamServiceListener<T>();
    IF_FALSE_LOGE_AND_RETURN(listener != nullptr);
    int32_t ret = sam->SubscribeSystemAbility(SystemAbilityId<T>::id, listener);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to suscribe iam service status, ret:%{public}d", ret);
    }
}

template<typename T>
int32_t EventListenerCallbackManager<T>::RegisterListener(const std::vector<AuthType> &authTypes,
    const std::shared_ptr<T> &listener)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    if (!IsExistEventListener()) {
        auto proxy = IpcClientUtils::GetRemoteObject(SystemAbilityId<T>::id);
        IF_FALSE_LOGE_AND_RETURN_VAL(proxy != nullptr, GENERAL_ERROR);
        IF_FALSE_LOGE_AND_RETURN_VAL(proxy->IsProxyObject(), GENERAL_ERROR);

        auto listenerImpl = EventListenerCallbackService::GetInstance();
        IF_FALSE_LOGE_AND_RETURN_VAL(listenerImpl != nullptr, GENERAL_ERROR);
        int32_t ret = RegisterListenerDispatcher(proxy, listenerImpl);
        if (ret != SUCCESS) {
            IAM_LOGE("RegisterListenerDispatcher fail, ret:%{public}d", ret);
            return ret;
        }
    }

    {
        std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
        for (auto authType : authTypes) {
            auto addCount = eventListenerMap_[authType].insert(listener);
            IAM_LOGI("AddEventListener addCount:%{public}d, authType:%{public}d, listenerSize:%{public}zu",
                addCount.second, static_cast<int32_t>(authType), eventListenerMap_[authType].size());
        }
    }
    return SUCCESS;
}

template<typename T>
int32_t EventListenerCallbackManager<T>::UnRegisterListener(const std::shared_ptr<T> &listener)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    {
        std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
        auto mapIter = eventListenerMap_.begin();
        while (mapIter != eventListenerMap_.end()) {
            size_t eraseCount = mapIter->second.erase(listener);
            IAM_LOGI("RemoveEventListener eraseCount:%{public}zu, authType:%{public}d, listenerSize:%{public}zu",
                eraseCount, mapIter->first, mapIter->second.size());
            if (mapIter->second.size() == 0) {
                mapIter = eventListenerMap_.erase(mapIter);
            } else {
                mapIter++;
            }
        }
    }

    if (!IsExistEventListener()) {
        auto proxy = IpcClientUtils::GetRemoteObject(SystemAbilityId<T>::id);
        IF_FALSE_LOGE_AND_RETURN_VAL(proxy != nullptr, GENERAL_ERROR);
        IF_FALSE_LOGE_AND_RETURN_VAL(proxy->IsProxyObject(), GENERAL_ERROR);

        auto listenerImpl = EventListenerCallbackService::GetInstance();
        IF_FALSE_LOGE_AND_RETURN_VAL(listenerImpl != nullptr, GENERAL_ERROR);
        return UnRegisterListenerDispatcher(proxy, listenerImpl);
    }
    return SUCCESS;
}

template<> int32_t EventListenerCallbackManager<AuthSuccessEventListener>::RegisterListenerDispatcher(
    sptr<IRemoteObject> proxy, sptr<EventListenerCallbackService> listenerImpl)
{
    int32_t ret = iface_cast<IUserAuth>(proxy)->RegistUserAuthSuccessEventListener(listenerImpl);
    if (ret != SUCCESS) {
        IAM_LOGE("RegistUserAuthSuccessEventListener fail, ret:%{public}d", ret);
    }
    return ret;
}

template<> int32_t EventListenerCallbackManager<CredChangeEventListener>::RegisterListenerDispatcher(
    sptr<IRemoteObject> proxy, sptr<EventListenerCallbackService> listenerImpl)
{
    int32_t ret = iface_cast<IUserIdm>(proxy)->RegistCredChangeEventListener(listenerImpl);
    if (ret != SUCCESS) {
        IAM_LOGE("RegistCredChangeEventListener fail, ret:%{public}d", ret);
    }
    return ret;
}

template<> int32_t EventListenerCallbackManager<AuthSuccessEventListener>::UnRegisterListenerDispatcher(
    sptr<IRemoteObject> proxy, sptr<EventListenerCallbackService> listenerImpl)
{
    int32_t ret = iface_cast<IUserAuth>(proxy)->UnRegistUserAuthSuccessEventListener(listenerImpl);
    if (ret != SUCCESS) {
        IAM_LOGE("UnRegistUserAuthSuccessEventListener fail, ret:%{public}d", ret);
    }
    return ret;
}

template<> int32_t EventListenerCallbackManager<CredChangeEventListener>::UnRegisterListenerDispatcher(
    sptr<IRemoteObject> proxy, sptr<EventListenerCallbackService> listenerImpl)
{
    int32_t ret = iface_cast<IUserIdm>(proxy)->UnRegistCredChangeEventListener(listenerImpl);
    if (ret != SUCCESS) {
        IAM_LOGE("UnRegistCredChangeEventListener fail, ret:%{public}d", ret);
    }
    return ret;
}

template<typename T>
std::set<std::shared_ptr<T>> EventListenerCallbackManager<T>::GetEventListenerSet(AuthType authType)
{
    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    if (eventListenerMap_.find(authType) != eventListenerMap_.end()) {
        return eventListenerMap_[authType];
    }
    return {};
}

template<typename T>
bool EventListenerCallbackManager<T>::IsExistEventListener()
{
    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    return eventListenerMap_.size() != 0;
}

template<typename T>
EventListenerCallbackManager<T> &EventListenerCallbackManager<T>::GetInstance()
{
    static EventListenerCallbackManager<T> eventListenerCallbackManager;
    return eventListenerCallbackManager;
}

template<typename T>
class IamServiceListener : public SystemAbilityStatusChangeStub {
public:
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    IamServiceListener() = default;
    ~IamServiceListener() override = default;
};

template<typename T>
void IamServiceListener<T>::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != SystemAbilityId<T>::id) {
        return;
    }
    IAM_LOGI("OnAddSystemAbility systemAbilityId:%{public}d added", systemAbilityId);

    if (!EventListenerCallbackManager<T>::GetInstance().IsExistEventListener()) {
        IAM_LOGI("not exist eventListner, no need regist");
        return;
    }

    auto proxy = IpcClientUtils::GetRemoteObject(SystemAbilityId<T>::id);
    IF_FALSE_LOGE_AND_RETURN(proxy != nullptr);
    IF_FALSE_LOGE_AND_RETURN(proxy->IsProxyObject());

    auto listenerImpl = EventListenerCallbackService::GetInstance();
    IF_FALSE_LOGE_AND_RETURN(listenerImpl != nullptr);
    EventListenerCallbackManager<T>::GetInstance().RegisterListenerDispatcher(proxy, listenerImpl);
}

template<typename T>
void IamServiceListener<T>::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != SystemAbilityId<T>::id) {
        return;
    }
    IAM_LOGI("OnRemoveSystemAbility systemAbilityId:%{public}d remove", systemAbilityId);
}

template class IamServiceListener<CredChangeEventListener>;
template class IamServiceListener<AuthSuccessEventListener>;
template class EventListenerCallbackManager<CredChangeEventListener>;
template class EventListenerCallbackManager<AuthSuccessEventListener>;
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS