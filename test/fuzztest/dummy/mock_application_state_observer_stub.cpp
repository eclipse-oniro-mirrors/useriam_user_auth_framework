/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "application_state_observer_stub.h"

namespace OHOS {
namespace AppExecFwk {

bool AppStateData::Marshalling(Parcel &parcel) const
{
    return true;
}

AppStateData *AppStateData::Unmarshalling(Parcel &parcel)
{
    return new AppStateData();
}

bool AppStateData::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool ProcessData::Marshalling(Parcel &parcel) const
{
    return true;
}

ProcessData *ProcessData::Unmarshalling(Parcel &parcel)
{
    return new ProcessData();
}

bool ProcessData::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool AbilityStateData::Marshalling(Parcel &parcel) const
{
    return true;
}

bool AbilityStateData::MarshallingOne(Parcel &parcel) const
{
    return true;
}

AbilityStateData *AbilityStateData::Unmarshalling(Parcel &parcel)
{
    return new AbilityStateData();
}

bool AbilityStateData::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool PageStateData::Marshalling(Parcel &parcel) const
{
    return true;
}

PageStateData *PageStateData::Unmarshalling(Parcel &parcel)
{
    return new PageStateData();
}

bool PageStateData::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool PreloadProcessData::Marshalling(Parcel &parcel) const
{
    return true;
}

PreloadProcessData *PreloadProcessData::Unmarshalling(Parcel &parcel)
{
    return new PreloadProcessData();
}

bool PreloadProcessData::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool ProcessBindData::Marshalling(Parcel &parcel) const
{
    return true;
}

ProcessBindData *ProcessBindData::Unmarshalling(Parcel &parcel)
{
    return new ProcessBindData();
}

bool ProcessBindData::ReadFromParcel(Parcel &parcel)
{
    return true;
}

std::mutex ApplicationStateObserverStub::callbackMutex_;

int ApplicationStateObserverStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    return 0;
}

void ApplicationStateObserverStub::OnForegroundApplicationChanged(const AppStateData &appStateData)
{
}

void ApplicationStateObserverStub::OnAbilityStateChanged(const AbilityStateData &abilityStateData)
{
}

void ApplicationStateObserverStub::OnExtensionStateChanged(const AbilityStateData &abilityStateData)
{
}

void ApplicationStateObserverStub::OnProcessCreated(const ProcessData &processData)
{
}

void ApplicationStateObserverStub::OnProcessStateChanged(const ProcessData &processData)
{
}

void ApplicationStateObserverStub::OnWindowShow(const ProcessData &processData)
{
}

void ApplicationStateObserverStub::OnWindowHidden(const ProcessData &processData)
{
}

void ApplicationStateObserverStub::OnProcessDied(const ProcessData &processData)
{
}

void ApplicationStateObserverStub::OnApplicationStateChanged(const AppStateData &appStateData)
{
}

void ApplicationStateObserverStub::OnAppStateChanged(const AppStateData &appStateData)
{
}

void ApplicationStateObserverStub::OnProcessReused(const ProcessData &processData)
{
}

void ApplicationStateObserverStub::OnAppStarted(const AppStateData &appStateData)
{
}

void ApplicationStateObserverStub::OnAppStopped(const AppStateData &appStateData)
{
}

void ApplicationStateObserverStub::OnPageShow(const PageStateData &pageStateData)
{
}

void ApplicationStateObserverStub::OnPageHide(const PageStateData &pageStateData)
{
}

void ApplicationStateObserverStub::OnAppCacheStateChanged(const AppStateData &appStateData)
{
}

void ApplicationStateObserverStub::OnProcessBindingRelationChanged(const ProcessBindData &processBindData)
{
}

void ApplicationStateObserverStub::OnKeepAliveStateChanged(const ProcessData &processData)
{
}

void ApplicationStateObserverStub::OnProcessPreForegroundChanged(const PreloadProcessData &preloadProcessData)
{
}

void ApplicationStateObserverStub::OnProcessTypeChanged(const ProcessData &processData)
{
}

int32_t ApplicationStateObserverStub::HandleOnForegroundApplicationChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnAbilityStateChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnExtensionStateChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnProcessCreated(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnProcessStateChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnWindowShow(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnWindowHidden(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnProcessDied(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnApplicationStateChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnAppStateChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnProcessReused(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnAppStarted(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnAppStopped(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnPageShow(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnPageHide(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnAppCacheStateChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnProcessBindingRelationChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnKeepAliveStateChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnProcessPreForegroundChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

int32_t ApplicationStateObserverStub::HandleOnProcessTypeChanged(MessageParcel &data, MessageParcel &reply)
{
    return 0;
}

ApplicationStateObserverRecipient::ApplicationStateObserverRecipient(RemoteDiedHandler handler) : handler_(handler)
{
}

ApplicationStateObserverRecipient::~ApplicationStateObserverRecipient()
{
}

void ApplicationStateObserverRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (handler_) {
        handler_(remote);
    }
}

} // namespace AppExecFwk
} // namespace OHOS