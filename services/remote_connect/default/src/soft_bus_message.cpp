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

#include "soft_bus_message.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SOFT_BUS_MESSAGE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
SoftBusMessage::SoftBusMessage(int32_t messageSeq, const std::string &connectionName,
    const std::string &srcEndPoint, const std::string &destEndPoint,
    const std::shared_ptr<Attributes> &attributes)
    : messageSeq_(messageSeq), connectionName_(connectionName), srcEndPoint_(srcEndPoint),
    destEndPoint_(destEndPoint), attributes_(attributes)
{
    IAM_LOGD("start");
}

uint32_t SoftBusMessage::GetMessageSeq()
{
    return messageSeq_;
}

uint32_t SoftBusMessage::GetMessageVersion()
{
    return messageVersion_;
}

uint32_t SoftBusMessage::GetAckFlag()
{
    return isAck_;
}

std::shared_ptr<Attributes> SoftBusMessage::GetAttributes()
{
    return attributes_;
}

std::string SoftBusMessage::GetSrcEndPoint()
{
    return srcEndPoint_;
}

std::string SoftBusMessage::GetDestEndPoint()
{
    return destEndPoint_;
}

std::string SoftBusMessage::GetConnectionName()
{
    return connectionName_;
}

std::shared_ptr<Attributes> SoftBusMessage::CreateMessage(bool isAck)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes_ != nullptr, nullptr);

    auto attributes = Common::MakeShared<Attributes>(attributes_->Serialize());
    if (attributes == nullptr) {
        IAM_LOGE("attributes create fail");
        return nullptr;
    }

    bool ret = attributes->SetInt32Value(Attributes::ATTR_MSG_SEQ_NUM, messageSeq_);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    if (isAck == true) {
        ret = attributes->SetBoolValue(Attributes::ATTR_MSG_ACK, true);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);
    } else {
        ret = attributes->SetBoolValue(Attributes::ATTR_MSG_ACK, false);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);
    }

    ret = attributes->SetStringValue(Attributes::ATTR_MSG_SRC_END_POINT, srcEndPoint_);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    ret = attributes->SetStringValue(Attributes::ATTR_MSG_DEST_END_POINT, destEndPoint_);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    ret = attributes->SetStringValue(Attributes::ATTR_CONNECTION_NAME, connectionName_);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    ret = attributes->SetUint32Value(Attributes::ATTR_MSG_VERSION, DEFAULT_MESSAGE_VERSION);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    int32_t msgType = -1;
    attributes->GetInt32Value(Attributes::ATTR_MSG_TYPE, msgType); // ATTR_MSG_TYPE may be empty

    std::string udid;
    bool getLocalUdidRet = DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(udid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getLocalUdidRet, nullptr);

    ret = attributes->SetStringValue(Attributes::ATTR_MSG_SRC_UDID, udid);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    IAM_LOGI("CreateMessage success: messageVersion:%{public}u, messageSeq:%{public}u, connectionName:%{public}s, "
        "msgType:%{public}d, isAck:%{public}d, srcEndPoint:%{public}s, destEndPoint:%{public}s",
        DEFAULT_MESSAGE_VERSION, messageSeq_, connectionName_.c_str(), msgType, isAck, srcEndPoint_.c_str(),
        destEndPoint_.c_str());
    
    return attributes;
}

std::shared_ptr<Attributes> SoftBusMessage::ParseMessage(const void *message, uint32_t messageLen)
{
    IAM_LOGD("start.");
    if (message == nullptr || messageLen == 0) {
        IAM_LOGE("ParseMessage fail");
        return nullptr;
    }

    std::vector<uint8_t> data(static_cast<const char *>(message), static_cast<const char *>(message) + messageLen);
    auto attributes = Common::MakeShared<Attributes>(data);
    if (attributes == nullptr) {
        IAM_LOGE("attributes create fail");
        return nullptr;
    }

    bool ret = attributes->GetUint32Value(Attributes::ATTR_MSG_SEQ_NUM, messageSeq_);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);
    
    ret = attributes->GetBoolValue(Attributes::ATTR_MSG_ACK, isAck_);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    ret = attributes->GetStringValue(Attributes::ATTR_MSG_SRC_END_POINT, srcEndPoint_);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    ret = attributes->GetStringValue(Attributes::ATTR_MSG_DEST_END_POINT, destEndPoint_);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    ret = attributes->GetStringValue(Attributes::ATTR_CONNECTION_NAME, connectionName_);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    ret = attributes->GetUint32Value(Attributes::ATTR_MSG_VERSION, messageVersion_);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret, nullptr);

    int32_t msgType = -1;
    attributes->GetInt32Value(Attributes::ATTR_MSG_TYPE, msgType); // ATTR_MSG_TYPE may be empty
    attributes_ = attributes;

    IAM_LOGI("ParseMessage success: messageVersion:%{public}u messageSeq:%{public}u, connectionName:%{public}s, "
        "msgType:%{public}d, isAck:%{public}d, srcEndPoint:%{public}s, destEndPoint:%{public}s",
        messageVersion_, messageSeq_, connectionName_.c_str(), msgType, isAck_, srcEndPoint_.c_str(),
        destEndPoint_.c_str());
    return attributes;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS