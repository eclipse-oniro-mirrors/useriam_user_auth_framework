/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "user_idm_client_test.h"

#include "iam_ptr.h"
#include "iuser_idm.h"
#include "user_idm_client.h"
#include "user_idm_client_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserIdmClientTest::SetUpTestCase()
{
}

void UserIdmClientTest::TearDownTestCase()
{
}

void UserIdmClientTest::SetUp()
{
}

void UserIdmClientTest::TearDown()
{
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientOpenSession001, TestSize.Level0)
{
    int32_t testUserId = 21200;

    IpcClientUtils::ResetObj();
    std::vector<uint8_t> challenge = UserIdmClient::GetInstance().OpenSession(testUserId);
    EXPECT_TRUE(challenge.empty());
}

HWTEST_F(UserIdmClientTest, UserIdmClientOpenSession002, TestSize.Level0)
{
    int32_t testUserId = 21200;
    std::vector<uint8_t> testChallenge = {1, 3, 4, 7};

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OpenSession(_, _)).Times(1);
    ON_CALL(*service, OpenSession)
        .WillByDefault(
            [&testUserId, &testChallenge](int32_t userId, std::vector<uint8_t> &challenge) {
                EXPECT_EQ(userId, testUserId);
                challenge = testChallenge;
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    std::vector<uint8_t> challenge = UserIdmClient::GetInstance().OpenSession(testUserId);
    EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientCloseSession001, TestSize.Level0)
{
    int32_t testUserId = 200;

    IpcClientUtils::ResetObj();
    EXPECT_NO_THROW(UserIdmClient::GetInstance().CloseSession(testUserId));
}

HWTEST_F(UserIdmClientTest, UserIdmClientCloseSession002, TestSize.Level0)
{
    int32_t testUserId = 200;

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CloseSession(_)).Times(1);
    ON_CALL(*service, CloseSession)
        .WillByDefault(
            [&testUserId](int32_t userId) {
                EXPECT_EQ(userId, testUserId);
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    
    UserIdmClient::GetInstance().CloseSession(testUserId);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientCloseSession003, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));

    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillOnce(Return(false))
        .WillRepeatedly([&dr](const sptr<IRemoteObject::DeathRecipient> &recipient) {
            dr = recipient;
            return true;
        });

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).WillRepeatedly(Return(OHOS::NO_ERROR));

    IpcClientUtils::SetObj(obj);

    int32_t testUserId = 1326;
    UserIdmClient::GetInstance().CloseSession(testUserId);
    UserIdmClient::GetInstance().CloseSession(testUserId);
    UserIdmClient::GetInstance().CloseSession(testUserId);

    EXPECT_NE(dr, nullptr);
    sptr<IRemoteObject> remote(nullptr);
    dr->OnRemoteDied(remote);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientAddCredential001, TestSize.Level0)
{
    int32_t testUserId = 200;
    CredentialParameters testPara = {};
    std::shared_ptr<MockUserIdmClientCallback> testCallback = nullptr;
    UserIdmClient::GetInstance().AddCredential(testUserId, testPara, testCallback);
    
    testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcClientUtils::ResetObj();
    UserIdmClient::GetInstance().AddCredential(testUserId, testPara, testCallback);
}

HWTEST_F(UserIdmClientTest, UserIdmClientAddCredential002, TestSize.Level0)
{
    int32_t testUserId = 200;
    CredentialParameters testPara = {};
    testPara.authType = FACE;
    testPara.pinType = std::nullopt;
    testPara.token = {1, 4, 7, 0};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AddCredential(_, _, _, _)).Times(1);
    ON_CALL(*service, AddCredential)
        .WillByDefault(
            [&testUserId, &testPara](int32_t userId, const IpcCredentialPara &credPara,
                const sptr<IIamCallback> &callback, bool isUpdate) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(credPara.authType, testPara.authType);
                EXPECT_THAT(credPara.token, ElementsAreArray(testPara.token));
                EXPECT_EQ(isUpdate, false);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo.Serialize());
                }
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    UserIdmClient::GetInstance().AddCredential(testUserId, testPara, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientUpdateCredential001, TestSize.Level0)
{
    int32_t testUserId = 200;
    CredentialParameters testPara = {};
    std::shared_ptr<MockUserIdmClientCallback> testCallback = nullptr;
    UserIdmClient::GetInstance().UpdateCredential(testUserId, testPara, testCallback);
    
    testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcClientUtils::ResetObj();
    UserIdmClient::GetInstance().UpdateCredential(testUserId, testPara, testCallback);
}

HWTEST_F(UserIdmClientTest, UserIdmClientUpdateCredential002, TestSize.Level0)
{
    int32_t testUserId = 200;
    CredentialParameters testPara = {};
    testPara.authType = PIN;
    testPara.pinType = PIN_SIX;
    testPara.token = {1, 4, 7, 0};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdateCredential(_, _, _)).Times(1);
    ON_CALL(*service, UpdateCredential)
        .WillByDefault(
            [&testUserId, &testPara](int32_t userId, const IpcCredentialPara &credPara,
                const sptr<IIamCallback> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(credPara.authType, testPara.authType);
                EXPECT_TRUE(testPara.pinType.has_value());
                EXPECT_EQ(credPara.pinType, testPara.pinType.value());
                EXPECT_THAT(credPara.token, ElementsAreArray(testPara.token));
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo.Serialize());
                }
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    UserIdmClient::GetInstance().UpdateCredential(testUserId, testPara, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientCancel001, TestSize.Level0)
{
    int32_t testUserId = 200;

    IpcClientUtils::ResetObj();
    int32_t ret = UserIdmClient::GetInstance().Cancel(testUserId);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserIdmClientTest, UserIdmClientCancel002, TestSize.Level0)
{
    int32_t testUserId = 200;

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Cancel(_)).Times(1);
    ON_CALL(*service, Cancel)
        .WillByDefault(
            [&testUserId](int32_t userId) {
                EXPECT_EQ(userId, testUserId);
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    int32_t ret = UserIdmClient::GetInstance().Cancel(testUserId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientDeleteCredential001, TestSize.Level0)
{
    int32_t testUserId = 200;
    uint64_t testCredentialId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::shared_ptr<MockUserIdmClientCallback> testCallback = nullptr;
    UserIdmClient::GetInstance().DeleteCredential(testUserId, testCredentialId, testAuthToken, testCallback);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserIdmClient::GetInstance().DeleteCredential(testUserId, testCredentialId, testAuthToken, testCallback);
}

HWTEST_F(UserIdmClientTest, UserIdmClientDeleteCredential002, TestSize.Level0)
{
    int32_t testUserId = 200;
    uint64_t testCredentialId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, DelCredential(_, _, _, _)).Times(1);
    ON_CALL(*service, DelCredential)
        .WillByDefault(
            [&testUserId, &testCredentialId, &testAuthToken](int32_t userId, uint64_t credentialId,
                const std::vector<uint8_t> &authToken, const sptr<IIamCallback> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(credentialId, testCredentialId);
                EXPECT_THAT(authToken, ElementsAreArray(testAuthToken));
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo.Serialize());
                }
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    UserIdmClient::GetInstance().DeleteCredential(testUserId, testCredentialId, testAuthToken, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientDeleteUser001, TestSize.Level0)
{
    int32_t testUserId = 200;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::shared_ptr<MockUserIdmClientCallback> testCallback = nullptr;
    UserIdmClient::GetInstance().DeleteUser(testUserId, testAuthToken, testCallback);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserIdmClient::GetInstance().DeleteUser(testUserId, testAuthToken, testCallback);
}

HWTEST_F(UserIdmClientTest, UserIdmClientDeleteUser002, TestSize.Level0)
{
    int32_t testUserId = 200;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, DelUser(_, _, _)).Times(1);
    ON_CALL(*service, DelUser)
        .WillByDefault(
            [&testUserId, &testAuthToken](int32_t userId, const std::vector<uint8_t> authToken,
                const sptr<IIamCallback> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_THAT(authToken, ElementsAreArray(testAuthToken));
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo.Serialize());
                }
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    UserIdmClient::GetInstance().DeleteUser(testUserId, testAuthToken, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientEraseUser001, TestSize.Level0)
{
    int32_t testUserId = 200;
    std::shared_ptr<MockUserIdmClientCallback> testCallback = nullptr;
    int32_t ret = UserIdmClient::GetInstance().EraseUser(testUserId, testCallback);
    EXPECT_EQ(ret, GENERAL_ERROR);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    ret = UserIdmClient::GetInstance().EraseUser(testUserId, testCallback);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserIdmClientTest, UserIdmClientEraseUser002, TestSize.Level0)
{
    int32_t testUserId = 200;
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, EnforceDelUser(_, _)).Times(1);
    ON_CALL(*service, EnforceDelUser)
        .WillByDefault(
            [&testUserId](int32_t userId, const sptr<IIamCallback> &callback) {
                EXPECT_EQ(userId, testUserId);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo.Serialize());
                }
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    int32_t ret = UserIdmClient::GetInstance().EraseUser(testUserId, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetCredentialInfo001, TestSize.Level0)
{
    int32_t testUserId = 200;
    AuthType testAuthType = PIN;
    std::shared_ptr<MockGetCredentialInfoCallback> testCallback = nullptr;
    int32_t ret = UserIdmClient::GetInstance().GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_EQ(ret, GENERAL_ERROR);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockGetCredentialInfoCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnCredentialInfo(_, _)).Times(1);
    ret = UserIdmClient::GetInstance().GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetCredentialInfo002, TestSize.Level0)
{
    int32_t testUserId = 200;
    AuthType testAuthType = PIN;
    auto testCallback = Common::MakeShared<MockGetCredentialInfoCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnCredentialInfo(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetCredentialInfo(_, _, _, _)).Times(1);
    ON_CALL(*service, GetCredentialInfo)
        .WillByDefault(
            [&testUserId, &testAuthType](int32_t userId, int32_t authType,
                const sptr<IIdmGetCredInfoCallback> &callback, int32_t &funcResult) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, static_cast<int32_t>(testAuthType));
                if (callback != nullptr) {
                    std::vector<IpcCredentialInfo> credInfoList;
                    callback->OnCredentialInfos(SUCCESS, credInfoList);
                }
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    int32_t ret = UserIdmClient::GetInstance().GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetSecUserInfo001, TestSize.Level0)
{
    int32_t testUserId = 200;
    std::shared_ptr<MockGetSecUserInfoCallback> testCallback = nullptr;
    int32_t ret = UserIdmClient::GetInstance().GetSecUserInfo(testUserId, testCallback);
    EXPECT_EQ(ret, GENERAL_ERROR);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockGetSecUserInfoCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnSecUserInfo(_, _)).Times(1);
    ret = UserIdmClient::GetInstance().GetSecUserInfo(testUserId, testCallback);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetSecUserInfo002, TestSize.Level0)
{
    int32_t testUserId = 200;
    auto testCallback = Common::MakeShared<MockGetSecUserInfoCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetSecInfo(_, _)).Times(1);
    ON_CALL(*service, GetSecInfo)
        .WillByDefault(
            [&testUserId](int32_t userId, const sptr<IIdmGetSecureUserInfoCallback> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_NE(callback, nullptr);
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    int32_t ret = UserIdmClient::GetInstance().GetSecUserInfo(testUserId, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientImplClearRedundancyCredential, TestSize.Level0)
{
    std::shared_ptr<MockUserIdmClientCallback> testCallback = nullptr;
    testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_NO_THROW(UserIdmClient::GetInstance().ClearRedundancyCredential(testCallback));
}

HWTEST_F(UserIdmClientTest, UserIdmClientRegistCredChangeEventListener, TestSize.Level0)
{
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);
    auto testCallback = Common::MakeShared<MockCredChangeEventListener>();
    int32_t ret = UserIdmClient::GetInstance().RegistCredChangeEventListener(authTypeList, testCallback);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserIdmClientTest, UserIdmClientRegistCredChangeEventListenerSuccess, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillRepeatedly([&dr](const sptr<IRemoteObject::DeathRecipient> &recipient) {
            dr = recipient;
            return true;
        });
    IpcClientUtils::SetObj(obj);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(SUCCESS);
            return OHOS::NO_ERROR;
        });

    std::vector<AuthType> authTypeList = {AuthType::PIN};
    auto testCallback = Common::MakeShared<MockCredChangeEventListener>();
    int32_t ret = UserIdmClient::GetInstance().RegistCredChangeEventListener(authTypeList, testCallback);
    EXPECT_EQ(ret, SUCCESS);

    auto listenerImpl = EventListenerCallbackService::GetInstance();
    int32_t userId = 100;
    int32_t authType = 1;
    int32_t callerType = 1;
    IpcCredChangeEventInfo eventInfo = {};
    listenerImpl->OnNotifyCredChangeEvent(userId, authType, callerType, eventInfo);
    uint32_t ipcCode = 1;
    listenerImpl->CallbackEnter(ipcCode);
    listenerImpl->CallbackExit(ipcCode, SUCCESS);
    ret = UserIdmClient::GetInstance().UnRegistCredChangeEventListener(testCallback);
    EXPECT_EQ(ret, SUCCESS);
    ASSERT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientUnRegistCredChangeEventListener, TestSize.Level0)
{
    auto testCallback = Common::MakeShared<MockCredChangeEventListener>();
    int32_t ret = UserIdmClient::GetInstance().UnRegistCredChangeEventListener(testCallback);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

void UserIdmClientTest::CallRemoteObject(const std::shared_ptr<MockUserIdmService> service,
    const sptr<MockRemoteObject> &obj, sptr<IRemoteObject::DeathRecipient> &dr)
{
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillRepeatedly([&dr](const sptr<IRemoteObject::DeathRecipient> &recipient) {
            dr = recipient;
            return true;
        });

    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetCredentialInfoSync001, TestSize.Level0)
{
    int32_t testUserId = 200;
    AuthType testAuthType = PIN;
    std::vector<CredentialInfo> credentialInfoList;
    int32_t ret = UserIdmClient::GetInstance().GetCredentialInfoSync(testUserId, testAuthType, credentialInfoList);
    EXPECT_EQ(ret, GENERAL_ERROR);

    IpcClientUtils::ResetObj();
    ret = UserIdmClient::GetInstance().GetCredentialInfoSync(testUserId, testAuthType, credentialInfoList);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetCredentialInfoSync002, TestSize.Level0)
{
    int32_t testUserId = 200;
    AuthType testAuthType = PIN;
    std::vector<CredentialInfo> credentialInfoList;

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetCredentialInfoSync(_, _, _)).Times(1);
    ON_CALL(*service, GetCredentialInfoSync)
        .WillByDefault(
            [&testUserId, &testAuthType](int32_t userId, int32_t authType,
                std::vector<IpcCredentialInfo> &credentialInfoList) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testAuthType);
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    int32_t ret = UserIdmClient::GetInstance().GetCredentialInfoSync(testUserId, testAuthType, credentialInfoList);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetLatestEnrollmentTime001, TestSize.Level0)
{
    int32_t testUserId = 200;
    AuthType testAuthType = PIN;
    uint64_t latestEnrollmentTime = 0;
    int32_t ret = UserIdmClient::GetInstance().GetLatestEnrollmentTime(testUserId, testAuthType,
        latestEnrollmentTime);
    EXPECT_EQ(ret, GENERAL_ERROR);

    IpcClientUtils::ResetObj();
    ret = UserIdmClient::GetInstance().GetLatestEnrollmentTime(testUserId, testAuthType, latestEnrollmentTime);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetLatestEnrollmentTime002, TestSize.Level0)
{
    int32_t testUserId = 200;
    AuthType testAuthType = PIN;
    uint64_t expectTime = 1700000000000;

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetLatestEnrollmentTime(_, _, _)).Times(1);
    ON_CALL(*service, GetLatestEnrollmentTime)
        .WillByDefault(
            [&testUserId, &testAuthType, &expectTime](int32_t userId, int32_t authType,
                uint64_t &latestEnrollmentTime) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, static_cast<int32_t>(testAuthType));
                latestEnrollmentTime = expectTime;
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    uint64_t latestEnrollmentTime = 0;
    int32_t ret = UserIdmClient::GetInstance().GetLatestEnrollmentTime(testUserId, testAuthType,
        latestEnrollmentTime);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(latestEnrollmentTime, expectTime);

    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmStubRegistCredChangeEventListenerDispatch, TestSize.Level0)
{
    auto service = Common::MakeShared<MockUserIdmService>();
    ASSERT_NE(service, nullptr);
    ON_CALL(*service, CallbackEnter).WillByDefault(Return(ERR_NONE));
    ON_CALL(*service, CallbackExit).WillByDefault(Return(ERR_NONE));
    ON_CALL(*service, RegistCredChangeEventListener).WillByDefault(Return(SUCCESS));

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IUserIdm::GetDescriptor());
    data.WriteRemoteObject(nullptr);

    int32_t ret = service->OnRemoteRequest(
        static_cast<uint32_t>(IUserIdmIpcCode::COMMAND_REGIST_CRED_CHANGE_EVENT_LISTENER),
        data, reply, option);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
}

HWTEST_F(UserIdmClientTest, UserIdmStubUnRegistCredChangeEventListenerDispatch, TestSize.Level0)
{
    auto service = Common::MakeShared<MockUserIdmService>();
    ASSERT_NE(service, nullptr);
    ON_CALL(*service, CallbackEnter).WillByDefault(Return(ERR_NONE));
    ON_CALL(*service, CallbackExit).WillByDefault(Return(ERR_NONE));
    ON_CALL(*service, UnRegistCredChangeEventListener).WillByDefault(Return(SUCCESS));

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IUserIdm::GetDescriptor());
    data.WriteRemoteObject(nullptr);

    int32_t ret = service->OnRemoteRequest(
        static_cast<uint32_t>(IUserIdmIpcCode::COMMAND_UN_REGIST_CRED_CHANGE_EVENT_LISTENER),
        data, reply, option);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS