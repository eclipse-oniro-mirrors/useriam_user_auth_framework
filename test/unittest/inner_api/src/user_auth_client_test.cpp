/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "user_auth_client_test.h"

#include "iam_ptr.h"
#include "user_auth_client.h"
#include "user_auth_client_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthClientTest::SetUpTestCase()
{
}

void UserAuthClientTest::TearDownTestCase()
{
}

void UserAuthClientTest::SetUp()
{
}

void UserAuthClientTest::TearDown()
{
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetEnrolledState001, TestSize.Level0)
{
    AuthType testAuthType = FACE;
    int32_t testApiVersion = 0;
    EnrolledState testEnrolledState = {};

    IpcClientUtils::ResetObj();
    int32_t ret = UserAuthClientImpl::Instance().GetEnrolledState(testApiVersion, testAuthType, testEnrolledState);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetEnrolledState002, TestSize.Level0)
{
    AuthType testAuthType = FACE;
    int32_t testApiVersion = 0;
    EnrolledState testEnrolledState = {};

    uint16_t credentialDigest = 23962;
    uint16_t credentialCount = 1;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetEnrolledState(_, _, _)).Times(1);
    ON_CALL(*service, GetEnrolledState)
        .WillByDefault(
            [&testApiVersion, &testAuthType, &credentialDigest, &credentialCount](int32_t apiVersion, AuthType authType,
                EnrolledState &enrolledState) {
                EXPECT_EQ(apiVersion, testApiVersion);
                EXPECT_EQ(authType, testAuthType);

                enrolledState.credentialDigest = credentialDigest;
                enrolledState.credentialCount = credentialCount;
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    int32_t ret = UserAuthClientImpl::Instance().GetEnrolledState(testApiVersion, testAuthType, testEnrolledState);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(testEnrolledState.credentialDigest, credentialDigest);
    EXPECT_EQ(testEnrolledState.credentialCount, credentialCount);

    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetAvailableStatus001, TestSize.Level0)
{
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL1;

    IpcClientUtils::ResetObj();
    int32_t ret = UserAuthClientImpl::Instance().GetAvailableStatus(testAuthType, testAtl);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetAvailableStatus002, TestSize.Level0)
{
    int32_t testApiVersion = 9;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL1;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetAvailableStatus(_, _, _)).Times(1);
    ON_CALL(*service, GetAvailableStatus)
        .WillByDefault(
            [&testApiVersion, &testAuthType, &testAtl](int32_t apiVersion, AuthType authType,
                AuthTrustLevel authTrustLevel) {
                EXPECT_EQ(apiVersion, testApiVersion);
                EXPECT_EQ(authType, testAuthType);
                EXPECT_EQ(authTrustLevel, testAtl);
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    int32_t ret = UserAuthClientImpl::Instance().GetAvailableStatus(testApiVersion, testAuthType, testAtl);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetProperty001, TestSize.Level0)
{
    int32_t testUserId = 200;
    GetPropertyRequest testRequest = {};

    std::shared_ptr<MockGetPropCallback> testCallback = nullptr;
    UserAuthClient::GetInstance().GetProperty(testUserId, testRequest, testCallback);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserAuthClient::GetInstance().GetProperty(testUserId, testRequest, testCallback);
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetProperty002, TestSize.Level0)
{
    int32_t testUserId = 200;
    GetPropertyRequest testRequest = {};
    testRequest.authType = FACE;
    testRequest.keys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE};

    auto testCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetProperty(_, _, _, _)).Times(1);
    ON_CALL(*service, GetProperty)
        .WillByDefault(
            [&testUserId, &testRequest](int32_t userId, AuthType authType,
                const std::vector<Attributes::AttributeKey> &keys,
                sptr<GetExecutorPropertyCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testRequest.authType);
                EXPECT_THAT(keys, ElementsAreArray(testRequest.keys));
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnGetExecutorPropertyResult(SUCCESS, extraInfo);
                }
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    UserAuthClient::GetInstance().GetProperty(testUserId, testRequest, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientSetProperty001, TestSize.Level0)
{
    int32_t testUserId = 200;
    SetPropertyRequest testRequest = {};
    std::shared_ptr<MockSetPropCallback> testCallback = nullptr;
    UserAuthClient::GetInstance().SetProperty(testUserId, testRequest, testCallback);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockSetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserAuthClient::GetInstance().SetProperty(testUserId, testRequest, testCallback);
}

HWTEST_F(UserAuthClientTest, UserAuthClientSetProperty002, TestSize.Level0)
{
    int32_t testUserId = 200;
    SetPropertyRequest testRequest = {};
    testRequest.authType = PIN;
    testRequest.mode = PROPERTY_INIT_ALGORITHM;
    EXPECT_EQ(testRequest.attrs.SetInt32Value(static_cast<Attributes::AttributeKey>(testRequest.mode), FAIL), true);
    auto testCallback = Common::MakeShared<MockSetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetProperty(_, _, _, _)).Times(1);
    ON_CALL(*service, SetProperty)
        .WillByDefault(
            [&testUserId, &testRequest](int32_t userId, AuthType authType, const Attributes &attributes,
                sptr<SetExecutorPropertyCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testRequest.authType);
                if (callback != nullptr) {
                    callback->OnSetExecutorPropertyResult(SUCCESS);
                }
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    UserAuthClient::GetInstance().SetProperty(testUserId, testRequest, testCallback);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginNorthAuthentication001, TestSize.Level0)
{
    int32_t testApiVersion = 8;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4, 3, 2, 1, 0};
    AuthType testAuthType = PIN;
    AuthTrustLevel testAtl = ATL1;
    std::shared_ptr<MockAuthenticationCallback> testCallback = nullptr;
    uint64_t contextId = UserAuthClientImpl::Instance().BeginNorthAuthentication(testApiVersion, testChallenge,
        testAuthType, testAtl, testCallback);
    EXPECT_EQ(contextId, 0);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    contextId = UserAuthClientImpl::Instance().BeginNorthAuthentication(testApiVersion, testChallenge,
        testAuthType, testAtl, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginNorthAuthentication002, TestSize.Level0)
{
    int32_t testApiVersion = 9;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4, 3, 2, 1, 0};
    AuthType testAuthType = PIN;
    AuthTrustLevel testAtl = ATL1;
    auto testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    uint64_t testContextId = 15858;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Auth(_, _, _, _, _)).Times(1);
    ON_CALL(*service, Auth)
        .WillByDefault(
            [&testApiVersion, &testChallenge, &testAuthType, &testAtl, &testContextId](int32_t apiVersion,
                const std::vector<uint8_t> &challenge, AuthType authType, AuthTrustLevel authTrustLevel,
                sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_EQ(apiVersion, testApiVersion);
                EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
                EXPECT_EQ(authType, testAuthType);
                EXPECT_EQ(authTrustLevel, testAtl);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
                }
                return testContextId;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    uint64_t contextId = UserAuthClientImpl::Instance().BeginNorthAuthentication(testApiVersion, testChallenge,
        testAuthType, testAtl, testCallback);
    EXPECT_EQ(contextId, testContextId);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginAuthentication001, TestSize.Level0)
{
    AuthParam testAuthParam = {
        .userId = 84548,
        .challenge = {1, 2, 3, 4, 8, 7, 5, 4},
        .authType = PIN,
        .authTrustLevel = ATL1
    };
    std::shared_ptr<MockAuthenticationCallback> testCallback = nullptr;
    uint64_t contextId = UserAuthClient::GetInstance().BeginAuthentication(testAuthParam, testCallback);
    EXPECT_EQ(contextId, 0);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    contextId = UserAuthClient::GetInstance().BeginAuthentication(testAuthParam, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginAuthentication002, TestSize.Level0)
{
    AuthParam testAuthParam = {
        .userId = 84548,
        .challenge = {1, 2, 3, 4, 8, 7, 5, 4},
        .authType = PIN,
        .authTrustLevel = ATL1,
    };
    auto testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    uint64_t testContextId = 15858;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AuthUser(_, _, _)).Times(1);
    ON_CALL(*service, AuthUser)
        .WillByDefault(
            [&testAuthParam, &testContextId](AuthParamInner &authParam,
            std::optional<RemoteAuthParam> &remoteAuthParam, sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_EQ(authParam.userId, testAuthParam.userId);
                EXPECT_THAT(authParam.challenge, ElementsAreArray(testAuthParam.challenge));
                EXPECT_EQ(authParam.authType, testAuthParam.authType);
                EXPECT_EQ(authParam.authTrustLevel, testAuthParam.authTrustLevel);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
                }
                return testContextId;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    uint64_t contextId = UserAuthClient::GetInstance().BeginAuthentication(testAuthParam, testCallback);
    EXPECT_EQ(contextId, testContextId);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientCancelAuthentication001, TestSize.Level0)
{
    uint64_t testContextId = 12345562;

    IpcClientUtils::ResetObj();
    int32_t ret = UserAuthClient::GetInstance().CancelAuthentication(testContextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientCancelAuthentication002, TestSize.Level0)
{
    uint64_t testContextId = 12345562;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CancelAuthOrIdentify(_)).Times(1);
    ON_CALL(*service, CancelAuthOrIdentify)
        .WillByDefault(
            [&testContextId](uint64_t contextId) {
                EXPECT_EQ(contextId, testContextId);
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    int32_t ret = UserAuthClient::GetInstance().CancelAuthentication(testContextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginIdentification_1001, TestSize.Level0)
{
    std::vector<uint8_t> testChallenge = {4, 5, 6, 7, 3, 4, 1, 2};
    AuthType testAuthType = FACE;
    std::shared_ptr<MockIdentificationCallback> testCallback = nullptr;
    uint64_t contextId = UserAuthClient::GetInstance().BeginIdentification(testChallenge, testAuthType, testCallback);
    EXPECT_EQ(contextId, 0);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    contextId = UserAuthClient::GetInstance().BeginIdentification(testChallenge, testAuthType, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginIdentification_1002, TestSize.Level0)
{
    std::vector<uint8_t> testChallenge = {4, 5, 6, 7, 3, 4, 1, 2};
    AuthType testAuthType = FACE;
    auto testCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    uint64_t testContextId = 548781;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Identify(_, _, _)).Times(1);
    ON_CALL(*service, Identify)
        .WillByDefault(
            [&testChallenge, &testAuthType, &testContextId](const std::vector<uint8_t> &challenge,
                AuthType authType, sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
                EXPECT_EQ(authType, testAuthType);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
                }
                return testContextId;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);

    uint64_t contextId = UserAuthClient::GetInstance().BeginIdentification(testChallenge, testAuthType, testCallback);
    EXPECT_EQ(contextId, testContextId);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientCancelIdentification001, TestSize.Level0)
{
    uint64_t testContextId = 1221215;
    
    IpcClientUtils::ResetObj();
    int32_t ret = UserAuthClient::GetInstance().CancelIdentification(testContextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientCancelIdentification002, TestSize.Level0)
{
    uint64_t testContextId = 1221215;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CancelAuthOrIdentify(_)).Times(1);
    ON_CALL(*service, CancelAuthOrIdentify)
        .WillByDefault(
            [&testContextId](uint64_t contextId) {
                EXPECT_EQ(contextId, testContextId);
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    
    int32_t ret = UserAuthClient::GetInstance().CancelIdentification(testContextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetVersion001, TestSize.Level0)
{
    IpcClientUtils::ResetObj();
    int32_t version = -1;
    int32_t ret = UserAuthClientImpl::Instance().GetVersion(version);
    EXPECT_EQ(ret, GENERAL_ERROR);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetVersion002, TestSize.Level0)
{
    int32_t testVersion = 20000;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetVersion(_)).Times(1);
    ON_CALL(*service, GetVersion)
        .WillByDefault(
            [&testVersion](int32_t &version) {
                version = testVersion;
                return SUCCESS;
            }
        );

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    int32_t version;
    int32_t result = UserAuthClientImpl::Instance().GetVersion(version);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(version, testVersion);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetVersion003, TestSize.Level0)
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

    int32_t version;
    EXPECT_EQ(UserAuthClientImpl::Instance().GetVersion(version), GENERAL_ERROR);
    EXPECT_EQ(UserAuthClientImpl::Instance().GetVersion(version), GENERAL_ERROR);
    EXPECT_EQ(UserAuthClientImpl::Instance().GetVersion(version), GENERAL_ERROR);

    EXPECT_NE(dr, nullptr);
    sptr<IRemoteObject> remote(nullptr);
    dr->OnRemoteDied(remote);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginWidgetAuth001, TestSize.Level0)
{
    static const int32_t apiVersion = 0;
    AuthParamInner authParam;
    WidgetParam widgetParam;
    std::shared_ptr<MockAuthenticationCallback> testCallback = nullptr;
    testCallback = Common::MakeShared<MockAuthenticationCallback>();
    uint64_t widgetAuth = UserAuthClientImpl::Instance().BeginWidgetAuth(apiVersion, authParam,
    widgetParam, testCallback);
    EXPECT_EQ(widgetAuth, 0);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginWidgetAuth002, TestSize.Level0)
{
    static const int32_t apiVersion = 0;
    AuthParamInner authParam;
    WidgetParam widgetParam;
    std::shared_ptr<MockAuthenticationCallback> testCallback = nullptr;
    uint64_t widgetAuth = UserAuthClientImpl::Instance().BeginWidgetAuth(apiVersion, authParam,
    widgetParam, testCallback);
    EXPECT_EQ(widgetAuth, 0);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginWidgetAuth003, TestSize.Level0)
{
    int32_t testVersion = 0;
    AuthParamInner testParam = {};
    testParam.challenge = {0};
    testParam.authType = {ALL};
    WidgetParam testWidgetParam = {};
    testWidgetParam.title = "title";
    auto testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);

    uint64_t testContextVersion = 1;
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AuthWidget(_, _, _, _)).WillRepeatedly(Return(true));
    ON_CALL(*service, AuthWidget)
        .WillByDefault(
            [&testVersion, &testParam, &testWidgetParam, &testContextVersion](int32_t apiVersion,
            const AuthParamInner &authParam, const WidgetParam &widgetParam,
            sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_EQ(apiVersion, testVersion);
                EXPECT_EQ(authParam.authType, testParam.authType);
                EXPECT_EQ(widgetParam.title, testWidgetParam.title);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);
                }
                return testContextVersion;
            }
        );

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    uint64_t widgetAuth = UserAuthClientImpl::Instance().BeginWidgetAuth(testVersion, testParam,
    testWidgetParam, testCallback);
    EXPECT_EQ(widgetAuth, testContextVersion);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}


HWTEST_F(UserAuthClientTest, UserAuthClientSetWidgetCallback001, TestSize.Level0)
{
    static const int32_t apiVersion = 0;
    auto testCallback = Common::MakeShared<MockIUserAuthWidgetCallback>();
    int32_t widgetCallback = UserAuthClientImpl::Instance().SetWidgetCallback(apiVersion, testCallback);
    EXPECT_NE(widgetCallback, SUCCESS);
}

HWTEST_F(UserAuthClientTest, UserAuthClientSetWidgetCallback002, TestSize.Level0)
{
    static const int32_t apiVersion = 0;
    std::shared_ptr<IUserAuthWidgetCallback> testCallback = nullptr;
    int32_t widgetCallback = UserAuthClientImpl::Instance().SetWidgetCallback(apiVersion, testCallback);
    EXPECT_EQ(widgetCallback, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientSetWidgetCallback003, TestSize.Level0)
{
    int32_t testVersion = 0;
    auto testCallback = Common::MakeShared<MockIUserAuthWidgetCallback>();
    EXPECT_NE(testCallback, nullptr);

    uint64_t testContextVersion = 1;
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterWidgetCallback(_, _)).WillRepeatedly(Return(true));
    ON_CALL(*service, RegisterWidgetCallback)
        .WillByDefault(
            [&testVersion, &testContextVersion](int32_t version, sptr<WidgetCallbackInterface> &callback) {
                EXPECT_EQ(version, testVersion);
                return testContextVersion;
            }
        );

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    uint64_t widgetAuth = UserAuthClientImpl::Instance().SetWidgetCallback(testVersion, testCallback);
    EXPECT_EQ(widgetAuth, testContextVersion);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientNotice001, TestSize.Level0)
{
    int32_t notice = UserAuthClientImpl::Instance().Notice(NoticeType::WIDGET_NOTICE, "notice");
    EXPECT_NE(notice, SUCCESS);
}

HWTEST_F(UserAuthClientTest, UserAuthClientNotice002, TestSize.Level0)
{
    int32_t notice = UserAuthClientImpl::Instance().Notice((enum NoticeType)0, "notice");
    EXPECT_EQ(notice, GENERAL_ERROR);
}

void UserAuthClientTest::CallRemoteObject(const std::shared_ptr<MockUserAuthService> service,
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
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });
}

HWTEST_F(UserAuthClientTest, UserAuthClientRegistUserAuthSuccessEventListener001, TestSize.Level0)
{
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);

    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListenerService();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegistUserAuthSuccessEventListener(_, _)).Times(1);
    ON_CALL(*service, RegistUserAuthSuccessEventListener)
        .WillByDefault(
            [](const std::vector<AuthType> &authType, const sptr<AuthEventListenerInterface> &callback) {
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    int32_t ret = UserAuthClientImpl::Instance().RegistUserAuthSuccessEventListener(authTypeList, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientRegistUserAuthSuccessEventListener002, TestSize.Level0)
{
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);

    int32_t ret = UserAuthClientImpl::Instance().RegistUserAuthSuccessEventListener(authTypeList, nullptr);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientRegistUserAuthSuccessEventListener003, TestSize.Level0)
{
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);

    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListenerService();
    EXPECT_NE(testCallback, nullptr);

    int32_t ret = UserAuthClientImpl::Instance().RegistUserAuthSuccessEventListener(authTypeList, testCallback);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientUnRegistUserAuthSuccessEventListener001, TestSize.Level0)
{
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListenerService();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UnRegistUserAuthSuccessEventListener(_)).Times(1);
    ON_CALL(*service, UnRegistUserAuthSuccessEventListener)
        .WillByDefault(
            [](const sptr<AuthEventListenerInterface> &callback) {
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    int32_t ret = UserAuthClientImpl::Instance().UnRegistUserAuthSuccessEventListener(testCallback);
    EXPECT_EQ(ret, SUCCESS);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientUnRegistUserAuthSuccessEventListener002, TestSize.Level0)
{
    int32_t ret = UserAuthClientImpl::Instance().UnRegistUserAuthSuccessEventListener(nullptr);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientUnRegistUserAuthSuccessEventListener003, TestSize.Level0)
{
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListenerService();
    EXPECT_NE(testCallback, nullptr);

    int32_t ret = UserAuthClientImpl::Instance().UnRegistUserAuthSuccessEventListener(testCallback);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientSetGlobalConfigParam001, TestSize.Level0)
{
    GlobalConfigParam param = {};
    int32_t ret = UserAuthClient::GetInstance().SetGlobalConfigParam(param);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientSetGlobalConfigParam002, TestSize.Level0)
{
    GlobalConfigParam param = {};
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetGlobalConfigParam(_)).Times(1);
    ON_CALL(*service, SetGlobalConfigParam)
        .WillByDefault(
            [](const GlobalConfigParam &param) {
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IRemoteObject::DeathRecipient> dr(nullptr);
    CallRemoteObject(service, obj, dr);
    
    int32_t ret = UserAuthClient::GetInstance().SetGlobalConfigParam(param);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(dr, nullptr);
    dr->OnRemoteDied(obj);
    IpcClientUtils::ResetObj();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS