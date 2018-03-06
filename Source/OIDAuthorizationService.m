/*! @file OIDAuthorizationService.m
    @brief AppAuth iOS SDK
    @copyright
        Copyright 2015 Google Inc. All Rights Reserved.
    @copydetails
        Licensed under the Apache License, Version 2.0 (the "License");
        you may not use this file except in compliance with the License.
        You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

        Unless required by applicable law or agreed to in writing, software
        distributed under the License is distributed on an "AS IS" BASIS,
        WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
        See the License for the specific language governing permissions and
        limitations under the License.
 */

#import "OIDAuthorizationService.h"

#import "OIDAuthorizationRequest.h"
#import "OIDAuthorizationResponse.h"

#import "OIDEndSessionRequest.h"
#import "OIDEndSessionResponse.h"

#import "OIDDefines.h"
#import "OIDErrorUtilities.h"
#import "OIDAuthorizationFlowSession.h"
#import "OIDExternalUserAgentFlowSession.h"
#import "OIDExternalUserAgentUICoordinator.h"
#import "OIDRegistrationRequest.h"
#import "OIDRegistrationResponse.h"
#import "OIDServiceConfiguration.h"
#import "OIDServiceDiscovery.h"
#import "OIDTokenRequest.h"
#import "OIDTokenResponse.h"
#import "OIDURLQueryComponent.h"
#import "OIDURLSessionProvider.h"

/*! @brief Path appended to an OpenID Connect issuer for discovery
    @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
 */
static NSString *const kOpenIDConfigurationWellKnownPath = @".well-known/openid-configuration";


NS_ASSUME_NONNULL_BEGIN

@interface OIDAuthorizationFlowSessionImplementation : NSObject<OIDExternalUserAgentFlowSession, OIDAuthorizationFlowSession> {
  // private variables
  OIDAuthorizationRequest *_request;
  OIDEndSessionRequest *_endSessionRequest;
  id<OIDExternalUserAgentUICoordinator> _UICoordinator;
  OIDAuthorizationCallback _pendingauthorizationFlowCallback;
  OIDEndSessionCallback _pendingEndSessionFlowCallback;
}

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithRequest:(OIDAuthorizationRequest *)request
    NS_DESIGNATED_INITIALIZER;

- (instancetype)initWithEndSessionRequest:(OIDEndSessionRequest *)request
    NS_DESIGNATED_INITIALIZER;

@end

@implementation OIDAuthorizationFlowSessionImplementation

- (instancetype)initWithRequest:(OIDAuthorizationRequest *)request {
  self = [super init];
  if (self) {
    _request = [request copy];
  }
  return self;
}

- (instancetype)initWithEndSessionRequest:(OIDEndSessionRequest *)request {
    self = [super init];
    if (self) {
        _endSessionRequest = [request copy];
    }
    return self;
}

- (void)presentAuthorizationWithCoordinator:(id<OIDExternalUserAgentUICoordinator>)UICoordinator
                                   callback:(OIDAuthorizationCallback)authorizationFlowCallback {
  _UICoordinator = UICoordinator;
  _pendingauthorizationFlowCallback = authorizationFlowCallback;
  BOOL authorizationFlowStarted =
      [_UICoordinator presentExternalUserAgentRequest:_request session:self];
  if (!authorizationFlowStarted) {
    NSError *safariError = [OIDErrorUtilities errorWithCode:OIDErrorCodeSafariOpenError
                                            underlyingError:nil
                                                description:@"Unable to open Safari."];
    [self didFinishWithResponse:nil error:safariError];
  }
}

- (void)presentEndSessionWithCoordinator:(id<OIDExternalUserAgentUICoordinator>)UICoordinator
                                   callback:(OIDEndSessionCallback)endSessionFlowCallback {
    _UICoordinator = UICoordinator;
    _pendingEndSessionFlowCallback = endSessionFlowCallback;
    BOOL endSessionFlowStarted =
    [_UICoordinator presentExternalUserAgentRequest:_endSessionRequest session:self];
    if (!endSessionFlowStarted) {
        NSError *safariError = [OIDErrorUtilities errorWithCode:OIDErrorCodeSafariOpenError
                                                underlyingError:nil
                                                    description:@"Unable to open Safari."];
        [self didFinishWithResponse:nil error:safariError];
    }
}

- (void)cancel {
  [_UICoordinator dismissExternalUserAgentUIAnimated:YES completion:^{
      NSError *error = [OIDErrorUtilities
                        errorWithCode:OIDErrorCodeUserCanceledAuthorizationFlow
                        underlyingError:nil
                        description:nil];
      [self didFinishWithResponse:nil error:error];
  }];
}

- (BOOL)shouldHandleURL:(NSURL *)URL {
  NSURL *standardizedURL = [URL standardizedURL];
  NSURL *standardizedRedirectURL = [_request.redirectURL standardizedURL];
  //NSURL *standardizedRedirectURL = nil;

  if (_pendingauthorizationFlowCallback) {
    standardizedRedirectURL = [_request.redirectURL standardizedURL];
  } else if(_pendingEndSessionFlowCallback){
    standardizedRedirectURL = [_endSessionRequest.postLogoutRedirectURL standardizedURL];
  }
  
  NSLog(@"stdURL scheme:%@, stdRedirectURL scheme: %@ ", standardizedURL.scheme, standardizedRedirectURL.scheme);
  NSLog(@"stdURL user:%@, stdRedirectURL user: %@ ", standardizedURL.user, standardizedRedirectURL.user);
  NSLog(@"stdURL password:%@, stdRedirectURL password: %@ ", standardizedURL.password, standardizedRedirectURL.password);
  NSLog(@"stdURL host:%@, stdRedirectURL host: %@ ", standardizedURL.host, standardizedRedirectURL.host);
  NSLog(@"stdURL port:%@, stdRedirectURL port: %@ ", standardizedURL.port, standardizedRedirectURL.port);
  NSLog(@"stdURL path:%@, stdRedirectURL path: %@ ", standardizedURL.path, standardizedRedirectURL.path);


  return OIDIsEqualIncludingNil(standardizedURL.scheme, standardizedRedirectURL.scheme) &&
      OIDIsEqualIncludingNil(standardizedURL.user, standardizedRedirectURL.user) &&
      OIDIsEqualIncludingNil(standardizedURL.password, standardizedRedirectURL.password) &&
      OIDIsEqualIncludingNil(standardizedURL.host, standardizedRedirectURL.host) &&
      OIDIsEqualIncludingNil(standardizedURL.port, standardizedRedirectURL.port) &&
      OIDIsEqualIncludingNil(standardizedURL.path, standardizedRedirectURL.path);
}

- (BOOL)resumeExternalUserAgentFlowWithURL:(NSURL *)URL {
  // rejects URLs that don't match redirect (these may be completely unrelated to the authorization)
  if (![self shouldHandleURL:URL]) {
    return NO;
  }
  // checks for an invalid state
  if (!_pendingauthorizationFlowCallback && !_pendingEndSessionFlowCallback) {
    [NSException raise:OIDOAuthExceptionInvalidAuthorizationFlow
                format:@"%@", OIDOAuthExceptionInvalidAuthorizationFlow, nil];
  }


  if (_pendingauthorizationFlowCallback) {
    OIDURLQueryComponent *query = [[OIDURLQueryComponent alloc] initWithURL:URL];

    NSError *error;
    OIDAuthorizationResponse *response = nil;

    // checks for an OAuth error response as per RFC6749 Section 4.1.2.1
    if (query.dictionaryValue[OIDOAuthErrorFieldError]) {
      error = [OIDErrorUtilities OAuthErrorWithDomain:OIDOAuthAuthorizationErrorDomain
                                        OAuthResponse:query.dictionaryValue
                                      underlyingError:nil];
    }

    // no error, should be a valid OAuth 2.0 response
    if (!error) {
      response = [[OIDAuthorizationResponse alloc] initWithRequest:_request
                                                        parameters:query.dictionaryValue];
      
      // verifies that the state in the response matches the state in the request, or both are nil
      if (!OIDIsEqualIncludingNil(_request.state, response.state)) {
        NSMutableDictionary *userInfo = [query.dictionaryValue mutableCopy];
        userInfo[NSLocalizedDescriptionKey] =
          [NSString stringWithFormat:@"State mismatch, expecting %@ but got %@ in authorization "
                                     "response %@",
                                     _request.state,
                                     response.state,
                                     response];
        response = nil;
        error = [NSError errorWithDomain:OIDOAuthAuthorizationErrorDomain
                                    code:OIDErrorCodeOAuthAuthorizationClientError
                                userInfo:userInfo];
        }
    }

    [_UICoordinator dismissExternalUserAgentUIAnimated:YES completion:^{
        [self didFinishWithResponse:response error:error];
    }];
  }
  
  if (_pendingEndSessionFlowCallback) {
    OIDURLQueryComponent *query = [[OIDURLQueryComponent alloc] initWithURL:URL];
    
    NSError *error;
    OIDEndSessionResponse *response = nil;
    
    // checks for an OAuth error response as per RFC6749 Section 4.1.2.1
    if (query.dictionaryValue[OIDOAuthErrorFieldError]) {
      error = [OIDErrorUtilities OAuthErrorWithDomain:OIDOAuthAuthorizationErrorDomain
                                        OAuthResponse:query.dictionaryValue
                                      underlyingError:nil];
    }
    
    // no error, should be a valid OAuth 2.0 response
    if (!error) {
      response = [[OIDEndSessionResponse alloc] initWithRequest:_endSessionRequest
                                                        parameters:query.dictionaryValue];
      
      // verifies that the state in the response matches the state in the request, or both are nil
      if (!OIDIsEqualIncludingNil(_endSessionRequest.state, response.state)) {
        NSMutableDictionary *userInfo = [query.dictionaryValue mutableCopy];
        userInfo[NSLocalizedDescriptionKey] =
        [NSString stringWithFormat:@"State mismatch, expecting %@ but got %@ in end session "
         "response %@",
         _endSessionRequest.state,
         response.state,
         response];
        response = nil;
        error = [NSError errorWithDomain:OIDOAuthAuthorizationErrorDomain
                                    code:OIDErrorCodeOAuthAuthorizationClientError
                                userInfo:userInfo];
      }
    }
    
    [_UICoordinator dismissExternalUserAgentUIAnimated:YES completion:^{
      [self didFinishEndSessionWithResponse:response error:error];
    }];
  }

  return YES;
}

- (void)failExternalUserAgentFlowWithError:(NSError *)error {
  if (_pendingauthorizationFlowCallback) {
    [self didFinishWithResponse:nil error:error];
  } else {
    [self didFinishEndSessionWithResponse:nil error:error];
  }
}

/*! @brief Invokes the pending callback and performs cleanup.
    @param response The authorization response, if any to return to the callback.
    @param error The error, if any, to return to the callback.
 */
- (void)didFinishWithResponse:(nullable OIDAuthorizationResponse *)response
                        error:(nullable NSError *)error {
  OIDAuthorizationCallback callback = _pendingauthorizationFlowCallback;
  _pendingauthorizationFlowCallback = nil;
  _UICoordinator = nil;
  if (callback) {
    callback(response, error);
  }
}

- (void)didFinishEndSessionWithResponse:(nullable OIDEndSessionResponse *)response
                                  error:(nullable NSError *)error {
  OIDEndSessionCallback callback = _pendingEndSessionFlowCallback;
  _pendingEndSessionFlowCallback = nil;
  _UICoordinator = nil;
  if (callback) {
    dispatch_async(dispatch_get_main_queue(), ^{
      callback(response, error);
    });
  }
}

- (void)failAuthorizationFlowWithError:(NSError *)error {
  [self failExternalUserAgentFlowWithError:error];
}

- (BOOL)resumeAuthorizationFlowWithURL:(NSURL *)URL {
  return [self resumeExternalUserAgentFlowWithURL:URL];
}

@end

@implementation OIDAuthorizationService

@synthesize configuration = _configuration;

+ (void)discoverServiceConfigurationForIssuer:(NSURL *)issuerURL
                                   completion:(OIDDiscoveryCallback)completion {
  NSURL *fullDiscoveryURL =
      [issuerURL URLByAppendingPathComponent:kOpenIDConfigurationWellKnownPath];

  return [[self class] discoverServiceConfigurationForDiscoveryURL:fullDiscoveryURL
                                                        completion:completion];
}

+ (void)discoverServiceConfigurationForDiscoveryURL:(NSURL *)discoveryURL
    completion:(OIDDiscoveryCallback)completion {

  NSURLSession *session = [OIDURLSessionProvider session];
  NSURLSessionDataTask *task =
      [session dataTaskWithURL:discoveryURL
             completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
    // If we got any sort of error, just report it.
    if (error || !data) {
      error = [OIDErrorUtilities errorWithCode:OIDErrorCodeNetworkError
                               underlyingError:error
                                   description:error.localizedDescription];
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(nil, error);
      });
      return;
    }

    NSHTTPURLResponse *urlResponse = (NSHTTPURLResponse *)response;

    // Check for non-200 status codes.
    // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
    if (urlResponse.statusCode != 200) {
      NSError *URLResponseError = [OIDErrorUtilities HTTPErrorWithHTTPResponse:urlResponse
                                                                          data:data];
      error = [OIDErrorUtilities errorWithCode:OIDErrorCodeNetworkError
                               underlyingError:URLResponseError
                                   description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(nil, error);
      });
      return;
    }

    // Construct an OIDServiceDiscovery with the received JSON.
    OIDServiceDiscovery *discovery =
        [[OIDServiceDiscovery alloc] initWithJSONData:data error:&error];
    if (error || !discovery) {
      error = [OIDErrorUtilities errorWithCode:OIDErrorCodeNetworkError
                               underlyingError:error
                                   description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(nil, error);
      });
      return;
    }

    // Create our service configuration with the discovery document and return it.
    OIDServiceConfiguration *configuration =
        [[OIDServiceConfiguration alloc] initWithDiscoveryDocument:discovery];
    dispatch_async(dispatch_get_main_queue(), ^{
      completion(configuration, nil);
    });
  }];
  [task resume];
}

#pragma mark - Authorization Endpoint

+ (id<OIDExternalUserAgentFlowSession, OIDAuthorizationFlowSession>)
    presentAuthorizationRequest:(OIDAuthorizationRequest *)request
                  UICoordinator:(id<OIDExternalUserAgentUICoordinator>)UICoordinator
                       callback:(OIDAuthorizationCallback)callback {
  OIDAuthorizationFlowSessionImplementation *flowSession =
      [[OIDAuthorizationFlowSessionImplementation alloc] initWithRequest:request];
  [flowSession presentAuthorizationWithCoordinator:UICoordinator callback:callback];
  return flowSession;
}

+ (id<OIDExternalUserAgentFlowSession, OIDAuthorizationFlowSession>)
presentEndSessionRequest:(OIDEndSessionRequest *)request
UICoordinator:(id<OIDExternalUserAgentUICoordinator>)UICoordinator
callback:(OIDEndSessionCallback)callback {
    
    OIDAuthorizationFlowSessionImplementation *flowSession =
    [[OIDAuthorizationFlowSessionImplementation alloc] initWithEndSessionRequest:request];
    [flowSession presentEndSessionWithCoordinator:UICoordinator callback:callback];
    return flowSession;
//    _UICoordinator = UICoordinator;
//    _pendingauthorizationFlowCallback = authorizationFlowCallback;
//    BOOL authorizationFlowStarted =
//    [_UICoordinator presentExternalUserAgentRequest:request session:self];
//    if (!authorizationFlowStarted) {
//        NSError *safariError = [OIDErrorUtilities errorWithCode:OIDErrorCodeSafariOpenError
//                                                underlyingError:nil
//                                                    description:@"Unable to open Safari."];
//        [self didFinishWithResponse:nil error:safariError];
//    }
}

#pragma mark - Token Endpoint

+ (void)performTokenRequest:(OIDTokenRequest *)request callback:(OIDTokenCallback)callback {
  NSURLRequest *URLRequest = [request URLRequest];
  NSURLSession *session = [OIDURLSessionProvider session];
  [[session dataTaskWithRequest:URLRequest
              completionHandler:^(NSData *_Nullable data,
                                  NSURLResponse *_Nullable response,
                                  NSError *_Nullable error) {
    if (error) {
      // A network error or server error occurred.
      NSError *returnedError =
          [OIDErrorUtilities errorWithCode:OIDErrorCodeNetworkError
                           underlyingError:error
                               description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        callback(nil, returnedError);
      });
      return;
    }

    NSHTTPURLResponse *HTTPURLResponse = (NSHTTPURLResponse *)response;
    NSInteger statusCode = HTTPURLResponse.statusCode;
    if (statusCode != 200) {
      // A server error occurred.
      NSError *serverError =
          [OIDErrorUtilities HTTPErrorWithHTTPResponse:HTTPURLResponse data:data];

      // HTTP 400 may indicate an RFC6749 Section 5.2 error response.
      // HTTP 429 may occur during polling for device-flow requests for the slow_down error
      // https://tools.ietf.org/html/draft-ietf-oauth-device-flow-03#section-3.5
      if (statusCode == 400 || statusCode == 429) {
        NSError *jsonDeserializationError;
        NSDictionary<NSString *, NSObject<NSCopying> *> *json =
            [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonDeserializationError];

        // if the HTTP 400 response parses as JSON and has an 'error' key, it's an OAuth error
        // these errors are special as they indicate a problem with the authorization grant
        if (json[OIDOAuthErrorFieldError]) {
          NSError *oauthError =
            [OIDErrorUtilities OAuthErrorWithDomain:OIDOAuthTokenErrorDomain
                                      OAuthResponse:json
                                    underlyingError:serverError];
          dispatch_async(dispatch_get_main_queue(), ^{
            callback(nil, oauthError);
          });
          return;
        }
      }

      // not an OAuth error, just a generic server error
      NSError *returnedError =
          [OIDErrorUtilities errorWithCode:OIDErrorCodeServerError
                           underlyingError:serverError
                               description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        callback(nil, returnedError);
      });
      return;
    }

    NSError *jsonDeserializationError;
    NSDictionary<NSString *, NSObject<NSCopying> *> *json =
        [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonDeserializationError];
    if (jsonDeserializationError) {
      // A problem occurred deserializing the response/JSON.
      NSError *returnedError =
          [OIDErrorUtilities errorWithCode:OIDErrorCodeJSONDeserializationError
                           underlyingError:jsonDeserializationError
                               description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        callback(nil, returnedError);
      });
      return;
    }

    OIDTokenResponse *tokenResponse =
        [[OIDTokenResponse alloc] initWithRequest:request parameters:json];
    if (!tokenResponse) {
      // A problem occurred constructing the token response from the JSON.
      NSError *returnedError =
          [OIDErrorUtilities errorWithCode:OIDErrorCodeTokenResponseConstructionError
                           underlyingError:jsonDeserializationError
                               description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        callback(nil, returnedError);
      });
      return;
    }

    // Success
    dispatch_async(dispatch_get_main_queue(), ^{
      callback(tokenResponse, nil);
    });
  }] resume];
}


#pragma mark - Registration Endpoint

+ (void)performRegistrationRequest:(OIDRegistrationRequest *)request
                          completion:(OIDRegistrationCompletion)completion {
  NSURLRequest *URLRequest = [request URLRequest];
  if (!URLRequest) {
    // A problem occurred deserializing the response/JSON.
    NSError *returnedError = [OIDErrorUtilities errorWithCode:OIDErrorCodeJSONSerializationError
                                              underlyingError:nil
                                                  description:@"The registration request could not "
                                                               "be serialized as JSON."];
    dispatch_async(dispatch_get_main_queue(), ^{
      completion(nil, returnedError);
    });
    return;
  }

  NSURLSession *session = [OIDURLSessionProvider session];
  [[session dataTaskWithRequest:URLRequest
              completionHandler:^(NSData *_Nullable data,
                                  NSURLResponse *_Nullable response,
                                  NSError *_Nullable error) {
    if (error) {
      // A network error or server error occurred.
      NSError *returnedError = [OIDErrorUtilities errorWithCode:OIDErrorCodeNetworkError
                                                underlyingError:error
                                                    description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(nil, returnedError);
      });
      return;
    }

    NSHTTPURLResponse *HTTPURLResponse = (NSHTTPURLResponse *) response;

    if (HTTPURLResponse.statusCode != 201 && HTTPURLResponse.statusCode != 200) {
      // A server error occurred.
      NSError *serverError = [OIDErrorUtilities HTTPErrorWithHTTPResponse:HTTPURLResponse
                                                                     data:data];

      // HTTP 400 may indicate an OpenID Connect Dynamic Client Registration 1.0 Section 3.3 error
      // response, checks for that
      if (HTTPURLResponse.statusCode == 400) {
        NSError *jsonDeserializationError;
        NSDictionary<NSString *, NSObject <NSCopying> *> *json =
            [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonDeserializationError];

        // if the HTTP 400 response parses as JSON and has an 'error' key, it's an OAuth error
        // these errors are special as they indicate a problem with the authorization grant
        if (json[OIDOAuthErrorFieldError]) {
          NSError *oauthError =
              [OIDErrorUtilities OAuthErrorWithDomain:OIDOAuthRegistrationErrorDomain
                                        OAuthResponse:json
                                      underlyingError:serverError];
          dispatch_async(dispatch_get_main_queue(), ^{
            completion(nil, oauthError);
          });
          return;
        }
      }

      // not an OAuth error, just a generic server error
      NSError *returnedError = [OIDErrorUtilities errorWithCode:OIDErrorCodeServerError
                                                underlyingError:serverError
                                                    description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(nil, returnedError);
      });
      return;
    }

    NSError *jsonDeserializationError;
    NSDictionary<NSString *, NSObject <NSCopying> *> *json =
        [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonDeserializationError];
    if (jsonDeserializationError) {
      // A problem occurred deserializing the response/JSON.
      NSError *returnedError = [OIDErrorUtilities errorWithCode:OIDErrorCodeJSONDeserializationError
                                                underlyingError:jsonDeserializationError
                                                    description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(nil, returnedError);
      });
      return;
    }

    OIDRegistrationResponse *registrationResponse =
        [[OIDRegistrationResponse alloc] initWithRequest:request
                                              parameters:json];
    if (!registrationResponse) {
      // A problem occurred constructing the registration response from the JSON.
      NSError *returnedError =
          [OIDErrorUtilities errorWithCode:OIDErrorCodeRegistrationResponseConstructionError
                           underlyingError:jsonDeserializationError
                               description:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        completion(nil, returnedError);
      });
      return;
    }

    // Success
    dispatch_async(dispatch_get_main_queue(), ^{
      completion(registrationResponse, nil);
    });
  }] resume];
}

@end

NS_ASSUME_NONNULL_END
