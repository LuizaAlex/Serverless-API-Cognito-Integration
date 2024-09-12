package com.task10;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.HashMap;
import java.util.Map;

import static com.task10.LambdaHelper.*;
import static com.task10.LambdaVariables.*;

public class SignInHandler {
    public APIGatewayProxyResponseEvent handleSignIn(APIGatewayProxyRequestEvent event, Context context,
                                                     CognitoIdentityProviderClient cognitoClient) {
        Map<String, Object> body = eventToBody(event, context);
        String email = (String) body.get(EMAIL_NAME);
        String password = (String) body.get(PASSWORD_NAME);

        String cognitoId = getCognitoIdByName(COGNITO, cognitoClient, context);
        UserPoolClientDescription appClient = getUserPoolApiDesc(cognitoId, cognitoClient, context);
        Map<String, String> authParameters = new HashMap<>();
        authParameters.put("USERNAME", email);
        authParameters.put("PASSWORD", password);
        AdminInitiateAuthResponse authResponse;
        try {
            authResponse = cognitoClient.adminInitiateAuth(AdminInitiateAuthRequest.builder()
                    .userPoolId(cognitoId)
                    .clientId(appClient.clientId())
                    .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .authParameters(authParameters)
                    .build());
        } catch (UserNotFoundException e) {
            context.getLogger().log("Failed to sign in" + e.getMessage());
            return new APIGatewayProxyResponseEvent()
                    .withBody(e.getMessage())
                    .withStatusCode(400);
        }

        Map<String, String> responseBody = new HashMap<>();
        responseBody.put(ACCESS_TOKEN, authResponse.authenticationResult().accessToken());

        return createSuccessResponse(responseBody, context);
    }
}