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

        // Basic input validation
        if (email == null || password == null) {
            context.getLogger().log("Missing required parameters");
            return new APIGatewayProxyResponseEvent()
                    .withBody("Missing required parameters")
                    .withStatusCode(400);
        }

        String cognitoId = getCognitoIdByName(COGNITO, cognitoClient, context);
        UserPoolClientDescription appClient = getUserPoolApiDesc(cognitoId, cognitoClient, context);
        Map<String, String> authParameters = new HashMap<>();
        authParameters.put("USERNAME", email);
        authParameters.put("PASSWORD", password);

        try {
            AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(AdminInitiateAuthRequest.builder()
                    .userPoolId(cognitoId)
                    .clientId(appClient.clientId())
                    .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .authParameters(authParameters)
                    .build());

            Map<String, String> responseBody = new HashMap<>();
            responseBody.put(ACCESS_TOKEN, authResponse.authenticationResult().accessToken());

            return createSuccessResponse(responseBody, context);
        } catch (UserNotFoundException e) {
            context.getLogger().log("User not found: " + e.getMessage());
            return new APIGatewayProxyResponseEvent()
                    .withBody("User not found")
                    .withStatusCode(404);
        } catch (NotAuthorizedException e) {
            context.getLogger().log("Not authorized: " + e.getMessage());
            return new APIGatewayProxyResponseEvent()
                    .withBody("Invalid credentials")
                    .withStatusCode(401);
        } catch (CognitoIdentityProviderException e) {
            context.getLogger().log("Cognito exception: " + e.getMessage());
            return new APIGatewayProxyResponseEvent()
                    .withBody("Error with Cognito service")
                    .withStatusCode(500);
        } catch (Exception e) {
            context.getLogger().log("Unexpected error: " + e.getMessage());
            return new APIGatewayProxyResponseEvent()
                    .withBody("Unexpected error: " + e.getMessage())
                    .withStatusCode(500);
        }
    }
}