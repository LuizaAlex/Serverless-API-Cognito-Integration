package com.task10;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.Map;

import static com.task10.LambdaHelper.*;
import static com.task10.LambdaVariables.*;

public class SignUpHandler {
        public APIGatewayProxyResponseEvent handleSignUp(APIGatewayProxyRequestEvent event, Context context,
                                                         CognitoIdentityProviderClient cognitoClient) {
            Map<String, Object> body = eventToBody(event, context);
            String firstName = (String) body.get(FIRST_NAME);
            String lastName = (String) body.get(LAST_NAME);
            String email = (String) body.get(EMAIL_NAME);
            String password = (String) body.get(PASSWORD_NAME);
    
            // Basic input validation
            if (firstName == null || lastName == null || email == null || password == null) {
                context.getLogger().log("Missing required parameters");
                return new APIGatewayProxyResponseEvent()
                        .withBody("Missing required parameters")
                        .withStatusCode(400);
            }
    
            String cognitoId = getCognitoIdByName(COGNITO, cognitoClient, context);
            try {
                AdminCreateUserResponse creationResult = cognitoClient.adminCreateUser(AdminCreateUserRequest.builder()
                        .userPoolId(cognitoId)
                        .username(email)
                        .temporaryPassword(password)
                        .messageAction(MessageActionType.SUPPRESS)
                        .userAttributes(
                                AttributeType.builder().name("email").value(email).build(),
                                AttributeType.builder().name("given_name").value(firstName).build(),
                                AttributeType.builder().name("family_name").value(lastName).build(),
                                AttributeType.builder().name("email_verified").value("true").build()
                        )
                        .build());
                context.getLogger().log("Admin user created successfully: " + creationResult);
    
                cognitoClient.adminSetUserPassword(AdminSetUserPasswordRequest.builder()
                        .userPoolId(cognitoId)
                        .username(email)
                        .password(password)
                        .permanent(true)
                        .build());
                context.getLogger().log("User password set successfully");
    
                return createSuccessResponse("User created and password set successfully", context);
            } catch (CognitoIdentityProviderException e) {
                context.getLogger().log("Cognito exception: " + e.getMessage());
                return new APIGatewayProxyResponseEvent()
                        .withBody("Cognito exception: " + e.getMessage())
                        .withStatusCode(400);
            } catch (Exception e) {
                context.getLogger().log("Unexpected error: " + e.getMessage());
                return new APIGatewayProxyResponseEvent()
                        .withBody("Unexpected error: " + e.getMessage())
                        .withStatusCode(500);
            }
        }
    }