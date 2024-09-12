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
            context.getLogger().log("Admin user was created successfully: " + creationResult);

            cognitoClient.adminSetUserPassword(AdminSetUserPasswordRequest.builder()
                    .userPoolId(cognitoId)
                    .username(email)
                    .password(password)
                    .permanent(true)
                    .build());
            context.getLogger().log("The new password was  saved successfully");
        } catch (CognitoIdentityProviderException e) {
            context.getLogger().log(e.getMessage());
            return new APIGatewayProxyResponseEvent()
                    .withBody(e.getMessage())
                    .withStatusCode(400);
        }
        return createSuccessResponse(null, context);
    }
}