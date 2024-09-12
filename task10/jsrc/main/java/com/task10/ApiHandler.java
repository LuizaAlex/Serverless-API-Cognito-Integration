package com.task10;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.syndicate.deployment.annotations.environment.EnvironmentVariable;
import com.syndicate.deployment.annotations.environment.EnvironmentVariables;
import com.syndicate.deployment.annotations.lambda.LambdaHandler;
import com.syndicate.deployment.annotations.resources.DependsOn;
import com.syndicate.deployment.model.ResourceType;

import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

import static com.task10.LambdaHelper.createUserPoolApiClientIfNotExist;
import static com.task10.LambdaHelper.getCognitoIdByName;
import static com.task10.LambdaVariables.COGNITO_CLIENT_API;
import static com.task10.LambdaVariables.COGNITO;

import static com.syndicate.deployment.model.environment.ValueTransformer.USER_POOL_NAME_TO_CLIENT_ID;
import static com.syndicate.deployment.model.environment.ValueTransformer.USER_POOL_NAME_TO_USER_POOL_ID;

@LambdaHandler(lambdaName = "api_handler",
        roleName = "api_handler-role",
		isPublishVersion = false

	
)

@DependsOn(resourceType = ResourceType.COGNITO_USER_POOL, name = "${booking_userpool}")
@EnvironmentVariables(value = {
        @EnvironmentVariable(key = "REGION", value = "${region}"),
        @EnvironmentVariable(key = "COGNITO_ID", value = "${pool_name}", valueTransformer = USER_POOL_NAME_TO_USER_POOL_ID),
        @EnvironmentVariable(key = "CLIENT_ID", value = "${pool_name}", valueTransformer = USER_POOL_NAME_TO_CLIENT_ID)
})
public class ApiHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent event, Context context) {
        String urlPath = event.getPath();
        String httpMethod = event.getHttpMethod();
        context.getLogger().log("Received request: urlPath: " + urlPath + ", HTTP method: " + httpMethod);

        CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create();
        String cognitoId = getCognitoIdByName(COGNITO, cognitoClient, context);
        createUserPoolApiClientIfNotExist(cognitoId, COGNITO_CLIENT_API, cognitoClient, context);

        if ("/signup".equals(urlPath)) {
            if ("POST".equals(httpMethod)) return new SignUpHandler().handleSignUp(event, context, cognitoClient);
        } else if ("/signin".equals(urlPath)) {
            if ("POST".equals(httpMethod)) return new SignInHandler().handleSignIn(event, context, cognitoClient);
        } else if ("/tables".equals(urlPath)) {
            if ("POST".equals(httpMethod)) {
                return new TablesHandler().handleCreateTable(event, context, cognitoClient);
            } else if ("GET".equals(httpMethod)) {
                return new TablesHandler().handleGetTables(event, context, cognitoClient);
            }
        } else if (urlPath.matches("/tables/\\d+")) {
            if ("GET".equals(httpMethod)) {
                return new TablesHandler().handleGetSpecificTable(event, context, cognitoClient);
            }
        } else if ("/reservations".equals(urlPath)) {
            if ("POST".equals(httpMethod)) {
                return new ReservationsHandler().handleCreateReservation(event, context, cognitoClient);
            } else if ("GET".equals(httpMethod)) {
                return new ReservationsHandler().handleGetReservations(event, context, cognitoClient);
            }
        }

        context.getLogger().log("Handler for urlPath: " + urlPath + ", and HTTP method: " + httpMethod
                + "was not found");
        throw new RuntimeException("Handler for urlPath: " + urlPath + ", and HTTP method: " + httpMethod
                + "was not found");
    }

}