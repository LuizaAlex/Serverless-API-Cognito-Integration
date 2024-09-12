package com.task10;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;

import com.syndicate.deployment.annotations.lambda.LambdaHandler;

import com.syndicate.deployment.model.RetentionSetting;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GetUserRequest;


import static com.task10.ApiHandlerConstants.*;
import static com.task10.MyApiHandlerUtils.*;


import java.util.*;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.*;

import software.amazon.awssdk.services.cognitoidentityprovider.model.*;


@LambdaHandler(
    lambdaName = "api_handler",
	roleName = "api_handler-role",
	isPublishVersion = false,
	logsExpiration = RetentionSetting.SYNDICATE_ALIASES_SPECIFIED
)

public class ApiHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

	public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent event, Context context) {
		String path = event.getPath();
		String httpMethod = event.getHttpMethod();
		context.getLogger().log("Handle request with path: " + path + ", and http method: " + httpMethod + ";");

		CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create();
		String cognitoId = getCognitoIdByName(COGNITO_NAME, cognitoClient, context);
		createUserPoolApiClientIfNotExists(cognitoId, COGNITO_CLIENT_API_NAME, cognitoClient, context);

		if("/signup".equals(path)) {
			if("POST".equals(httpMethod)) return handleSignUp(event, context, cognitoClient);
		}
		else if("/signin".equals(path)) {
			if("POST".equals(httpMethod)) return handleSignIn(event, context, cognitoClient);
		}
		else if("/tables".equals(path)) {
			if("POST".equals(httpMethod)) {
				return handleCreateTable(event, context, cognitoClient);
			}
			else if("GET".equals(httpMethod)) {
				return handleGetTables(event, context, cognitoClient);
			}
		}
		else if(path.matches("/tables/\\d+")) {
			if("GET".equals(httpMethod)) {
				return handleGetSpecificTable(event, context, cognitoClient);
			}
		}
		else if("/reservations".equals(path)) {
			if("POST".equals(httpMethod)) {
				return handleCreateReservation(event, context, cognitoClient);
			}
			else if("GET".equals(httpMethod)) {
				return handleGetReservations(event, context, cognitoClient);
			}
		}

		context.getLogger().log("No handler found for path: " + path + ", and http method: " + httpMethod + ";");
		throw new RuntimeException("No handler found for path: " + path + ", and http method: " + httpMethod + ";");
	}

	private APIGatewayProxyResponseEvent handleSignUp(APIGatewayProxyRequestEvent event, Context context, CognitoIdentityProviderClient cognitoClient) {
		Map<String, Object> body = eventToBody(event, context);
		String firstName = (String) body.get(FIRST_NAME_ATTR);
		String lastName = (String) body.get(LAST_NAME_ATTR);
		String email = (String) body.get(EMAIL_NAME_ATTR);
		String password = (String) body.get(PASSWORD_NAME_ATTR);

		String cognitoId = getCognitoIdByName(COGNITO_NAME, cognitoClient, context);
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
			context.getLogger().log("Create admin: " + creationResult);

			cognitoClient.adminSetUserPassword(AdminSetUserPasswordRequest.builder()
							.userPoolId(cognitoId)
							.username(email)
							.password(password)
							.permanent(true)
							.build());
			context.getLogger().log("Set new password successful.");
		} catch (CognitoIdentityProviderException e) {
			context.getLogger().log(e.getMessage());
			return new APIGatewayProxyResponseEvent()
					.withBody(e.getMessage())
					.withStatusCode(400);
		}
		return formSuccessResponse(null, context);
	}

	private APIGatewayProxyResponseEvent handleSignIn(APIGatewayProxyRequestEvent event, Context context, CognitoIdentityProviderClient cognitoClient) {
		Map<String, Object> body = eventToBody(event, context);
		String email = (String) body.get(EMAIL_NAME_ATTR);
		String password = (String) body.get(PASSWORD_NAME_ATTR);

		String cognitoId = getCognitoIdByName(COGNITO_NAME, cognitoClient, context);
		UserPoolClientDescription appClient = getUserPoolApiDesc(cognitoId, cognitoClient, context);
		Map<String, String> authParameters = new HashMap<>();
		authParameters.put("USERNAME", email);
		authParameters.put("PASSWORD", password);
		AdminInitiateAuthResponse authResponse = null;
		try {
			authResponse = cognitoClient.adminInitiateAuth(AdminInitiateAuthRequest.builder()
					.userPoolId(cognitoId)
					.clientId(appClient.clientId())
					.authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
					.authParameters(authParameters)
					.build());
		} catch (UserNotFoundException e) {
			context.getLogger().log(e.getMessage());
			return new APIGatewayProxyResponseEvent()
					.withBody(e.getMessage())
					.withStatusCode(400);
		}

		Map<String, String> responseBody = new HashMap<>();
		responseBody.put(ACCESS_TOKEN_ATTR, authResponse.authenticationResult().accessToken());

		return formSuccessResponse(responseBody, context);
	}

	private APIGatewayProxyResponseEvent handleCreateTable(APIGatewayProxyRequestEvent event, Context context, CognitoIdentityProviderClient cognitoClient) {
		Map<String, Object> body = eventToBody(event, context);
		try {
			cognitoClient.getUser(GetUserRequest.builder()
					.accessToken(getAccessToken(getHeadersFromEvent(event, context), context))
					.build());

			Map<String, AttributeValue> item = new HashMap<>();
			String id = String.valueOf(body.get(TABLE_ID));
			item.put(TABLE_ID, new AttributeValue().withN(id));
			item.put(TABLE_NUMBER, new AttributeValue().withN(String.valueOf(body.get(TABLE_NUMBER))));
			item.put(TABLE_PLACES, new AttributeValue().withN(String.valueOf(body.get(TABLE_PLACES))));
			item.put(TABLE_IS_VIP, new AttributeValue().withBOOL((boolean) body.get(TABLE_IS_VIP)));
			String minOrder = String.valueOf(body.get(TABLE_MIN_ORDER));
			if(minOrder != null) {
				item.put(TABLE_MIN_ORDER, new AttributeValue().withN(minOrder));
			}

			PutItemRequest putItemRequest = new PutItemRequest(TABLES_TABLE_NAME, item);
			AmazonDynamoDB dynamoDb = AmazonDynamoDBClientBuilder.defaultClient();
			dynamoDb.putItem(putItemRequest);

			Map<String, Object> responseBody = new HashMap<>();
			responseBody.put(ID_ATTR, Integer.parseInt(id));

			return formSuccessResponse(responseBody, context);
		} catch (NotAuthorizedException ex) {
			context.getLogger().log("Table can't be created because customer is unauthorized. Invalid Access Token.");
			return new APIGatewayProxyResponseEvent()
					.withBody("Table can't be created because customer is unauthorized. Invalid Access Token.")
					.withStatusCode(400);
		}
	}

	private APIGatewayProxyResponseEvent handleGetTables(APIGatewayProxyRequestEvent event, Context context, CognitoIdentityProviderClient cognitoClient) {
		try {
			cognitoClient.getUser(GetUserRequest.builder()
					.accessToken(getAccessToken(getHeadersFromEvent(event, context), context))
					.build());

			AmazonDynamoDB dynamoDb = AmazonDynamoDBClientBuilder.defaultClient();
			ScanRequest scanRequest = new ScanRequest().withTableName(TABLES_TABLE_NAME);

			Map<String, Object> responseBody = new HashMap<>();
			responseBody.put(TABLES_ATTR, getAllTables(dynamoDb, scanRequest));

			return formSuccessResponse(responseBody, context);
		} catch (NotAuthorizedException ex) {
			context.getLogger().log("Can't get tables because customer is unauthorized. Invalid Access Token.");
			return new APIGatewayProxyResponseEvent()
					.withBody("Can't get tables because customer is unauthorized. Invalid Access Token.")
					.withStatusCode(400);
		}
	}

	private APIGatewayProxyResponseEvent handleGetSpecificTable(APIGatewayProxyRequestEvent event, Context context, CognitoIdentityProviderClient cognitoClient) {
		try {
			cognitoClient.getUser(GetUserRequest.builder()
					.accessToken(getAccessToken(getHeadersFromEvent(event, context), context))
					.build());

			AmazonDynamoDB dynamoDb = AmazonDynamoDBClientBuilder.defaultClient();
			String tableId = event.getPathParameters().get("tableId");
			context.getLogger().log("Handle request with tableId path parameter: " + tableId);

//			Map<String, AttributeValue> keyToGet = new HashMap<>();
//			keyToGet.put(TABLE_ID, new AttributeValue().withN(tableId));
//			GetItemRequest request = new GetItemRequest()
//					.withTableName(TABLES_TABLE_NAME)
//					.withKey(keyToGet);
//			Map<String, AttributeValue> item = dynamoDb.getItem(request).getItem();

			ScanRequest scanRequest = new ScanRequest().withTableName(TABLES_TABLE_NAME);
			List<Map<String, Object>> tables = getAllTables(dynamoDb, scanRequest);
			Optional<Map<String, Object>> item = tables.stream().filter(table -> tableId.equals(String.valueOf(table.get(TABLE_ID))))
					.findFirst();

			if (item.isPresent()) {
				Map<String, Object> result = item.get();
				context.getLogger().log("Result: " + result);
				return formSuccessResponse(result, context);
			} else {
				return new APIGatewayProxyResponseEvent()
						.withBody("No table found for id: " + tableId)
						.withStatusCode(404);
			}
		} catch (NotAuthorizedException ex) {
			context.getLogger().log("Can't get table because customer is unauthorized. Invalid Access Token.");
			return new APIGatewayProxyResponseEvent()
					.withBody("Can't get table because customer is unauthorized. Invalid Access Token.")
					.withStatusCode(400);
		}
	}

	private APIGatewayProxyResponseEvent handleCreateReservation(APIGatewayProxyRequestEvent event, Context context, CognitoIdentityProviderClient cognitoClient) {
		Map<String, Object> body = eventToBody(event, context);
		try {
			cognitoClient.getUser(GetUserRequest.builder()
					.accessToken(getAccessToken(getHeadersFromEvent(event, context), context))
					.build());

			Map<String, AttributeValue> item = new HashMap<>();
			String tableNumber = String.valueOf(body.get(RESERVATION_TABLE_NUMBER));
			String reservationId = UUID.randomUUID().toString();
			AmazonDynamoDB dynamoDb = AmazonDynamoDBClientBuilder.defaultClient();
			if (checkIfTableExists(tableNumber, dynamoDb, context) && checkIfReservationWithTableIsNotExists(tableNumber, dynamoDb, context)) {
				item.put(RESERVATION_ID, new AttributeValue().withS(reservationId));
				item.put(RESERVATION_TABLE_NUMBER, new AttributeValue().withN(tableNumber));
				item.put(RESERVATION_CLIENT_NAME, new AttributeValue().withS(String.valueOf(body.get(RESERVATION_CLIENT_NAME))));
				item.put(RESERVATION_PHONE_NUMBER, new AttributeValue().withS(String.valueOf(body.get(RESERVATION_PHONE_NUMBER))));
				item.put(RESERVATION_DATE, new AttributeValue().withS(String.valueOf(body.get(RESERVATION_DATE))));
				item.put(RESERVATION_SLOT_TIME_START, new AttributeValue().withS(String.valueOf(body.get(RESERVATION_SLOT_TIME_START))));
				item.put(RESERVATION_SLOT_TIME_END, new AttributeValue().withS(String.valueOf(body.get(RESERVATION_SLOT_TIME_END))));
			} else {
				context.getLogger().log("Table with number: " + tableNumber + " dose not exists.");
				return new APIGatewayProxyResponseEvent()
						.withStatusCode(400);
			}

			PutItemRequest putItemRequest = new PutItemRequest(RESERVATIONS_TABLE_NAME, item);
			dynamoDb.putItem(putItemRequest);

			Map<String, Object> responseBody = new HashMap<>();
			responseBody.put(RESERVATION_ID_ATTR, reservationId);

			return formSuccessResponse(responseBody, context);
		} catch (NotAuthorizedException ex) {
			context.getLogger().log("Reservation can't be created because customer is unauthorized. Invalid Access Token.");
			return new APIGatewayProxyResponseEvent()
					.withBody("Reservation can't be created because customer is unauthorized. Invalid Access Token.")
					.withStatusCode(400);
		}
	}

	private APIGatewayProxyResponseEvent handleGetReservations(APIGatewayProxyRequestEvent event, Context context, CognitoIdentityProviderClient cognitoClient) {
		try {
			cognitoClient.getUser(GetUserRequest.builder()
					.accessToken(getAccessToken(getHeadersFromEvent(event, context), context))
					.build());

			AmazonDynamoDB dynamoDb = AmazonDynamoDBClientBuilder.defaultClient();
			ScanRequest scanRequest = new ScanRequest().withTableName(RESERVATIONS_TABLE_NAME);

			List<Map<String, Object>> reservations = getAllReservations(dynamoDb, scanRequest);

			Map<String, Object> responseBody = new HashMap<>();
			responseBody.put(RESERVATIONS_ATTR, reservations);

			return formSuccessResponse(responseBody, context);
		} catch (NotAuthorizedException ex) {
			context.getLogger().log("Can't get reservations because customer is unauthorized. Invalid Access Token.");
			return new APIGatewayProxyResponseEvent()
					.withBody("Can't get reservations because customer is unauthorized. Invalid Access Token.")
					.withStatusCode(400);
		}
	}
}