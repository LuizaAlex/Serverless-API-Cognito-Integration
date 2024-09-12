package com.task10;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.NotAuthorizedException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.task10.LambdaHelper.*;
import static com.task10.LambdaVariables.*;

public class ReservationsHandler {
    public APIGatewayProxyResponseEvent handleCreateReservation(APIGatewayProxyRequestEvent event, Context context,
                                                                CognitoIdentityProviderClient cognitoClient) {
        Map<String, Object> body = eventToBody(event, context);
        try {
            cognitoClient.getUser(GetUserRequest.builder()
                    .accessToken(getAccessToken(getHeadersFromEvent(event, context), context))
                    .build());

            Map<String, AttributeValue> item = new HashMap<>();
            String tableNumber = String.valueOf(body.get(RESERVATION_TABLE_NUMBER));
            String reservationId = UUID.randomUUID().toString();
            AmazonDynamoDB dynamoDb = AmazonDynamoDBClientBuilder.defaultClient();
            if (isTableExist(tableNumber, dynamoDb) && isReservationWithTableDoNotExist(tableNumber, dynamoDb)) {
                item.put(ID, new AttributeValue().withS(reservationId));
                item.put(RESERVATION_TABLE_NUMBER, new AttributeValue().withN(tableNumber));
                item.put(RESERVATION_CLIENT_NAME,
                        new AttributeValue().withS(String.valueOf(body.get(RESERVATION_CLIENT_NAME))));
                item.put(RESERVATION_PHONE_NUMBER,
                        new AttributeValue().withS(String.valueOf(body.get(RESERVATION_PHONE_NUMBER))));
                item.put(RESERVATION_DATE, new AttributeValue().withS(String.valueOf(body.get(RESERVATION_DATE))));
                item.put(RESERVATION_SLOT_TIME_START,
                        new AttributeValue().withS(String.valueOf(body.get(RESERVATION_SLOT_TIME_START))));
                item.put(RESERVATION_SLOT_TIME_END,
                        new AttributeValue().withS(String.valueOf(body.get(RESERVATION_SLOT_TIME_END))));
            } else {
                context.getLogger().log("The table with number: " + tableNumber + " does not exist.");
                return new APIGatewayProxyResponseEvent()
                        .withStatusCode(400);
            }

            PutItemRequest putItemRequest = new PutItemRequest(TABLE_RESERVATIONS, item);
            dynamoDb.putItem(putItemRequest);

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put(RESERVATION_ID, reservationId);

            return createSuccessResponse(responseBody, context);
        } catch (NotAuthorizedException ex) {
            context.getLogger().log("Failed to create reservation. Invalid Access Token.");
            return new APIGatewayProxyResponseEvent()
                    .withBody("Failed to create reservation. Invalid Access Token.")
                    .withStatusCode(400);
        }
    }

    public APIGatewayProxyResponseEvent handleGetReservations(APIGatewayProxyRequestEvent event, Context context,
                                                              CognitoIdentityProviderClient cognitoClient) {
        try {
            cognitoClient.getUser(GetUserRequest.builder()
                    .accessToken(getAccessToken(getHeadersFromEvent(event, context), context))
                    .build());

            AmazonDynamoDB dynamoDb = AmazonDynamoDBClientBuilder.defaultClient();
            ScanRequest scanRequest = new ScanRequest().withTableName(TABLE_RESERVATIONS);

            List<Map<String, Object>> reservations = getAllReservations(dynamoDb, scanRequest);

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put(RESERVATIONS, reservations);

            return createSuccessResponse(responseBody, context);
        } catch (NotAuthorizedException ex) {
            context.getLogger().log("Failed to obtain reservation. Invalid Access Token.");
            return new APIGatewayProxyResponseEvent()
                    .withBody("Failed to obtain reservation. Invalid Access Token.")
                    .withStatusCode(400);
        }
    }
}