package com.task10;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.io.IOException;
import java.util.*;

import static com.task10.LambdaVariables.*;

public class LambdaHelper {

    public static void createUserPoolApiClientIfNotExist(String cognitoId, String clientName,
                                                         CognitoIdentityProviderClient cognitoClient,
                                                         Context context) {
        boolean noOneApiClient = cognitoClient.listUserPoolClients(ListUserPoolClientsRequest.builder()
                .userPoolId(cognitoId)
                .build()).userPoolClients().isEmpty();
        if (noOneApiClient) {
            CreateUserPoolClientResponse createUserPoolClientResponse =
                    cognitoClient.createUserPoolClient(CreateUserPoolClientRequest.builder()
                            .userPoolId(cognitoId)
                            .clientName(clientName)
                            .explicitAuthFlows(ExplicitAuthFlowsType.ADMIN_NO_SRP_AUTH)
                            .generateSecret(false)
                            .build());
            context.getLogger().log("User pool client was created: " + createUserPoolClientResponse);
        }
    }

    public static UserPoolClientDescription getUserPoolApiDesc(String cognitoId,
                                                               CognitoIdentityProviderClient cognitoClient,
                                                               Context context) {
        ListUserPoolClientsResponse response = cognitoClient.listUserPoolClients(ListUserPoolClientsRequest.builder()
                .userPoolId(cognitoId)
                .build());
        Iterator<UserPoolClientDescription> iterator = response.userPoolClients().iterator();
        UserPoolClientDescription result = null;
        if (iterator.hasNext()) {
            result = iterator.next();
            context.getLogger().log("User pool client: " + result);
        } else {
            context.getLogger().log("Creating user pool client");
            createUserPoolApiClientIfNotExist(cognitoId, COGNITO_CLIENT_API, cognitoClient, context);
        }
        return result;
    }

    public static String getCognitoIdByName(String name, CognitoIdentityProviderClient client, Context context) {
        ListUserPoolsResponse listUserPoolsResponse = client.listUserPools(ListUserPoolsRequest.builder().build());
        List<UserPoolDescriptionType> userPools = listUserPoolsResponse.userPools();
        for (UserPoolDescriptionType userPool : userPools) {
            if (name.equals(userPool.name())) {
                String cognitoId = userPool.id();
                context.getLogger().log("Cognito id was found: " + cognitoId);
                return cognitoId;
            }
        }
        return null;
    }

    public static List<Map<String, Object>> getAllTables(AmazonDynamoDB dynamoDb, ScanRequest scanRequest) {
        ScanResult result = dynamoDb.scan(scanRequest);
        List<Map<String, Object>> tables = new ArrayList<>();
        for (Map<String, AttributeValue> item : result.getItems()) {
            Map<String, Object> table = new HashMap<>();
            convertTableToMap(table, item);
            tables.add(table);
        }
        return tables;
    }

    public static void convertTableToMap(Map<String, Object> map, Map<String, AttributeValue> item) {
        map.put(TABLE_ID, Integer.parseInt(item.get(TABLE_ID).getN()));
        map.put(TABLE_NUMBER, Integer.parseInt(item.get(TABLE_NUMBER).getN()));
        map.put(TABLE_PLACES, Integer.parseInt(item.get(TABLE_PLACES).getN()));
        map.put(TABLE_IS_VIP, item.get(TABLE_IS_VIP).getBOOL());
        if (item.containsKey(TABLE_MIN_ORDER)) {
            map.put(TABLE_MIN_ORDER, Integer.parseInt(item.get(TABLE_MIN_ORDER).getN()));
        }
    }

    public static List<Map<String, Object>> getAllReservations(AmazonDynamoDB dynamoDb, ScanRequest scanRequest) {
        ScanResult result = dynamoDb.scan(scanRequest);
        List<Map<String, Object>> reservations = new ArrayList<>();
        for (Map<String, AttributeValue> item : result.getItems()) {
            Map<String, Object> reservation = new HashMap<>();
            convertReservationToMap(reservation, item);
            reservations.add(reservation);
        }
        return reservations;
    }

    public static void convertReservationToMap(Map<String, Object> map, Map<String, AttributeValue> item) {
        map.put(RESERVATION_TABLE_NUMBER, Integer.parseInt(item.get(RESERVATION_TABLE_NUMBER).getN()));
        map.put(RESERVATION_CLIENT_NAME, item.get(RESERVATION_CLIENT_NAME).getS());
        map.put(RESERVATION_PHONE_NUMBER, item.get(RESERVATION_PHONE_NUMBER).getS());
        map.put(RESERVATION_DATE, item.get(RESERVATION_DATE).getS());
        map.put(RESERVATION_SLOT_TIME_START, item.get(RESERVATION_SLOT_TIME_START).getS());
        map.put(RESERVATION_SLOT_TIME_END, item.get(RESERVATION_SLOT_TIME_END).getS());
    }


    public static Map<String, Object> eventToBody(APIGatewayProxyRequestEvent event, Context context) {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> body;
        try {
            body = mapper.readValue(event.getBody(), Map.class);
        } catch (IOException e) {
            context.getLogger().log(e.getMessage());
            throw new RuntimeException(e);
        }
        context.getLogger().log("Request body: " + body);
        return body;
    }

    public static APIGatewayProxyResponseEvent createSuccessResponse(Object responseBody, Context context) {
        ObjectMapper mapper = new ObjectMapper();
        APIGatewayProxyResponseEvent response;
        try {
            if (Objects.nonNull(responseBody)) {
                response = new APIGatewayProxyResponseEvent().withBody(mapper.writeValueAsString(responseBody))
                        .withStatusCode(200);
            } else {
                response = new APIGatewayProxyResponseEvent()
                        .withStatusCode(200);
            }
        } catch (JsonProcessingException e) {
            context.getLogger().log(e.getMessage());
            throw new RuntimeException(e);
        }
        context.getLogger().log("Response: " + response);
        return response;
    }

    public static Map<String, String> getHeadersFromEvent(APIGatewayProxyRequestEvent event, Context context) {
        Map<String, String> headers = event.getHeaders();
        context.getLogger().log("Request headers: " + headers);
        return headers;
    }

    public static String getAccessToken(Map<String, String> headers, Context context) {
        String accessToken = headers.get(AUTHORIZATION).split(" ")[1];
        context.getLogger().log("Access token: " + accessToken);
        return accessToken;
    }

    public static boolean isTableExist(String tableNumber, AmazonDynamoDB dynamoDb) {
        ScanRequest scanRequest = new ScanRequest().withTableName(TABLE_TABLES);
        List<Map<String, Object>> tables = getAllTables(dynamoDb, scanRequest);
        return tables.stream().anyMatch(table -> tableNumber.equals(String.valueOf(table.get(TABLE_NUMBER))));
    }

    public static boolean isReservationWithTableDoNotExist(String tableNumber, AmazonDynamoDB dynamoDb) {
        ScanRequest scanRequest = new ScanRequest().withTableName(TABLE_RESERVATIONS);
        List<Map<String, Object>> tables = getAllReservations(dynamoDb, scanRequest);
        return tables.stream().noneMatch(reservation ->
                tableNumber.equals(String.valueOf(reservation.get(RESERVATION_TABLE_NUMBER))));
    }
}