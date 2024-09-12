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
import java.util.Optional;

import static com.task10.LambdaHelper.*;
import static com.task10.LambdaVariables.*;

public class TablesHandler {
    public APIGatewayProxyResponseEvent handleCreateTable(APIGatewayProxyRequestEvent event, Context context,
                                                          CognitoIdentityProviderClient cognitoClient) {
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
            if (minOrder != null) {
                item.put(TABLE_MIN_ORDER, new AttributeValue().withN(minOrder));
            }

            PutItemRequest putItemRequest = new PutItemRequest(TABLE_TABLES, item);
            AmazonDynamoDB dynamoDb = AmazonDynamoDBClientBuilder.defaultClient();
            dynamoDb.putItem(putItemRequest);

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put(ID, Integer.parseInt(id));

            return createSuccessResponse(responseBody, context);
        } catch (NotAuthorizedException ex) {
            context.getLogger().log("Failed to create table. Invalid Access Token.");
            return new APIGatewayProxyResponseEvent()
                    .withBody("Failed to create table. Invalid Access Token.")
                    .withStatusCode(400);
        }
    }

    public APIGatewayProxyResponseEvent handleGetTables(APIGatewayProxyRequestEvent event, Context context,
                                                        CognitoIdentityProviderClient cognitoClient) {
        try {
            cognitoClient.getUser(GetUserRequest.builder()
                    .accessToken(getAccessToken(getHeadersFromEvent(event, context), context))
                    .build());

            AmazonDynamoDB dynamoDb = AmazonDynamoDBClientBuilder.defaultClient();
            ScanRequest scanRequest = new ScanRequest().withTableName(TABLE_TABLES);

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put(TABLES, getAllTables(dynamoDb, scanRequest));

            return createSuccessResponse(responseBody, context);
        } catch (NotAuthorizedException ex) {
            context.getLogger().log("Failed to obtain tables. Invalid Access Token.");
            return new APIGatewayProxyResponseEvent()
                    .withBody("Failed to obtain tables. Invalid Access Token.")
                    .withStatusCode(400);
        }
    }

    public APIGatewayProxyResponseEvent handleGetSpecificTable(APIGatewayProxyRequestEvent event, Context context,
                                                               CognitoIdentityProviderClient cognitoClient) {
        try {
            cognitoClient.getUser(GetUserRequest.builder()
                    .accessToken(getAccessToken(getHeadersFromEvent(event, context), context))
                    .build());

            AmazonDynamoDB dynamoDb = AmazonDynamoDBClientBuilder.defaultClient();
            String tableId = event.getPathParameters().get("tableId");
            context.getLogger().log("Handling the /tables/{tableId} type request: " + tableId);
            ScanRequest scanRequest = new ScanRequest().withTableName(TABLE_TABLES);
            List<Map<String, Object>> tables = getAllTables(dynamoDb, scanRequest);
            Optional<Map<String, Object>> item =
                    tables.stream().filter(table -> tableId.equals(String.valueOf(table.get(TABLE_ID)))).findFirst();

            if (item.isPresent()) {
                Map<String, Object> result = item.get();
                context.getLogger().log("Result: " + result);
                return createSuccessResponse(result, context);
            } else {
                return new APIGatewayProxyResponseEvent()
                        .withBody("A table with id was not found: " + tableId)
                        .withStatusCode(404);
            }
        } catch (NotAuthorizedException ex) {
            context.getLogger().log("Failed to obtain table. Invalid Access Token.");
            return new APIGatewayProxyResponseEvent()
                    .withBody("Failed to obtain table. Invalid Access Token.")
                    .withStatusCode(400);
        }
    }
}