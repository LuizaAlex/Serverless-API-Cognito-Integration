package com.task10;


public class ApiHandlerConstants {

    public static final String RESOURCE_PROFIX = "cmtr-4df2c6a7-";
    public static final String RESOURCE_SUFFIX = "-test";

    public static final String TABLES_TABLE_NAME = RESOURCE_PROFIX + "Tables" + RESOURCE_SUFFIX;
    public static final String RESERVATIONS_TABLE_NAME = RESOURCE_PROFIX + "Reservations" + RESOURCE_SUFFIX;
    public static final String COGNITO_NAME = RESOURCE_PROFIX + "simple-booking-userpool" + RESOURCE_SUFFIX;
    public static final String COGNITO_CLIENT_API_NAME = RESOURCE_PROFIX + "task10_app_client_id" + RESOURCE_SUFFIX;

    public static final String ACCESS_TOKEN_ATTR = "accessToken";
    public static final String AUTHORIZATION_ATTR = "Authorization";

    public static final String TABLE_ID_PATHVAR = "tableId";

    public static final String ID_ATTR = "id";
    public static final String RESERVATION_ID_ATTR = "reservationId";
    public static final String TABLES_ATTR = "tables";
    public static final String RESERVATIONS_ATTR = "reservations";
    public static final String FIRST_NAME_ATTR = "firstName";
    public static final String LAST_NAME_ATTR = "lastName";
    public static final String EMAIL_NAME_ATTR = "email";
    public static final String PASSWORD_NAME_ATTR = "password";

    // Table fields
    public static final String TABLE_ID = "id";
    public static final String TABLE_NUMBER = "number";
    public static final String TABLE_PLACES = "places";
    public static final String TABLE_IS_VIP = "isVip";
    public static final String TABLE_MIN_ORDER = "minOrder";

    // Reservation fields
    public static final String RESERVATION_ID = "id";
    public static final String RESERVATION_TABLE_NUMBER = "tableNumber";
    public static final String RESERVATION_CLIENT_NAME = "clientName";
    public static final String RESERVATION_PHONE_NUMBER = "phoneNumber";
    public static final String RESERVATION_DATE = "date";
    public static final String RESERVATION_SLOT_TIME_START = "slotTimeStart";
    public static final String RESERVATION_SLOT_TIME_END = "slotTimeEnd";

}