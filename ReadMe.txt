========================================================================
    OAuth2 CPP 03 Library Project Overview
========================================================================

class RFC_values_for_grant_types
{
    //Implicit Grant
    //
    //Authorization Request:
    //----------------------
    //response_type REQUIRED == "token".
    //client_id REQUIRED RFC6749 Section 2.2.
    //redirect_uri OPTIONAL RFC6749 Section 3.1.2.
    //scope OPTIONAL RFC6749 Section 3.3.
    //state RECOMMENDED
    //
    //Authorization Response:
    //-----------------------

    //Resource Owner Password Credentials Grant
    //
    //Authorization Request and Response - NO
    //
    //Access Token Request:
    //---------------------
    //grant_type REQUIRED == "password".
    //username REQUIRED
    //password REQUIRED
    //scope OPTIONAL RFC6749 Section 3.3.
    //
    //Access Token Response:
    //----------------------
    //

    //Client Credentials Grant
    //
    //Authorization Request and Response - NO
    //
    //Access Token Request:
    //---------------------
    //grant_type REQUIRED == "password".
    //scope OPTIONAL RFC6749 Section 3.3.
    //
    //Access Token Response:
    //----------------------
    //
};
