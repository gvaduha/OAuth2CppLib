========================================================================
    OAuth2 CPP 03 Library Project Overview
========================================================================

//TODO:
- Remove logic from storage
- Make interface for storage politics
- Make profile as normal resource
- URI as class

- Template function in TokenFactory call T Token.Create
- TokenFactory::Create by type

- Make language resource loader Interface
- Make request.context.getUserID() (it will eliminate dependence on UserAuthN)
- Remove darn SharedPtrs
- Review URI parsing against RFC3986 #3



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
