#include "Mocks.h"

#include <vector>
#include <iostream>
#include <sstream>

using std::vector;
using std::istringstream;

namespace OAuth2
{
namespace Test
{

const string UserAuthenticationFacadeMock::_authnPageBody =
    "<html><body><form id='authn' action='authenticate' method='POST'>" \
    "<input type='hidden' id='<<OriginalRequestFieldName>>' value='<<OriginalRequestValue>>'>" \
    "User:&nbsp<input type='text' id='user'><br>Password:&nbsp<input type='text' id='pass'><br>" \
    "<button id='submit' type='submit'>Accept</button>"\
    "</form></body></html>";
const string UserAuthenticationFacadeMock::_originalRequestFieldName = "nextPage";

const string UserAuthenticationFacadeMock::UserIdParamName = "UserId";

};// namespace Test
};// namespace OAuth2
