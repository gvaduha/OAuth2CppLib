#include "Types.h"
#include "Entities.h"

namespace OAuth2
{

    const std::regex Scope::_illegal_sym_regex("[ \\\\\"]+");
    const std::string Scope::_illegal_sym_replace("_");

};