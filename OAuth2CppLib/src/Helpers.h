#include "Types.h"
#include <map>

namespace OAuth2
{
namespace Helpers
{
    typedef std::map<string, string> jsonmap_t;
    typedef std::pair<string, string> jsonpair_t;

    std::string mapToJSON (const std::map<string, string>& map);

};};
