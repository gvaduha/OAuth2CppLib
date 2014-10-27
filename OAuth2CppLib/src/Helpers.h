#include <string>
#include <map>

namespace OAuth2
{
namespace Helpers
{
    typedef std::map<std::string, std::string> jsonmap_t;
    typedef std::pair<std::string, std::string> jsonpair_t;

    std::string mapToJSON (const std::map<std::string, std::string>& map);

};};
