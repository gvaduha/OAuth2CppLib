//
// ATTENTION
// Consider that these helpers are using boost and C++11 syntax and 
// not intended to use as-is in conjunction with C++03 valid OAuth2 code
//
#include "Helpers.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace OAuth2
{
namespace Helpers
{

using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;

std::string mapToJSON (const std::map<std::string, std::string>& map)
{
  ptree pt; 
  for (auto& entry: map) 
      pt.put (entry.first, entry.second);
  std::ostringstream buf; 
  write_json (buf, pt, false); 
  return buf.str();
};

};
};
