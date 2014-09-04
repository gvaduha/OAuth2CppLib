#pragma once
#include <cassert>

namespace OAuth2
{
namespace Test
{
#define ASSERT_EXCEPTION(EXPRESSION,TYPE,MESSAGE) do { try { EXPRESSION; } catch(TYPE &ex) { assert(MESSAGE == ex.what()); break; } assert(false); } while(0);
#define ASSERT_NO_EXCEPTION(EXPRESSION) do { try { EXPRESSION; } catch(...) { assert(false); } } while(0);
}; //namespace Test
}; //namespace OAuth2
