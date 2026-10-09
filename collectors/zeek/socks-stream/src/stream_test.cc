#include "Stream.h"
#include <cstdlib>
#include <iostream>
#include <utility>
#include <vector>
using Frames = std::vector<std::pair<bool,std::string>>;
std::string Hex(const char* value) {
 std::string out;
 for (; *value; value+=2) { char byte[]{value[0],value[1],0}; out+=static_cast<char>(std::strtoul(byte,nullptr,16)); }
 return out;
}
void Require(bool condition,const char* why) { if (!condition) { std::cerr<<why<<'\n'; std::exit(1); } }
Frames Conversation(std::string request,std::string reply,bool credentials) {
 Frames result{{true,Hex(credentials?"050102":"050100")},{false,Hex(credentials?"0502":"0500")}};
 if (credentials) { result.emplace_back(true,Hex("0101750170")); result.emplace_back(false,Hex("0100")); }
 result.emplace_back(true,std::move(request)); result.emplace_back(false,std::move(reply)); return result;
}
void Exact(const Frames& input) {
 // Every possible split and one-byte fragments must preserve protocol boundaries.
 for (size_t split=0;split<=24;++split) {
  SOCKSFrames parser; Frames actual;
  auto emit=[&](std::string_view data,bool orig){ actual.emplace_back(orig,data); };
  for (const auto& [orig,data]:input) {
   const size_t n=std::min(split,data.size());
   Require(parser.Feed(std::string_view(data).substr(0,n),orig,emit),"first fragment rejected");
   Require(parser.Feed(std::string_view(data).substr(n),orig,emit),"second fragment rejected");
  }
  Require(parser.Complete(),"complete transaction did not complete");
  Require(actual==input,"framing changed byte content, direction or number of PDUs");
  const std::string payload(65536,'x');
  Require(parser.Feed(payload,true,emit),"tunnel buffer applied handshake limit");
  Require(actual.back()==std::make_pair(true,payload),"tunnel content changed");
 }
 SOCKSFrames parser; Frames actual;
 auto emit=[&](std::string_view data,bool orig){ actual.emplace_back(orig,data); };
 for (const auto& [orig,data]:input)
  for (char byte:data) Require(parser.Feed(std::string_view(&byte,1),orig,emit),"one-byte fragment rejected");
 Require(actual==input,"one-byte fragmentation changed framing");
}
int main() {
 for (auto line:{"HTTP/1.1junk 200 OK","HTTP/1.10 200 OK","HTTP/1.x 200 OK","HTTP/1.1 2000 OK","HTTP/1.1 200junk OK","HTTP/1.1 20 OK","","HTTP/1.1   "}) {
  HTTPHeaderState malformed;
  Require(!malformed.Observe(line,false,false,0),"malformed status token accepted");
  Require(malformed.Observe(line,false,false,0),"status diagnostic repeated");
 }
 for (auto line:{"HTTP/1.0 200 OK","HTTP/1.1 200","HTTP/1.1\t200\tOK","http/1.1 200 OK","HTTP/1.1 200 2000 tunneled"}) {
  HTTPHeaderState valid;
  Require(valid.Observe(line,false,false,0),"normal status line rejected");
 }
 const std::string nul("a\0b",3);
 HTTPHeaderState bad_header;
 Require(!bad_header.Observe(nul,true,true,0),"NUL header accepted");
 Require(bad_header.Observe(nul,true,true,0),"invalid header diagnostic repeated");
 HTTPHeaderState body;
 body.Request(false);
 Require(body.Observe("POST / HTTP/1.1",true,false,0),"ordinary request rejected");
 Require(body.Observe("",true,true,0),"request boundary rejected");
 Require(body.Observe(nul,true,true,0),"binary request body treated as header");
 Require(body.Observe("HTTP/1.1 200 OK",false,false,0),"ordinary response rejected");
 Require(body.Observe("",false,true,200),"response boundary rejected");
 Require(body.Observe(nul,false,true,200),"binary response body treated as header");
 for (int status:{200,201,204,299}) {
  HTTPHeaderState tunnel;
  tunnel.Request(true);
  Require(tunnel.Observe("",true,true,0),"CONNECT request boundary rejected");
  Require(tunnel.Observe("HTTP/1.1 100 Continue",false,false,0),"interim status rejected");
  Require(tunnel.Observe("",false,true,100),"interim header boundary rejected");
  Require(tunnel.Observe("HTTP/1.1 200 Established",false,false,0),"final status rejected");
  Require(tunnel.Observe("",false,true,status),"CONNECT response boundary rejected");
  Require(tunnel.Observe(nul,true,false,status),"binary client tunnel data treated as headers");
  Require(tunnel.Observe(nul,false,false,status),"binary server tunnel data treated as headers");
 }
 HTTPHeaderState retry;
 retry.Request(true);
 Require(retry.Observe("",false,true,403),"denial boundary rejected");
 Require(retry.Observe(nul,false,true,403),"binary denial body rejected");
 Require(retry.Observe("CONNECT target:443 HTTP/1.1",true,false,0),"retry request rejected");
 Require(!retry.Observe(nul,true,true,0),"retry NUL header accepted");
 auto v4=Frames{{true,Hex("040100507f0000017500")},{false,Hex("005a00007f000001")}};
 Exact(v4);
 Exact(Frames{{true,Hex("04010050000000017500612e6578616d706c6500")},{false,Hex("005a00007f000001")}});
 for (bool credentials:{false,true}) {
  Exact(Conversation(Hex("050100017f0000010050"),Hex("050000017f0000010000"),credentials));
  Exact(Conversation(Hex("05010004")+std::string(16,'\0')+Hex("0050"),Hex("05000004")+std::string(18,'\0'),credentials));
  Exact(Conversation(Hex("05010003ff")+std::string(255,'a')+Hex("0050"),Hex("0505000301610000"),credentials));
 }
 auto reject=[](const Frames& input) {
  SOCKSFrames parser;
  bool accepted=true;
  auto emit=[](std::string_view,bool){};
  for (const auto& [orig,data]:input) { if (!parser.Feed(data,orig,emit)) { accepted=false; break; } }
  Require(!accepted,"invalid handshake accepted");
  Require(!parser.Complete(),"invalid handshake completed");
 };
 reject({{true,Hex("0500")}});
 reject({{true,Hex("050100")},{false,Hex("0502")}});
 reject({{true,Hex("050100")},{false,Hex("05ff")}});
 reject({{true,Hex("160301")}});
 reject({{true,std::string(1025,'x')}});
 reject(Conversation(Hex("050101017f0000010050"),Hex("050000017f0000010000"),false));
 reject(Conversation(Hex("0501000300"),Hex("050000017f0000010000"),false));
 reject(Conversation(Hex("050400017f0000010050"),Hex("050000017f0000010000"),false));
 reject({{true,Hex("050102")},{false,Hex("0502")},{true,Hex("0101750170")},{false,Hex("0101")}});
 const auto request=Hex("050100017f0000010050"), reply=Hex("050000017f0000010000");
 reject({{true,Hex("050100")},{false,Hex("0500")},{false,reply},{true,request}});
 reject({{true,Hex("050100")},{false,Hex("0500")+reply},{true,request}});
 reject({{true,Hex("050100")},{true,request},{false,Hex("0500")},{false,reply}});
 reject({{true,Hex("050100")+request},{false,Hex("0500")},{false,reply}});
 reject({{true,Hex("050102")},{false,Hex("0502")},{true,Hex("0101750170")},{true,request},{false,Hex("0100")},{false,reply}});
 reject({{true,Hex("050102")},{false,Hex("0502")},{true,Hex("0101750170")},{false,Hex("0100")+reply},{true,request}});
 reject({{true,Hex("050100")},{false,Hex("0500")},{true,request.substr(0,4)},{false,reply},{true,request.substr(4)}});
 reject({{true,Hex("050100")},{false,Hex("0500")},{true,request},{true,"premature-data"},{false,reply}});
 SOCKSFrames coalesced; Frames actual;
 auto emit=[&](std::string_view data,bool orig){ actual.emplace_back(orig,data); };
 for (const auto& [orig,data]: Conversation(request,reply+"tunnel-data",false)) Require(coalesced.Feed(data,orig,emit),"reply and tunnel coalescing rejected");
 Require(coalesced.Complete(),"coalesced reply did not complete");
 Require(actual[actual.size()-2]==std::make_pair(false,reply) && actual.back()==std::make_pair(false,std::string("tunnel-data")),"reply/tunnel boundary changed");
 SOCKSFrames gap; gap.Stop();
 Require(!gap.Feed(Hex("050100"),true,[](std::string_view,bool){}),"stopped stream resumed");
 std::cout<<"Proxy framing and header guards: SOCKS fragments/order, HTTP NUL headers, interim responses, retries and binary bodies/tunnels passed\n";
}
