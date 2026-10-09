#include "Stream.h"
#include <memory>
#include <unordered_map>
#include "zeek/Conn.h"
#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/http/HTTP.h"
#include "zeek/analyzer/protocol/socks/SOCKS.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/plugin/Plugin.h"
#include "zeek/session/Manager.h"

namespace {
constexpr const char* header_guard="Sentinel_HTTP_Headers";
constexpr const char* invalid_header="Sentinel_HTTP_invalid_header";
std::unordered_map<zeek::analyzer::ID,std::weak_ptr<HTTPHeaderState>> header_states;
// HTTP invokes TCP-specific lifecycle callbacks on every support analyzer.
class HTTPHeaders final : public zeek::analyzer::tcp::TCP_SupportAnalyzer {
 std::shared_ptr<HTTPHeaderState> state;
 zeek::analyzer::ID parent_id;
 bool owner;
public:
 HTTPHeaders(zeek::Connection* c,bool orig,zeek::analyzer::ID aid,std::shared_ptr<HTTPHeaderState> s)
  : TCP_SupportAnalyzer(header_guard,c,orig),state(std::move(s)),parent_id(aid),owner(orig) {}
 ~HTTPHeaders() override {
  if (!owner) return;
  auto it=header_states.find(parent_id);
  if (it!=header_states.end() && it->second.lock()==state) header_states.erase(it);
 }
 void DeliverStream(int len,const u_char* data,bool orig) override {
  auto* http=dynamic_cast<zeek::analyzer::http::HTTP_Analyzer*>(Parent());
  if (http && !state->Observe(std::string_view(reinterpret_cast<const char*>(data),len),orig,
        orig?http->GetRequestOngoing():http->GetReplyOngoing(),http->HTTP_ReplyCode()))
   http->HTTP_Event(invalid_header,"invalid HTTP header or status line");
  // Observe native line boundaries without altering the HTTP parser's bytes.
  ForwardStream(len,data,orig);
 }
 void Undelivered(uint64_t seq,int len,bool orig) override { ForwardUndelivered(seq,len,orig); }
};
std::shared_ptr<HTTPHeaderState> Headers(zeek::analyzer::http::HTTP_Analyzer* http) {
 auto it=header_states.find(http->GetID());
 if (it!=header_states.end())
  if (auto state=it->second.lock()) return state;
 auto state=std::make_shared<HTTPHeaderState>();
 header_states[http->GetID()]=state;
 http->AddSupportAnalyzer(new HTTPHeaders(http->Conn(),true,http->GetID(),state));
 http->AddSupportAnalyzer(new HTTPHeaders(http->Conn(),false,http->GetID(),state));
 return state;
}
class StreamAnalyzer final : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
 SOCKSFrames frames;
public:
 explicit StreamAnalyzer(zeek::Connection* c) : TCP_ApplicationAnalyzer("Sentinel_SOCKS_Stream",c) {
  if (!AddChildAnalyzer(zeek::analyzer::socks::SOCKS_Analyzer::Instantiate(c))) { frames.Stop(); SetSkip(true); }
 }
 static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* c) { return new StreamAnalyzer(c); }
 void DeliverStream(int len, const u_char* data, bool orig) override {
  TCP_ApplicationAnalyzer::DeliverStream(len,data,orig);
  if (TCP() && TCP()->IsPartial()) { frames.Stop(); SetSkip(true); return; }
  if (!frames.Feed(std::string_view(reinterpret_cast<const char*>(data),len),orig,
       [this](std::string_view frame,bool direction) {
        ForwardStream(frame.size(),reinterpret_cast<const u_char*>(frame.data()),direction);
       })) {
   AnalyzerViolation("invalid, out-of-order or oversized SOCKS handshake");
   SetSkip(true);
  }
 }
 void Undelivered(uint64_t seq, int len, bool orig) override {
  TCP_ApplicationAnalyzer::Undelivered(seq,len,orig);
  frames.Stop(); SetSkip(true);
 }
};
class Plugin final : public zeek::plugin::Plugin {
 bool HookQueueEvent(zeek::Event* event) override {
  if (!event->Handler()) return false;
  const std::string_view name=event->Handler()->Name();
  const auto& args=event->Args();
  if (name!="http_request" || args.size()!=5) return false;
  const auto aid=event->Analyzer();
  const auto* method=args[1]->AsString();
  const bool connect=std::string_view(reinterpret_cast<const char*>(method->Bytes()),method->Len())=="CONNECT";
  if (!connect && header_states.find(aid)==header_states.end()) return false;
  auto* c=args[0]->AsRecordVal();
  auto* conn=zeek::session_mgr->FindConnection(c->GetField("id").get());
  if (!conn) return false;
  auto* http=dynamic_cast<zeek::analyzer::http::HTTP_Analyzer*>(conn->FindAnalyzer(aid));
  if (!http) return false;
  auto state=Headers(http);
  {
   state->Request(connect);
   // Confirmation is raised while parsing the first request line. Its URI
   // is also checked, since the support guard joins after that line begins.
   const auto* uri=args[2]->AsString();
   if (connect && std::string_view(reinterpret_cast<const char*>(uri->Bytes()),uri->Len()).find('\0')!=std::string_view::npos && state->Reject())
    http->HTTP_Event(invalid_header,"NUL in CONNECT target");
  }
  return false;
 }
 zeek::plugin::Configuration Configure() override {
  AddComponent(new zeek::analyzer::Component(header_guard,nullptr));
  AddComponent(new zeek::analyzer::Component("Sentinel_SOCKS_Stream",StreamAnalyzer::Instantiate));
  EnableHook(zeek::plugin::HOOK_QUEUE_EVENT);
  zeek::plugin::Configuration config;
  config.name = "Sentinel::SOCKSStream";
  config.description = "Bounded SOCKS framing and native HTTP header proof guards";
  config.version.major = 1;
  config.version.minor = 3;
  config.version.patch = 0;
  return config;
 }
} plugin;
}
