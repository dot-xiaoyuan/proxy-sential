#include "Stream.h"
#include <algorithm>

namespace {
constexpr size_t MaxBuffered = 1024;
uint8_t Byte(const std::string& s, size_t n) { return static_cast<uint8_t>(s[n]); }
// Zero means incomplete, negative means invalid. Includes version and port.
int AddressFrame(const std::string& s) {
 if (s.size() < 4) return 0;
 if (Byte(s,0) != 5 || Byte(s,2) != 0) return -1;
 switch (Byte(s,3)) {
  case 1: return 10;
  case 4: return 22;
  case 3:
   if (s.size() < 5) return 0;
   if (Byte(s,4) == 0) return -1;
   return 7 + Byte(s,4);
  default: return -1;
 }
}
}

bool SOCKSFrames::Feed(std::string_view bytes, bool orig, const Deliver& deliver) {
 if (failed) return false;
 if (bytes.empty()) return true;
 if (Complete()) { deliver(bytes,orig); return true; }
 // Never postpone a response or pre-authentication request and later give
 // it the timestamp of a different handshake phase.
 if (orig != ExpectedOriginator()) { Stop(); return false; }
 auto& buffer = buffers[orig ? 0 : 1];
 if (bytes.size() > MaxBuffered - buffer.size()) { Stop(); return false; }
 buffer.append(bytes);
 if (!Process(deliver)) { Stop(); return false; }
 return true;
}

bool SOCKSFrames::ExpectedOriginator() const {
 return stage == Stage::Greeting || stage == Stage::Credentials || stage == Stage::Request;
}

bool SOCKSFrames::Process(const Deliver& deliver) {
 while (!Complete()) {
  const bool orig = ExpectedOriginator();
  // Coalesced payload must obey the same phase boundary as separate chunks.
  if (!buffers[orig ? 1 : 0].empty()) return false;
  auto& s = buffers[orig ? 0 : 1];
  if (s.empty()) return true;
  int length = 0;
  Stage next = stage;
  switch (stage) {
   case Stage::Greeting:
    if (Byte(s,0) == 4) {
     if (s.size() < 8) return true;
     if (Byte(s,1) != 1 && Byte(s,1) != 2) return false;
     const auto user_end = s.find('\0',8);
     if (user_end == std::string::npos) return s.size() <= 263;
     if (user_end > 263) return false;
     size_t end = user_end;
     if (Byte(s,4)==0 && Byte(s,5)==0 && Byte(s,6)==0 && Byte(s,7)!=0) {
      end = s.find('\0',user_end+1);
      if (end == std::string::npos) return s.size() <= user_end+256;
      if (end == user_end+1 || end > user_end+256) return false;
     }
     length = end + 1;
     next = Stage::V4Reply;
     break;
    }
    if (Byte(s,0) != 5) return false;
    if (s.size() < 2) return true;
    if (Byte(s,1) == 0) return false;
    length = 2 + Byte(s,1);
    if (s.size() < static_cast<size_t>(length)) return true;
    methods = s.substr(2,length-2);
    next = Stage::Selection;
    break;
   case Stage::V4Reply:
    if (Byte(s,0) != 0) return false;
    if (s.size() < 2) return true;
    if (Byte(s,1) < 90 || Byte(s,1) > 93) return false;
    length = 8;
    next = Stage::Tunnel;
    break;
   case Stage::Selection:
    if (Byte(s,0) != 5) return false;
    if (s.size() < 2) return true;
    if (methods.find(s[1]) == std::string::npos) return false;
    if (Byte(s,1) != 0 && Byte(s,1) != 2) return false;
    length = 2;
    next = Byte(s,1) == 2 ? Stage::Credentials : Stage::Request;
    break;
   case Stage::Credentials: {
    if (Byte(s,0) != 1) return false;
    if (s.size() < 2) return true;
    const size_t user = Byte(s,1);
    if (user == 0) return false;
    if (s.size() < user + 3) return true;
    const size_t password = Byte(s,user+2);
    if (password == 0) return false;
    length = 3 + user + password;
    next = Stage::Authentication;
    break;
   }
   case Stage::Authentication:
    if (Byte(s,0) != 1) return false;
    if (s.size() < 2) return true;
    if (Byte(s,1) != 0) return false;
    length = 2;
    next = Stage::Request;
    break;
   case Stage::Request:
    length = AddressFrame(s);
    if (s.size() >= 2 && (Byte(s,1) < 1 || Byte(s,1) > 3)) return false;
    next = Stage::Reply;
    break;
   case Stage::Reply:
    length = AddressFrame(s);
    if (s.size() >= 2 && Byte(s,1) > 8) return false;
    next = Stage::Tunnel;
    break;
   case Stage::Tunnel: break;
  }
  if (length < 0) return false;
  if (length == 0 || s.size() < static_cast<size_t>(length)) return true;
  std::string frame = s.substr(0,length);
  s.erase(0,length);
  stage = next;
  deliver(frame,orig);
 }
 // Native SOCKS only supports tunnel content after both protocol endpoints finish.
 for (size_t n = 0; n < buffers.size(); ++n) {
  if (!buffers[n].empty()) { deliver(buffers[n],n==0); buffers[n].clear(); }
 }
 return true;
}
