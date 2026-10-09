#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

// Bound only the SOCKS handshake; tunnel data is not retained by this framer.
class SOCKSFrames {
public:
 using Deliver = std::function<void(std::string_view, bool)>;
 bool Feed(std::string_view bytes, bool orig, const Deliver& deliver);
 bool Complete() const { return !failed && stage == Stage::Tunnel; }
 void Stop() { failed = true; buffers = {}; }
private:
 enum class Stage { Greeting, V4Reply, Selection, Credentials, Authentication, Request, Reply, Tunnel };
 Stage stage = Stage::Greeting;
 bool failed = false;
 std::array<std::string, 2> buffers;
 std::string methods;
 bool ExpectedOriginator() const;
 bool Process(const Deliver& deliver);
};

// Native HTTP already splits/reassembles lines. Keep only phase flags, never
// header bytes, and leave bodies and established tunnel payloads untouched.
class HTTPHeaderState {
public:
 void Request(bool is_connect) { if (!tunnel) connect=is_connect; }
 bool Reject() { if (invalid) return false; invalid=true; return true; }
 bool Observe(std::string_view line,bool orig,bool ongoing,int status) {
  if (invalid || tunnel) return true;
  const size_t direction=orig?0:1;
  if (!ongoing) headers[direction]=true;
  if (!headers[direction]) return true;
  // Native HTTP accepts a valid prefix of version/status tokens. Require
  // complete tokens before their parsed values can become tunnel evidence.
  if (!orig && !ongoing && !ResponseLine(line)) return !Reject();
  if (line.find('\0')!=std::string_view::npos) return !Reject();
  if (line.empty()) {
   headers[direction]=false;
   if (!orig && connect && status>=200 && status<300) tunnel=true;
  }
  return true;
 }
private:
 static bool Space(char c) { return c==' ' || c=='\t'; }
 static bool Digit(char c) { return c>='0' && c<='9'; }
 static bool ResponseLine(std::string_view line) {
  if (line.size()<12 || (line[0]!='H' && line[0]!='h') ||
      (line[1]!='T' && line[1]!='t') || (line[2]!='T' && line[2]!='t') ||
      (line[3]!='P' && line[3]!='p') || line[4]!='/' || !Digit(line[5]) ||
      line[6]!='.' || !Digit(line[7]) || !Space(line[8])) return false;
  size_t code=8;
  while (code<line.size() && Space(line[code])) ++code;
  return line.size()-code>=3 && Digit(line[code]) && Digit(line[code+1]) &&
      Digit(line[code+2]) && (line.size()==code+3 || Space(line[code+3]));
 }
 std::array<bool,2> headers{true,true};
 bool connect=false,tunnel=false,invalid=false;
};
