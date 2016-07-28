// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef UNIK_REGISTER_INSTANCE_HPP
#define UNIK_REGISTER_INSTANCE_HPP

#include <net/inet4>
#include <regex>
#include <info>

std::unique_ptr<net::Inet4<VirtioNet> > inet;

/**
 * UniK instance listener hearbeat / http registration
 **/ 

namespace unik {
  
  void register_instance(const net::UDP::port_t port = 9876) {
    
    // Bring up a network device
    auto& eth0 = hw::Dev::eth<0, VirtioNet>();
    
    // Bring up an IP stack on top of the device
    inet = std::make_unique<net::Inet4<VirtioNet> >(eth0);
    
    // Wait for DHCP
    inet->dhclient()->on_config([port](bool timeout) {
	
	if(timeout) {
	  INFO("Unik client","DHCP request timed out. \n");
	  return;
	}
	
	INFO("Unik client","IP address updated: %s\n", inet->ip_addr().str().c_str());
	INFO("Unik client","Listening for UDP hearbeat on port %i\n", port);
	
	// Set up an UDP port for receiving UniK heartbeat
	auto& sock = inet->udp().bind(port);
	
	INFO("Unik client","IP address updated: %s\n", inet->ip_addr().str().c_str());
	sock.on_read([&sock] (auto addr, auto port, const char* data, size_t len) {
	    	    	    
	    static bool registered_with_unik = false;
	    static const int max_attempts = 5;
	    static int attempts_left = max_attempts;
	    
	    if (registered_with_unik or not attempts_left) 
	      return;	
	    
	    std::string strdata(data, len);
	    INFO("Unik client","received UDP data from %s:%i: %s \n", addr.str().c_str(), port, strdata.c_str());
	    
	    auto dotloc = strdata.find(":");
	    
	    if (dotloc == std::string::npos) {
	      INFO("Unik client","Unexpected UDP data format - no ':' in string.\n");
	      return;
	    }
	    
	    std::string prefix = strdata.substr(0,dotloc);
	    std::string ip_str = strdata.substr(dotloc + 1);
	    
	    INFO("Unik client","Prefix: %s , IP: %s \n", prefix.c_str(), ip_str.c_str());
	    
	    // Parse Unik instance listener IP address
	    // @note : IncludeOS lacks facilities to construct IP from string (we use e.g. {192,168,0,1})
	    // Issue #687 will fix this.
	    const std::regex ip_address_pattern
	    {
	      "^(25[0–5]|2[0–4]\\d|[01]?\\d\\d?)\\."
          "(25[0–5]|2[0–4]\\d|[01]?\\d\\d?)\\."
          "(25[0–5]|2[0–4]\\d|[01]?\\d\\d?)\\."
          "(25[0–5]|2[0–4]\\d|[01]?\\d\\d?)$"
	    };

	    std::smatch ip_parts;
	    
	    if (not std::regex_match(ip_str, ip_parts, ip_address_pattern)) {
	      INFO("Unik client","Couldn't parse IP address\n");
	      return;
	    }
	    
	    net::IP4::addr ip
	    {
	      static_cast<uint8_t>(std::stoi(ip_parts[1])),
		  static_cast<uint8_t>(std::stoi(ip_parts[2])),
		  static_cast<uint8_t>(std::stoi(ip_parts[3])),
		  static_cast<uint8_t>(std::stoi(ip_parts[4]))
		};

	    net::TCP::Socket unik_instance_listener {ip , 3000};
	    
	    attempts_left --;
	    INFO("Unik client", "Connecting to UniK instance listener %s:%i (attempt %i / %i) \n", 
		 ip.str().c_str(), 3000, max_attempts - attempts_left, max_attempts);
	    
	    // Connect to the instance listener
	    auto http = inet->tcp().connect(unik_instance_listener);
	   
	    http->onConnect([&http](auto unik) {
		
		// Get our mac address
		// @note: IncludeOS mac address string representation doesn't include leading zeros, causing issues with unik.
		// Issue #688 will fix this, and we can do like so: 
		// auto mac_str = inet->link_addr().str();		
		auto mac = inet->link_addr();
		char mac_str[18];
		snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
			 mac.part[0], mac.part[1], mac.part[2],
			 mac.part[3], mac.part[4], mac.part[5]);
		
		// Construct a HTTP request to the Unik instance listener, providing our mac-address in the query string
		std::string http_request="POST /register?mac_address=" + std::string(mac_str) + " HTTP/1.1\r\n\n";
		printf("Connected to UniK instance listener. Sending HTTP request: %s \n", http_request.c_str());
		
		unik->write(http_request.c_str(), http_request.size());
		
		// Expect a response with meta data (which we ignore)
		unik->read(1024, [&http](auto buf, size_t n) {
		    std::string response((char*)buf.get(), n);
		    printf("UniK reply: %s \n", response.c_str());	      
		    
		    if (response.find("200 OK") != std::string::npos) {
		      registered_with_unik = true;
		      return;
		    }
		    
		    http->close();
		    
		  });				
	      });
	  }); 
      });
  } // register_instance
} // Namespace
      
#endif
