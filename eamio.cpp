#include "bemanitools/eamio.h"

#include "server_http.hpp"
#include "server_ws.hpp"

#include <algorithm>
#include <vector>
#include <fstream>
#include <unordered_set>
#include <future>
#include <bitset>

typedef SimpleWeb::SocketServer<SimpleWeb::WS> WsServer;
typedef SimpleWeb::Server<SimpleWeb::HTTP> HttpServer;

#include "index.html.h"
#include "scanner.html.h"

HttpServer http_server;
WsServer ws_server;
int server_thread;

log_formatter_t misc_ptr;
log_formatter_t info_ptr;
log_formatter_t warning_ptr;
log_formatter_t fatal_ptr;

thread_create_t thread_create_ptr;
thread_join_t thread_join_ptr;
thread_destroy_t thread_destroy_ptr;

std::bitset<EAM_IO_KEYPAD_COUNT> keypad_state[2];
uint8_t ID[2][8];
uint16_t ID_TIMER[2] = {0, 0};
std::map<std::string, std::string> cardid_mapper;
 
unsigned char hexval(char c){
	if ('0' <= c && c <= '9') { return c - '0'; }
	if ('a' <= c && c <= 'f') { return c + 10 - 'a'; }
	if ('A' <= c && c <= 'F') { return c + 10 - 'A'; }
	throw "Eeek";
	return 0;
}

void eam_io_set_loggers(log_formatter_t misc, log_formatter_t info, log_formatter_t warning, log_formatter_t fatal)
{
	misc_ptr = misc;
	info_ptr = info;
	warning_ptr = warning;
	fatal_ptr = fatal;
}

bool eam_io_init(thread_create_t thread_create, thread_join_t thread_join, thread_destroy_t thread_destroy)
{
	http_server.config.port = 573;

	auto& reader_endpoint = ws_server.endpoint["^/reader/?$"];

	http_server.resource["^/scanner/([0-9]+)/$"]["GET"] = [](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request) {
		std::string number = request->path_match[1];

		uint16_t unitno = std::stoul(number);
		if (unitno >= 2){
			unitno = 0;
		}

		SimpleWeb::CaseInsensitiveMultimap query = request->parse_query_string();

		auto &it2 = query.find("TYPE");
		if (it2 != query.end()){
			std::string type = it2->second;
		}

		auto &it = query.find("ID");
		if (it != query.end()){
			info_ptr("web_eamio", "Recieved card id: %s", it->second);
			number += it->second;
			std::string id = it->second;
			id.erase(std::remove(id.begin(), id.end(), ':'), id.end());

			if (id.length() == 16){
				info_ptr("web_eamio", "Sanitized ID: %s", id);

				for (std::size_t i = 0; i < 8; ++i){
					uint8_t n = hexval(id[2 * i]) * 16 + hexval(id[2 * i + 1]);
					ID[unitno][i] = n;
				}
				ID_TIMER[unitno] = 32;
			}
		}


		*response << "HTTP/1.1 200 OK\r\nContent-Length: " << sizeof(SCANNER_HTML) << "\r\n\r\n"
			<< std::string(SCANNER_HTML, sizeof(SCANNER_HTML));

	};

	http_server.resource["^/_mapping/get"]["GET"] = [](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request) {
		std::string str;

		for (const auto& kv : cardid_mapper) {
			str += "\"";
			str += kv.first;
			str += "\": \"";
			str += kv.second;
			str += "\"\n";
		}


		*response << "HTTP/1.1 200 OK\r\nContent-Length: " << str.length() << "\r\n\r\n"
			<< str;
	};

	http_server.resource["^/pad"]["GET"] = [](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request) {
		*response << "HTTP/1.1 200 OK\r\nContent-Length: " << sizeof(INDEX_HTML) << "\r\n\r\n"
			<< std::string(INDEX_HTML, sizeof(INDEX_HTML));
	};

	http_server.default_resource["GET"] = [](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request) {
		SimpleWeb::CaseInsensitiveMultimap header;

		header.emplace("Location", "http:/pad");
		response->write(SimpleWeb::StatusCode::redirection_temporary_redirect, header);
	};

	http_server.on_upgrade = [&](std::unique_ptr<SimpleWeb::HTTP> &socket, std::shared_ptr<HttpServer::Request> request) {
		auto connection = std::make_shared<WsServer::Connection>(std::move(socket));
		connection->method = std::move(request->method);
		connection->path = std::move(request->path);
		connection->http_version = std::move(request->http_version);
		connection->header = std::move(request->header);
		connection->remote_endpoint_address = std::move(request->remote_endpoint_address);
		connection->remote_endpoint_port = request->remote_endpoint_port;
		ws_server.upgrade(connection);
	};


	reader_endpoint.on_message = [](std::shared_ptr<WsServer::Connection> connection, std::shared_ptr<WsServer::Message> message) {
		auto message_str = message->string();

		uint8_t cardno = 0;
		if (message_str[0] == '0'){

		}else if (message_str[0] == '1'){
			cardno = 1;
		}else{
			return;
		}

		std::size_t pos_start = message_str.find("start: ");
		if (pos_start == 1){
			std::string num = message_str.substr(1 + 7);
			if (num == "00"){
				keypad_state[cardno][EAM_IO_KEYPAD_00] = 1;
			} else if (num == "."){
				keypad_state[cardno][EAM_IO_KEYPAD_DECIMAL] = 1;
			} else if (num == "1"){
				keypad_state[cardno][EAM_IO_KEYPAD_1] = 1;
			} else if (num == "2"){
				keypad_state[cardno][EAM_IO_KEYPAD_2] = 1;
			} else if (num == "3"){
				keypad_state[cardno][EAM_IO_KEYPAD_3] = 1;
			} else if (num == "4"){
				keypad_state[cardno][EAM_IO_KEYPAD_4] = 1;
			} else if (num == "5"){
				keypad_state[cardno][EAM_IO_KEYPAD_5] = 1;
			} else if (num == "6"){
				keypad_state[cardno][EAM_IO_KEYPAD_6] = 1;
			} else if (num == "7"){
				keypad_state[cardno][EAM_IO_KEYPAD_7] = 1;
			} else if (num == "8"){
				keypad_state[cardno][EAM_IO_KEYPAD_8] = 1;
			} else if (num == "9"){
				keypad_state[cardno][EAM_IO_KEYPAD_9] = 1;
			} else if (num == "0"){
				keypad_state[cardno][EAM_IO_KEYPAD_0] = 1;
			}
		}
		std::size_t pos_end = message_str.find("end: ");
		if (pos_end == 1){
			std::string num = message_str.substr(1 + 5);
			if (num == "00"){
				keypad_state[cardno][EAM_IO_KEYPAD_00] = 0;
			} else if (num == "."){
				keypad_state[cardno][EAM_IO_KEYPAD_DECIMAL] = 0;
			} else if (num == "1"){
				keypad_state[cardno][EAM_IO_KEYPAD_1] = 0;
			} else if (num == "2"){
				keypad_state[cardno][EAM_IO_KEYPAD_2] = 0;
			} else if (num == "3"){
				keypad_state[cardno][EAM_IO_KEYPAD_3] = 0;
			} else if (num == "4"){
				keypad_state[cardno][EAM_IO_KEYPAD_4] = 0;
			} else if (num == "5"){
				keypad_state[cardno][EAM_IO_KEYPAD_5] = 0;
			} else if (num == "6"){
				keypad_state[cardno][EAM_IO_KEYPAD_6] = 0;
			} else if (num == "7"){
				keypad_state[cardno][EAM_IO_KEYPAD_7] = 0;
			} else if (num == "8"){
				keypad_state[cardno][EAM_IO_KEYPAD_8] = 0;
			} else if (num == "9"){
				keypad_state[cardno][EAM_IO_KEYPAD_9] = 0;
			} else if (num == "0"){
				keypad_state[cardno][EAM_IO_KEYPAD_0] = 0;
			}
		}
	};

	info_ptr("web_eamio", "Launching Server");
	server_thread = thread_create([](void* ctx) {
		info_ptr("web_eamio", "thread_create: Launching Server");
		http_server.start();
		return 0;
	}, nullptr, 0x4000, 0);
	info_ptr("web_eamio", "Launched Server ID: %d", server_thread);

	thread_create_ptr = thread_create;
	thread_join_ptr = thread_join;
	thread_destroy_ptr = thread_destroy;

	return true;
}

void eam_io_fini(void)
{
	int result;
	http_server.stop();
	thread_join_ptr(server_thread, &result);
}

uint16_t eam_io_get_keypad_state(uint8_t unit_no)
{
	if (unit_no >= 2){
		return 0;
	}
	return keypad_state[unit_no].to_ulong();
}

uint8_t eam_io_get_sensor_state(uint8_t unit_no)
{
	if (unit_no >= 2){
		return 0;
	}
	if (ID_TIMER[unit_no]){
		--ID_TIMER[unit_no];
		return 3;
	}
	return 0;
}

uint8_t eam_io_read_card(uint8_t unit_no, uint8_t * card_id, uint8_t nbytes)
{
	if (unit_no >= 2){
		return EAM_IO_CARD_NONE;
	}

	if (ID[unit_no][6] == 0x04 && ID[unit_no][7] == 0xe0)
	{
		for (size_t i = 0; i < 8; ++i)
		{
			card_id[i] = ID[unit_no][7 - i];
		}
	}
	else
	{
		memcpy(card_id, ID[unit_no], nbytes);
	}

	info_ptr("web_eamio", "Actual lo: %x", *(uint32_t*)card_id);
	info_ptr("web_eamio", "Actual hi: %x", *(uint32_t*)(card_id + 4));

	if (card_id[0] == 0xe0 && card_id[1] == 0x04) {
		info_ptr("web_eamio", "Found: EAM_IO_CARD_ISO15696");
		return EAM_IO_CARD_ISO15696;
	} else {
		info_ptr("web_eamio", "Found: EAM_IO_CARD_FELICA");
		return EAM_IO_CARD_FELICA;
	}
}

bool eam_io_card_slot_cmd(uint8_t unit_no, uint8_t cmd)
{
	return false;
}

bool eam_io_poll(uint8_t unit_no)
{
	return true;
}

const eam_io_config_api * eam_io_get_config_api(void)
{
	return nullptr;
}
